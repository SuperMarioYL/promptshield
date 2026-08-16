"""Command-line interface for PromptShield.

    promptshield scan <path>            # walk a repo/file
    promptshield scan --diff <ref>      # scan git diff added lines + commits
    promptshield scan --pr <file.json>  # scan a gh-api PR-files JSON

HIGH findings make the command exit with status 1 so it drops straight into CI.
"""

from __future__ import annotations

import re
import sys

import click
import yaml
from rich.console import Console
from rich.table import Table

from promptshield import __version__
from promptshield.baseline import (
    DEFAULT_BASELINE_NAME,
    Baseline,
    write_baseline,
)
from promptshield.report import render_json, render_table
from promptshield.rules import Rule, load_rule_packs, load_rules
from promptshield.sarif import sarif_json
from promptshield.scanner import scan_diff, scan_path, scan_pr_json

# ---------------------------------------------------------------------------
# Shared guarded loader for user-supplied ``--rules`` packs (scan + rules list)
# ---------------------------------------------------------------------------


def _load_rule_packs_guarded(rules_paths: tuple[str, ...]) -> list[Rule]:
    """Load stacked ``--rules`` packs, surfacing a malformed/invalid pack as a
    clean ``click.ClickException`` instead of a raw traceback.

    ``load_rule_packs`` (rules.py) parses and compiles user-supplied YAML, which
    can fail at two levels:

    * file-level — a YAML *syntax* error raises ``yaml.YAMLError`` (v0.8.0,
      fix-malformed-baseline-rules-yaml-crash), and an invalid-UTF-8 byte
      raises ``UnicodeDecodeError`` (v0.9.0, fix-baseline-rules-invalid-utf8-
      crash);
    * rule-semantic — a typo'd regex raises ``re.error`` during ``re.compile``
      (NOT a subclass of YAMLError/UnicodeDecodeError/ValueError — verified
      issubclass), and a typo'd severity / unknown category / missing key /
      duplicate id raises ``ValueError`` (v0.10.0,
      fix-scan-rules-semantic-error-crash).

    The v0.8/v0.9 guard caught only the file-level pair; the rule-semantic
    siblings crashed the CLI with a raw traceback on the identical
    hand-edited-pack scenario. v0.10.0 widens the tuple to also catch
    ``ValueError, re.error``. This helper is shared by both ``scan`` and
    ``rules list`` so the two commands cannot diverge again
    (fix-rules-list-unguarded-load — ``rules list`` previously had NO guard at
    all). ``click.Path(exists=True)`` on the ``--rules`` option already covers
    ``FileNotFoundError``; only the parse/compile failures need guarding here.
    """
    try:
        return load_rule_packs(list(rules_paths))
    except (yaml.YAMLError, UnicodeDecodeError, ValueError, re.error) as exc:
        raise click.ClickException(
            f"rules file is malformed or not valid UTF-8 "
            f"({', '.join(rules_paths)}): {exc}; fix the file and re-run"
        ) from exc


@click.group()
@click.version_option(__version__, prog_name="promptshield")
def main() -> None:
    """PromptShield — scan code your AI coding agent reads, before it obeys it."""


@main.command()
@click.argument("path", required=False, default=".", type=click.Path())
@click.option(
    "--diff",
    "diff_ref",
    metavar="REF",
    help="Scan only added lines + new commit messages of `git diff REF`.",
)
@click.option(
    "--pr",
    "pr_json",
    metavar="FILE.json",
    type=click.Path(exists=True, dir_okay=False),
    help="Scan a `gh api .../files` PR-files JSON document.",
)
@click.option(
    "--baseline",
    "baseline_path",
    metavar="FILE",
    default=DEFAULT_BASELINE_NAME,
    show_default=True,
    help="Baseline file of accepted findings to suppress.",
)
@click.option(
    "--update-baseline",
    is_flag=True,
    help="Write all current findings to the baseline file and exit 0.",
)
@click.option(
    "--rules",
    "rules_paths",
    metavar="FILE_OR_DIR",
    multiple=True,
    type=click.Path(exists=True),
    help=(
        "Custom rules.yaml or a directory of them. Repeatable; packs stack in "
        "order and later packs override same-id built-ins."
    ),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    show_default=True,
    help="Output format. `sarif` emits a SARIF 2.1.0 log for CI ingestion.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Alias for --format json (back-compat).",
)
@click.option(
    "--no-decode",
    is_flag=True,
    help="Disable the obfuscation decode pass (base64/hex/zero-width/homoglyph).",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored output.",
)
@click.option(
    "--repo",
    metavar="DIR",
    default=".",
    help="Repository directory for --diff (default: current dir).",
)
def scan(
    path: str,
    diff_ref: str | None,
    pr_json: str | None,
    baseline_path: str,
    update_baseline: bool,
    rules_paths: tuple[str, ...],
    fmt: str,
    as_json: bool,
    no_decode: bool,
    no_color: bool,
    repo: str,
) -> None:
    """Scan PATH (default: current dir), or a diff/PR, for hidden injections."""
    if diff_ref and pr_json:
        raise click.UsageError("--diff and --pr are mutually exclusive.")
    # --json is a back-compat alias for --format json; it can't combine with
    # an explicit non-json --format.
    if as_json and fmt == "sarif":
        raise click.UsageError("--json is incompatible with --format sarif.")
    if as_json:
        fmt = "json"

    # ``--rules`` packs are user-supplied YAML parsed/compiled OUTSIDE the scan
    # try/except below; a hand-edited or malformed pack would crash the CLI with
    # a raw traceback (``yaml.YAMLError`` / ``UnicodeDecodeError`` / ``re.error``
    # / ``ValueError``) instead of a clean error. The shared guarded loader
    # surfaces a clear, path-aware message and is reused by ``rules list`` so
    # the two commands cannot diverge (v0.8.0 -> v0.9.0 -> v0.10.0
    # crash-handling arc; fix-scan-rules-semantic-error-crash,
    # fix-rules-list-unguarded-load).
    rules = _load_rule_packs_guarded(rules_paths) if rules_paths else None
    # When updating the baseline we capture *all* findings, so don't pre-filter.
    # Use an EMPTY baseline (not None) so that forwarding ``baseline_path`` to
    # the scan seam below can't trigger delegated baseline loading/filtering
    # inside ``_resolve_baseline`` (which treats ``baseline=None`` as "load
    # from baseline_path") — that would drop already-accepted findings on a
    # re-baseline and shrink the written baseline. An empty baseline filters
    # nothing, preserving the capture-all promise (fix-cli-custom-baseline-name-
    # self-scan).
    #
    # ``Baseline.load`` parses the (often hand-edited ``--update-baseline``
    # artifact) baseline YAML outside the scan try/except; a syntax error
    # introduced while reviewing/trimming accepted findings would crash the CLI
    # with a raw ``yaml.YAMLError`` traceback. Catch it here and surface a
    # clear, path-aware message. A MISSING baseline file is intentionally NOT
    # an error (``Baseline.load`` returns empty so the default
    # ``.promptshield-baseline.yaml`` is silent on a fresh repo) — only the
    # YAML-syntax failure is guarded (fix-malformed-baseline-rules-yaml-crash).
    #
    # v0.9.0 (fix-baseline-rules-invalid-utf8-crash): the v0.8.0 guard caught
    # ``yaml.YAMLError`` (a YAML *syntax* error) but NOT ``UnicodeDecodeError`` —
    # ``Baseline.load`` reads with strict ``read_text(encoding="utf-8")``, so a
    # baseline file containing invalid UTF-8 BYTES (a stray ``\xff``, or a file
    # saved as Latin-1/CP1252 during a hand-edit) raised an uncaught
    # ``UnicodeDecodeError`` (a ``ValueError``, NOT a ``yaml.YAMLError``) and
    # crashed the CLI with a raw traceback — the encoding sibling v0.8.0 missed.
    # Widen the except tuple to also catch ``UnicodeDecodeError`` so a
    # bad-encoding baseline surfaces the same clean, path-aware error.
    try:
        active_baseline = (
            Baseline.empty() if update_baseline else Baseline.load(baseline_path)
        )
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise click.ClickException(
            f"baseline file {baseline_path} is malformed or not valid UTF-8: "
            f"{exc}; fix the file and re-run"
        ) from exc
    decode = not no_decode

    try:
        if pr_json:
            result = scan_pr_json(
                pr_json,
                rules=rules,
                baseline=active_baseline,
                baseline_path=baseline_path,
                decode=decode,
            )
        elif diff_ref:
            result = scan_diff(
                diff_ref,
                repo=repo,
                rules=rules,
                baseline=active_baseline,
                baseline_path=baseline_path,
                decode=decode,
            )
        else:
            result = scan_path(
                path,
                rules=rules,
                baseline=active_baseline,
                baseline_path=baseline_path,
                decode=decode,
            )
    except (RuntimeError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    if update_baseline:
        # ``write_baseline`` (baseline.py) opens ``baseline_path`` for writing
        # OUTSIDE the scan try/except above — a ``--baseline`` path whose parent
        # directory does not exist raises an uncaught ``FileNotFoundError``
        # (an ``OSError``), and a read-only / unwritable target directory raises
        # a ``PermissionError``. Both crashed the CLI with a raw traceback +
        # exit 1 instead of a clean ``click.ClickException`` on the identical
        # "user points --baseline somewhere odd" scenario the v0.8.0 / v0.9.0 /
        # v0.10.0 crash-handling arc already closed for the LOAD side
        # (``Baseline.load`` / ``load_rule_packs``). This is the unguarded WRITE
        # sibling of that arc — guard it the same way
        # (fix-update-baseline-write-unguarded-oserror).
        try:
            n = write_baseline(result.findings, baseline_path)
        except OSError as exc:
            raise click.ClickException(
                f"cannot write baseline file {baseline_path}: {exc}; "
                f"check the path and permissions"
            ) from exc
        click.echo(f"Wrote {n} findings to baseline {baseline_path}.")
        sys.exit(0)

    if fmt == "sarif":
        click.echo(sarif_json(result, tool_version=__version__))
    elif fmt == "json":
        render_json(result)
    else:
        render_table(result, no_color=no_color)

    sys.exit(result.exit_code)


# ---------------------------------------------------------------------------
# `promptshield rules list` — inspect the active merged ruleset
# ---------------------------------------------------------------------------


@main.group()
def rules() -> None:
    """Inspect the active ruleset (built-in + stacked packs)."""


@rules.command("list")
@click.option(
    "--rules",
    "rules_paths",
    metavar="FILE_OR_DIR",
    multiple=True,
    type=click.Path(exists=True),
    help="Custom rules.yaml or a directory of them (same stacking as `scan`).",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored output.",
)
def rules_list(
    rules_paths: tuple[str, ...],
    no_color: bool,
) -> None:
    """Print the active merged ruleset (one row per rule)."""
    # ``--rules`` packs were parsed/compiled here with NO guard in v0.9.0, so a
    # malformed/invalid pack crashed ``rules list`` with a raw traceback on the
    # identical input ``scan`` already handled. Reuse the shared guarded loader
    # so the two commands cannot diverge (fix-rules-list-unguarded-load).
    active: list[Rule] = (
        _load_rule_packs_guarded(rules_paths) if rules_paths else load_rules()
    )
    console = Console(no_color=no_color, highlight=False)
    table = Table(
        title="PromptShield active ruleset",
        title_style="bold",
        show_lines=False,
        expand=False,
    )
    table.add_column("Source", no_wrap=True, style="dim")
    table.add_column("Rule", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Enabled", no_wrap=True)
    for r in active:
        table.add_row(
            r.source or "-",
            r.id,
            r.severity.value,
            r.category,
            "yes" if r.enabled else "no",
        )
    console.print(table)


if __name__ == "__main__":
    main()
