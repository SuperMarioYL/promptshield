"""Command-line interface for PromptShield.

    promptshield scan <path>            # walk a repo/file
    promptshield scan --diff <ref>      # scan git diff added lines + commits
    promptshield scan --pr <file.json>  # scan a gh-api PR-files JSON

HIGH findings make the command exit with status 1 so it drops straight into CI.
"""

from __future__ import annotations

import sys

import click
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

    rules = load_rule_packs(list(rules_paths)) if rules_paths else None
    # When updating the baseline we capture *all* findings, so don't pre-filter.
    active_baseline = None if update_baseline else Baseline.load(baseline_path)
    decode = not no_decode

    try:
        if pr_json:
            result = scan_pr_json(
                pr_json, rules=rules, baseline=active_baseline, decode=decode
            )
        elif diff_ref:
            result = scan_diff(
                diff_ref,
                repo=repo,
                rules=rules,
                baseline=active_baseline,
                decode=decode,
            )
        else:
            result = scan_path(
                path, rules=rules, baseline=active_baseline, decode=decode
            )
    except (RuntimeError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    if update_baseline:
        n = write_baseline(result.findings, baseline_path)
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
    active: list[Rule] = (
        load_rule_packs(list(rules_paths)) if rules_paths else load_rules()
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
