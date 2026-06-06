"""Command-line interface for PromptShield.

    promptshield scan <path>            # walk a repo/file
    promptshield scan --diff <ref>      # scan git diff added lines + commits
    promptshield scan --pr <file.json>  # scan a gh-api PR-files JSON

HIGH findings make the command exit with status 1 so it drops straight into CI.
"""

from __future__ import annotations

import sys

import click

from promptshield import __version__
from promptshield.baseline import (
    DEFAULT_BASELINE_NAME,
    Baseline,
    write_baseline,
)
from promptshield.report import render_json, render_table
from promptshield.rules import load_rules
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
    "rules_path",
    metavar="FILE",
    type=click.Path(exists=True, dir_okay=False),
    help="Use a custom rules.yaml instead of the packaged ruleset.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON instead of the Rich table.",
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
    rules_path: str | None,
    as_json: bool,
    no_color: bool,
    repo: str,
) -> None:
    """Scan PATH (default: current dir), or a diff/PR, for hidden injections."""
    if diff_ref and pr_json:
        raise click.UsageError("--diff and --pr are mutually exclusive.")

    rules = load_rules(rules_path) if rules_path else None
    # When updating the baseline we capture *all* findings, so don't pre-filter.
    active_baseline = None if update_baseline else Baseline.load(baseline_path)

    try:
        if pr_json:
            result = scan_pr_json(pr_json, rules=rules, baseline=active_baseline)
        elif diff_ref:
            result = scan_diff(
                diff_ref, repo=repo, rules=rules, baseline=active_baseline
            )
        else:
            result = scan_path(path, rules=rules, baseline=active_baseline)
    except (RuntimeError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    if update_baseline:
        n = write_baseline(result.findings, baseline_path)
        click.echo(f"Wrote {n} findings to baseline {baseline_path}.")
        sys.exit(0)

    if as_json:
        render_json(result)
    else:
        render_table(result, no_color=no_color)

    sys.exit(result.exit_code)


if __name__ == "__main__":
    main()
