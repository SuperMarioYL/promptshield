"""Reporting — render a ScanResult as a Rich table or JSON.

The default human view is a colored findings table plus a severity-count
summary line. ``--json`` emits a machine-readable document for CI tooling.
"""

from __future__ import annotations

import dataclasses
import json
import sys

from rich.console import Console
from rich.table import Table
from rich.text import Text

from promptshield.rules import Severity
from promptshield.scanner import ScanResult

_SEVERITY_STYLE = {
    Severity.HIGH: "bold white on red",
    Severity.MED: "bold black on yellow",
    Severity.LOW: "cyan",
}

_SEVERITY_COLOR = {
    Severity.HIGH: "red",
    Severity.MED: "yellow",
    Severity.LOW: "cyan",
}


def _console(no_color: bool) -> Console:
    return Console(stderr=False, no_color=no_color, highlight=False)


def render_table(result: ScanResult, *, no_color: bool = False) -> None:
    """Print the Rich findings table + summary to stdout."""
    console = _console(no_color)

    if not result.findings:
        console.print(
            Text("✓ No prompt-injection findings.", style="bold green")
        )
        _print_summary(console, result)
        return

    table = Table(
        title="PromptShield findings",
        title_style="bold",
        show_lines=False,
        expand=False,
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Location", no_wrap=True, style="dim")
    table.add_column("Surface", no_wrap=True, style="dim")
    table.add_column("Excerpt", overflow="fold")

    for f in result.findings:
        sev = Text(f.severity.value, style=_SEVERITY_STYLE[f.severity])
        # Prefix a decoded-variant finding's excerpt with its encoding layer
        # (m12) so a base64/hex hit is not mistaken for a false positive on the
        # opaque blob visible in the file.
        excerpt = f"[{f.decoded_from}] {f.excerpt}" if f.decoded_from else f.excerpt
        table.add_row(
            sev,
            f.rule_id,
            f.category,
            f"{f.file}:{f.line}",
            f.surface.value,
            excerpt,
        )

    console.print(table)
    _print_why(console, result)
    _print_summary(console, result)


def _print_why(console: Console, result: ScanResult) -> None:
    """Print the rationale for HIGH findings so each flag carries evidence."""
    highs = [f for f in result.findings if f.severity is Severity.HIGH]
    if not highs:
        return
    console.print()
    seen: set[str] = set()
    for f in highs:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        console.print(
            Text(f"  {f.rule_id}: ", style="bold red")
            + Text(f.why, style="default")
        )


def _print_summary(console: Console, result: ScanResult) -> None:
    parts = []
    for sev in (Severity.HIGH, Severity.MED, Severity.LOW):
        n = result.counts.get(sev, 0)
        parts.append(Text(f"{n} {sev.value}", style=_SEVERITY_COLOR[sev]))
    summary = Text("Scanned ", style="dim")
    summary.append(str(result.surface_count), style="bold")
    summary.append(" surfaces · ", style="dim")
    for i, p in enumerate(parts):
        if i:
            summary.append(" · ", style="dim")
        summary.append_text(p)
    if result.suppressed_count:
        summary.append(
            f" · {result.suppressed_count} suppressed", style="dim"
        )
    console.print()
    console.print(summary)
    if result.has_high:
        console.print(
            Text(
                "✗ HIGH findings present — exit 1 (CI gate failed).",
                style="bold red",
            )
        )


def render_json(result: ScanResult) -> None:
    """Emit a machine-readable JSON document to stdout."""
    doc = {
        "surface_count": result.surface_count,
        "suppressed_count": result.suppressed_count,
        "counts": {sev.value: result.counts.get(sev, 0) for sev in Severity},
        "exit_code": result.exit_code,
        "findings": [
            {
                **dataclasses.asdict(f),
                "severity": f.severity.value,
                "surface": f.surface.value,
            }
            for f in result.findings
        ],
    }
    json.dump(doc, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
