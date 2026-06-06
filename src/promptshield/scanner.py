"""Scanner — orchestrate collectors -> rules -> baseline -> result.

This is the single seam the CLI and tests call. It picks a collector based on
the requested mode, runs the rule engine, applies baseline suppression, and
returns a :class:`ScanResult` carrying findings, severity counts, and the
surface count for reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from promptshield import collectors
from promptshield.baseline import Baseline
from promptshield.collectors import Surface
from promptshield.rules import Finding, Rule, Severity, load_rules, run_rules


@dataclass
class ScanResult:
    """The outcome of a scan."""

    findings: list[Finding]
    surface_count: int
    suppressed_count: int = 0
    counts: dict[Severity, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.counts:
            self.counts = {sev: 0 for sev in Severity}
            for f in self.findings:
                self.counts[f.severity] += 1

    @property
    def high_count(self) -> int:
        return self.counts.get(Severity.HIGH, 0)

    @property
    def has_high(self) -> bool:
        return self.high_count > 0

    @property
    def exit_code(self) -> int:
        """0 unless there are HIGH findings, in which case 1 (CI-friendly)."""
        return 1 if self.has_high else 0


def _scan_surfaces(
    surfaces: list[Surface],
    *,
    rules: list[Rule] | None,
    baseline: Baseline | None,
) -> ScanResult:
    rules = rules if rules is not None else load_rules()
    findings = run_rules(surfaces, rules)
    suppressed = 0
    if baseline is not None:
        before = len(findings)
        findings = baseline.filter(findings)
        suppressed = before - len(findings)
    return ScanResult(
        findings=findings,
        surface_count=len(surfaces),
        suppressed_count=suppressed,
    )


def _resolve_baseline(
    baseline: Baseline | None,
    baseline_path: str | Path | None,
) -> Baseline | None:
    if baseline is not None:
        return baseline
    if baseline_path is not None:
        return Baseline.load(baseline_path)
    return None


def scan_path(
    path: str | Path,
    *,
    rules: list[Rule] | None = None,
    baseline: Baseline | None = None,
    baseline_path: str | Path | None = None,
) -> ScanResult:
    """Walk ``path`` (file or dir), extract surfaces, and scan them."""
    surfaces = collectors.collect_path(path)
    return _scan_surfaces(
        surfaces,
        rules=rules,
        baseline=_resolve_baseline(baseline, baseline_path),
    )


def scan_diff(
    ref: str,
    *,
    repo: str | Path = ".",
    rules: list[Rule] | None = None,
    baseline: Baseline | None = None,
    baseline_path: str | Path | None = None,
) -> ScanResult:
    """Scan added lines + new commit messages of ``git diff <ref>``."""
    surfaces = collectors.collect_diff(ref, repo=repo)
    return _scan_surfaces(
        surfaces,
        rules=rules,
        baseline=_resolve_baseline(baseline, baseline_path),
    )


def scan_pr_json(
    pr_json: str | Path,
    *,
    rules: list[Rule] | None = None,
    baseline: Baseline | None = None,
    baseline_path: str | Path | None = None,
) -> ScanResult:
    """Scan a ``gh api`` PR-files JSON document."""
    surfaces = collectors.collect_pr_json(pr_json)
    return _scan_surfaces(
        surfaces,
        rules=rules,
        baseline=_resolve_baseline(baseline, baseline_path),
    )
