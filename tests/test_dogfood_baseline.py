"""Dogfood baseline regression (v0.15.0).

fix-dogfood-selfscan-red-ci: the repo's own "PromptShield" GitHub Action
    (.github/workflows/promptshield.yml, step "Scan repository",
    ``promptshield scan .``) failed on EVERY push to main since 2026-06-19 —
    the tool flags its own rules.yaml patterns, collectors.py fix docstrings,
    README evasion examples and test fixtures (87-99 HIGH findings per run,
    exit 1), because the repo never adopted its own m3 baseline mechanism even
    though README.md prescribes exactly that workflow
    (``promptshield scan . --update-baseline`` + ``git add
    .promptshield-baseline.yaml``). v0.15.0 ships that committed baseline, so
    the flagship CI gate is green while a NEW injection still fails it
    (fingerprints are rule_id + file + excerpt-scoped).

These tests enforce the dogfood contract on every commit: the repo must scan
green WITH the shipped baseline (and the baseline must actually be
suppressing something), while detection itself must still fire on the
un-baselined tree.
"""

from __future__ import annotations

from pathlib import Path

from promptshield.baseline import Baseline
from promptshield.scanner import scan_path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / ".promptshield-baseline.yaml"


def test_repo_scans_green_with_shipped_baseline():
    """The dogfood gate: `promptshield scan .` on this repo must be green.

    This is the exact scan the "PromptShield" workflow's gating step runs
    (``promptshield scan .`` from the repo root, which loads the default
    ``.promptshield-baseline.yaml``). If it regresses to HIGH findings, the
    flagship CI gate goes red again — refresh the baseline via
    ``promptshield scan . --update-baseline`` ONLY for intentional additions.
    """
    assert BASELINE_PATH.exists(), (
        "the committed .promptshield-baseline.yaml is missing — the repo's "
        "own CI gate (the PromptShield workflow) is red without it "
        "(fix-dogfood-selfscan-red-ci)"
    )
    result = scan_path(REPO_ROOT, baseline_path=BASELINE_PATH)
    assert not result.has_high, (
        "the repo's own scan must be green under the shipped baseline; "
        "unsuppressed HIGH findings (refresh the baseline only for "
        "intentional additions):\n"
        + "\n".join(
            f"  {f.rule_id} {f.file}:{f.line} {f.excerpt[:60]!r}"
            for f in result.findings
            if f.severity.value == "HIGH"
        )
    )


def test_shipped_baseline_actually_suppresses():
    """Guardrail: the baseline is doing real work, not vacuously green.

    If the tree produced no findings at all, ``suppressed_count`` would be 0 —
    meaning detection (not the baseline) made the scan green, which would make
    the dogfood test pass for the wrong reason.
    """
    result = scan_path(REPO_ROOT, baseline_path=BASELINE_PATH)
    assert result.suppressed_count > 0, (
        "the shipped baseline must suppress at least one finding — otherwise "
        "the green dogfood scan proves nothing about the baseline mechanism"
    )


def test_detection_still_fires_without_baseline():
    """Guardrail: the green dogfood scan is the baseline, not broken detection.

    Scanning ``src/`` with NO baseline must still yield HIGH findings (the
    tool's own source legitimately trips its rules — that is WHY the baseline
    exists). If this ever fails, the dogfood gate went green because
    detection broke.
    """
    result = scan_path(REPO_ROOT / "src", baseline=Baseline.empty())
    assert result.has_high, (
        "scanning src/ without the baseline must still find HIGH findings — "
        "otherwise the dogfood gate is green for the wrong reason"
    )
