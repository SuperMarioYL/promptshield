"""Baseline suppression — accept known Findings so the tool is adoptable.

A baseline file (`.promptshield-baseline.yaml`) lists fingerprints of findings a
team has reviewed and accepted. On the next scan, matching findings are filtered
out, so PromptShield can be dropped onto a noisy legacy repo and only surface
*new* issues.

A fingerprint is ``rule_id + file + sha1(normalized-excerpt)`` — stable across
re-runs but sensitive to the actual flagged text changing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import yaml

from promptshield.rules import Finding

DEFAULT_BASELINE_NAME = ".promptshield-baseline.yaml"


def fingerprint(finding: Finding) -> str:
    """Stable fingerprint = rule_id + file + sha1(normalized excerpt)."""
    digest = hashlib.sha1(
        finding.fingerprint_excerpt().encode("utf-8")
    ).hexdigest()[:16]
    return f"{finding.rule_id}:{finding.file}:{digest}"


@dataclass
class Baseline:
    """A set of accepted finding fingerprints."""

    fingerprints: set[str]

    @classmethod
    def empty(cls) -> Baseline:
        return cls(fingerprints=set())

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        """Load a baseline file; missing file yields an empty baseline."""
        p = Path(path)
        if not p.exists():
            return cls.empty()
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        entries = data.get("findings", []) if isinstance(data, dict) else []
        fps = {
            e["fingerprint"]
            for e in entries
            if isinstance(e, dict) and "fingerprint" in e
        }
        return cls(fingerprints=fps)

    def is_suppressed(self, finding: Finding) -> bool:
        return fingerprint(finding) in self.fingerprints

    def filter(self, findings: list[Finding]) -> list[Finding]:
        """Return only findings not present in the baseline."""
        return [f for f in findings if not self.is_suppressed(f)]


def write_baseline(findings: list[Finding], path: str | Path) -> int:
    """Write a baseline file capturing all ``findings``. Returns the count."""
    entries = []
    for f in findings:
        entries.append(
            {
                "fingerprint": fingerprint(f),
                "rule_id": f.rule_id,
                "file": f.file,
                "line": f.line,
                "excerpt": f.excerpt,
            }
        )
    doc = {
        "version": 1,
        "note": "Findings accepted via `promptshield scan --update-baseline`.",
        "findings": entries,
    }
    Path(path).write_text(
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return len(entries)
