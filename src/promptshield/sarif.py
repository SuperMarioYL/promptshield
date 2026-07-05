"""SARIF 2.1.0 output — project a ScanResult into the industry-standard log.

SARIF (Static Analysis Results Intermediary Format) is the interchange format
GitHub code scanning, Azure DevOps, and other CI consumers ingest. This module
is a pure dict transform: it takes a :class:`~promptshield.scanner.ScanResult`
(or a plain ``list[Finding]``) and returns a JSON-serializable SARIF 2.1.0 log.
No I/O, no network — ``sarif_json`` just ``json.dumps`` what ``to_sarif``
builds so the CLI can echo it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from promptshield.rules import Finding, Severity
from promptshield.scanner import ScanResult

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_NAME = "PromptShield"
_INFORMATION_URI = "https://github.com/SuperMarioYL/promptshield"

# SARIF levels are the three standard static-analysis buckets; HIGH findings
# map to "error" so they surface as failing annotations in GitHub code scanning.
_LEVEL_FOR_SEVERITY: dict[Severity, str] = {
    Severity.HIGH: "error",
    Severity.MED: "warning",
    Severity.LOW: "note",
}


def _as_findings(result: ScanResult | Iterable[Finding]) -> list[Finding]:
    """Accept either a ScanResult or a bare iterable of Findings."""
    if isinstance(result, ScanResult):
        return list(result.findings)
    return list(result)


def _rule_entries(findings: list[Finding]) -> list[dict]:
    """One driver rule entry per distinct rule_id, in first-appearance order."""
    by_id: dict[str, Finding] = {}
    for f in findings:
        by_id.setdefault(f.rule_id, f)
    return [
        {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.why},
            "defaultConfiguration": {
                "level": _LEVEL_FOR_SEVERITY[f.severity]
            },
        }
        for f in by_id.values()
    ]


def _result_entry(f: Finding) -> dict:
    # For a decoded-variant finding, name the encoding layer in the message (m12)
    # so a code-scanning alert on a base64 blob explains where the text came from.
    excerpt = f"[{f.decoded_from}] {f.excerpt}" if f.decoded_from else f.excerpt
    return {
        "ruleId": f.rule_id,
        "level": _LEVEL_FOR_SEVERITY[f.severity],
        "message": {"text": f"{f.why}: {excerpt}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(f.line, 1)},
                }
            }
        ],
    }


def to_sarif(result: ScanResult | Iterable[Finding], *, tool_version: str) -> dict:
    """Return a SARIF 2.1.0 log dict for ``result``.

    ``result`` may be a :class:`ScanResult` or a plain ``list[Finding]``.
    ``tool_version`` is stamped into ``runs[0].tool.driver.version`` so consumers
    can tell which PromptShield release produced the log.
    """
    findings = _as_findings(result)
    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _INFORMATION_URI,
                        "version": tool_version,
                        "rules": _rule_entries(findings),
                    }
                },
                "results": [_result_entry(f) for f in findings],
            }
        ],
    }


def sarif_json(result: ScanResult | Iterable[Finding], *, tool_version: str) -> str:
    """Return ``to_sarif(...)`` pretty-printed as a 2-space-indented JSON string."""
    return json.dumps(to_sarif(result, tool_version=tool_version), indent=2)
