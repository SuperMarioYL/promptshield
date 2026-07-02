"""SARIF 2.1.0 output tests (m4).

Lock in the shape of the SARIF log produced from a real ScanResult and from a
bare list of Findings: the industry-standard envelope, the driver block, one
driver rule entry per distinct rule id, per-result level mapping (HIGH ->
"error"), and JSON round-trip fidelity. An empty findings list must still yield
a valid SARIF 2.1.0 log with an empty results array.
"""

from __future__ import annotations

import json
from pathlib import Path

from promptshield.rules import Severity
from promptshield.sarif import sarif_json, to_sarif
from promptshield.scanner import scan_path

FIXTURE = Path(__file__).parent / "fixtures" / "malicious_pr"


def _scan():
    # Real scan of the malicious fixture -> a ScanResult with HIGH findings.
    return scan_path(FIXTURE)


def test_sarif_envelope_and_driver_block():
    log = to_sarif(_scan(), tool_version="0.2.0")
    assert log["version"] == "2.1.0"
    assert isinstance(log["$schema"], str) and log["$schema"]
    assert len(log["runs"]) == 1
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "PromptShield"
    assert driver["version"] == "0.2.0"
    assert isinstance(driver["rules"], list) and driver["rules"]


def test_one_driver_rule_per_distinct_rule_id():
    result = _scan()
    log = to_sarif(result, tool_version="0.2.0")
    driver_rules = log["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in driver_rules]
    # no duplicate driver entries
    assert len(rule_ids) == len(set(rule_ids))
    # exactly one entry per distinct rule id hit in the findings
    distinct = {f.rule_id for f in result.findings}
    assert set(rule_ids) == distinct
    # every result references a declared driver rule
    for entry in log["runs"][0]["results"]:
        assert entry["ruleId"] in set(rule_ids)


def test_result_fields_well_formed():
    log = to_sarif(_scan(), tool_version="0.2.0")
    results = log["runs"][0]["results"]
    assert results
    for entry in results:
        assert entry["level"] in {"error", "warning", "note"}
        assert entry["message"]["text"]
        phys = entry["locations"][0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"]
        assert phys["region"]["startLine"] >= 1


def test_high_severity_maps_to_error_level():
    result = _scan()
    log = to_sarif(result, tool_version="0.2.0")
    results = log["runs"][0]["results"]
    # results are emitted one-per-finding, preserving findings order
    assert len(results) == len(result.findings)
    assert any(f.severity is Severity.HIGH for f in result.findings)
    for finding, entry in zip(result.findings, results, strict=True):
        if finding.severity is Severity.HIGH:
            assert entry["level"] == "error"


def test_sarif_json_roundtrips_and_equals_to_sarif():
    result = _scan()
    as_json = sarif_json(result, tool_version="0.2.0")
    parsed = json.loads(as_json)
    assert parsed == to_sarif(result, tool_version="0.2.0")


def test_empty_findings_produce_valid_log():
    log = to_sarif([], tool_version="0.2.0")
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []
