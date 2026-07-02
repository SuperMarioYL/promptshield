"""Rule-pack stacking tests (m5).

The packaged ruleset is the base layer; extra packs stack on top with
last-wins override semantics, can disable a built-in by id, and expand a
directory of .yaml files in sorted order. ``load_rule_packs(None)`` collapses
back to the packaged set, and a pack missing a required key raises ValueError.
"""

from __future__ import annotations

import pytest

from promptshield.rules import Severity, load_rule_packs, load_rules

_PACKAGED_COUNT = 13


def _write(path, body):
    path.write_text(body, encoding="utf-8")
    return path


def test_load_packs_none_equals_packaged():
    packs = load_rule_packs(None)
    packaged = load_rules()
    assert len(packs) == _PACKAGED_COUNT
    assert len(packaged) == _PACKAGED_COUNT
    assert sorted(r.id for r in packs) == sorted(r.id for r in packaged)
    assert all(r.source == "packaged" for r in packs)


def test_extra_pack_adds_rule_and_keeps_packaged(tmp_path):
    pack = _write(
        tmp_path / "extra.yaml",
        "rules:\n"
        "  - id: PS999-test-extra\n"
        "    severity: LOW\n"
        "    category: instruction_override\n"
        "    why: test rule for pack stacking\n"
        "    patterns: ['__ps999_test_marker__']\n",
    )
    rules = load_rule_packs([str(pack)])
    ids = {r.id for r in rules}
    assert "PS999-test-extra" in ids
    # every packaged rule is still present
    assert {r.id for r in load_rules()} <= ids
    assert len(rules) == _PACKAGED_COUNT + 1
    extra = next(r for r in rules if r.id == "PS999-test-extra")
    assert extra.source != "packaged"
    assert extra.source == str(pack)


def test_override_is_last_wins_not_addition(tmp_path):
    pack = _write(
        tmp_path / "override.yaml",
        "rules:\n"
        "  - id: PS003-role-reassignment\n"
        "    severity: LOW\n"
        "    category: instruction_override\n"
        "    why: overridden severity for testing\n"
        "    patterns: ['you are now a developer mode']\n",
    )
    rules = load_rule_packs([str(pack)])
    by_id = {r.id: r for r in rules}
    assert by_id["PS003-role-reassignment"].severity is Severity.LOW
    # override replaces the built-in, it does not add a second entry
    assert len(rules) == _PACKAGED_COUNT


def test_disabled_pack_drops_built_in(tmp_path):
    pack = _write(
        tmp_path / "disable.yaml",
        "rules:\n"
        "  - id: PS003-role-reassignment\n"
        "    enabled: false\n",
    )
    rules = load_rule_packs([str(pack)])
    ids = {r.id for r in rules}
    assert "PS003-role-reassignment" not in ids
    assert len(rules) == _PACKAGED_COUNT - 1


def test_directory_stacks_yaml_in_sorted_order(tmp_path):
    _write(
        tmp_path / "01-a.yaml",
        "rules:\n"
        "  - id: PS998-dir-a\n"
        "    severity: LOW\n"
        "    category: instruction_override\n"
        "    why: first dir pack\n"
        "    patterns: ['__ps998_a__']\n",
    )
    _write(
        tmp_path / "02-b.yaml",
        "rules:\n"
        "  - id: PS997-dir-b\n"
        "    severity: LOW\n"
        "    category: instruction_override\n"
        "    why: second dir pack\n"
        "    patterns: ['__ps997_b__']\n",
    )
    rules = load_rule_packs([str(tmp_path)])
    ids = {r.id for r in rules}
    assert "PS998-dir-a" in ids
    assert "PS997-dir-b" in ids
    assert len(rules) == _PACKAGED_COUNT + 2


def test_malformed_pack_raises_value_error(tmp_path):
    pack = _write(
        tmp_path / "broken.yaml",
        "rules:\n"
        "  - id: PS999-broken\n"
        "    category: instruction_override\n"
        "    why: missing severity on purpose\n"
        "    patterns: ['x']\n",
    )
    with pytest.raises(ValueError):
        load_rule_packs([str(pack)])
