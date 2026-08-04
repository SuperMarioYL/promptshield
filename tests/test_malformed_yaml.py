"""Malformed-baseline / malformed-rules YAML regression tests (v0.8.0).

fix-malformed-baseline-rules-yaml-crash: ``Baseline.load`` (cli.py) and
    ``load_rule_packs`` (cli.py) parsed YAML OUTSIDE the scan try/except, and
    the except tuple ``(RuntimeError, ValueError, OSError)`` omitted
    ``yaml.YAMLError``. The baseline file is the tool's OWN ``--update-baseline``
    artifact that users routinely open to review/trim accepted findings, and a
    custom ``--rules`` pack is user-supplied YAML; a YAML syntax error
    introduced during such a hand-edit (or a malformed pack) therefore crashed
    ``promptshield scan`` with a raw ``yaml.parser.ParserError`` traceback and
    exited 1, instead of a clean ``click.ClickException``. v0.8.0 wraps both
    load sites so they surface a clean, path-aware error. These tests drive the
    CLI itself via the ``CliRunner`` and assert a clean ``ClickException`` (NOT
    a ``YAMLError`` traceback) for a corrupted baseline file and a corrupted
    ``--rules`` pack.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from promptshield.cli import main

# A YAML body that is syntactically invalid (an unterminated flow sequence) —
# the exact shape reproduced in the bug-hunter report
# (``fingerprint: [oops unterminated``).
_MALFORMED_BODY = (
    "version: 1\n"
    "findings:\n"
    "  - fingerprint: [oops unterminated\n"
)


def _assert_clean_click_exception(res, needle: str) -> None:
    """Assert ``res`` is a clean ``ClickException``, not a raw crash.

    A clean ``ClickException`` leaves ``res.exception`` as ``None`` (the
    ``CliRunner`` prints ``Error: <msg>`` and sets exit_code=1), so an
    uncaught ``yaml.YAMLError`` (which ``CliRunner`` stashes in
    ``res.exception``) fails this guard — that is the regression signal.
    """
    assert res.exception is None or isinstance(
        res.exception, SystemExit
    ), (
        "scan raised an uncaught exception (not a clean ClickException): "
        f"{res.exception!r}"
    )
    assert not isinstance(res.exception, yaml.YAMLError), (
        "a malformed YAML file must surface as a clean ClickException, not a "
        "raw yaml.YAMLError traceback (fix-malformed-baseline-rules-yaml-crash)"
    )
    assert res.exit_code != 0, (
        "a malformed YAML file must fail the scan with a non-zero exit"
    )
    assert "malformed" in res.output, (
        "the clean error message must say 'malformed'; got:\n" + res.output
    )
    assert needle in res.output, (
        f"the clean error message must mention '{needle}'; got:\n" + res.output
    )


def test_malformed_baseline_file_is_clean_error(tmp_path: Path):
    """A corrupted ``--baseline`` file surfaces a clean error, not a crash.

    The baseline file is the tool's OWN ``--update-baseline`` artifact that
    users routinely open to review/trim accepted findings; a YAML syntax error
    introduced during such a hand-edit used to crash ``promptshield scan`` with
    a raw ``yaml.parser.ParserError`` traceback. After the fix it surfaces as a
    clean ``ClickException`` naming the malformed file.
    """
    target = tmp_path / "repo"
    target.mkdir()
    (target / "empty.py").write_text("# benign\n", encoding="utf-8")
    bad_baseline = tmp_path / "broken-baseline.yaml"
    bad_baseline.write_text(_MALFORMED_BODY, encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(
        main,
        ["scan", str(target), "--baseline", str(bad_baseline)],
    )
    _assert_clean_click_exception(res, str(bad_baseline))


def test_malformed_rules_pack_is_clean_error(tmp_path: Path):
    """A corrupted ``--rules`` pack surfaces a clean error, not a crash.

    A custom ``--rules`` pack is user-supplied YAML; a malformed pack used to
    raise an uncaught ``yaml.parser.ParserError`` and crash the CLI. After the
    fix it surfaces as a clean ``ClickException`` naming the malformed pack.
    """
    target = tmp_path / "repo"
    target.mkdir()
    (target / "empty.py").write_text("# benign\n", encoding="utf-8")
    bad_rules = tmp_path / "broken-rules.yaml"
    bad_rules.write_text(_MALFORMED_BODY, encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(
        main,
        ["scan", str(target), "--rules", str(bad_rules)],
    )
    _assert_clean_click_exception(res, str(bad_rules))


def test_malformed_default_baseline_name_is_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Guardrail: the DEFAULT baseline name path is guarded too.

    Users run ``promptshield scan .`` against a repo whose
    ``.promptshield-baseline.yaml`` (the tool's own ``--update-baseline``
    artifact at the default name) they hand-edited into a syntax error; that
    must surface a clean error, not a crash. ``Baseline.load`` resolves the
    default name relative to the cwd, so this test chdirs into the repo root.
    """
    (tmp_path / "empty.py").write_text("# benign\n", encoding="utf-8")
    (tmp_path / ".promptshield-baseline.yaml").write_text(
        _MALFORMED_BODY, encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    res = runner.invoke(main, ["scan", "."])
    _assert_clean_click_exception(res, ".promptshield-baseline.yaml")
