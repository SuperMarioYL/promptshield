"""Invalid-UTF-8 baseline / rules regression tests (v0.9.0).

fix-baseline-rules-invalid-utf8-crash: ``Baseline.load`` (baseline.py:49) and
    ``_load_pack_file`` (rules.py:251) read their file with strict
    ``read_text(encoding="utf-8")`` (no ``errors="replace"``), so a baseline or
    ``--rules`` file containing invalid UTF-8 BYTES (a stray ``\\xff``, or a file
    saved as Latin-1/CP1252) raised an uncaught ``UnicodeDecodeError`` — a
    ``ValueError``, NOT a ``yaml.YAMLError``. The v0.8.0
    ``except yaml.YAMLError`` guard at cli.py (added by
    fix-malformed-baseline-rules-yaml-crash) did NOT catch it, so the CLI
    crashed with a raw ``UnicodeDecodeError`` traceback and exited 1 instead of
    a clean ``click.ClickException``. v0.8.0 caught the YAML *syntax* error but
    not the *encoding* error — the sibling defect it missed. v0.9.0 widens the
    guard to also catch ``UnicodeDecodeError``. These tests drive the CLI itself
    via the ``CliRunner`` and assert a clean ``ClickException`` (NOT a
    ``UnicodeDecodeError`` traceback) for a bad-encoding baseline file and a
    bad-encoding ``--rules`` pack.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from promptshield.cli import main

# A baseline/rules body that is VALID YAML structure but contains an INVALID
# UTF-8 byte (0xff) inside a value — `read_text(encoding="utf-8")` in strict
# mode raises UnicodeDecodeError before yaml.safe_load ever sees the text.
# (The 0xff byte is illegal in any valid UTF-8 stream.)
_BAD_UTF8_BODY = b"version: 1\nfindings:\n  - fingerprint: \xffoops\n"


def _assert_clean_click_exception(res, needle: str) -> None:
    """Assert ``res`` is a clean ``ClickException``, not a raw crash.

    A clean ``ClickException`` leaves ``res.exception`` as ``None`` (the
    ``CliRunner`` prints ``Error: <msg>`` and sets exit_code=1), so an
    uncaught ``UnicodeDecodeError`` (which ``CliRunner`` stashes in
    ``res.exception``) fails this guard — that is the regression signal.
    """
    assert res.exception is None or isinstance(
        res.exception, SystemExit
    ), (
        "scan raised an uncaught exception (not a clean ClickException): "
        f"{res.exception!r}"
    )
    assert not isinstance(res.exception, UnicodeDecodeError), (
        "an invalid-UTF-8 file must surface as a clean ClickException, not a "
        "raw UnicodeDecodeError traceback (fix-baseline-rules-invalid-utf8-crash)"
    )
    assert res.exit_code != 0, (
        "an invalid-UTF-8 file must fail the scan with a non-zero exit"
    )
    assert "UTF-8" in res.output, (
        "the clean error message must mention 'UTF-8'; got:\n" + res.output
    )
    assert needle in res.output, (
        f"the clean error message must mention '{needle}'; got:\n" + res.output
    )


def test_invalid_utf8_baseline_file_is_clean_error(tmp_path: Path):
    """A bad-encoding ``--baseline`` file surfaces a clean error, not a crash.

    The baseline file is the tool's OWN ``--update-baseline`` artifact that
    users routinely open to review/trim accepted findings; a file saved with a
    stray invalid byte (or as Latin-1) used to crash ``promptshield scan`` with
    a raw ``UnicodeDecodeError`` traceback. After the fix it surfaces as a clean
    ``ClickException`` naming the offending file.
    """
    target = tmp_path / "repo"
    target.mkdir()
    (target / "empty.py").write_text("# benign\n", encoding="utf-8")
    bad_baseline = tmp_path / "bad-utf8-baseline.yaml"
    bad_baseline.write_bytes(_BAD_UTF8_BODY)

    runner = CliRunner()
    res = runner.invoke(
        main,
        ["scan", str(target), "--baseline", str(bad_baseline)],
    )
    _assert_clean_click_exception(res, str(bad_baseline))


def test_invalid_utf8_rules_pack_is_clean_error(tmp_path: Path):
    """A bad-encoding ``--rules`` pack surfaces a clean error, not a crash.

    A custom ``--rules`` pack is user-supplied YAML; a pack saved with an
    invalid byte used to raise an uncaught ``UnicodeDecodeError`` and crash the
    CLI. After the fix it surfaces as a clean ``ClickException`` naming the
    offending pack.
    """
    target = tmp_path / "repo"
    target.mkdir()
    (target / "empty.py").write_text("# benign\n", encoding="utf-8")
    bad_rules = tmp_path / "bad-utf8-rules.yaml"
    bad_rules.write_bytes(_BAD_UTF8_BODY)

    runner = CliRunner()
    res = runner.invoke(
        main,
        ["scan", str(target), "--rules", str(bad_rules)],
    )
    _assert_clean_click_exception(res, str(bad_rules))


def test_invalid_utf8_default_baseline_name_is_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Guardrail: the DEFAULT baseline name path is guarded too.

    Users run ``promptshield scan .`` against a repo whose
    ``.promptshield-baseline.yaml`` (the tool's own ``--update-baseline``
    artifact at the default name) they saved with an invalid byte; that must
    surface a clean error, not a crash. ``Baseline.load`` resolves the default
    name relative to the cwd, so this test chdirs into the repo root.
    """
    (tmp_path / "empty.py").write_text("# benign\n", encoding="utf-8")
    (tmp_path / ".promptshield-baseline.yaml").write_bytes(_BAD_UTF8_BODY)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    res = runner.invoke(main, ["scan", "."])
    _assert_clean_click_exception(res, ".promptshield-baseline.yaml")
