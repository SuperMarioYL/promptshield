"""Rule-semantic-error rules-pack regression tests (v0.10.0).

fix-scan-rules-semantic-error-crash: the v0.8.0/v0.9.0 ``--rules`` load guard
    at cli.py caught only file-level failures (``yaml.YAMLError`` YAML-syntax,
    ``UnicodeDecodeError`` bad UTF-8). But a user-supplied ``--rules`` pack can
    ALSO fail at the rule-semantic level inside ``_parse_rule`` /
    ``_compile_patterns`` (rules.py): a typo'd regex raises ``re.error`` during
    ``re.compile`` (rules.py:162), and a typo'd severity / unknown category /
    missing key / duplicate id raises ``ValueError`` (rules.py:187-202, 224).
    None of these were caught — ``re.error`` is NOT a subclass of
    YAMLError/UnicodeDecodeError/ValueError (verified issubclass), and the
    ``load_rule_packs`` call sat OUTSIDE the scan try/except — so
    ``promptshield scan <repo> --rules <bad pack>`` crashed the CLI with a raw
    ``re.error`` / ``ValueError`` traceback (exit 1, empty stdout) instead of a
    clean ``click.ClickException``, on the identical hand-edited-pack scenario
    v0.8.0/v0.9.0 targeted — the rule-semantic sibling both missed. v0.10.0
    widens the guard to also catch ``ValueError, re.error``. These tests drive
    the CLI via the ``CliRunner`` and assert a clean ``ClickException`` (NOT a
    raw ``re.error`` / ``ValueError`` traceback) for an invalid-regex pack and
    an invalid-severity pack.
"""

from __future__ import annotations

import re
from pathlib import Path

from click.testing import CliRunner

from promptshield.cli import main

# A pack that is VALID YAML structure and VALID UTF-8, but whose rule has a
# typo'd regex — ``re.compile("(unclosed")`` raises ``re.error`` inside
# ``_compile_patterns`` (rules.py:162). This is the rule-semantic sibling the
# v0.8.0 (YAML syntax) / v0.9.0 (UTF-8) guards missed: the file PARSES and
# DECODES fine, but a rule PATTERN is invalid. ``re.error`` is NOT a subclass
# of YAMLError/UnicodeDecodeError/ValueError (verified issubclass), so the v0.8
# /v0.9 ``except (yaml.YAMLError, UnicodeDecodeError)`` guard did not catch it.
_BAD_REGEX_PACK = (
    "rules:\n"
    "  - id: PS999-bad-regex\n"
    "    severity: LOW\n"
    "    category: instruction_override\n"
    "    why: typo'd regex on purpose\n"
    "    patterns: ['(unclosed']\n"
)

# A pack that is VALID YAML/UTF-8 but whose rule has a typo'd severity value —
# ``Severity('TOTALLY')`` raises ``ValueError`` inside ``_parse_rule``
# (rules.py:202). ``ValueError`` IS a real exception type, but the
# ``load_rule_packs`` call sat OUTSIDE the scan try/except (which only catches
# RuntimeError/ValueError/OSError for the *scan* call, not the *load*), so it
# crashed the CLI with a raw traceback.
_BAD_SEVERITY_PACK = (
    "rules:\n"
    "  - id: PS999-bad-severity\n"
    "    severity: TOTALLY\n"
    "    category: instruction_override\n"
    "    why: typo'd severity on purpose\n"
    "    patterns: ['__ps999_bad_sev__']\n"
)


def _assert_clean_click_exception(res, raw_type, needle: str) -> None:
    """Assert ``res`` is a clean ``ClickException``, not a raw ``raw_type`` crash.

    A clean ``ClickException`` leaves ``res.exception`` as ``None`` (the
    ``CliRunner`` prints ``Error: <msg>`` and sets exit_code=1), so an uncaught
    ``raw_type`` (which ``CliRunner`` stashes in ``res.exception``) fails this
    guard — that is the regression signal.
    """
    assert res.exception is None or isinstance(
        res.exception, SystemExit
    ), (
        "scan raised an uncaught exception (not a clean ClickException): "
        f"{res.exception!r}"
    )
    assert not isinstance(res.exception, raw_type), (
        f"an invalid pack must surface as a clean ClickException, not a raw "
        f"{raw_type.__name__} traceback (fix-scan-rules-semantic-error-crash)"
    )
    assert res.exit_code != 0, (
        "an invalid pack must fail the scan with a non-zero exit"
    )
    assert "malformed" in res.output, (
        "the clean error message must say 'malformed'; got:\n" + res.output
    )
    assert needle in res.output, (
        f"the clean error message must mention '{needle}'; got:\n" + res.output
    )


def test_invalid_regex_pack_is_clean_error(tmp_path: Path):
    """A typo'd-regex ``--rules`` pack surfaces a clean error, not a crash.

    A custom ``--rules`` pack is user-supplied YAML; a pack whose rule has an
    invalid regex used to raise an uncaught ``re.error`` (NOT a subclass of
    YAMLError/UnicodeDecodeError/ValueError — verified issubclass) and crash
    the CLI with a raw traceback on the identical hand-edited-pack scenario
    v0.8.0/v0.9.0 targeted. After the fix it surfaces as a clean
    ``ClickException`` naming the offending pack.
    """
    target = tmp_path / "repo"
    target.mkdir()
    (target / "empty.py").write_text("# benign\n", encoding="utf-8")
    bad_rules = tmp_path / "bad-regex-rules.yaml"
    bad_rules.write_text(_BAD_REGEX_PACK, encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(
        main,
        ["scan", str(target), "--rules", str(bad_rules)],
    )
    _assert_clean_click_exception(res, re.error, str(bad_rules))


def test_invalid_severity_pack_is_clean_error(tmp_path: Path):
    """A typo'd-severity ``--rules`` pack surfaces a clean error, not a crash.

    A pack whose rule has an invalid severity value used to raise an uncaught
    ``ValueError`` (the ``load_rule_packs`` call sat outside the scan
    try/except, which only wraps the *scan* call itself) and crash the CLI with
    a raw traceback. After the fix it surfaces as a clean ``ClickException``
    naming the offending pack.
    """
    target = tmp_path / "repo"
    target.mkdir()
    (target / "empty.py").write_text("# benign\n", encoding="utf-8")
    bad_rules = tmp_path / "bad-severity-rules.yaml"
    bad_rules.write_text(_BAD_SEVERITY_PACK, encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(
        main,
        ["scan", str(target), "--rules", str(bad_rules)],
    )
    _assert_clean_click_exception(res, ValueError, str(bad_rules))
