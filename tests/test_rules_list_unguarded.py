"""`rules list` unguarded-load regression tests (v0.10.0).

fix-rules-list-unguarded-load: the ``rules list`` command called
    ``load_rule_packs(list(rules_paths))`` (cli.py) with NO try/except at all,
    so every malformed / invalid ``--rules`` pack that the ``scan`` command now
    converts to a clean ``click.ClickException`` crashed ``rules list`` with a
    raw traceback (``yaml.ParserError`` / ``UnicodeDecodeError`` / ``re.error``
    / ``ValueError``). This is the sibling defect v0.8.0/v0.9.0 fixed for
    ``scan`` but never applied to ``rules list``: the m5-shipped ``--rules``
    option on ``rules list`` makes this a first-typo crash for any user
    inspecting a custom pack via ``rules list --rules mypack.yaml``. v0.10.0
    wraps the load with the same guard ``scan`` uses — factored into a shared
    helper (``_load_rule_packs_guarded``) reused by both commands so they cannot
    diverge again. These tests drive the CLI via the ``CliRunner`` and assert a
    clean ``ClickException`` (NOT a raw traceback) for a malformed-yaml,
    invalid-UTF-8, invalid-regex, and invalid-severity ``--rules`` pack under
    ``rules list``.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from click.testing import CliRunner

from promptshield.cli import main

# A YAML body that is syntactically invalid (an unterminated flow sequence) —
# the same shape test_malformed_yaml.py uses; ``load_rule_packs`` raises an
# uncaught ``yaml.parser.ParserError`` (a ``yaml.YAMLError``).
_MALFORMED_YAML = "rules:\n  - id: [oops unterminated\n"

# A pack body that is VALID YAML structure but contains an INVALID UTF-8 byte
# (0xff) inside a value — ``read_text(encoding="utf-8")`` in strict mode raises
# ``UnicodeDecodeError`` before yaml.safe_load ever sees the text. (The 0xff
# byte is illegal in any valid UTF-8 stream.) Same shape as
# test_invalid_utf8.py's ``_BAD_UTF8_BODY``.
_BAD_UTF8 = b"rules:\n  - id: \xffoops\n"

# A pack that is VALID YAML/UTF-8 but whose rule has a typo'd regex — raises
# ``re.error`` inside ``_compile_patterns`` (rules.py:162).
_BAD_REGEX_PACK = (
    "rules:\n"
    "  - id: PS999-bad-regex\n"
    "    severity: LOW\n"
    "    category: instruction_override\n"
    "    why: typo'd regex on purpose\n"
    "    patterns: ['(unclosed']\n"
)

# A pack that is VALID YAML/UTF-8 but whose rule has a typo'd severity value —
# raises ``ValueError`` inside ``_parse_rule`` (rules.py:202).
_BAD_SEVERITY_PACK = (
    "rules:\n"
    "  - id: PS999-bad-severity\n"
    "    severity: TOTALLY\n"
    "    category: instruction_override\n"
    "    why: typo'd severity on purpose\n"
    "    patterns: ['__ps999_bad_sev__']\n"
)


def _assert_clean_click_exception(res, raw_types, needle: str) -> None:
    """Assert ``res`` is a clean ``ClickException``, not a raw crash.

    A clean ``ClickException`` leaves ``res.exception`` as ``None`` (the
    ``CliRunner`` prints ``Error: <msg>`` and sets exit_code=1), so an uncaught
    raw exception (which ``CliRunner`` stashes in ``res.exception``) fails this
    guard — that is the regression signal.
    """
    assert res.exception is None or isinstance(
        res.exception, SystemExit
    ), (
        "rules list raised an uncaught exception (not a clean "
        f"ClickException): {res.exception!r}"
    )
    for raw_type in raw_types:
        assert not isinstance(res.exception, raw_type), (
            f"a malformed/invalid pack must surface as a clean "
            f"ClickException, not a raw {raw_type.__name__} traceback "
            f"(fix-rules-list-unguarded-load)"
        )
    assert res.exit_code != 0, (
        "a malformed/invalid pack must fail `rules list` with a non-zero exit"
    )
    assert "malformed" in res.output, (
        "the clean error message must say 'malformed'; got:\n" + res.output
    )
    assert needle in res.output, (
        f"the clean error message must mention '{needle}'; got:\n" + res.output
    )


def test_rules_list_malformed_yaml_is_clean_error(tmp_path: Path):
    """``rules list --rules <malformed yaml>`` surfaces a clean error.

    A custom ``--rules`` pack a user inspects via ``rules list`` with a YAML
    syntax error used to raise an uncaught ``yaml.ParserError`` and crash
    ``rules list`` with a raw traceback — the identical input ``scan`` already
    surfaced as a clean error. After the fix it surfaces as a clean
    ``ClickException`` naming the offending pack.
    """
    bad = tmp_path / "broken-rules.yaml"
    bad.write_text(_MALFORMED_YAML, encoding="utf-8")
    res = CliRunner().invoke(main, ["rules", "list", "--rules", str(bad)])
    _assert_clean_click_exception(res, (yaml.YAMLError,), str(bad))


def test_rules_list_invalid_utf8_is_clean_error(tmp_path: Path):
    """``rules list --rules <invalid utf8>`` surfaces a clean error.

    A pack saved with an invalid UTF-8 byte used to raise an uncaught
    ``UnicodeDecodeError`` and crash ``rules list`` with a raw traceback. After
    the fix it surfaces as a clean ``ClickException`` naming the offending pack.
    """
    bad = tmp_path / "bad-utf8-rules.yaml"
    bad.write_bytes(_BAD_UTF8)
    res = CliRunner().invoke(main, ["rules", "list", "--rules", str(bad)])
    _assert_clean_click_exception(res, (UnicodeDecodeError,), str(bad))


def test_rules_list_invalid_regex_is_clean_error(tmp_path: Path):
    """``rules list --rules <invalid regex>`` surfaces a clean error.

    A pack whose rule has a typo'd regex used to raise an uncaught ``re.error``
    (NOT a YAMLError/UnicodeDecodeError/ValueError — verified issubclass) and
    crash ``rules list`` with a raw traceback. After the fix it surfaces as a
    clean ``ClickException`` naming the offending pack.
    """
    bad = tmp_path / "bad-regex-rules.yaml"
    bad.write_text(_BAD_REGEX_PACK, encoding="utf-8")
    res = CliRunner().invoke(main, ["rules", "list", "--rules", str(bad)])
    _assert_clean_click_exception(res, (re.error,), str(bad))


def test_rules_list_invalid_severity_is_clean_error(tmp_path: Path):
    """``rules list --rules <invalid severity>`` surfaces a clean error.

    A pack whose rule has a typo'd severity value used to raise an uncaught
    ``ValueError`` and crash ``rules list`` with a raw traceback. After the fix
    it surfaces as a clean ``ClickException`` naming the offending pack.
    """
    bad = tmp_path / "bad-severity-rules.yaml"
    bad.write_text(_BAD_SEVERITY_PACK, encoding="utf-8")
    res = CliRunner().invoke(main, ["rules", "list", "--rules", str(bad)])
    _assert_clean_click_exception(res, (ValueError,), str(bad))
