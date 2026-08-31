"""Version-drift guard (v0.14.0).

fix-version-drift-013-stale-init-version: the v0.13.0 release shipped
``pyproject.toml [project].version = "0.13.0"`` and a CHANGELOG ``## [0.13.0]``
entry but left ``src/promptshield/__init__.py:__version__`` at ``"0.12.0"``, so
``promptshield --version`` (cli.py ``click.version_option(__version__)``) and
the SARIF ``tool.driver.version`` stamp (cli.py ``sarif_json(...,
tool_version=__version__)``) both misreported the release to every user and
to GitHub code scanning. There was no test asserting ``__version__`` tracks
the package version, which is why the drift slipped. These tests parse
``pyproject.toml`` and assert the in-source ``__version__`` — and the CLI
``--version`` output — match it, so a future ship that bumps one but not the
other fails CI.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import promptshield

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _pyproject_version() -> str:
    with _PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_init_version_matches_pyproject() -> None:
    """``__version__`` must equal ``pyproject [project].version`` (drift guard)."""
    expected = _pyproject_version()
    assert promptshield.__version__ == expected, (
        f"version drift: promptshield.__version__={promptshield.__version__!r} "
        f"but pyproject.toml [project].version={expected!r}; bump both "
        f"together (fix-version-drift-013-stale-init-version)"
    )


def test_cli_version_reports_release() -> None:
    """``promptshield --version`` must print the pyproject version, not a stale one."""
    from click.testing import CliRunner

    from promptshield.cli import main

    res = CliRunner().invoke(main, ["--version"])
    assert res.exit_code == 0, res.output
    expected = _pyproject_version()
    assert expected in res.output, (
        f"--version output {res.output!r} does not report the pyproject "
        f"version {expected!r} (fix-version-drift-013-stale-init-version)"
    )
