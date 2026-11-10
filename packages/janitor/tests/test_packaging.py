"""Packaging regression — the fix for the missing reap-attribution deps.

The reap path imports ``devin_office`` and ``devin_redact`` at runtime;
an environment that installed ``devin-janitor`` alone reaped sessions
with ``attribution_ok=false``.  These tests fail if either dependency
ever drops out of ``pyproject.toml`` again.
"""

from __future__ import annotations

from pathlib import Path

import tomllib

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _deps() -> list[str]:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["dependencies"]


def test_reap_attribution_deps_declared() -> None:
    deps = _deps()
    for pkg in ("devin-office", "devin-redact"):
        assert any(d == pkg or d.startswith((pkg + ">", pkg + "="))
                   for d in deps), f"{pkg} missing from project.dependencies"


def test_version_matches_changelog() -> None:
    with PYPROJECT.open("rb") as fh:
        version = tomllib.load(fh)["project"]["version"]
    changelog = (Path(__file__).resolve().parents[1] / "CHANGELOG.md").read_text()
    assert f"## [{version}]" in changelog, \
        f"pyproject version {version} has no changelog section"
