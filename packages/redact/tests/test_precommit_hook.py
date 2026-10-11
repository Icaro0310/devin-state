"""Hook-level coverage for the pre-commit integration.

The `gate` command's behavior is pinned in test_hook_gate.py; this file
checks the published ``.pre-commit-hooks.yaml`` wiring — the surface
pre-commit actually runs — stays pointed at it.
"""

from pathlib import Path

HOOKS = Path(__file__).parents[3] / ".pre-commit-hooks.yaml"


def _text() -> str:
    return HOOKS.read_text(encoding="utf-8")


def test_hooks_manifest_exists():
    assert HOOKS.is_file()


def test_hook_entry_runs_gate():
    text = _text()
    assert "id: devin-redact-gate" in text
    assert "language: system" in text


def test_hook_entry_scans_staged_blobs():
    """The gate must read the staged index blobs (`--staged`), not the
    working tree — a file edited or deleted after `git add` still
    ships its staged content in the commit."""
    text = _text()
    assert "entry: devin-redact gate --staged" in text


def test_hook_receives_staged_filenames():
    # gate needs path arguments; pass_filenames must not be disabled.
    text = _text()
    assert "pass_filenames: false" not in text
    assert "types:" in text
