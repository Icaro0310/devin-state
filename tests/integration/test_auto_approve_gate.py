"""Static pins for .github/workflows/auto-approve.yml.

The caller is thin by design: it triggers the reusable ``pr-approve``
gate in devin-powerups. These checks pin the v1.9 caller contract —
the gate pin, the ``pull_request_review_comment`` trigger that lets a
fix-commit reply re-run the gate without waiting for a push, and the
scoped permissions — without requiring PyYAML.
"""

from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
    / "auto-approve.yml"
)
GATE_USES = "uses: Icaro0310/devin-powerups/.github/workflows/pr-approve.yml@"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_gate_pin_is_v1_9():
    """The v1.9 gate fixes self-cancellation so a successful approval no
    longer renders as a failed check, plus a fresh-head recheck and
    paginated dedup; a silent repin back to an older tag must fail
    here."""
    text = _text()
    assert GATE_USES + "v1.9" in text


def test_review_comment_trigger_re_evaluates_gate():
    """Replies citing fix commits must re-run the gate, not wait for
    the next push."""
    text = _text()
    assert "  pull_request_review_comment:" in text
    assert "    types: [created]" in text


def test_gate_permissions_stay_scoped():
    text = _text()
    approve = text.split("  approve:", 1)[1]
    assert "contents: read" in approve
    assert "pull-requests: write" in approve
    assert "contents: write" not in approve
