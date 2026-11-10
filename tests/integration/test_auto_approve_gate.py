"""Static pins for .github/workflows/auto-approve.yml.

The caller is thin by design: it triggers the reusable ``pr-approve``
gate in devin-powerups. These checks pin the v1.16 caller contract —
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


def test_gate_pin_is_v1_16():
    """The v1.16 gate splits the auto-merge arm into a dedicated
    ``arm-auto-merge`` job so approve runs read-only again; the arm
    still requires ``contents: write`` in the caller. A silent repin
    back to an older tag must fail here."""
    text = _text()
    assert GATE_USES + "v1.16" in text


def test_review_comment_trigger_re_evaluates_gate():
    """Replies citing fix commits must re-run the gate, not wait for
    the next push."""
    text = _text()
    assert "  pull_request_review_comment:" in text
    assert "    types: [created]" in text


def test_gate_permissions_allow_auto_merge_arm():
    """v1.16 arms ``gh pr merge --auto`` from the dedicated
    ``arm-auto-merge`` job once checks pass — the caller must grant
    ``contents: write`` at workflow level AND on the approve job, or
    the arm warns and skips the merge."""
    text = _text()
    head = text.split("jobs:", 1)[0]
    approve = text.split("  approve:", 1)[1]
    assert "contents: write" in head
    assert "contents: write" in approve
    assert "pull-requests: write" in approve
    assert "contents: read" not in text


def test_gate_permissions_grant_statuses_read():
    """pr-approve.yml@v1.16 declares ``statuses: read`` internally and the
    judge gate + arm re-verification read the ``Devin Review`` /
    ``devin-judge/review`` commit statuses through it. ``workflow_call``
    caps the reusable's permissions by the caller's, so the caller must
    grant ``statuses: read`` at workflow level AND on the approve job —
    without it every run dies in ``startup_failure`` before any job
    starts (regression pin for the v1.16 bump that shipped without it)."""
    text = _text()
    head = text.split("jobs:", 1)[0]
    approve = text.split("  approve:", 1)[1]
    assert "statuses: read" in head
    assert "statuses: read" in approve
