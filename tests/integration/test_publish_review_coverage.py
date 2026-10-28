"""Tests for scripts/publish-review-coverage.py — verdict matrix.

Contract under test: ``--b`` is the devin-judge verdict (the poordjaevin
ACP gate is the final decider). EXECUTED means approved, REJECTED means
rejected, and anything else means no verdict exists — which holds the
gate at action_required because lane A alone can never clear a PR.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "publish_review_coverage",
    ROOT / "scripts" / "publish-review-coverage.py",
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def test_devin_executed_needs_no_fallback():
    conclusion, desc, verdict = mod.compute_verdict("EXECUTED", "SKIPPED", "SKIPPED")
    assert conclusion == "success" and verdict == "EXECUTED"
    assert "fallback not needed" in desc


def test_judge_approve_with_lane_a_is_covered():
    """Judge approved and lane A also inspected: full honest coverage."""
    conclusion, desc, verdict = mod.compute_verdict("SKIPPED_CREDITS", "EXECUTED", "EXECUTED")
    assert conclusion == "success" and verdict == "COVERED"
    assert "judge approved" in desc
    assert "lane A also executed" in desc
    assert "devin=SKIPPED_CREDITS" in desc


def test_judge_approve_without_lane_a_is_covered_judge_only():
    """Lane A absent + judge approve -> success, honestly judge-only."""
    conclusion, desc, verdict = mod.compute_verdict("UNVERIFIED", "UNAVAILABLE", "EXECUTED")
    assert conclusion == "success" and verdict == "COVERED"
    assert "judge-only" in desc
    assert "did not execute" in desc


def test_judge_reject_overrides_lane_a_executed():
    """Lane A EXECUTED + judge REJECTED -> failure. The judge is the
    final decider; advisory evidence cannot clear its reject."""
    conclusion, desc, verdict = mod.compute_verdict("SKIPPED_CREDITS", "EXECUTED", "REJECTED")
    assert conclusion == "failure" and verdict == "FAILURE"
    assert "judge rejected" in desc


def test_judge_reject_with_failed_lane_a_is_failure():
    conclusion, desc, verdict = mod.compute_verdict("SKIPPED_CREDITS", "FAILED", "REJECTED")
    assert conclusion == "failure" and verdict == "FAILURE"
    assert "judge rejected" in desc


def test_judge_unavailable_holds_even_when_lane_a_ran():
    """judge UNAVAILABLE + lane A EXECUTED -> action_required, never
    success: lane A alone cannot clear a PR (small models never make
    security decisions)."""
    conclusion, desc, verdict = mod.compute_verdict("SKIPPED_CREDITS", "EXECUTED", "UNAVAILABLE")
    assert conclusion == "action_required" and verdict == "ACTION_REQUIRED"
    assert "no judge verdict" in desc
    assert "lane A alone cannot clear" in desc


def test_judge_skipped_is_action_required():
    conclusion, _, verdict = mod.compute_verdict("FAILED_BEFORE_REVIEW", "EXECUTED", "SKIPPED")
    assert conclusion == "action_required" and verdict == "ACTION_REQUIRED"


def test_judge_failed_is_action_required():
    conclusion, _, verdict = mod.compute_verdict("SKIPPED_CREDITS", "FAILED", "FAILED")
    assert conclusion == "action_required" and verdict == "ACTION_REQUIRED"


def test_nothing_ran_is_action_required_not_failure():
    """All lanes down means no judge verdict — a human decides, so the
    honest conclusion is action_required, not a code-blaming failure."""
    conclusion, _, verdict = mod.compute_verdict("SKIPPED_CREDITS", "UNAVAILABLE", "UNAVAILABLE")
    assert conclusion == "action_required" and verdict == "ACTION_REQUIRED"


def test_unverified_devin_still_judged():
    _, _, verdict = mod.compute_verdict("UNVERIFIED", "EXECUTED", "EXECUTED")
    assert verdict == "COVERED"


def test_failed_before_review_uses_fallback():
    _, _, verdict = mod.compute_verdict("FAILED_BEFORE_REVIEW", "EXECUTED", "EXECUTED")
    assert verdict == "COVERED"


def test_critical_findings_marker_on_covered():
    """Lane A's critical findings are execution data: coverage stays
    success under a judge approve but carries the blocking marker the
    merge gate reads."""
    conclusion, desc, verdict = mod.compute_verdict(
        "SKIPPED_CREDITS", "EXECUTED", "EXECUTED", a_critical=2)
    assert conclusion == "success" and verdict == "COVERED"
    assert "findings=blocking(critical=2)" in desc


def test_critical_findings_marker_on_rejected():
    conclusion, desc, verdict = mod.compute_verdict(
        "SKIPPED_CREDITS", "EXECUTED", "REJECTED", a_critical=1)
    assert conclusion == "failure" and verdict == "FAILURE"
    assert "findings=blocking" in desc


def test_mirror_state_never_greens_without_verdict():
    """The compatibility status mirror: action_required maps to pending
    (waiting on a human), never to a green that automation could adopt."""
    assert mod._mirror_state("success") == "success"
    assert mod._mirror_state("action_required") == "pending"
    assert mod._mirror_state("failure") == "failure"
