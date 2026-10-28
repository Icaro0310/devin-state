"""Static regression tests for the vendored AI review fallback workflow.

These pin the security boundaries as executable assertions: SHA-pinned
actions only, no Devin-context spoofing, no PR-head checkout, the judge
job's pull-model contract (it polls the ``devin-judge/review`` commit
status and never checks out code), and the static-scan lane's
advisory-only posture. Stdlib only — pytest alone runs the suite.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github" / "workflows"
TEXT = (WF / "ai-review-fallback.yml").read_text()
SHA40 = re.compile(r"^[a-f0-9]{40}$")


def _job_block(name: str) -> str:
    m = re.search(rf"\n  {name}:\n(.*?)(?=\n  \w|\Z)", TEXT, re.DOTALL)
    return m.group(1) if m else ""


def test_every_action_pinned_to_full_sha():
    uses = re.findall(r"uses: ([^\s@]+)@([^\s]+)", TEXT)
    assert uses, "no actions found"
    for name, ref in uses:
        assert SHA40.match(ref), f"{name}@{ref} is not a full SHA pin"


def test_fallback_never_posts_devin_context():
    assert "context=Devin Review" not in TEXT
    assert '"Review Coverage"' in TEXT


def test_fallback_runs_on_pull_request_target():
    """pull_request_target means a PR cannot alter its own review
    pipeline — the requirement is pinned in-file."""
    assert "pull_request_target:" in TEXT


def test_no_checkout_of_pr_head():
    """No actions/checkout may materialize PR-controlled code."""
    for m in re.finditer(r"uses: actions/checkout@[a-f0-9]{40}(.*?)(?=\n      - |\Z)",
                         TEXT, re.DOTALL):
        assert "head" not in m.group(1), f"checkout references PR head: {m.group(1)}"


def test_fallback_jobs_gate_on_classifier():
    for name in ("review-a", "static-scan", "judge"):
        block = _job_block(name)
        needs_line = next(l for l in block.splitlines() if "needs:" in l)
        assert "classify" in needs_line, needs_line
        assert "EXECUTED" in block


def test_review_b_replaced_by_static_scan_and_judge():
    """The authoritative lane-B is now the devin-judge verdict; the old
    review-b job name must be gone."""
    assert _job_block("review-b") == ""
    assert _job_block("static-scan") != ""
    assert _job_block("judge") != ""


def test_static_scan_is_advisory_and_always_succeeds():
    """Scanners post findings as evidence only: every step is
    continue-on-error and the result is EXECUTED|FAILED observability."""
    block = _job_block("static-scan")
    assert "continue-on-error" in block
    assert "outputs:" in block and "result:" in block
    # Advisory lane must not gate: it needs classify only, not judge.
    needs_line = next(l for l in block.splitlines() if "needs:" in l)
    assert "judge" not in needs_line


def test_static_scan_does_not_serialize_behind_review_a():
    """The static lane is deterministic on the runner — no shared
    Ollama slot exists, so it must NOT queue behind review-a;
    always() keeps its own outcome honest when classify flaked."""
    block = _job_block("static-scan")
    needs_line = next(l for l in block.splitlines() if "needs:" in l)
    assert "review-a" not in needs_line, needs_line
    assert "always()" in block


def test_judge_never_checks_out_pr_code():
    """The untrusted diff stays data: the judge job polls a commit
    status and comments — it must not materialize the PR head."""
    block = _job_block("judge")
    assert "actions/checkout" not in block
    assert "id-token" not in block


def test_judge_polls_devin_judge_review_status():
    block = _job_block("judge")
    assert "devin-judge/review" in block
    assert "statuses/" in block
    assert "judge-requested" in block
    assert "pull-requests: write" in block  # verdict comment
    assert "statuses: read" in block        # commit status read


def test_judge_wait_is_bounded():
    """Standalone copy: no workflow_call inputs exist, so the poll
    budget is a fixed env on the job — 15 minutes."""
    block = _job_block("judge")
    assert "JUDGE_WAIT_MINUTES" in block
    assert re.search(r"JUDGE_WAIT_MINUTES:\s*\"?15\"?", block)


def test_judge_maps_verdict_states():
    """success -> EXECUTED, failure -> REJECTED, else UNAVAILABLE."""
    block = _job_block("judge")
    assert "success) r=EXECUTED" in block
    assert "failure) r=REJECTED" in block
    assert "UNAVAILABLE" in block


def test_coverage_reads_judge_not_static_scan():
    block = _job_block("coverage")
    assert "always()" in block
    assert "statuses: write" in block
    assert "checks: write" in block  # the check run is the source of truth
    assert "publish-review-coverage.py" in block
    assert "needs.judge.outputs.result" in block
    needs_line = next(l for l in block.splitlines() if "needs:" in l)
    assert "judge" in needs_line


def test_id_token_write_only_on_tailscale_lane():
    """id-token: write exists for the Tailscale step of review-a only —
    judge and static-scan have no OIDC need."""
    assert "id-token: write" in _job_block("review-a")
    for name in ("static-scan", "judge", "coverage", "classify"):
        assert "id-token" not in _job_block(name), name


def test_no_tailscale_off_lane_a():
    for name in ("static-scan", "judge", "coverage"):
        assert "tailscale/github-action" not in _job_block(name), name
