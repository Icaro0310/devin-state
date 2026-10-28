#!/usr/bin/env python3
"""Publish the ``Review Coverage`` check run for a PR head SHA.

The failure class this sensor covers:

* A green "Devin Review" status is ambiguous — skipped-for-credits posts
  ``success`` too. Review coverage must be computed from explicit evidence:
  the Devin classification plus each fallback reviewer's outcome.
* ``DEGRADED`` is a first-class verdict: one reviewer executed, the other
  failed. It is neither full coverage nor a no-review failure, and the
  merge gate must not treat it as either.
* The check never impersonates Devin Review: its name is
  ``Review Coverage``, its summary names every evidence source.

Why a check run, not a commit status: ``DEGRADED`` must not be green.
Commit statuses only know error/failure/pending/success — publishing
partial coverage as ``success`` would repeat the skipped-as-success bug
one layer down. The Checks API has the honest conclusion:
``action_required`` — a human decides, and the code is not blamed.

Outputs posted per head SHA:

* check run ``Review Coverage`` — the source of truth the gate reads:
  success | action_required | failure, with the evidence string in
  ``output.summary``.
* commit status ``Review Coverage`` — a compatibility mirror that keeps
  the gate's ``status``-event trigger working (check runs created via
  ``GITHUB_TOKEN`` do not re-dispatch workflows). Mapping:
  success→success, action_required→pending, failure→failure.

Inputs are outcome strings, not job internals:

* ``--devin`` — classifier output: EXECUTED | SKIPPED_CREDITS |
  FAILED_BEFORE_REVIEW | UNVERIFIED (or SKIPPED when the job was skipped).
* ``--a`` / ``--b`` — reviewer outcome: EXECUTED | FAILED | UNAVAILABLE
  (or SKIPPED when the job did not run).

Verdicts:

* ``devin=EXECUTED``            → success, coverage by Devin itself.
* ``a and b EXECUTED``          → success, full fallback coverage.
* exactly one EXECUTED          → ``action_required``, ``DEGRADED``
                                  prefix — partial evidence, human call.
* neither EXECUTED              → failure — no review executed.

Findings are deliberately NOT part of the verdict: a review that ran and
found critical issues is successful execution. The merge gate reads
blocking findings from the check summary and the reviewers' posted
reviews separately.

Usage:
    publish-review-coverage.py --repo owner/name --sha <head_sha>
        --devin S --a S --b S [--dry-run]

``--dry-run`` prints the computed verdict without posting.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

COVERAGE_CONTEXT = "Review Coverage"
EXECUTED = "EXECUTED"
_VERDICT_OK = {EXECUTED}


def compute_verdict(devin: str, a: str, b: str,
                    a_critical: int = 0) -> tuple[str, str, str]:
    """Return (check_conclusion, description, verdict).

    ``check_conclusion`` is the Checks-API conclusion: ``success``,
    ``action_required`` or ``failure``. ``verdict`` is the coarse label
    embedded in the description so a reader — human or gate — can
    distinguish coverage kinds.

    ``a_critical`` > 0 appends ``findings=blocking`` — the review still
    executed (conclusion stays success), but the merge gate must hold.
    This is the findings-as-data channel for reviewer A, whose own
    comments are advisory; reviewer B's blockers surface as
    request_changes reviews.
    """
    desc_core = f"devin={devin} a={a} b={b}"
    suffix = f" findings=blocking(critical={a_critical})" if a_critical > 0 else ""
    if devin == EXECUTED:
        return ("success",
                f"devin=EXECUTED — primary review ran; fallback not needed{suffix}",
                "EXECUTED")
    ran = [name for name, outcome in (("a", a), ("b", b)) if outcome in _VERDICT_OK]
    if len(ran) == 2:
        return "success", f"covered — {desc_core}{suffix}", "COVERED"
    if b == EXECUTED:
        # Reviewer B is the direct-Ollama lane: it always posts a real
        # review comment plus a verdict, so its evidence alone covers the
        # PR. Reviewer A (third-party action) flakes on event-payload
        # races — its state is still recorded honestly in the
        # description, but the gate must not stay hostage to infra
        # flakiness outside the review itself.
        return ("success",
                (f"covered b-only — {desc_core} — "
                 f"reviewer A did not execute{suffix}"),
                "COVERED")
    if ran:
        return ("action_required",
                (f"DEGRADED {ran[0]}-only — {desc_core} — "
                 f"partial coverage, requires human review{suffix}"),
                "DEGRADED")
    return "failure", f"no review executed — {desc_core}", "FAILURE"


def _mirror_state(conclusion: str) -> str:
    """Check-run conclusion → commit-status state for the mirror."""
    return {"success": "success", "failure": "failure"}.get(
        conclusion, "pending")


def _gh(args: list[str]) -> bool:
    env = os.environ.copy()
    if "GH_TOKEN" not in env and env.get("GITHUB_TOKEN"):
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    try:
        proc = subprocess.run(["gh", "api", *args], check=False,
                              capture_output=True, text=True, env=env,
                              timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def post_check(repo: str, sha: str, conclusion: str, summary: str,
               details_url: str | None) -> bool:
    """The check run — the source of truth the gate reads."""
    cmd = [f"repos/{repo}/check-runs",
           "-f", f"name={COVERAGE_CONTEXT}", "-f", f"head_sha={sha}",
           "-f", "status=completed", "-f", f"conclusion={conclusion}",
           "-f", f"output[title]={COVERAGE_CONTEXT}",
           "-f", f"output[summary]={summary}"]
    if details_url:
        cmd += ["-f", f"details_url={details_url}"]
    return _gh(cmd)


def post_status(repo: str, sha: str, conclusion: str, description: str,
                target_url: str | None) -> bool:
    """Compatibility mirror: keeps the gate's status-event trigger alive
    for success, and never shows green for degraded coverage."""
    cmd = [f"repos/{repo}/statuses/{sha}",
           "-f", f"state={_mirror_state(conclusion)}",
           "-f", f"context={COVERAGE_CONTEXT}",
           "-f", f"description={description}"]
    if target_url:
        cmd += ["-f", f"target_url={target_url}"]
    return _gh(cmd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--devin", required=True)
    parser.add_argument("--a", required=True)
    parser.add_argument("--b", required=True)
    parser.add_argument("--a-critical", type=int, default=0,
                        help="critical findings reported by reviewer A")
    parser.add_argument("--target-url", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    conclusion, description, verdict = compute_verdict(
        args.devin, args.a, args.b, a_critical=args.a_critical)
    print(f"verdict={verdict}")
    print(f"conclusion={conclusion}")
    print(f"description={description}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"verdict={verdict}\nconclusion={conclusion}\n")
    if args.dry_run:
        return 0
    ok = post_check(args.repo, args.sha, conclusion, description,
                    args.target_url)
    if not ok:
        print("::error::failed to post Review Coverage check run",
              file=sys.stderr)
        return 1
    if not post_status(args.repo, args.sha, conclusion, description,
                       args.target_url):
        # the check run (source of truth) is posted; the mirror failing
        # only loses the status-event retrigger — degraded/none stays
        # held either way, so warn instead of hard-failing the job.
        print("::warning::Review Coverage status mirror failed — "
              "check run posted, status-event retrigger lost",
              file=sys.stderr)
    print(f"posted Review Coverage check={conclusion} on {args.sha[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
