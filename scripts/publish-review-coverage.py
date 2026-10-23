#!/usr/bin/env python3
"""Publish the ``Review Coverage`` commit status for a PR head SHA.

The failure class this sensor covers:

* A green "Devin Review" status is ambiguous — skipped-for-credits posts
  ``success`` too. Review coverage must be computed from explicit evidence:
  the Devin classification plus each fallback reviewer's outcome.
* ``DEGRADED`` is a first-class verdict: one reviewer executed, the other
  failed. It is neither full coverage nor a no-review failure, and the
  merge gate must not treat it as either.
* The status never impersonates Devin Review: its context is
  ``Review Coverage``, its description names every evidence source.

Inputs are outcome strings, not job internals:

* ``--devin`` — classifier output: EXECUTED | SKIPPED_CREDITS |
  FAILED_BEFORE_REVIEW | UNVERIFIED (or SKIPPED when the job was skipped).
* ``--a`` / ``--b`` — reviewer outcome: EXECUTED | FAILED | UNAVAILABLE
  (or SKIPPED when the job did not run).

Verdicts:

* ``devin=EXECUTED``            → state success, coverage by Devin itself.
* ``a and b EXECUTED``          → state success, full fallback coverage.
* exactly one EXECUTED          → state success, ``DEGRADED`` prefix —
                                  review evidence exists but partial.
* neither EXECUTED              → state failure — no review executed.

Findings are deliberately NOT part of the verdict: a review that ran and
found critical issues is successful execution. The merge gate reads
blocking findings from the reviewers' posted reviews separately.

Usage:
    publish-review-coverage.py --repo owner/name --sha <head_sha>
        --devin S --a S --b S [--dry-run]

``--dry-run`` prints the computed status without posting.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

COVERAGE_CONTEXT = "Review Coverage"
EXECUTED = "EXECUTED"
_VERDICT_OK = {EXECUTED}


def compute_verdict(devin: str, a: str, b: str,
                    a_critical: int = 0) -> tuple[str, str, str]:
    """Return (commit_status_state, description, verdict).

    ``state`` is what the commit status shows (success/failure);
    ``verdict`` is the coarse label embedded in the description so a
    reader — human or gate — can distinguish coverage kinds.

    ``a_critical`` > 0 appends ``findings=blocking`` — the review still
    executed (state stays success), but the merge gate must hold. This is
    the findings-as-data channel for reviewer A, whose own comments are
    advisory; reviewer B's blockers surface as request_changes reviews.
    """
    desc_core = f"devin={devin} a={a} b={b}"
    suffix = f" findings=blocking(critical={a_critical})" if a_critical > 0 else ""
    if devin == EXECUTED:
        return "success", f"devin=EXECUTED — primary review ran; fallback not needed{suffix}", "EXECUTED"
    ran = [name for name, outcome in (("a", a), ("b", b)) if outcome in _VERDICT_OK]
    if len(ran) == 2:
        return "success", f"covered — {desc_core}{suffix}", "COVERED"
    if ran:
        return "success", f"DEGRADED {ran[0]}-only — {desc_core}{suffix}", "DEGRADED"
    return "failure", f"no review executed — {desc_core}", "FAILURE"


def post_status(repo: str, sha: str, state: str, description: str,
                target_url: str | None) -> bool:
    env = os.environ.copy()
    if "GH_TOKEN" not in env and env.get("GITHUB_TOKEN"):
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    cmd = ["gh", "api", f"repos/{repo}/statuses/{sha}",
           "-f", f"state={state}", "-f", f"context={COVERAGE_CONTEXT}",
           "-f", f"description={description}"]
    if target_url:
        cmd += ["-f", f"target_url={target_url}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              env=env, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


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

    state, description, verdict = compute_verdict(
        args.devin, args.a, args.b, a_critical=args.a_critical)
    print(f"verdict={verdict}")
    print(f"state={state}")
    print(f"description={description}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"verdict={verdict}\nstate={state}\n")
    if args.dry_run:
        return 0
    if not post_status(args.repo, args.sha, state, description,
                       args.target_url):
        print("::error::failed to post Review Coverage status",
              file=sys.stderr)
        return 1
    print(f"posted Review Coverage={state} on {args.sha[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
