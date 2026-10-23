#!/usr/bin/env python3
"""Classify the Devin Review signal on a PR head SHA.

The failure class this sensor covers:

* Devin Review reports as a **commit status**, never a check run — the
  ``/check-runs`` API never sees it, and ``gh pr checks`` only works
  because it aggregates both surfaces.
* The status ``state`` alone cannot distinguish execution from skip:
  both a completed analysis and a credit-exhausted skip post
  ``state: success``. The ``description`` carries the truth.
* A status on an old SHA must never be adopted for a new head.

States emitted on stdout / GITHUB_OUTPUT (``state=``):

* ``EXECUTED``            — ``state=success`` AND description matches the
                            completed-analysis form (``completed analysis``).
* ``SKIPPED_CREDITS``     — ``state=success`` AND description carries a
                            skip marker (``skipped`` / ``no credits`` /
                            ``trial expired``).
* ``FAILED_BEFORE_REVIEW``— ``state`` is ``failure`` or ``error``.
* ``UNVERIFIED``          — no Devin status on this SHA, unrecognized
                            description, or ambiguous identity. Anything
                            not positively classified falls here, so the
                            fallback reviews run rather than trust a
                            vacuous green.

Identity pinning: a status only counts when ``context == "Devin Review"``,
``target_url`` is on ``app.devin.ai`` AND ``avatar_url`` carries the app
install id ``/in/811515`` — anyone with write access can forge a context
name; they cannot forge the app avatar.

Usage:
    classify-devin-status.py --repo owner/name --sha <head_sha>
        [--wait-seconds N] [--poll-interval S]

Environment: ``GH_TOKEN`` (or ``GITHUB_TOKEN``) used for ``gh api``.

Exits 0 always — the classification is data, not a verdict. Network/API
errors during the wait window degrade to ``UNVERIFIED``, never a crash:
the fallback is the safe side.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

DEVIN_CONTEXT = "Devin Review"
DEVIN_APP_MARKER = "/in/811515"  # avatar_url fragment of devin-ai-integration
DEVIN_URL_HOST = "app.devin.ai"

SKIP_MARKERS = ("skipped", "no credits", "trial expired")
EXECUTED_MARKER = "completed analysis"


def _is_devin_status(status: dict) -> bool:
    """True only when the status is verifiably from the Devin app."""
    if status.get("context") != DEVIN_CONTEXT:
        return False
    if DEVIN_APP_MARKER not in (status.get("avatar_url") or ""):
        return False
    if DEVIN_URL_HOST not in (status.get("target_url") or ""):
        return False
    return True


def classify_statuses(statuses: list[dict]) -> tuple[str, dict | None]:
    """Classify from a raw statuses payload (``/status`` response).

    ``statuses`` arrives newest-first. Multiple Devin statuses on one SHA
    resolve to the most recent matching one. Returns (state, raw_status).
    """
    devin = [s for s in statuses if _is_devin_status(s)]
    if not devin:
        return "UNVERIFIED", None
    latest = devin[0]
    state = latest.get("state")
    if state in ("failure", "error"):
        return "FAILED_BEFORE_REVIEW", latest
    if state != "success":
        # pending or anything unexpected: not affirmative evidence
        return "UNVERIFIED", latest
    desc = (latest.get("description") or "").lower()
    if any(marker in desc for marker in SKIP_MARKERS):
        return "SKIPPED_CREDITS", latest
    if EXECUTED_MARKER in desc:
        return "EXECUTED", latest
    return "UNVERIFIED", latest


def fetch_statuses(repo: str, sha: str) -> list[dict] | None:
    """Statuses payload for ``sha`` via ``gh api``; None on any failure."""
    env = os.environ.copy()
    if "GH_TOKEN" not in env and env.get("GITHUB_TOKEN"):
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    try:
        proc = subprocess.run(
            ["gh", "api", f"repos/{repo}/commits/{sha}/status"],
            capture_output=True, text=True, env=env, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    statuses = payload.get("statuses")
    return statuses if isinstance(statuses, list) else None


def classify(repo: str, sha: str, wait_seconds: int = 180,
             poll_interval: int = 15) -> tuple[str, dict | None]:
    """Poll until a Devin status appears on ``sha`` or the window ends.

    The status posts within seconds of a PR event; absent-after-window is
    genuinely UNVERIFIED, not merely slow. API errors degrade to
    UNVERIFIED (the fallback side), keeping the sensor fail-safe.
    """
    deadline = time.monotonic() + wait_seconds
    last: tuple[str, dict | None] = ("UNVERIFIED", None)
    while True:
        statuses = fetch_statuses(repo, sha)
        if statuses is not None:
            last = classify_statuses(statuses)
            if last[0] != "UNVERIFIED" or wait_seconds <= 0:
                return last
            if any(_is_devin_status(s) for s in statuses):
                # A Devin status exists but is unrecognized/pending —
                # classified on the spot, no point polling for a second.
                return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--sha", required=True, help="PR head SHA")
    parser.add_argument("--wait-seconds", type=int, default=180,
                        help="how long to wait for the Devin status to "
                             "appear before calling UNVERIFIED")
    parser.add_argument("--poll-interval", type=int, default=15)
    args = parser.parse_args(argv)

    state, raw = classify(args.repo, args.sha,
                          wait_seconds=args.wait_seconds,
                          poll_interval=args.poll_interval)
    print(f"state={state}")
    if raw:
        print(f"description={raw.get('description')!r}")
        print(f"target_url={raw.get('target_url')}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"state={state}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
