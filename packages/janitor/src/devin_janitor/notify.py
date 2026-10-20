"""Post-run notification hook — optional, fail-open.

``run --notify-cmd "<command>"`` (or ``JANITOR_NOTIFY_CMD`` when the flag
is absent) names a shell command that receives a compact JSON summary of
the run on its stdin once the pipeline finishes — the mirror image of
``--export-cmd``, which runs *before* any deletion instead of after the
run. A typical pairing is a slack/mail notifier so a scheduled purge is
never silent; the janitor ships no notifier and keeps no dependency on
any notification service.

Fail-open by design: an unrunnable command, non-zero exit or timeout
prints a stderr warning and never changes the run's exit code —
notification must never be the reason a cleanup run reports failure.
With no flag and no env var, nothing is spawned and the run is
byte-for-byte unchanged.

Payload (one line of JSON)::

    {"apply": true, "total": 12, "planned": 3, "deleted": 3,
     "retained": 9, "pending": 0, "rc": 0}

``planned`` is what the plan selected for deletion (a dry-run reports it
with ``apply: false`` and ``deleted: 0``); ``retained`` mirrors the
plan's keep count; ``rc`` is the run's own exit code, so failed runs
notify too.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

NOTIFY_TIMEOUT_S = 10
ENV_NOTIFY_CMD = "JANITOR_NOTIFY_CMD"


def resolve_notify_cmd(
    flag: str | None, environ: dict[str, str] | None = None
) -> str | None:
    """Resolve the notify command: flag beats env; env only when absent.

    An explicit empty flag (``--notify-cmd ""``) disables notification
    even when ``JANITOR_NOTIFY_CMD`` is set.
    """
    if flag is not None:
        return flag or None
    env = os.environ if environ is None else environ
    return env.get(ENV_NOTIFY_CMD) or None


def send_notification(
    cmd: str | None, payload: dict, timeout: float | None = None
) -> None:
    """Pipe ``payload`` as JSON to ``cmd``'s stdin. Never raises.

    Fail-open: every failure mode (unrunnable command, non-zero exit,
    timeout, anything else) becomes a stderr warning and the caller's
    exit code stands. A falsy ``cmd`` means no hook configured — return
    without spawning anything.
    """
    if not cmd:
        return
    timeout = NOTIFY_TIMEOUT_S if timeout is None else timeout
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            input=json.dumps(payload) + "\n",
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(
            f"warning: notify command timed out after {timeout:g}s — "
            "run result unchanged",
            file=sys.stderr,
        )
    except OSError as exc:
        print(
            f"warning: notify command failed to run: {exc} — "
            "run result unchanged",
            file=sys.stderr,
        )
    except Exception as exc:  # noqa: BLE001 - notify must never break a run
        print(
            f"warning: notify failed: {exc} — run result unchanged",
            file=sys.stderr,
        )
    else:
        if proc.returncode != 0:
            print(
                f"warning: notify command exited {proc.returncode} — "
                "run result unchanged",
                file=sys.stderr,
            )
