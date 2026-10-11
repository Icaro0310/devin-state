"""Pluggable judge for ambiguous (JUDGE-tier) sessions.

Every backend is **fail-open**: unavailable, error, timeout or an unclear
verdict all mean *keep* — the janitor never deletes without an explicit
"no durable knowledge" verdict.

Specs (``--judge``):

- ``none``           — default. Judges nothing; all JUDGE sessions are kept.
                       Purely rules-based operation, no LLM involved.
- ``devin-judge``    — shells ``poordjaevin ask`` per session (local, typed
                       answers with calibrated confidence). ``devin-judge:<bin>``
                       overrides the binary path; ``poordjaevin`` is an alias.
- ``command:<cmd>``  — pipe a JSON payload to any local CLI; its stdout is
                       parsed as a verdict (``{"keep": bool}`` JSON, or a
                       bare keep/delete/true/false/yes/no token). This is the
                       extension point: wire in any script you trust —
                       nothing external is required.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from devin_janitor.inventory import SessionRow

COMMAND_TIMEOUT_S = 60


@dataclass(frozen=True)
class Verdict:
    """A judge's decision. ``keep=None`` means abstained → treat as keep."""

    keep: bool | None
    reason: str = ""


class Judge:
    """Backend protocol: ``judge(session) -> Verdict``."""

    name = "judge"

    def available(self) -> bool:  # pragma: no cover - overridden
        return True

    def judge(self, session: SessionRow, statement: str) -> Verdict:
        raise NotImplementedError

    def close(self) -> None:
        pass


class NoneJudge(Judge):
    """Default backend: abstains on everything → every JUDGE row is kept."""

    name = "none"

    def available(self) -> bool:
        return True

    def judge(self, session: SessionRow, statement: str) -> Verdict:
        return Verdict(keep=None, reason="judge=none")


def _session_summary(session: SessionRow) -> str:
    parts = [session.title]
    if session.prompt:
        parts.append(session.prompt[:1500])
    return "\n\n".join(parts)[:4000]


_TRUE_TOKENS = ("keep", "true", "yes", "durable", "preserve")
_FALSE_TOKENS = ("delete", "false", "no", "noise", "ephemeral")


def _parse_verdict_text(text: str) -> bool | None:
    """``keep``→True, ``delete``→False from free text; None if unclear."""
    t = text.strip().lower()
    try:
        obj = json.loads(t)
    except (json.JSONDecodeError, TypeError):
        obj = None
    if isinstance(obj, dict):
        for key in ("keep", "value", "verdict"):
            if key in obj:
                val = obj[key]
                if isinstance(val, bool):
                    return val
                return _parse_verdict_text(str(val))
        if obj.get("abstained"):
            return None
    token = re.sub(r"[^a-z]", "", t)[:16]
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    if any(tok in t.split() for tok in _FALSE_TOKENS):
        return False
    if any(tok in t.split() for tok in _TRUE_TOKENS):
        return True
    return None


class CommandJudge(Judge):
    """Runs an external CLI judge: JSON payload on stdin, verdict on stdout."""

    name = "command"

    def __init__(self, cmd: str, timeout: float = COMMAND_TIMEOUT_S) -> None:
        self.cmd = cmd
        self.timeout = timeout

    def available(self) -> bool:
        return True

    def judge(self, session: SessionRow, statement: str) -> Verdict:
        payload = json.dumps(
            {
                "statement": statement,
                "session_id": session.id,
                "title": session.title,
                "text": _session_summary(session),
            }
        )
        try:
            proc = subprocess.run(
                self.cmd,
                input=payload,
                capture_output=True,
                text=True,
                shell=True,
                check=False,
                timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Verdict(keep=None, reason=f"command failed: {exc}")
        if proc.returncode != 0:
            return Verdict(keep=None, reason=f"exit {proc.returncode}")
        keep = _parse_verdict_text(proc.stdout)
        return Verdict(keep=keep, reason=proc.stdout.strip()[:200])


class PoordjaevinJudge(Judge):
    """devin-judge backend: shells ``poordjaevin ask`` per session.

    The typed-answer contract (``{"keep": {"value": ..., "confidence":
    ...}}``) maps straight onto :class:`Verdict`. Anything but a decided
    ``delete`` is a fail-open keep — including abstained, low-confidence,
    unparseable or missing answers.
    """

    name = "devin-judge"

    _QUESTIONS: ClassVar[dict] = {
        "keep": {"type": "choice", "options": ["keep", "delete"]},
    }

    def __init__(
        self, binary: str = "poordjaevin", timeout: float = COMMAND_TIMEOUT_S
    ) -> None:
        self.binary = binary
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(shlex.split(self.binary)[0]) is not None

    def judge(self, session: SessionRow, statement: str) -> Verdict:
        with tempfile.TemporaryDirectory(
            prefix="devin-janitor-judge-"
        ) as td:
            state_file = Path(td) / "state.txt"
            questions_file = Path(td) / "questions.json"
            state_file.write_text(
                f"{statement}\n\n{_session_summary(session)}",
                encoding="utf-8",
            )
            questions_file.write_text(
                json.dumps(self._QUESTIONS), encoding="utf-8"
            )
            try:
                proc = subprocess.run(
                    [
                        *shlex.split(self.binary),
                        "ask",
                        "--state-file",
                        str(state_file),
                        "--questions",
                        str(questions_file),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=self.timeout,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return Verdict(
                    keep=None, reason=f"poordjaevin failed: {exc}"
                )
        if proc.returncode != 0:
            return Verdict(keep=None, reason=f"exit {proc.returncode}")
        try:
            answer = json.loads(proc.stdout).get("keep") or {}
        except json.JSONDecodeError:
            return Verdict(keep=None, reason="unparseable output")
        value, conf = answer.get("value"), answer.get("confidence")
        if value == "delete":
            return Verdict(keep=False, reason=f"poordjaevin delete ({conf})")
        if value == "keep":
            return Verdict(keep=True, reason=f"poordjaevin keep ({conf})")
        return Verdict(
            keep=None, reason=f"poordjaevin abstained ({value})"
        )


def make_judge(spec: str | None) -> Judge:
    """Build a judge backend from a ``--judge`` spec string."""
    spec = (spec or "none").strip()
    if spec == "none":
        return NoneJudge()
    if spec in ("devin-judge", "poordjaevin", "judge"):
        return PoordjaevinJudge()
    if spec.startswith("devin-judge:"):
        return PoordjaevinJudge(spec.split(":", 1)[1])
    if spec.startswith("command:"):
        return CommandJudge(spec.split(":", 1)[1])
    raise ValueError(
        f"unknown judge spec {spec!r} — expected "
        "none|devin-judge[:<bin>]|command:<cmd>"
    )
