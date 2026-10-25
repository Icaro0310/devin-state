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
import os
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
MIN_DELETE_CONFIDENCE = 0.6


def _win_argv(spec: str) -> list[str]:
    r"""Windows argv split: ``"``/``'`` toggle quoting anywhere in a token
    (so ``--config="C:\My Data\x"`` or a single-quoted path stays one
    argument), backslashes are literal, and a bare ``""`` yields an empty
    argument rather than vanishing. Quotes are consumed, never emitted."""
    parts: list[str] = []
    cur: list[str] = []
    quoted = False
    started = False  # token exists even when it yields no chars ("")
    for ch in spec:
        if ch in "\"'":
            quoted = not quoted
            started = True
            continue
        if ch in " \t" and not quoted:
            if started:
                parts.append("".join(cur))
                cur, started = [], False
            continue
        cur.append(ch)
        started = True
    if started:
        parts.append("".join(cur))
    return parts


def _split_binary(spec: str, *, posix: bool | None = None) -> list[str]:
    r"""Split a ``--judge <bin>`` spec into argv, Windows-path safe.

    POSIX-mode ``shlex.split`` eats backslashes, so ``C:\Tools\poordjaevin.exe``
    would collapse into ``C:Toolspoordjaevin.exe``; on Windows we use the
    CommandLineToArgvW convention instead (shlex ``posix=False`` still
    mis-splits mid-token quotes).
    """
    if posix is None:
        posix = os.name != "nt"
    if posix:
        return shlex.split(spec)
    return _win_argv(spec)


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
_NEGATORS = ("not", "never", "don't", "dont", "cannot", "can't", "cant")


def _parse_verdict_text(text: str) -> bool | None:
    """``keep``→True, ``delete``→False from free text; None if unclear.

    Fail-closed at the word level: a negated ``delete`` ("do not
    delete") or text mixing keep- and delete-tokens abstains rather
    than returning a delete verdict."""
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
    words = t.split()
    has_false = any(tok in words for tok in _FALSE_TOKENS)
    has_true = any(tok in words for tok in _TRUE_TOKENS)
    if has_false and has_true:
        return None
    if has_false:
        if any(w in _NEGATORS or w.endswith("n't") for w in words):
            return None
        return False
    if has_true:
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
        parts = _split_binary(self.binary)
        return bool(parts) and shutil.which(parts[0]) is not None

    def judge(self, session: SessionRow, statement: str) -> Verdict:
        argv = _split_binary(self.binary)
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
                        *argv,
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
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return Verdict(keep=None, reason="unparseable output")
        if not isinstance(parsed, dict):
            return Verdict(keep=None, reason="unexpected output shape")
        answer = parsed.get("keep")
        if not isinstance(answer, dict):
            return Verdict(keep=None, reason="no typed keep answer")
        value, conf = answer.get("value"), answer.get("confidence")
        if answer.get("abstained"):
            return Verdict(
                keep=None, reason=f"poordjaevin abstained ({value})"
            )
        if value == "delete":
            if (
                isinstance(conf, (int, float))
                and not isinstance(conf, bool)
                and conf >= MIN_DELETE_CONFIDENCE
            ):
                return Verdict(
                    keep=False, reason=f"poordjaevin delete ({conf})"
                )
            return Verdict(
                keep=None,
                reason=f"poordjaevin delete below confidence ({conf})",
            )
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
