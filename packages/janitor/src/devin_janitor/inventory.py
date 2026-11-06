"""Build a unified session inventory from Devin's two stores.

- ``cli/sessions.db``      → rows with ``origin="cli"`` (via devin-internals-spec)
- ``User/acp-messages/``   → rows with ``origin="gui"`` for session ids that
  do not exist in ``sessions.db`` (GUI sessions missing from the CLI store)

Timestamps in ``sessions.db`` are epoch *milliseconds*; ``SessionRow`` exposes
epoch *seconds* so comparisons against ``time.time()`` are obvious.

Also inventories ``.devin/`` runtime artifacts — the PAS learning loop's
accumulators (``hook-fires.jsonl``, ``search.db``, ``graph.db``,
``learning-state.json``) plus the janitor's own keep/pending/log files.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from devin_internals.parsers import AcpMessagesStore, SessionsStore
from devin_internals.schema import SchemaError

from devin_janitor.paths import DevinPaths

_MS = 1000.0
_PATH_KEY_RE = re.compile(r"path|file", re.IGNORECASE)
_PATH_VALUE_RE = re.compile(r"[/\\][^/\\\s]+|^[A-Za-z]:[/\\]")


@dataclass(frozen=True)
class SessionRow:
    """One session as the janitor sees it (either store)."""

    id: str
    origin: str  # "cli" | "gui"
    title: str
    project: str
    created: float | None
    last_activity: float | None
    user_msgs: int = 0
    assistant_msgs: int = 0
    tool_calls: int = 0
    files_touched: int = 0
    prompt: str = ""
    empty_flag: bool = False

    @property
    def score(self) -> int:
        return self.user_msgs * 3 + self.tool_calls

    @property
    def is_empty(self) -> bool:
        return self.empty_flag or (
            self.user_msgs == 0
            and self.assistant_msgs == 0
            and self.tool_calls == 0
        )


# ------------------------------------------------------------- cli rows ----


def _role_of(payload: Any) -> str | None:
    """Best-effort role extraction from a chat_message JSON blob."""
    if not isinstance(payload, dict):
        return None
    for key in ("role", "type", "kind", "author"):
        value = payload.get(key)
        if not isinstance(value, str):
            continue
        v = value.lower()
        if "user" in v or "human" in v:
            return "user"
        if "assistant" in v or "agent" in v or "model" in v or "ai" in v:
            return "assistant"
    return None


def _text_of(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    if not isinstance(payload, dict):
        return ""
    for key in ("text", "content", "prompt", "message"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _count_files_touched(tool_jsons: Iterable[str | None]) -> int:
    """Distinct path-like values found in tool-call payloads (heuristic)."""
    found: set[str] = set()

    def walk(node: Any, path_key: bool) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, path_key or bool(_PATH_KEY_RE.search(str(k))))
        elif isinstance(node, list):
            for v in node:
                walk(v, path_key)
        elif isinstance(node, str) and path_key and _PATH_VALUE_RE.search(node):
            found.add(node)

    for raw in tool_jsons:
        if not raw:
            continue
        try:
            walk(json.loads(raw), False)
        except (json.JSONDecodeError, TypeError):
            continue
    return len(found)


def _cli_rows(store: SessionsStore) -> list[SessionRow]:
    rows = []
    for s in store.sessions():
        nodes = store.message_nodes(s.id)
        user_msgs = assistant_msgs = 0
        prompt = ""
        for n in nodes:
            try:
                payload = json.loads(n.chat_message)
            except (json.JSONDecodeError, TypeError):
                payload = n.chat_message
            role = _role_of(payload)
            if role == "user":
                user_msgs += 1
                if not prompt:
                    prompt = _text_of(payload)
            elif role == "assistant":
                assistant_msgs += 1
            else:
                assistant_msgs += 1  # unknown role still proves activity

        tool_states = store.tool_call_state(s.id)
        files = _count_files_touched(
            [t.tool_call_json for t in tool_states]
            + [t.tool_call_update_json for t in tool_states]
        )
        rows.append(
            SessionRow(
                id=s.id,
                origin="cli",
                title=s.title or "",
                project=s.working_directory or "",
                created=(s.created_at / _MS) if s.created_at else None,
                last_activity=(
                    s.last_activity_at / _MS if s.last_activity_at else None
                ),
                user_msgs=user_msgs,
                assistant_msgs=assistant_msgs,
                tool_calls=len(tool_states),
                files_touched=files,
                prompt=prompt,
            )
        )
    return rows


# ------------------------------------------------------------- gui rows ----


def _gui_row(db_path: Path) -> SessionRow | None:
    if not db_path.is_file():
        return None
    sid = db_path.name.split(".db", 1)[0]
    try:
        with AcpMessagesStore(db_path) as store:
            meta = store.meta()
            messages = store.messages()
    except (SchemaError, sqlite3.Error, OSError):
        return None

    title = ""
    created = None
    for key, value in meta.items():
        lk = key.lower()
        if not title and "title" in lk:
            title = str(value)
        if created is None and ("created" in lk or "ts" in lk):
            try:
                created = float(value)
            except (TypeError, ValueError):
                pass
    if created and created > 1e12:  # ms → s
        created /= _MS

    mtime = db_path.stat().st_mtime
    user_msgs = sum(1 for m in messages if "user" in m.kind.lower())
    return SessionRow(
        id=sid,
        origin="gui",
        title=title,
        project=str(meta.get("cwd", "")),
        created=created or mtime,
        last_activity=mtime,
        user_msgs=user_msgs,
        assistant_msgs=len(messages) - user_msgs,
        tool_calls=sum(1 for m in messages if "tool" in m.kind.lower()),
    )


def load_inventory(paths: DevinPaths) -> list[SessionRow]:
    """All sessions visible to the janitor, both stores merged by id."""
    rows: list[SessionRow] = []
    seen: set[str] = set()
    if paths.sessions_db.is_file():
        with SessionsStore(paths.sessions_db) as store:
            for row in _cli_rows(store):
                rows.append(row)
                seen.add(row.id)
    if paths.acp_messages_dir.is_dir():
        for db in sorted(paths.acp_messages_dir.glob("*.db")):
            row = _gui_row(db)
            if row and row.id not in seen:
                rows.append(row)
                seen.add(row.id)
    return rows


def live_session_ids(paths: DevinPaths) -> set[str]:
    """Session ids present in ``sessions.db`` (for orphan-lock detection)."""
    if not paths.sessions_db.is_file():
        return set()
    with SessionsStore(paths.sessions_db) as store:
        return {s.id for s in store.sessions()}


# ---------------------------------------------------- .devin/ artifacts ----


class DevinArtifactError(OSError):
    """A ``.devin/`` path exists but is unreadable or malformed.

    Absence is fine — an empty inventory is returned for a missing dir.
    A path that exists but cannot be read is *data*, and unreadable data
    is an error, never a silent skip.
    """


@dataclass(frozen=True)
class DevinArtifact:
    """One file under a ``.devin/`` runtime-state dir."""

    rel_path: str  # posix-style path relative to the .devin dir
    bytes: int
    mtime: float


def _validate_state_file(p: Path) -> None:
    """``.json`` files under ``.devin/`` are state — verify they parse."""
    try:
        json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DevinArtifactError(
            f"malformed .devin state file: {p} ({exc})"
        ) from exc
    except OSError as exc:
        raise DevinArtifactError(
            f"unreadable .devin artifact: {p} ({exc})"
        ) from exc


def load_devin_artifacts(devin_dir: str | Path) -> list[DevinArtifact]:
    """Every file under a ``.devin/`` dir, sorted by relative path.

    A missing dir yields ``[]``. A ``.devin`` that exists but is not a
    directory, a non-regular file (fifo, dead symlink), an unstat-able
    file and a malformed ``*.json`` state file all raise
    :class:`DevinArtifactError` — loudly, never silently skipped.
    """
    d = Path(devin_dir).expanduser()
    if not d.exists():
        return []
    if not d.is_dir():
        raise DevinArtifactError(f".devin path is not a directory: {d}")
    try:
        children = sorted(d.rglob("*"))
    except OSError as exc:
        raise DevinArtifactError(
            f"cannot list .devin dir: {d} ({exc})"
        ) from exc
    artifacts: list[DevinArtifact] = []
    for p in children:
        # pathlib's is_dir/is_file swallow ENOENT-class errors but
        # re-raise EACCES — probe once under a single wrap so every
        # unreadable case surfaces as DevinArtifactError
        try:
            if p.is_dir():
                continue
            if not p.is_file():
                raise DevinArtifactError(
                    f"unreadable .devin artifact: {p}"
                )
            st = p.stat()
        except DevinArtifactError:
            raise
        except OSError as exc:
            raise DevinArtifactError(
                f"unreadable .devin artifact: {p} ({exc})"
            ) from exc
        if p.name.lower().endswith(".json"):
            _validate_state_file(p)
        artifacts.append(
            DevinArtifact(
                rel_path=p.relative_to(d).as_posix(),
                bytes=st.st_size,
                mtime=st.st_mtime,
            )
        )
    return artifacts
