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

from devin_internals.parsers import SessionsStore

from devin_janitor.cleanup import _SIZE_QUERIES, _connect_ro
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
    # Provenance stamped by the automation bridge (sessions.db metadata
    # ``janitor_managed`` — e.g. "djaevin-acp", "janitor-pending"). A
    # ``Robot_`` title only auto-deletes when this is set; a user task that
    # happens to start with ``Robot_`` has no stamp and is never noise.
    managed: str | None = None

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


def _managed_of(metadata: str | None) -> str | None:
    """``janitor_managed`` tag from a sessions.db metadata JSON blob."""
    if not metadata:
        return None
    try:
        data = json.loads(metadata)
    except (json.JSONDecodeError, TypeError):
        return None
    tag = data.get("janitor_managed") if isinstance(data, dict) else None
    return tag if isinstance(tag, str) and tag else None


def _acp_payload_text(payload: str) -> str:
    """Non-empty user text from one acp-messages payload, else ``""``.

    Prefers the ``_meta`` full-message field, else joins the content-block
    texts — same decoding as ``_acp_first_user_text``.
    """
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return ""
    if not isinstance(data, dict):
        return ""
    meta = data.get("_meta")
    if isinstance(meta, dict):
        msg = meta.get("cognition.ai/message")
        if isinstance(msg, str) and msg.strip():
            return msg
    texts: list[str] = []
    for block in data.get("content") or []:
        if not isinstance(block, dict):
            continue
        inner = block.get("content")
        if isinstance(inner, dict):
            t = inner.get("text")
            if isinstance(t, str):
                texts.append(t)
    return "".join(texts).strip()


def _acp_first_user_text(messages: Iterable[Any]) -> str:
    """First ``user_message`` text from an acp-messages store.

    The scoring template lives in the first user turn; GUI-only sessions
    (no sessions.db row) carry it here, so the prompt-based classifier can
    see them. Prefers the ``_meta`` full-message field, else joins the
    content-block texts.
    """
    for m in messages:
        if "user" not in m.kind.lower():
            continue
        text = _acp_payload_text(m.payload)
        if text:
            return text
    return ""


def _gui_managed(meta: dict[str, str]) -> str | None:
    """``janitor_managed`` tag from an acp-messages ``meta`` table.

    GUI rows have no sessions.db metadata blob; the tag may still be
    stamped as a direct meta key or inside a JSON ``metadata`` value.
    """
    tag = meta.get("janitor_managed")
    if isinstance(tag, str) and tag:
        return tag
    return _managed_of(meta.get("metadata"))


def _walk_json_paths(node: Any, path_key: bool, found: set[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _walk_json_paths(
                v, path_key or bool(_PATH_KEY_RE.search(str(k))), found
            )
    elif isinstance(node, list):
        for v in node:
            _walk_json_paths(v, path_key, found)
    elif isinstance(node, str) and path_key and _PATH_VALUE_RE.search(node):
        found.add(node)


def _walk_paths(raw: str | None, found: set[str]) -> None:
    if not raw:
        return
    try:
        node = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return
    _walk_json_paths(node, False, found)


def _count_files_touched(tool_jsons: Iterable[str | None]) -> int:
    """Distinct path-like values found in tool-call payloads (heuristic)."""
    found: set[str] = set()
    for raw in tool_jsons:
        _walk_paths(raw, found)
    return len(found)


# ``_role_of`` as a SQL expression over ``chat_message``: the first of the
# role/type/kind/author keys holding a TEXT value — same key priority and
# same "user"/"human" substrings as the Python version. One GROUP BY pass
# replaces the per-session queries that used to pull every chat payload
# into Python just to count roles.
_ROLE_VALUE_SQL = (
    "CASE"
    " WHEN json_type(chat_message,'$.role')='text'"
    " THEN json_extract(chat_message,'$.role')"
    " WHEN json_type(chat_message,'$.type')='text'"
    " THEN json_extract(chat_message,'$.type')"
    " WHEN json_type(chat_message,'$.kind')='text'"
    " THEN json_extract(chat_message,'$.kind')"
    " WHEN json_type(chat_message,'$.author')='text'"
    " THEN json_extract(chat_message,'$.author')"
    " END"
)
_IS_USER_SQL = (
    f"(instr(lower(COALESCE({_ROLE_VALUE_SQL}, '')), 'user') > 0"
    f" OR instr(lower(COALESCE({_ROLE_VALUE_SQL}, '')), 'human') > 0)"
)


@dataclass(frozen=True)
class SessionsDbScan:
    """Single-pass aggregates over a ``sessions.db``.

    ``load_inventory`` builds one (or reuses a caller-provided one) and the
    space report derives byte estimates + orphan counts from it — one scan
    over the payload tables instead of three.
    """

    session_ids: frozenset[str]
    # message_nodes: rows, payload bytes and user-role rows per session
    node_count: dict[str, int]
    node_bytes: dict[str, int]
    user_msgs: dict[str, int]
    # tool_call_state: rows, payload bytes, files_touched per session
    tool_count: dict[str, int]
    tool_bytes: dict[str, int]
    files_touched: dict[str, int]
    # remaining _SIZE_QUERIES tables: table -> sid -> (rows, bytes)
    other_tables: dict[str, dict[str, tuple[int, int]]]


def scan_sessions_db(con: sqlite3.Connection) -> SessionsDbScan:
    """Aggregate every per-session stat in one pass per table.

    ``message_nodes`` role counting runs as ``json_extract`` inside the
    GROUP BY — C-side parsing that stops at the early ``role`` key instead
    of materialising the whole payload column into Python. A malformed
    ``chat_message`` aborts the query (``malformed JSON``); the fallback
    then replays the old exact Python parse so such a store is still
    counted correctly.
    """
    session_ids = {
        str(r[0]) for r in con.execute("SELECT id FROM sessions")
    }
    node_count: dict[str, int] = {}
    node_bytes: dict[str, int] = {}
    user_msgs: dict[str, int] = {}
    try:
        for sid, n, b, u in con.execute(
            f"SELECT session_id, COUNT(*),"
            f" COALESCE(SUM(LENGTH(chat_message)), 0),"
            f" COALESCE(SUM({_IS_USER_SQL}), 0)"
            f" FROM message_nodes GROUP BY session_id"
        ):
            sid = str(sid)
            node_count[sid] = int(n or 0)
            node_bytes[sid] = int(b or 0)
            user_msgs[sid] = int(u or 0)
    except sqlite3.Error:
        # fallback: exact Python role parse, one pass, same semantics
        node_count.clear()
        node_bytes.clear()
        user_msgs.clear()
        for sid, raw in con.execute(
            "SELECT session_id, chat_message FROM message_nodes"
        ):
            sid = str(sid)
            node_count[sid] = node_count.get(sid, 0) + 1
            node_bytes[sid] = node_bytes.get(sid, 0) + len(raw or "")
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                payload = raw
            if _role_of(payload) == "user":
                user_msgs[sid] = user_msgs.get(sid, 0) + 1

    tool_count: dict[str, int] = {}
    tool_bytes: dict[str, int] = {}
    file_sets: dict[str, set[str]] = {}
    try:
        for sid, j1, j2 in con.execute(
            "SELECT session_id, tool_call_json, tool_call_update_json"
            " FROM tool_call_state"
        ):
            sid = str(sid)
            tool_count[sid] = tool_count.get(sid, 0) + 1
            tool_bytes[sid] = (
                tool_bytes.get(sid, 0)
                + len(j1 or "")
                + len(j2 or "")
            )
            found = file_sets.setdefault(sid, set())
            _walk_paths(j1, found)
            _walk_paths(j2, found)
    except sqlite3.Error:
        pass  # table absent in older schemas — zero tools everywhere
    files_touched = {sid: len(s) for sid, s in file_sets.items()}

    other_tables: dict[str, dict[str, tuple[int, int]]] = {}
    for table, expr in _SIZE_QUERIES:
        if table in ("message_nodes", "tool_call_state"):
            continue  # already covered by the dedicated passes above
        try:
            other_tables[table] = {
                str(sid): (int(n or 0), int(b or 0))
                for sid, n, b in con.execute(
                    f"SELECT session_id, COUNT(*),"
                    f" COALESCE(SUM({expr}), 0)"
                    f" FROM {table} GROUP BY session_id"
                )
            }
        except sqlite3.Error:
            continue  # absent in older schemas — same as the estimators
    return SessionsDbScan(
        session_ids=frozenset(session_ids),
        node_count=node_count,
        node_bytes=node_bytes,
        user_msgs=user_msgs,
        tool_count=tool_count,
        tool_bytes=tool_bytes,
        files_touched=files_touched,
        other_tables=other_tables,
    )


def _first_user_prompt(
    con: sqlite3.Connection, session_id: str
) -> str:
    """First non-empty ``_text_of`` across a session's user-role nodes.

    Reads only the user payloads (one early-breaking pass in ``node_id``
    order) — the aggregate scan already established there is at least one.
    """
    try:
        cur = con.execute(
            f"SELECT chat_message FROM message_nodes"
            f" WHERE session_id = ? AND {_IS_USER_SQL} ORDER BY node_id",
            (session_id,),
        )
        for (raw,) in cur:
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                payload = raw
            if _role_of(payload) != "user":
                continue
            text = _text_of(payload)
            if text:
                return text
    except sqlite3.Error:
        pass
    return ""


def _cli_rows(
    store: SessionsStore,
    con: sqlite3.Connection,
    scan: SessionsDbScan,
) -> list[SessionRow]:
    rows = []
    for s in store.sessions():
        user_msgs = scan.user_msgs.get(s.id, 0)
        nodes = scan.node_count.get(s.id, 0)
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
                assistant_msgs=nodes - user_msgs,
                tool_calls=scan.tool_count.get(s.id, 0),
                files_touched=scan.files_touched.get(s.id, 0),
                prompt=(
                    _first_user_prompt(con, s.id) if user_msgs else ""
                ),
                managed=_managed_of(s.metadata),
            )
        )
    return rows


# ------------------------------------------------------------- gui rows ----


def _gui_row(db_path: Path) -> SessionRow | None:
    if not db_path.is_file():
        return None
    sid = db_path.name.split(".db", 1)[0]
    try:
        con = _connect_ro(db_path)
    except sqlite3.Error:
        return None
    try:
        tables = {
            r[0]
            for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not {"meta", "messages"} <= tables:
            return None  # not an acp-messages store (or unknown layout)
        meta = {
            str(k): v
            for k, v in con.execute(
                "SELECT key, value FROM meta ORDER BY key"
            )
        }
        total, users, tools = con.execute(
            "SELECT COUNT(*),"
            " COALESCE(SUM(instr(lower(kind), 'user') > 0), 0),"
            " COALESCE(SUM(instr(lower(kind), 'tool') > 0), 0)"
            " FROM messages"
        ).fetchone()
        # first user payload with text — early break, no full table read
        prompt = ""
        cur = con.execute(
            "SELECT payload FROM messages"
            " WHERE instr(lower(kind), 'user') > 0 ORDER BY position"
        )
        for (payload,) in cur:
            text = _acp_payload_text(payload)
            if text:
                prompt = text
                break
    except (sqlite3.Error, OSError):
        return None
    finally:
        con.close()

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
    return SessionRow(
        id=sid,
        origin="gui",
        title=title,
        project=str(meta.get("cwd", "")),
        created=created or mtime,
        last_activity=mtime,
        user_msgs=int(users),
        assistant_msgs=int(total) - int(users),
        tool_calls=int(tools),
        prompt=prompt,
        managed=_gui_managed(meta),
    )


def load_inventory(
    paths: DevinPaths, *, scan: SessionsDbScan | None = None
) -> list[SessionRow]:
    """All sessions visible to the janitor, both stores merged by id.

    ``scan`` lets the space report reuse one aggregate pass it already
    built for the byte estimates; ``None`` builds it here.
    """
    rows: list[SessionRow] = []
    seen: set[str] = set()
    if paths.sessions_db.is_file():
        with SessionsStore(paths.sessions_db) as store:
            con = _connect_ro(paths.sessions_db)
            try:
                if scan is None:
                    scan = scan_sessions_db(con)
                for row in _cli_rows(store, con, scan):
                    rows.append(row)
                    seen.add(row.id)
            finally:
                con.close()
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


def _strip_jsonc_comments(text: str) -> str:
    """Blank ``//`` line and ``/* */`` block comments (JSONC).

    Comments are *blanked*, not deleted: every comment char becomes a
    space except newlines, so the output keeps the original length and
    ``json`` errors still report the real line/column. Blanking also
    stops a comment from merging tokens — ``tr/* x */ue`` must not
    silently validate as ``true``.

    ``//`` inside string literals (e.g. ``"https://..."``) is preserved —
    the scan tracks string/escape state instead of a blind regex.

    Raises ``ValueError`` on an unterminated ``/*`` comment — a file that
    ends mid-comment is malformed JSONC, not a truncated-but-valid one.
    """
    out = list(text)
    i, n = 0, len(text)
    in_str = False
    esc = False
    while i < n:
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            i += 1
            continue
        if c == "/" and i + 1 < n:
            if text[i + 1] == "/":
                j = i
                while j < n and text[j] not in "\r\n":
                    j += 1
                for k in range(i, j):
                    out[k] = " "
                i = j
                continue
            if text[i + 1] == "*":
                j = i + 2
                while j + 1 < n and not (text[j] == "*" and text[j + 1] == "/"):
                    j += 1
                if j + 1 >= n:
                    raise ValueError("unterminated block comment")
                for k in range(i, j + 2):
                    if text[k] not in "\r\n":
                        out[k] = " "
                i = j + 2
                continue
        i += 1
    return "".join(out)


def _validate_state_file(p: Path) -> None:
    """``.json`` files under ``.devin/`` are state — verify they parse.

    ``devin_dir`` defaults to ``./.devin`` (the cwd's dir), so the scan
    also covers *workspace* ``.devin/`` dirs — which mix runtime state
    with harness config like ``mcp_config.json``, where ``//`` comments
    are legal JSONC (the Devin harness accepts them). Retry with
    comments stripped before calling a file malformed: corrupted JSON
    stays loud, legal JSONC no longer fails the whole report.
    """
    try:
        raw = p.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise DevinArtifactError(
            f"malformed .devin state file: {p} ({exc})"
        ) from exc
    except OSError as exc:
        raise DevinArtifactError(
            f"unreadable .devin artifact: {p} ({exc})"
        ) from exc
    try:
        json.loads(raw)
        return
    except json.JSONDecodeError:
        pass
    try:
        json.loads(_strip_jsonc_comments(raw))
    except ValueError as exc:
        raise DevinArtifactError(
            f"malformed .devin state file: {p} ({exc})"
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
