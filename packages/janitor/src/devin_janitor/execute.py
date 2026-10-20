"""Deletion engine: sessions.db rows, acp-messages files, locks, VACUUM.

Ported semantics:

- Delete a session's rows in every message table + the ``sessions`` row.
- Delete ``acp-messages/<id>.db*`` (incl. ``-wal``/``-shm`` sidecars and
  ``<id>.lock``). Locked files (Devin open) go to the pending retry queue.
- Remove orphaned ``session_locks/*.lock`` files.
- ``VACUUM`` only when no lock files exist AND the Devin process is absent.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from devin_internals.schema import detect_schema_version

from devin_janitor.inventory import SessionRow
from devin_janitor.paths import DevinPaths

# Message-bearing tables cleaned per session before the sessions row.
MSG_TABLES = [
    "message_nodes",
    "tool_call_state",
    "rendered_commits",
    "subagent_heads",
    "prompt_history",
]


# ------------------------------------------------------------ pending ----


def load_pending(path: str | Path) -> dict[str, int]:
    """``{session_id: first_seen_epoch}`` retry queue; tolerant of damage."""
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return {str(k): int(v) for k, v in data.items()}


def save_pending(path: str | Path, pending: dict[str, int]) -> None:
    p = Path(path)
    if pending:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(pending, indent=1), encoding="utf-8")
    elif p.exists():
        p.unlink()


# ------------------------------------------------------------ deletes ----


def delete_session_rows(con: sqlite3.Connection, session_id: str) -> bool:
    """Delete all rows for a session. Returns False if it wasn't present."""
    if not con.execute(
        "SELECT 1 FROM sessions WHERE id=?", (session_id,)
    ).fetchone():
        return False
    for table in MSG_TABLES:
        try:
            con.execute(
                f"DELETE FROM {table} WHERE session_id=?", (session_id,)
            )
        except sqlite3.Error:
            pass  # table may not exist in older schemas
    con.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    return True


def delete_gui_files(
    acp_dir: str | Path, session_id: str, pending: dict[str, int]
) -> bool:
    """Remove ``acp-messages/<id>.db*`` + ``<id>.lock``.

    Returns True when everything was removed; on failure the session id is
    added to ``pending`` for retry on a later run.
    """
    acp_dir = Path(acp_dir)
    files = list(acp_dir.glob(f"{session_id}.db*"))
    files += [p for p in acp_dir.glob(f"{session_id}.lock") if p not in files]
    ok = True
    for p in files:
        try:
            os.remove(p)
        except OSError:
            ok = False
    if ok:
        pending.pop(session_id, None)
    else:
        pending.setdefault(session_id, int(time.time()))
    return ok


def retry_pending(
    acp_dir: str | Path, pending: dict[str, int]
) -> dict[str, int]:
    """Retry every queued gui-file deletion; returns the updated queue."""
    for sid in list(pending):
        delete_gui_files(acp_dir, sid, pending)
    return pending


def remove_orphan_locks(paths: DevinPaths, live_ids: set[str]) -> int:
    """Delete ``session_locks/*.lock`` whose session no longer exists."""
    locks_dir = paths.session_locks_dir
    if not locks_dir.is_dir():
        return 0
    removed = 0
    for lock in locks_dir.glob("*.lock"):
        if lock.stem not in live_ids:
            try:
                lock.unlink()
                removed += 1
            except OSError:
                pass
    return removed


# ------------------------------------------------------------- vacuum ----


def devin_running() -> bool:
    """Best-effort check for a running Devin process. Fail-safe: True."""
    try:
        if sys.platform.startswith("win"):
            out = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq Devin.exe", "/FO", "CSV"],
                check=False, capture_output=True,
                text=True,
                timeout=20,
            ).stdout
            return out.count("Devin.exe") > 1
        out = subprocess.run(
            ["pgrep", "-fi", "devin"], capture_output=True, timeout=20, check=False
        )
        return out.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return True


def has_locks(paths: DevinPaths) -> bool:
    locks = paths.session_locks_dir
    return locks.is_dir() and any(locks.glob("*.lock"))


def vacuum_if_safe(
    paths: DevinPaths, running: bool | None = None
) -> bool:
    """Checkpoint + VACUUM sessions.db — only with Devin closed, no locks."""
    if running is None:
        running = devin_running()
    if running or has_locks(paths) or not paths.sessions_db.is_file():
        return False
    detect_schema_version(paths.sessions_db)  # gate: never vacuum non-store
    con = sqlite3.connect(str(paths.sessions_db))
    try:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        con.execute("VACUUM")
    finally:
        con.close()
    return True


# --------------------------------------------------------------- apply ----


def apply_deletions(
    paths: DevinPaths,
    targets: list[tuple[SessionRow, str]],
    pending: dict[str, int],
) -> dict[str, int]:
    """Delete target rows + gui files; returns counters for the report.

    ``sessions`` counts unique sessions actually removed — the inventory
    merges both stores by id, so a session holding a ``sessions.db`` row
    AND ``acp-messages`` files counts once and the total never exceeds
    ``len(targets)``. The per-store counters (``cli_rows``,
    ``gui_sessions``) are unchanged for the printed run summary.
    """
    stats = {"cli_rows": 0, "gui_sessions": 0, "still_locked": 0,
             "sessions": 0}
    con = sqlite3.connect(str(paths.sessions_db), timeout=30)
    con.execute("PRAGMA busy_timeout=30000")
    try:
        for row, _why in targets:
            removed = delete_session_rows(con, row.id)
            if removed:
                stats["cli_rows"] += 1
            files = list(paths.acp_messages_dir.glob(f"{row.id}.db*")) if (
                paths.acp_messages_dir.is_dir()
            ) else []
            if (row.origin == "gui" or files) \
                    and delete_gui_files(paths.acp_messages_dir, row.id, pending):
                stats["gui_sessions"] += 1
                removed = True
            if removed:
                stats["sessions"] += 1
        retry_pending(paths.acp_messages_dir, pending)
        con.commit()
    finally:
        con.close()
    stats["still_locked"] = len(pending)
    return stats
