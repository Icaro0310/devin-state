"""JA-2 — cleanup tiers and the tier-3 destructive guard.

Reclaimable items are grouped into three tiers, ordered by increasing
blast radius:

- **tier1 — orphans & cache**: sqlite checkpoint sidecars
  (``-wal``/``-shm``/``-journal``), message-table rows in ``sessions.db``
  whose session no longer exists, stale acp-messages leftovers and
  ``session_locks/*.lock`` for dead sessions. Nothing here is a session —
  reclaiming it loses no content.
- **tier2 — stale sessions**: whole sessions past the staleness window
  (``grace_hours``) that the classifier marks ``auto_delete`` (plus judge
  deletes / pending-queue ids) — the pipeline ``run`` already performs.
- **tier3 — GUI session state**: ``windsurfSpace.sessionWorkspace/*`` keys
  in ``state.vscdb``. This is Devin's own UI store, so tier3 is destructive
  and gated: ``run --apply --tiers 3`` requires ``--include-gui`` AND a
  verified ``devin-backup`` snapshot manifest younger than 24h passed via
  ``--snapshot PATH`` (the snapshot must cover ``state.vscdb``).

This module also hosts the low-level read-only byte estimators shared with
the recoverable-space report. Everything here is stdlib + sqlite only.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

TIER1 = 1
TIER2 = 2
TIER3 = 3
ALL_TIERS = frozenset({TIER1, TIER2, TIER3})
DEFAULT_TIERS = frozenset({TIER1, TIER2})
TIER_NAMES = {
    TIER1: "orphans & cache",
    TIER2: "stale sessions",
    TIER3: "gui state (state.vscdb)",
}

MANIFEST_NAME = "manifest.json"
SUPPORTED_MANIFEST_VERSIONS = {1, 2}
SNAPSHOT_MAX_AGE_S = 24 * 3600
# A tier3-eligible snapshot must actually contain the store tier3 deletes
# from — otherwise the guard's "exported first" promise is empty.
SNAPSHOT_REQUIRED_FRAGMENT = "state.vscdb"

# Devin's GUI session bindings in the Electron ItemTable store (same key
# family devin-history/devin-graph read for GR-1/HI-1).
GUI_STATE_PREFIX = "windsurfSpace.sessionWorkspace/"

# Tier3 leaves a metadata-only marker per deleted binding — auditability
# without keeping the payload (the snapshot owns restoration).
TOMBSTONE_PREFIX = "devin.janitor.tombstone/"

# Sqlite checkpoint sidecar suffixes (shared with the space report).
SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class CleanupRefused(RuntimeError):
    """A tier apply was refused by a safety gate (tier3's snapshot guard,
    or a running Devin). Carries a human-readable reason; never partial."""

# ------------------------------------------------------------------ bytes --

_SESSION_ROW_BYTES = 256  # estimate for the sessions-table row itself

# Payload columns summed per session for the recoverable estimate; tables
# absent in older schemas are skipped. ``subagent_heads`` has no blob
# column, so it contributes a fixed per-row estimate.
_SIZE_QUERIES = (
    ("message_nodes", "LENGTH(chat_message)"),
    ("tool_call_state",
     "LENGTH(tool_call_json) + LENGTH(tool_call_update_json)"),
    ("rendered_commits", "LENGTH(rendered_html)"),
    ("prompt_history", "LENGTH(content)"),
    ("subagent_heads", "64"),
)


def _connect_ro(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)


def _session_byte_estimates(db_path: Path) -> dict[str, int]:
    """Rough payload bytes per session — what delete+VACUUM would reclaim."""
    sizes: dict[str, int] = {}
    try:
        con = _connect_ro(db_path)
    except sqlite3.Error:
        return sizes
    try:
        try:
            for (sid,) in con.execute("SELECT id FROM sessions"):
                sizes[str(sid)] = _SESSION_ROW_BYTES
        except sqlite3.Error:
            return sizes
        for table, expr in _SIZE_QUERIES:
            try:
                for sid, n in con.execute(
                    f"SELECT session_id, COALESCE(SUM({expr}), 0)"
                    f" FROM {table} GROUP BY session_id"
                ):
                    sizes[str(sid)] = sizes.get(str(sid), 0) + int(n or 0)
            except sqlite3.Error:
                continue
    finally:
        con.close()
    return sizes


def orphan_row_bytes(db_path: str | Path) -> tuple[int, int]:
    """``(bytes, rows)`` in message tables for sessions that no longer exist.

    These rows are unreachable orphans — nothing references them and
    deleting the owning session can't have missed them on purpose.
    """
    db = Path(db_path)
    if not db.is_file():
        return 0, 0
    try:
        con = _connect_ro(db)
    except sqlite3.Error:
        return 0, 0
    total_bytes = total_rows = 0
    try:
        try:
            con.execute("SELECT 1 FROM sessions LIMIT 1").fetchone()
        except sqlite3.Error:
            return 0, 0
        for table, expr in _SIZE_QUERIES:
            try:
                n, b = con.execute(
                    f"SELECT COUNT(*), COALESCE(SUM({expr}), 0) FROM {table}"
                    " WHERE session_id NOT IN (SELECT id FROM sessions)"
                ).fetchone()
                total_rows += int(n or 0)
                total_bytes += int(b or 0)
            except sqlite3.Error:
                continue
    finally:
        con.close()
    return total_bytes, total_rows


# ------------------------------------------------------------- gui state --


def vscdb_path(paths) -> Path:
    """``state.vscdb`` location for a resolved :class:`DevinPaths`."""
    return paths.acp_messages_dir.parent / "globalStorage" / "state.vscdb"


def gui_state_entries(
    db_path: str | Path, *, stale_before: float | None = None
) -> list[dict]:
    """``windsurfSpace.sessionWorkspace/*`` keys with size + staleness.

    ``stale_before`` is epoch seconds; an entry is stale when its
    ``lastUpdated`` (ms) predates it — or when the value doesn't carry a
    parseable timestamp at all (unprovable freshness counts as stale).
    """
    db = Path(db_path)
    if not db.is_file():
        return []
    try:
        con = _connect_ro(db)
    except sqlite3.Error:
        return []
    out: list[dict] = []
    try:
        try:
            rows = con.execute(
                "SELECT key, value FROM ItemTable WHERE key LIKE ?",
                (f"{GUI_STATE_PREFIX}%",),
            ).fetchall()
        except sqlite3.Error:
            return []
        for key, raw in rows:
            raw = b"" if raw is None else raw
            text = (
                raw.decode("utf-8", "replace")
                if isinstance(raw, bytes)
                else str(raw)
            )
            try:
                data = json.loads(text)
            except ValueError:
                data = {}
            backend, sep, slug = str(key)[len(GUI_STATE_PREFIX):].rpartition(
                "/"
            )
            last_updated = (
                data.get("lastUpdated") if isinstance(data, dict) else None
            )
            fresh = (
                isinstance(last_updated, (int, float))
                and stale_before is not None
                and last_updated / 1000.0 >= stale_before
            )
            out.append(
                {
                    "key": str(key),
                    "slug": slug if sep else "",
                    "backend": backend if sep else "",
                    "bytes": len(str(key).encode("utf-8")) + len(raw),
                    "stale": not fresh,
                    "last_updated": last_updated,
                }
            )
    finally:
        con.close()
    return out


# ----------------------------------------------------------------- tiers --


def parse_tiers(spec: str | None) -> set[int]:
    """``"1,2"`` / ``"tier1,tier3"`` / ``"all"`` → ``{1, 2}`` / ``{1, 3}``.

    ``None``/empty yields the default ``{1, 2}`` — tier3 is always opt-in.
    """
    if spec is None or not str(spec).strip():
        return set(DEFAULT_TIERS)
    out: set[int] = set()
    for token in str(spec).replace(" ", ",").split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token == "all":
            out.update(ALL_TIERS)
            continue
        token = token.removeprefix("tier")
        try:
            n = int(token)
        except ValueError:
            raise ValueError(
                f"bad tier {token!r} — expected 1, 2, 3 or 'all'"
            ) from None
        if n not in ALL_TIERS:
            raise ValueError(f"unknown tier {n} — valid tiers are 1, 2, 3")
        out.add(n)
    if not out:
        raise ValueError("no tiers selected")
    return out


# --------------------------------------------------- snapshot verification --


def _sha256_file(path: Path, _chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_created_at(value) -> float | None:
    """ISO-8601 or epoch → epoch seconds; ``None`` when unusable."""
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def verify_snapshot(
    snapshot: str | Path | None,
    *,
    max_age_s: float = SNAPSHOT_MAX_AGE_S,
    now: float | None = None,
    required_fragment: str | None = SNAPSHOT_REQUIRED_FRAGMENT,
) -> dict:
    """Verify a ``devin-backup`` snapshot for the tier3 guard.

    ``snapshot`` may be the snapshot directory or its ``manifest.json``.
    A snapshot verifies when the manifest parses (supported
    ``manifest_version``, ``files`` list), ``created_at`` is younger than
    ``max_age_s``, the manifest covers ``required_fragment``
    (``state.vscdb`` — tier3's store), and every listed file exists with
    matching ``size``/``sha256``.

    Returns ``{"ok", "reason", "snapshot", "created_at", "age_s",
    "checked", "failed"}`` — never raises.
    """
    now = time.time() if now is None else now
    res: dict = {
        "ok": False,
        "reason": None,
        "snapshot": str(snapshot) if snapshot else None,
        "created_at": None,
        "age_s": None,
        "checked": 0,
        "failed": 0,
    }
    if not snapshot:
        res["reason"] = "no snapshot given (--snapshot PATH)"
        return res
    p = Path(snapshot).expanduser()
    snap_dir = p if p.is_dir() else p.parent
    mpath = (p / MANIFEST_NAME) if p.is_dir() else p
    if not mpath.is_file():
        res["reason"] = f"{p}: no {MANIFEST_NAME} — not a snapshot?"
        return res
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        res["reason"] = f"{mpath}: unreadable manifest: {exc}"
        return res
    if manifest.get("manifest_version") not in SUPPORTED_MANIFEST_VERSIONS:
        res["reason"] = (
            f"unsupported manifest_version "
            f"{manifest.get('manifest_version')!r}"
        )
        return res
    files = manifest.get("files")
    if not isinstance(files, list):
        res["reason"] = "manifest has no 'files' list"
        return res
    res["created_at"] = manifest.get("created_at")
    ts = _parse_created_at(manifest.get("created_at"))
    if ts is None:
        res["reason"] = "manifest has no usable created_at"
        return res
    age = now - ts
    res["age_s"] = int(age)
    if age > max_age_s:
        res["reason"] = (
            f"snapshot is {age / 3600:.1f}h old "
            f"(>{max_age_s / 3600:.0f}h max)"
        )
        return res
    def _covers(path: str) -> bool:
        if required_fragment == SNAPSHOT_REQUIRED_FRAGMENT:
            # Tier-3 coverage is an exact filename match — a
            # `state.vscdb.old` entry must not satisfy it.
            p = str(path).replace("\\", "/")
            return p.endswith("/" + required_fragment) or p == required_fragment
        return required_fragment in str(path)

    if required_fragment and not any(
        _covers(e.get("path", ""))
        for e in files
        if isinstance(e, dict)
    ):
        res["reason"] = (
            f"snapshot does not cover {required_fragment} — "
            "tier3 deletes GUI state; the backup must contain it"
        )
        return res
    checked = failed = 0
    for entry in files:
        if not isinstance(entry, dict) or not entry.get("path"):
            failed += 1
            continue
        rel = entry.get("snapshot_path") or entry["path"]
        fp = snap_dir / rel
        ok = fp.is_file()
        if ok and isinstance(entry.get("size"), (int, float)):
            ok = fp.stat().st_size == entry["size"]
        if ok and entry.get("sha256"):
            try:
                ok = _sha256_file(fp) == entry["sha256"]
            except OSError:
                ok = False
        checked += 1
        if not ok:
            failed += 1
    res.update(checked=checked, failed=failed)
    if failed:
        res["reason"] = f"{failed} file(s) failed verification"
    else:
        res["ok"] = True
    return res


# ------------------------------------------------------------------ apply --
#
# Tiered apply. ``report`` never reaches this code — it is read-only.
# ``run --apply`` drives it: tier1 orphans/cache, tier2 stale sessions (the
# sessions pipeline in execute.py), tier3 gui state (gated here).


def _leftover_sid(name: str) -> str | None:
    """``dead.db-wal`` → ``dead``; ``x.lock`` → ``x``; else ``None``."""
    for suffix in SIDECAR_SUFFIXES:
        if name.endswith(f".db{suffix}"):
            return name[: -len(f".db{suffix}")]
    if name.endswith(".lock"):
        return name[: -len(".lock")]
    return None


def _delete_orphan_message_rows(db_path: Path) -> int:
    """DELETE message-table rows whose session no longer exists."""
    total = 0
    con = sqlite3.connect(str(db_path), timeout=30)
    con.execute("PRAGMA busy_timeout=30000")
    try:
        for table, _expr in _SIZE_QUERIES:
            try:
                cur = con.execute(
                    f"DELETE FROM {table}"
                    " WHERE session_id NOT IN (SELECT id FROM sessions)"
                )
                if cur.rowcount and cur.rowcount > 0:
                    total += cur.rowcount
            except sqlite3.Error:
                continue  # table absent in older schemas
        con.commit()
    finally:
        con.close()
    return total


def apply_tier1(
    paths,
    live_ids: set[str],
    *,
    skip: set[str] | frozenset[str] = frozenset(),
) -> dict:
    """Tier1 apply: orphaned message rows + dead-session leftovers.

    - ``sessions.db``: rows in the message tables whose ``session_id`` is
      gone from ``sessions`` — unreachable orphans, freed by the next
      vacuum. The db's own ``-wal``/``-shm`` sidecars are NOT touched:
      ``wal_checkpoint(TRUNCATE)`` in the vacuum step reclaims them safely.
    - ``acp-messages/``: ``<sid>.db-*`` / ``<sid>.lock`` leftovers where
      ``<sid>.db`` is gone and ``sid`` is neither live nor in ``skip``
      (pending-queue ids are left for the retry queue).
    - ``session_locks/*.lock`` orphans are the caller's job
      (``execute.remove_orphan_locks``) — counted in the report as tier1.
    """
    stats = {"orphan_rows": 0, "leftover_files": 0, "leftover_bytes": 0}
    db = Path(paths.sessions_db)
    if db.is_file():
        try:
            stats["orphan_rows"] = _delete_orphan_message_rows(db)
        except sqlite3.Error:
            pass  # locked by a running Devin — leave for the next run
    acp = Path(paths.acp_messages_dir)
    if acp.is_dir():
        live_dbs = {p.name[:-3] for p in acp.glob("*.db") if p.is_file()}
        for p in sorted(acp.iterdir()):
            if not p.is_file() or p.name.endswith(".db"):
                continue
            sid = _leftover_sid(p.name)
            if sid is None or sid in live_dbs or sid in live_ids \
                    or sid in skip:
                continue
            try:
                size = p.stat().st_size
                p.unlink()
            except OSError:
                continue
            stats["leftover_files"] += 1
            stats["leftover_bytes"] += size
    return stats


def apply_tier3(
    paths,
    *,
    stale_before: float,
    include_gui: bool = False,
    snapshot: str | Path | None = None,
    now: float | None = None,
    running: bool | None = None,
) -> dict:
    """Tier3 apply: delete stale ``windsurfSpace.sessionWorkspace/*`` keys.

    Destructive and gated — every gate failing raises
    :class:`CleanupRefused` *before* a single write:

    1. ``--include-gui`` must be passed explicitly.
    2. ``--snapshot PATH`` must verify via :func:`verify_snapshot` — a
       ``devin-backup`` manifest <24h old that covers ``state.vscdb``.
    3. Devin must not be running (Electron owns ``state.vscdb`` while the
       GUI is up; detection failure counts as running — fail-safe).

    Deletes only keys proven stale (``lastUpdated`` older than
    ``stale_before``, or unparseable). Each deleted key leaves a
    ``devin.janitor.tombstone/…`` marker recording the original key,
    slug, backend, size and timestamps — metadata only; the verified
    snapshot owns payload restoration. Then checkpoints + VACUUMs so
    the bytes are actually reclaimed. Returns counters for the audit
    log.
    """
    if not include_gui:
        raise CleanupRefused(
            "tier3 deletes GUI session state from state.vscdb — "
            "pass --include-gui to confirm"
        )
    res = verify_snapshot(snapshot, now=now)
    if not res["ok"]:
        raise CleanupRefused(f"tier3 refused — {res['reason']}")
    if running is None:
        from devin_janitor.execute import devin_running
        running = devin_running()
    if running:
        raise CleanupRefused(
            "tier3 refused — Devin appears to be running; "
            "state.vscdb is only written when the GUI is closed"
        )
    db = vscdb_path(paths)
    stale = [
        e for e in gui_state_entries(db, stale_before=stale_before)
        if e["stale"]
    ]
    stats = {
        "keys": 0,
        "tombstoned": 0,
        "bytes": sum(e["bytes"] for e in stale),
        "snapshot": res["snapshot"],
        "snapshot_age_s": res["age_s"],
    }
    if not stale or not db.is_file():
        return stats
    deleted_at = now if now is not None else time.time()
    con = sqlite3.connect(str(db), timeout=30)
    con.execute("PRAGMA busy_timeout=30000")
    try:
        for e in stale:
            con.execute(
                "INSERT OR REPLACE INTO ItemTable (key, value)"
                " VALUES (?, ?)",
                (
                    f"{TOMBSTONE_PREFIX}{e['key']}",
                    json.dumps(
                        {
                            "key": e["key"],
                            "slug": e["slug"],
                            "backend": e["backend"],
                            "bytes": e["bytes"],
                            "last_updated": e["last_updated"],
                            "deleted_at": deleted_at,
                            "tool": "devin-janitor",
                        }
                    ),
                ),
            )
            con.execute("DELETE FROM ItemTable WHERE key=?", (e["key"],))
        con.commit()
        stats["keys"] = len(stale)
        stats["tombstoned"] = len(stale)
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("VACUUM")
        except sqlite3.Error:
            pass  # deletion already committed; reclaim is best-effort
    finally:
        con.close()
    return stats
