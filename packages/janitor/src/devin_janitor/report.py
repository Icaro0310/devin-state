"""Per-run audit log (JSONL) + human-readable plan summary.

Each applied run appends one JSON object to ``janitor-log.jsonl`` recording
what was deleted and why — id, tier, reason and judge verdict — so a bad
classification is always traceable after the fact.

Also hosts the ``report`` subcommand payload: an advisory, read-only
recoverable-space scan over every store the janitor knows.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from devin_internals.schema import SchemaError

from devin_janitor.cleanup import (
    SIDECAR_SUFFIXES,
    _connect_ro,
    _session_byte_estimates,
    gui_state_entries,
    orphan_row_bytes,
    vscdb_path,
)
from devin_janitor.config import JanitorConfig
from devin_janitor.inventory import (
    SessionRow,
    live_session_ids,
    load_inventory,
)
from devin_janitor.labels import (
    automatic_sessions,
    default_labels_path,
    load_labels,
)
from devin_janitor.paths import DevinPaths
from devin_janitor.tiers import Classification, classify


def audit_entry(
    *,
    deleted: list[tuple[SessionRow, str]],
    judged_keep: list[SessionRow],
    judged_delete: list[tuple[SessionRow, str]],
    judge_name: str,
    judge_down: int,
    pending_locked: list[str],
    orphan_locks_removed: int,
    vacuumed: bool,
) -> dict:
    return {
        "ts": int(time.time()),
        "judge": judge_name,
        "deleted": [
            {
                "id": r.id,
                "origin": r.origin,
                "title": r.title,
                "tier": "auto_delete",
                "reason": why,
            }
            for r, why in deleted
        ],
        "judged_delete": [
            {
                "id": r.id,
                "origin": r.origin,
                "title": r.title,
                "tier": "judge",
                "judge_verdict": why,
            }
            for r, why in judged_delete
        ],
        "judged_keep": [r.id for r in judged_keep],
        "judge_down": judge_down,
        "pending_locked": list(pending_locked),
        "orphan_locks_removed": orphan_locks_removed,
        "vacuumed": vacuumed,
    }


def append_log(log_file: str | Path, entry: dict) -> None:
    p = Path(log_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _fmt_target(row: SessionRow, why: str) -> str:
    dt = (
        datetime.fromtimestamp(row.created, tz=timezone.utc).astimezone().strftime("%Y-%m-%d")
        if row.created
        else "----------"
    )
    return f"    [{row.origin}] {row.id[:40]:40} {dt} {why:42} {row.title[:50]}"


def plan_summary(
    *,
    apply: bool,
    total: int,
    grace_hours: float,
    classification: Classification,
    judged_keep: list[SessionRow],
    judged_delete: list[tuple[SessionRow, str]],
    judge_down: int,
    targets: list[tuple[SessionRow, str]],
) -> str:
    """The printed plan — identical shape to the legacy output."""
    mode = "APPLY" if apply else "DRY-RUN"
    lines = [
        f"{mode} · {total} sessions · grace {grace_hours:.0f}h",
        f"  keep:    {len(classification.kept) + len(judged_keep) + judge_down} "
        f"(allowlist/grace/substantive + {len(judged_keep)} judged useful"
        + (f" + {judge_down} judge-down" if judge_down else "")
        + ")",
        f"  delete:  {len(targets)}",
    ]
    lines += [_fmt_target(r, why) for r, why in targets]
    if not apply:
        lines.append("")
        lines.append("(dry-run — rerun with --apply to execute)")
    return "\n".join(lines)


def run_summary(
    *,
    cli_rows: int,
    gui_sessions: int,
    orphan_locks: int,
    pending: int,
    vacuumed: bool,
) -> str:
    vacuum = (
        "vacuum done (Devin closed)"
        if vacuumed
        else "vacuum deferred (Devin open or locks present)"
    )
    return (
        f"deleted: {cli_rows} CLI rows + {gui_sessions} GUI sessions · "
        f"orphan locks: {orphan_locks} · pending (locked): {pending} · {vacuum}"
    )


# ------------------------------------------------------- space report ----

_SIDECAR_SUFFIXES = SIDECAR_SUFFIXES


def fmt_bytes(n: float) -> str:
    """``812`` → ``'812 B'``; ``2097152`` → ``'2.0 MB'``."""
    size = float(max(0, n))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def _sidecar_bytes(path: Path) -> int:
    """``x.db`` → bytes of ``x.db-wal``/``x.db-shm``/``x.db-journal``."""
    if not path.parent.is_dir():
        return 0
    return sum(
        _size(p) for p in path.parent.glob(f"{path.name}-*") if p.is_file()
    )


def _span(values) -> tuple[float | None, float | None]:
    vals = [v for v in values if v]
    return (min(vals), max(vals)) if vals else (None, None)


def _sessions_db_entry(
    paths: DevinPaths,
    rows: list[SessionRow],
    classification: Classification | None,
    deletable: set[str],
) -> dict:
    db = paths.sessions_db
    sidecars = _sidecar_bytes(db)
    cli_rows = [r for r in rows if r.origin == "cli"]
    oldest, newest = _span(
        t for r in cli_rows for t in (r.created, r.last_activity)
    )
    entry = {
        "name": "sessions.db",
        "path": str(db),
        "exists": db.is_file(),
        "bytes": _size(db) + sidecars,
        "sidecar_bytes": sidecars,
        "sessions": len(cli_rows),
        "oldest": oldest,
        "newest": newest,
        "deletable_sessions": 0,
        "recoverable_bytes": 0,
        "note": f"{len(cli_rows)} sessions",
        "recoverable_why": "auto_delete rows reclaimed by vacuum + "
                           "WAL sidecars truncated by checkpoint",
    }
    if classification is None or not db.is_file():
        # schema unreadable → the vacuum gate fails → nothing is freed
        return entry
    est = _session_byte_estimates(db)
    tier_of = {sid: "keep" for sid in classification.kept}
    tier_of.update(
        {r.id: "auto_delete" for r, _ in classification.auto_delete}
    )
    tier_of.update({r.id: "judge" for r in classification.judge})
    by_tier = {"keep": 0, "auto_delete": 0, "judge": 0}
    for sid, n in est.items():
        by_tier[tier_of.get(sid, "keep")] += n
    deletable_cli = deletable & set(est)
    entry.update(
        {
            "est_bytes_by_tier": by_tier,
            "deletable_sessions": len(deletable_cli),
            "recoverable_bytes": sum(est[sid] for sid in deletable_cli)
            + sidecars,
            "note": f"{len(cli_rows)} sessions · "
                    f"{len(deletable_cli)} deletable"
                    + (f" · sidecars {fmt_bytes(sidecars)}"
                       if sidecars else ""),
        }
    )
    return entry


def _acp_entry(paths: DevinPaths, deletable: set[str]) -> dict:
    acp = paths.acp_messages_dir
    dbs = sorted(acp.glob("*.db")) if acp.is_dir() else []
    seen: set[str] = set()
    files = []
    total = rec = 0
    for f in dbs:
        sid = f.name[:-3]
        seen.add(sid)
        size = _size(f) + _sidecar_bytes(f) + _size(acp / f"{sid}.lock")
        is_del = sid in deletable
        total += size
        if is_del:
            rec += size
        files.append(
            {
                "path": str(f),
                "session_id": sid,
                "bytes": size,
                "deletable": is_del,
            }
        )
    # leftovers of already-deleted sessions: <sid>.db-* sidecars or
    # <sid>.lock with no <sid>.db — freed when the pending queue retries
    # their id; anything else is reported but out of the janitor's reach
    orphan_files = []
    orphan_rec = 0
    if acp.is_dir():
        for p in sorted(acp.iterdir()):
            if not p.is_file() or p.name.endswith(".db"):
                continue
            sid = None
            for suffix in _SIDECAR_SUFFIXES:
                if p.name.endswith(f".db{suffix}"):
                    sid = p.name[: -len(f".db{suffix}")]
            if sid is None and p.name.endswith(".lock"):
                sid = p.name[: -len(".lock")]
            if sid is None or sid in seen:
                continue
            size = _size(p)
            if sid in deletable:
                orphan_rec += size
            orphan_files.append(
                {
                    "path": str(p),
                    "session_id": sid,
                    "bytes": size,
                    "deletable": sid in deletable,
                }
            )
            total += size
    oldest, newest = _span(_mtime(f) for f in dbs)
    n_del = sum(1 for f in files if f["deletable"])
    return {
        "name": "acp-messages",
        "path": str(acp),
        "exists": acp.is_dir(),
        "bytes": total,
        "files": len(dbs),
        "deletable_files": n_del,
        "oldest": oldest,
        "newest": newest,
        "recoverable_bytes": rec + orphan_rec,
        "unmanaged_bytes": sum(
            f["bytes"] for f in orphan_files if not f["deletable"]
        ),
        "note": f"{len(dbs)} db{'s' if len(dbs) != 1 else ''} · "
                f"{n_del} deletable"
                + (f" · {len(orphan_files)} leftovers"
                   if orphan_files else ""),
        "recoverable_why": "deletable sessions' <id>.db*/<id>.lock files",
        "detail": files + orphan_files,
    }


def _vscdb_entry(paths: DevinPaths) -> dict:
    db = vscdb_path(paths)
    items = None
    if db.is_file():
        try:
            con = _connect_ro(db)
            try:
                items = con.execute(
                    "SELECT COUNT(*) FROM ItemTable"
                ).fetchone()[0]
            finally:
                con.close()
        except sqlite3.Error:
            items = None
    return {
        "name": "state.vscdb",
        "path": str(db),
        "exists": db.is_file(),
        "bytes": _size(db) + _sidecar_bytes(db),
        "items": items,
        "oldest": None,
        "newest": _mtime(db) if db.is_file() else None,
        "recoverable_bytes": 0,
        "note": f"{items} keys" if items is not None else "",
        "recoverable_why": "untouched — the janitor deletes sessions only",
    }


def _locks_entry(paths: DevinPaths) -> dict:
    locks_dir = paths.session_locks_dir
    locks = sorted(locks_dir.glob("*.lock")) if locks_dir.is_dir() else []
    try:
        live: set[str] | None = live_session_ids(paths)
    except (SchemaError, sqlite3.Error, OSError):
        live = None  # unreadable store → fail-safe: no lock counts as orphan
    files = []
    total = rec = 0
    for lock in locks:
        orphan = live is not None and lock.stem not in live
        size = _size(lock)
        total += size
        if orphan:
            rec += size
        files.append({"path": str(lock), "bytes": size, "orphan": orphan})
    oldest, newest = _span(_mtime(f) for f in locks)
    n_orphan = sum(1 for f in files if f["orphan"])
    return {
        "name": "session_locks",
        "path": str(locks_dir),
        "exists": locks_dir.is_dir(),
        "bytes": total,
        "locks": len(locks),
        "orphan_locks": n_orphan,
        "oldest": oldest,
        "newest": newest,
        "recoverable_bytes": rec,
        "note": f"{len(locks)} lock{'s' if len(locks) != 1 else ''} · "
                f"{n_orphan} orphan",
        "recoverable_why": "orphan locks pruned on each run",
        "detail": files,
    }


def _cleanup_tier_summary(
    paths: DevinPaths,
    cfg: JanitorConfig,
    stores: list[dict],
    deletable: set[str],
    now: float | None,
) -> dict:
    """Per-tier recoverable bytes (JA-2).

    tier1 — orphans & cache: checkpoint sidecars, orphaned message rows,
            dead-session leftovers, stale locks. No session content.
    tier2 — stale sessions: what ``run`` deletes (auto_delete + judged).
    tier3 — gui state: ``windsurfSpace.sessionWorkspace/*`` keys in
            ``state.vscdb``; gated behind ``--include-gui`` + snapshot.
    """
    by_name = {s["name"]: s for s in stores}
    sdb = by_name.get("sessions.db", {})
    acp = by_name.get("acp-messages", {})
    locks = by_name.get("session_locks", {})

    try:
        live = live_session_ids(paths)
    except (SchemaError, sqlite3.Error, OSError):
        live = set()

    # acp leftovers (<sid>.db-*/<sid>.lock without <sid>.db): a leftover of
    # a session being deleted is tier2; a dead session's leftover is tier1;
    # a live session's leftover is managed — not counted as recoverable.
    leftover_t1_bytes = leftover_t1_n = leftover_t2_n = 0
    for f in acp.get("detail") or []:
        if str(f.get("path", "")).endswith(".db"):
            continue
        sid = f.get("session_id")
        if sid in deletable:
            leftover_t2_n += 1  # bytes already inside acp.recoverable
        elif sid not in live:
            leftover_t1_bytes += int(f.get("bytes", 0))
            leftover_t1_n += 1

    orphan_bytes = orphan_rows = 0
    if paths.sessions_db.is_file():
        try:
            orphan_bytes, orphan_rows = orphan_row_bytes(paths.sessions_db)
        except (sqlite3.Error, OSError):
            pass

    stale_before = (
        now if now is not None else time.time()
    ) - cfg.grace_hours * 3600
    gui = gui_state_entries(vscdb_path(paths), stale_before=stale_before)
    stale_gui = [e for e in gui if e["stale"]]

    stale_days = cfg.grace_hours / 24
    return {
        "tier1": {
            "label": "orphans & cache",
            "bytes": (
                sdb.get("sidecar_bytes", 0)
                + orphan_bytes
                + leftover_t1_bytes
                + locks.get("recoverable_bytes", 0)
            ),
            "items": orphan_rows
            + leftover_t1_n
            + locks.get("orphan_locks", 0),
            "why": "checkpoint sidecars, orphaned message rows, stale "
                   "locks & dead-session leftovers",
        },
        "tier2": {
            "label": "stale sessions",
            "bytes": max(
                0,
                sdb.get("recoverable_bytes", 0)
                - sdb.get("sidecar_bytes", 0)
                + acp.get("recoverable_bytes", 0),
            ),
            "items": sdb.get("deletable_sessions", 0)
            + acp.get("deletable_files", 0)
            + leftover_t2_n,
            "why": f"sessions past the {stale_days:g}d staleness window "
                   "(auto_delete + judged deletes)",
        },
        "tier3": {
            "label": "gui state (state.vscdb)",
            "bytes": sum(e["bytes"] for e in stale_gui),
            "items": len(stale_gui),
            "total_items": len(gui),
            "gated": True,
            "why": "GUI session state keys — requires --include-gui + a "
                   "verified devin-backup snapshot <24h old",
        },
    }


# ---------------------------------------------------- growth projection ----

# A store younger than this has no meaningful accumulation rate — a
# sessions.db created today would "project" its whole size per day.
MIN_OBSERVATION_DAYS = 1.0

_HORIZON_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([hdw])?$", re.IGNORECASE)
_HORIZON_UNIT_DAYS = {"h": 1.0 / 24.0, "d": 1.0, "w": 7.0}


def parse_horizon(spec: str) -> float:
    """``'90d'`` → ``90.0`` days; ``'12w'`` → ``84``; ``'48h'`` → ``2``.

    A bare number means days. Raises ``ValueError`` on anything else —
    the janitor refuses to print a fake projection.
    """
    m = _HORIZON_RE.match((spec or "").strip())
    if not m:
        raise ValueError(
            f"invalid --project horizon {spec!r} — use <N>[h|d|w] "
            "(e.g. 48h, 30d, 12w)"
        )
    unit = m.group(2).lower() if m.group(2) else "d"
    days = float(m.group(1)) * _HORIZON_UNIT_DAYS[unit]
    if days <= 0:
        raise ValueError("--project horizon must be positive")
    return days


def growth_projection(
    stores: list[dict],
    horizon_days: float,
    now: float | None = None,
) -> dict:
    """Project each store's size ``horizon_days`` ahead, linear model.

    The janitor keeps no size history (``report`` is read-only and the
    audit log records deletions, not sizes), so the rate is the simplest
    defensible one: current bytes ÷ days since the store's first-seen
    timestamp (``oldest``) — an average accumulation rate, not a trend
    fit. Honest output means printing the rate and the window it came
    from, not just a number.

    A store is ``ok: false`` with a ``reason`` when no honest rate
    exists: missing, no first-seen timestamp, or an observation window
    shorter than ``MIN_OBSERVATION_DAYS`` (a store created today has no
    rate — printing a number would be a fake projection).
    """
    now = time.time() if now is None else now
    out = []
    for s in stores:
        entry: dict = {"name": s.get("name", "?"),
                       "bytes": int(s.get("bytes") or 0)}
        if not s.get("exists"):
            out.append({**entry, "ok": False, "reason": "store missing"})
            continue
        oldest = s.get("oldest")
        if not oldest:
            out.append({**entry, "ok": False,
                        "reason": "no first-seen timestamp"})
            continue
        window_days = (now - float(oldest)) / 86400.0
        if window_days < MIN_OBSERVATION_DAYS:
            out.append({
                **entry,
                "ok": False,
                "reason": "insufficient data — observation window "
                          f"{window_days * 24:.1f}h < "
                          f"{MIN_OBSERVATION_DAYS * 24:.0f}h",
            })
            continue
        rate = entry["bytes"] / window_days
        projected = entry["bytes"] + rate * horizon_days
        out.append({
            **entry,
            "ok": True,
            "window_days": window_days,
            "rate_bytes_per_day": rate,
            "delta_bytes": projected - entry["bytes"],
            "projected_bytes": projected,
        })
    return {
        "horizon_days": horizon_days,
        "model": "linear",
        "caveat": "estimate — rate = current bytes ÷ days since "
                  "first-seen; assumes steady accumulation, ignores "
                  "inactivity gaps and future cleanups",
        "stores": out,
    }


def space_report(
    paths: DevinPaths,
    config: JanitorConfig | None = None,
    *,
    keep_ids: set[str] | None = None,
    keep_patterns: list[str] | None = None,
    extra_delete_ids: set[str] | None = None,
    now: float | None = None,
    labels_path: str | Path | None = None,
    exclude_labeled: bool = False,
    project_days: float | None = None,
) -> dict:
    """Recoverable-space report across every store the janitor manages.

    Advisory only — reads everything, writes nothing. Recoverable bytes are
    what the janitor's own rules would free: AUTO_DELETE sessions (plus
    ``extra_delete_ids`` for judge verdicts / pending-queue ids), sqlite
    sidecars of deleted stores, orphan session locks, and the sessions.db
    WAL that ``wal_checkpoint(TRUNCATE)`` reclaims during a safe vacuum.

    Also carries a per-tier cleanup summary (JA-2: orphans & cache /
    stale sessions / gated GUI state) and an ``automatic_sessions``
    section (JA-4) marking sessions the bridge sidecar labels as
    automation-created. ``exclude_labeled`` drops those sessions from the
    classification so the report reflects only non-automation sessions.

    ``project_days`` (``report --project``) adds a ``projection`` section:
    a linear estimate of each store's size that many days ahead, at the
    rate observed since first-seen — see :func:`growth_projection`.
    """
    cfg = config or JanitorConfig()
    labels_p = (
        Path(labels_path).expanduser()
        if labels_path is not None
        else default_labels_path()
    )
    labels = load_labels(labels_p)

    rows: list[SessionRow] = []
    automatic: list[dict] = []
    classification: Classification | None = None
    error = None
    try:
        rows = load_inventory(paths)
        automatic = automatic_sessions(rows, labels)
        labeled = {s["id"] for s in automatic}
        cls_rows = (
            [r for r in rows if r.id not in labeled]
            if exclude_labeled
            else rows
        )
        classification = classify(
            cls_rows,
            cfg,
            keep_ids=keep_ids or set(),
            keep_patterns=keep_patterns or [],
            now=now,
        )
    except (SchemaError, sqlite3.Error, OSError) as exc:
        error = str(exc)

    deletable = set(extra_delete_ids or ())
    if classification is not None:
        deletable.update(r.id for r, _ in classification.auto_delete)

    stores = []
    for name, builder in (
        ("sessions.db", lambda: _sessions_db_entry(
            paths, rows, classification, deletable)),
        ("acp-messages", lambda: _acp_entry(paths, deletable)),
        ("state.vscdb", lambda: _vscdb_entry(paths)),
        ("session_locks", lambda: _locks_entry(paths)),
    ):
        try:
            stores.append(builder())
        except (SchemaError, sqlite3.Error, OSError) as exc:
            stores.append(
                {
                    "name": name,
                    "path": "",
                    "exists": False,
                    "bytes": 0,
                    "recoverable_bytes": 0,
                    "error": str(exc),
                }
            )
    try:
        tiers = _cleanup_tier_summary(paths, cfg, stores, deletable, now)
    except (SchemaError, sqlite3.Error, OSError) as exc:
        tiers = {"error": str(exc)}

    now_s = now if now is not None else time.time()
    report = {
        "generated_at": int(now_s),
        "data_root": str(paths.root),
        "classification": (
            {**classification.summary(), "sessions": len(rows)}
            if classification is not None
            else None
        ),
        "stores": stores,
        "cleanup_tiers": tiers,
        "automatic_sessions": {
            "labels_file": str(labels_p),
            "count": len(automatic),
            "excluded_from_classification": bool(exclude_labeled),
            "sessions": automatic,
        },
        "totals": {
            "bytes": sum(s["bytes"] for s in stores),
            "recoverable_bytes": sum(
                s["recoverable_bytes"] for s in stores
            ),
        },
    }
    if project_days is not None:
        report["projection"] = growth_projection(
            stores, project_days, now=now_s
        )
    if error:
        report["classification_error"] = error
    return report


def _fmt_span(oldest: float | None, newest: float | None) -> str:
    if oldest is None and newest is None:
        return "-"
    a = (
        datetime.fromtimestamp(oldest, tz=timezone.utc).astimezone().strftime("%Y-%m-%d")
        if oldest
        else ""
    )
    b = (
        datetime.fromtimestamp(newest, tz=timezone.utc).astimezone().strftime("%Y-%m-%d")
        if newest
        else ""
    )
    if not a or a == b:
        return b or a
    return f"{a} → {b}"


def render_space_report(report: dict) -> str:
    """Human-readable table for ``devin-janitor report``."""
    totals = report["totals"]
    lines = [
        (f"REPORT · {fmt_bytes(totals['bytes'])} across "
         f"{len(report['stores'])} stores · "
         f"~{fmt_bytes(totals['recoverable_bytes'])} recoverable"),
        "",
    ]
    for s in report["stores"]:
        if not s["exists"]:
            tag = f"error: {s['error']}" if s.get("error") else "missing"
            lines.append(f"  {s['name']:<15} {'—':>9}  {tag}  {s['path']}")
            continue
        rec = s["recoverable_bytes"]
        rec_s = f"~{fmt_bytes(rec)}" if rec else "0 B"
        note = f"  {s['note']}" if s.get("note") else ""
        lines.append(
            f"  {s['name']:<15} {fmt_bytes(s['bytes']):>9}  "
            f"{_fmt_span(s.get('oldest'), s.get('newest')):<23} "
            f"{rec_s:>9}{note}"
        )
    cls = report.get("classification")
    if cls is not None:
        lines.append("")
        lines.append(
            f"  sessions: {cls['sessions']} · keep {cls['keep']} · "
            f"auto_delete {cls['auto_delete']} · judge {cls['judge']}"
        )
    tiers = report.get("cleanup_tiers")
    if tiers and not tiers.get("error"):
        lines.append("")
        lines.append("  cleanup tiers:")
        for key in ("tier1", "tier2", "tier3"):
            t = tiers.get(key)
            if not t:
                continue
            gated = " · gated" if t.get("gated") else ""
            lines.append(
                f"    {key} {t['label']:<26} "
                f"{('~' + fmt_bytes(t['bytes'])):>10}  "
                f"{t['items']} item(s){gated}"
            )
    proj = report.get("projection")
    if proj:
        h = proj["horizon_days"]
        h_s = f"{h:g}d" if h >= 1 else f"{h * 24:g}h"
        lines.append("")
        lines.append(
            f"  growth projection +{h_s} "
            "(estimate — linear rate since first-seen):"
        )
        for s in proj["stores"]:
            if not s["ok"]:
                lines.append(
                    f"    {s['name']:<15} {fmt_bytes(s['bytes']):>9}  "
                    f"insufficient data — {s['reason']}"
                )
                continue
            lines.append(
                f"    {s['name']:<15} {fmt_bytes(s['bytes']):>9} → "
                f"{fmt_bytes(s['projected_bytes']):>9}  "
                f"(+{fmt_bytes(s['delta_bytes'])} @ "
                f"{fmt_bytes(s['rate_bytes_per_day'])}/d over "
                f"{s['window_days']:.0f}d)"
            )
    auto = report.get("automatic_sessions") or {}
    if auto.get("count"):
        lines.append("")
        excluded = (
            "  (excluded from classification)"
            if auto.get("excluded_from_classification")
            else ""
        )
        lines.append(f"  automatic sessions: {auto['count']}{excluded}")
        shown = auto.get("sessions") or []
        for s in shown[:10]:
            mark = s.get("label") or s.get("origin") or "auto"
            lines.append(
                f"    [{mark}] {s['id'][:40]:40} "
                f"{(s.get('title') or '')[:50]}"
            )
        if auto["count"] > len(shown[:10]):
            lines.append(f"    … and {auto['count'] - 10} more")
    if report.get("classification_error"):
        lines.append("")
        lines.append(
            f"  classification error: {report['classification_error']}"
        )
    lines.append("")
    lines.append("(advisory — nothing is written; `run` frees it)")
    return "\n".join(lines)
