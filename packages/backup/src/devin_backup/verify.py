"""Integrity verification for snapshots.

Re-checks every file in ``manifest.json``: existence, size, sha256 — and for
SQLite stores additionally ``PRAGMA integrity_check``. The integrity step
exists for the case where the *source* was already corrupt at backup time
(a bit-identical copy of a broken database still hashes fine).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from devin_backup.snapshot import _connect_readonly, load_manifest, sha256_file
from devin_backup.stores import is_sqlite_store

_OK = "ok"
_SKIPPED = "skipped"


def _integrity_check(path: Path) -> str:
    """``"ok"``, ``"failed: <detail>"`` or ``"skipped"`` (not a SQLite file)."""
    try:
        con = _connect_readonly(path)
        try:
            rows = [r[0] for r in con.execute("PRAGMA integrity_check")]
        finally:
            con.close()
    except sqlite3.Error as exc:
        if "not a database" in str(exc):
            return _SKIPPED
        return f"failed: {exc}"
    if rows == ["ok"]:
        return _OK
    return "failed: " + "; ".join(str(r) for r in rows[:5])


def _verify_file(snapshot_dir: Path, entry: dict) -> dict:
    rel = entry["path"]
    display_path = (
        f"config/{rel}" if entry.get("root", "data") == "config" else rel
    )
    snapshot_path = Path(entry.get("snapshot_path", rel))
    path = (snapshot_dir / snapshot_path).resolve()
    if not path.is_relative_to(snapshot_dir.resolve()):
        return {"path": display_path, "ok": False, "status": "invalid-path",
                "checks": {"exists": False}, "detail": "path escapes snapshot"}
    checks: dict = {"exists": path.is_file()}
    if not checks["exists"]:
        return {"path": display_path, "ok": False, "status": "missing", "checks": checks,
                "detail": "file is missing"}

    checks["size"] = path.stat().st_size == entry.get("size")
    checks["sha256"] = sha256_file(path) == entry.get("sha256")

    integrity = _SKIPPED
    if entry.get("kind") == "sqlite" or is_sqlite_store(path):
        integrity = _integrity_check(path)
    checks["integrity"] = integrity

    if not checks["sha256"]:
        status = "sha256-mismatch"
    elif not checks["size"]:
        status = "size-mismatch"
    elif integrity not in (_OK, _SKIPPED):
        status = "integrity-failed"
    else:
        status = "ok"
    ok = status == "ok"
    return {
        "path": display_path,
        "ok": ok,
        "status": status,
        "checks": checks,
        "detail": None if ok else status,
    }


def verify_snapshot(snapshot_dir: str | Path) -> dict:
    """Verify a snapshot against its manifest.

    Returns ``{"ok": bool, "checked": int, "failed": int, "results": [...]}``.
    Raises :class:`devin_backup.snapshot.SnapshotError` if the manifest is
    missing or unreadable.
    """
    snapshot_dir = Path(snapshot_dir).expanduser()
    manifest = load_manifest(snapshot_dir)
    results = [_verify_file(snapshot_dir, e) for e in manifest["files"]]
    failed = sum(1 for r in results if not r["ok"])
    return {
        "snapshot": str(snapshot_dir),
        "ok": failed == 0,
        "checked": len(results),
        "failed": failed,
        "results": results,
    }
