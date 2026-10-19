"""Post-restore smoke checks (``devin-backup restore --smoke``).

Verifies the stores a restore touches by running ``PRAGMA integrity_check``
on every SQLite store and detecting its schema version via
``devin-internals-spec``. Two modes, same checks:

- ``smoke_restored`` — the files ``restore --apply`` just wrote, at the
  target roots.
- ``smoke_snapshot`` — the sources inside the snapshot itself, used when
  ``--smoke`` is passed without ``--apply`` (dry-run preview).

Everything is opened read-only (``mode=ro`` URI, via
:func:`devin_backup.verify._integrity_check`); this module never writes to
the stores.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from devin_internals.schema import SchemaError, detect_schema_version

from devin_backup.restore import _check_paths, _display_path
from devin_backup.snapshot import load_manifest
from devin_backup.stores import default_config_dir, is_sqlite_store
from devin_backup.verify import _integrity_check


def _detect_version(path: Path) -> int | None:
    """Schema version via devin-internals-spec; ``None`` when undetectable."""
    try:
        return int(detect_schema_version(path)["schema_version"])
    except (SchemaError, sqlite3.Error, OSError):
        return None


def _check_store(entry: dict, path: Path, display: str) -> dict:
    is_db = entry.get("kind") == "sqlite" or is_sqlite_store(path)
    if not path.is_file():
        return {
            "path": display,
            "ok": False,
            "integrity": "missing",
            "schema_version": None,
            "sqlite": is_db,
            "detail": "store is missing",
        }
    integrity = "skipped"
    schema_version = None
    if is_db:
        integrity = _integrity_check(path)
        schema_version = _detect_version(path)
    ok = integrity in ("ok", "skipped")
    return {
        "path": display,
        "ok": ok,
        "integrity": integrity,
        "schema_version": schema_version,
        "sqlite": is_db,
        "detail": None if ok else integrity,
    }


def _report(results: list[dict]) -> dict:
    failed = sum(1 for r in results if not r["ok"])
    return {
        "ok": failed == 0,
        "checked": len(results),
        "failed": failed,
        "results": results,
    }


def smoke_snapshot(snapshot_dir: str | Path) -> dict:
    """Smoke-check the stores inside a snapshot (dry-run preview).

    Returns ``{"ok": bool, "checked": int, "failed": int, "results": [...]}``.
    Raises :class:`devin_backup.snapshot.SnapshotError` if the manifest is
    missing or unreadable.
    """
    snapshot_dir = Path(snapshot_dir)
    manifest = load_manifest(snapshot_dir)
    root = snapshot_dir.resolve()
    results = []
    for entry in manifest["files"]:
        display = _display_path(entry)
        snapshot_path = Path(entry.get("snapshot_path", entry["path"]))
        path = (snapshot_dir / snapshot_path).resolve()
        if not path.is_relative_to(root):
            results.append({
                "path": display,
                "ok": False,
                "integrity": "invalid-path",
                "schema_version": None,
                "sqlite": False,
                "detail": "snapshot path escapes the snapshot",
            })
            continue
        results.append(_check_store(entry, path, display))
    return _report(results)


def smoke_restored(
    snapshot_dir: str | Path,
    target_dir: str | Path,
    config_dir: str | Path | None = None,
) -> dict:
    """Smoke-check the stores ``restore --apply`` wrote to the target roots.

    Uses the same manifest→destination mapping as the restore itself, so a
    tampered manifest fails safe (``RestoreError``) instead of reading
    arbitrary paths.
    """
    snapshot_dir = Path(snapshot_dir).expanduser()
    target_dir = Path(target_dir).expanduser()
    config_dir = (
        Path(config_dir).expanduser() if config_dir else default_config_dir()
    )
    manifest = load_manifest(snapshot_dir)
    mapped = _check_paths(manifest, snapshot_dir, target_dir, config_dir)
    return _report([
        _check_store(entry, dest, _display_path(entry))
        for entry, dest in mapped
    ])
