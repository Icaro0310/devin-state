"""Restore a snapshot into a data directory.

Safety model:

- **Dry-run by default** — ``dry_run=True`` writes nothing and returns the
  plan (``would_write`` / ``would_overwrite`` / ``warnings``).
- **Pre-restore backup** — if any target file would be overwritten, the
  current files are first copied into ``<backups>/pre-restore-<timestamp>/``
  (consistent SQLite copies, same as a regular snapshot). Restore refuses to
  proceed if that backup cannot be made.
- **No-backup mode** — ``backup=False`` refuses to overwrite anything rather
  than destroying data silently.
- **Schema drift warning** — manifest ``schema_version``s are compared against
  the live databases, so "backup is v15, current is v17" is loud, not silent.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path

from devin_internals.schema import SchemaError, detect_schema_version

from devin_backup.snapshot import (
    MANIFEST_NAME,
    MANIFEST_VERSION,
    PRE_RESTORE_PREFIX,
    _copy_store,
    _unique_dir,
    load_manifest,
    snapshot_timestamp,
)
from devin_backup.stores import Store, default_config_dir


class RestoreError(RuntimeError):
    """The restore was refused or could not be completed safely."""


def _display_path(entry: dict) -> str:
    rel = entry["path"]
    return f"config/{rel}" if entry.get("root", "data") == "config" else rel


def _check_paths(
    manifest: dict, snapshot_dir: Path, target_dir: Path, config_dir: Path
) -> list[tuple[dict, Path]]:
    """Keep snapshot and destination paths inside their selected roots."""
    snapshot_root = snapshot_dir.resolve()
    roots = {"data": target_dir, "config": config_dir}
    entries: list[tuple[dict, Path]] = []
    for entry in manifest["files"]:
        rel = entry.get("path")
        root_name = entry.get("root", "data")
        if not isinstance(rel, str) or not rel or root_name not in roots:
            raise RestoreError(f"manifest: invalid file entry {entry!r}")
        target_root = roots[root_name]
        target_base = target_root.resolve()
        dest = (target_root / rel).resolve()
        snapshot_path = Path(entry.get("snapshot_path", rel))
        source = (snapshot_dir / snapshot_path).resolve()
        if dest == target_base or not dest.is_relative_to(target_base):
            raise RestoreError(
                f"manifest: path {rel!r} escapes the restore target — refusing"
            )
        if not source.is_relative_to(snapshot_root):
            raise RestoreError(
                f"manifest: snapshot path {str(snapshot_path)!r} escapes the snapshot — refusing"
            )
        entries.append((entry, dest))
    return entries


def _schema_warnings(entries: list[tuple[dict, Path]]) -> list[str]:
    warnings = []
    for entry, live in entries:
        backed_up = entry.get("schema_version")
        if backed_up is None or not live.is_file():
            continue
        rel = _display_path(entry)
        try:
            current = detect_schema_version(live)["schema_version"]
        except (SchemaError, sqlite3.Error, OSError):
            warnings.append(
                f"{rel}: cannot detect schema version of the existing file"
            )
            continue
        if current != backed_up:
            warnings.append(
                f"{rel}: backup is schema v{backed_up}, "
                f"current file is v{current} — restoring will downgrade/upgrade it"
            )
    return warnings


def _pre_restore_parent(snapshot_dir: Path, target_dir: Path) -> Path:
    """Where the ``pre-restore-<ts>/`` safety backup lands.

    Normally next to the snapshots. The safety copy must be persistent
    and writable — never inside a temp dir that a context manager
    removes later — so fall back, in order:

    1. the target's parent (snapshot materialized into the system temp
       on read-only media, or the snapshots dir itself not writable);
    2. inside the target itself (target's parent not writable either —
       e.g. ``--to /mnt/devin`` where ``/mnt`` is protected but the
       volume mounted there is writable).
    """
    parent = snapshot_dir.parent
    tmp_root = Path(tempfile.gettempdir()).resolve()
    try:
        resolved = parent.resolve()
    except OSError:
        resolved = parent
    if resolved != tmp_root and os.access(parent, os.W_OK):
        return parent
    if os.access(target_dir.parent, os.W_OK):
        return target_dir.parent
    return target_dir


def _pre_restore_backup(
    snapshot_dir: Path,
    target_dir: Path,
    config_dir: Path,
    existing: list[tuple[dict, Path]],
) -> Path:
    """Copy files about to be overwritten into ``pre-restore-<ts>/``."""
    backups_dir = _pre_restore_parent(snapshot_dir, target_dir)
    pre_dir = _unique_dir(
        backups_dir, PRE_RESTORE_PREFIX + snapshot_timestamp()
    )
    try:
        entries = []
        for entry, path in existing:
            entries.append(_copy_store(
                Store(
                    path=path,
                    rel_path=entry["path"],
                    kind=entry.get("kind", "file"),
                    root=entry.get("root", "data"),
                ),
                pre_dir,
            ))
        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "kind": "pre-restore",
            "tool": "devin-backup",
            "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source_data_dir": str(target_dir.resolve()),
            "source_config_dir": str(config_dir.resolve()),
            "restores_snapshot": snapshot_dir.name,
            "files": entries,
        }
        (pre_dir / MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        shutil.rmtree(pre_dir, ignore_errors=True)
        raise RestoreError(
            f"could not create pre-restore backup in {backups_dir}: {exc} — "
            "refusing to overwrite existing files"
        ) from exc
    return pre_dir


def restore_snapshot(
    snapshot_dir: str | Path,
    target_dir: str | Path,
    *,
    config_dir: str | Path | None = None,
    dry_run: bool = True,
    backup: bool = True,
    now: datetime | None = None,
) -> dict:
    """Restore a snapshot to its Devin data and config roots.

    Args:
        config_dir: destination for UI/config stores; defaults to the current
            platform's Devin config root.
        dry_run: default ``True`` — plan only, write nothing.
        backup: when overwriting, first copy current files to a
            ``pre-restore-<ts>`` dir next to the snapshots. ``False`` makes
            any overwrite a hard refusal instead.
        now: timestamp override (tests).
    """
    snapshot_dir = Path(snapshot_dir).expanduser()
    target_dir = Path(target_dir).expanduser()
    config_dir = Path(config_dir).expanduser() if config_dir else default_config_dir()
    manifest = load_manifest(snapshot_dir)
    mapped = _check_paths(manifest, snapshot_dir, target_dir, config_dir)
    existing = [(entry, dest) for entry, dest in mapped if dest.exists()]
    warnings = _schema_warnings(mapped)
    writes = [_display_path(entry) for entry, _ in mapped]
    overwrites = [_display_path(entry) for entry, _ in existing]

    if dry_run:
        return {
            "dry_run": True,
            "snapshot": str(snapshot_dir),
            "target": str(target_dir),
            "config_target": str(config_dir),
            "would_write": writes,
            "would_overwrite": overwrites,
            "would_backup": overwrites if (overwrites and backup) else [],
            "warnings": warnings,
        }

    if existing:
        if not backup:
            raise RestoreError(
                f"{len(existing)} file(s) would be overwritten and backup=False — refusing"
            )
        pre_dir = _pre_restore_backup(
            snapshot_dir, target_dir, config_dir, existing
        )
        pre_restore: str | None = str(pre_dir)
    else:
        pre_restore = None

    for entry, dest in mapped:
        dest.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path = entry.get("snapshot_path", entry["path"])
        shutil.copy2(snapshot_dir / snapshot_path, dest)

    return {
        "dry_run": False,
        "snapshot": str(snapshot_dir),
        "target": str(target_dir),
        "config_target": str(config_dir),
        "written": writes,
        "overwritten": overwrites,
        "pre_restore_backup": pre_restore,
        "warnings": warnings,
    }
