"""Timestamped snapshots of Devin's local stores.

SQLite stores are copied through ``sqlite3.Connection.backup()``, which
produces a consistent standalone database even while Devin Desktop is
running; if that fails (locked file, not a real database) we fall back to a
plain copy and record ``copied_via`` in the manifest.

Each snapshot is ``<backups>/<UTC timestamp>/`` containing the stores under
their original relative paths plus ``manifest.json`` with sizes, sha256
digests and per-database ``schema_version`` (via devin-internals-spec) so a
later restore can warn "backup is v15, current is v17".
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from devin_internals.schema import SchemaError, detect_schema_version

from devin_backup import __version__, identity
from devin_backup.stores import DataDirError, Store, discover_stores

MANIFEST_VERSION = 2
MANIFEST_NAME = "manifest.json"
SNAPSHOT_NAME_RE = re.compile(r"^\d{8}T\d{6}Z(-\d+)?$")
PRE_RESTORE_PREFIX = "pre-restore-"

# Stores known to carry credentials / PII — skipped by ``--exclude-secrets``.
# A vscdb-scan audit of a live state.vscdb confirmed OAuth tokens (GitHub,
# Codeium/Windsurf) and user-identifying key names live there.
SENSITIVE_PATTERNS = (
    "globalStorage/state.vscdb",
    "*.pem",
    "*.key",
    "credentials.toml",
)


def _excluded(store: Store, patterns: tuple[str, ...]) -> bool:
    rel = store.rel_path.replace(os.sep, "/")
    return any(
        fnmatch.fnmatch(rel, pat) or pat.lower() in rel.lower()
        for pat in patterns
    )


class SnapshotError(RuntimeError):
    """A snapshot could not be created or read."""


def sha256_file(path: str | Path, _chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _connect_readonly(path: Path) -> sqlite3.Connection:
    uri = f"file:{quote(path.resolve().as_posix(), safe='/:')}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _copy_sqlite(src: Path, dst: Path) -> None:
    """Consistent copy via the SQLite online backup API."""
    source = _connect_readonly(src)
    try:
        target = sqlite3.connect(str(dst))
        try:
            source.backup(target)
        finally:
            target.close()
    finally:
        source.close()


def _detect_schema(dst: Path) -> int | None:
    try:
        return int(detect_schema_version(dst)["schema_version"])
    except (SchemaError, sqlite3.Error, OSError):
        return None


def snapshot_timestamp(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _unique_dir(parent: Path, name: str) -> Path:
    candidate = parent / name
    n = 1
    while candidate.exists():
        n += 1
        candidate = parent / f"{name}-{n}"
    return candidate


def _snapshot_path(store: Store) -> str:
    return (
        f"config/{store.rel_path}"
        if store.root == "config"
        else store.rel_path
    )


def _display_path(entry: dict) -> str:
    return (
        f"config/{entry['path']}"
        if entry.get("root", "data") == "config"
        else entry["path"]
    )


def _copy_store(store: Store, snap_dir: Path) -> dict:
    snapshot_path = _snapshot_path(store)
    dst = snap_dir / snapshot_path
    dst.parent.mkdir(parents=True, exist_ok=True)
    via = "file-copy"
    if store.kind == "sqlite":
        try:
            _copy_sqlite(store.path, dst)
            via = "sqlite-backup"
        except (sqlite3.Error, OSError):
            shutil.copy2(store.path, dst)
    else:
        shutil.copy2(store.path, dst)
    try:
        os.chmod(dst, 0o600)
    except OSError:
        pass  # Windows ACLs — mode bits are advisory there
    return {
        "path": store.rel_path,
        "root": store.root,
        "snapshot_path": snapshot_path,
        "kind": store.kind,
        "copied_via": via,
        "size": dst.stat().st_size,
        "sha256": sha256_file(dst),
        "schema_version": _detect_schema(dst) if store.kind == "sqlite" else None,
    }


def create_snapshot(
    data_dir: str | Path,
    out_dir: str | Path,
    *,
    config_dir: str | Path | None = None,
    now: datetime | None = None,
    exclude: tuple[str, ...] = (),
    exclude_secrets: bool = False,
) -> Path:
    """Snapshot Devin stores from its data and optional config roots.

    ``exclude`` filters stores by substring/fnmatch match on the relative
    path; ``exclude_secrets`` additionally skips stores known to carry
    credentials or PII (``state.vscdb``, ``credentials.toml``, key files).
    Snapshot dirs are created owner-only (0700) and files 0600 — a
    snapshot is a copy of every secret the stores hold.
    """
    data_dir = Path(data_dir).expanduser()
    config_dir = Path(config_dir).expanduser() if config_dir else None
    out_dir = Path(out_dir).expanduser()
    try:
        stores = discover_stores(data_dir, config_dir=config_dir, exclude=[out_dir])
    except DataDirError as exc:
        raise SnapshotError(str(exc)) from exc
    patterns = tuple(exclude) + (
        SENSITIVE_PATTERNS if exclude_secrets else ()
    )
    skipped = [s for s in stores if _excluded(s, patterns)]
    stores = [s for s in stores if not _excluded(s, patterns)]
    if not stores:
        raise SnapshotError(f"{data_dir}: no Devin stores found to back up")

    snap_dir = _unique_dir(out_dir, snapshot_timestamp(now))
    snap_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        os.chmod(snap_dir, 0o700)
    except OSError:
        pass
    try:
        entries = [_copy_store(store, snap_dir) for store in stores]
        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "tool": "devin-backup",
            "tool_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "provenance": identity.provenance(),
            "source_data_dir": str(data_dir.resolve()),
            "files": entries,
            "excluded": [
                {"path": s.rel_path, "root": s.root} for s in skipped
            ],
            "schema_versions": {
                e.get("snapshot_path", e["path"]): e["schema_version"]
                for e in entries
                if e["schema_version"] is not None
            },
        }
        if config_dir is not None:
            manifest["source_config_dir"] = str(config_dir.resolve())
        manifest_path = snap_dir / MANIFEST_NAME
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(manifest_path, 0o600)
        except OSError:
            pass
    except Exception:
        shutil.rmtree(snap_dir, ignore_errors=True)
        raise
    return snap_dir


def load_manifest(snapshot_dir: str | Path) -> dict:
    """Read and minimally validate a snapshot's ``manifest.json``."""
    snapshot_dir = Path(snapshot_dir)
    manifest_path = snapshot_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        raise SnapshotError(f"{snapshot_dir}: no {MANIFEST_NAME} — not a snapshot?")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"{manifest_path}: unreadable manifest: {exc}") from exc
    if manifest.get("manifest_version") not in {1, MANIFEST_VERSION}:
        raise SnapshotError(
            f"{manifest_path}: unsupported manifest_version "
            f"{manifest.get('manifest_version')!r} (supported: 1..{MANIFEST_VERSION})"
        )
    if not isinstance(manifest.get("files"), list):
        raise SnapshotError(f"{manifest_path}: manifest has no 'files' list")
    return manifest
