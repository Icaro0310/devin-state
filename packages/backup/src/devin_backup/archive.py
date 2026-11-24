"""Compressed snapshot archives (``.tar.zst`` / ``.tar.gz``).

A compressed snapshot is a single file ``<snapshot-name>.tar.zst`` (or
``.tar.gz`` when ``compression.zstd`` is unavailable — Python < 3.14)
holding the snapshot directory's *contents*: ``manifest.json`` first,
then every store file at its ``snapshot_path``. ``manifest.json`` being
the first tar member keeps ``list``/``preflight`` cheap — the manifest
can be read without decompressing the payload.

All archive-aware commands accept either form transparently: readers
materialize the archive into a temporary directory inside the archive's
own parent (so ``restore``'s ``pre-restore-*`` safety backups still land
next to the real snapshots) and run the unchanged directory code path.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from devin_backup.snapshot import (
    MANIFEST_NAME,
    MANIFEST_VERSION,
    SNAPSHOT_NAME_RE,
    SnapshotError,
)
from devin_backup.stores import SQLITE_SIDECAR_SUFFIXES

ARCHIVE_SUFFIXES = (".tar.zst", ".tar.gz")
_ZSTD_LEVEL = 19
_ZSTD_WINDOW_LOG = 27  # --long=27, same as scripts/sessions-db-backup.sh
_GZ_LEVEL = 9


def _zstd_fileobj(path: Path, mode: str):
    """compression.zstd file object, or None when unavailable (py<3.14)."""
    try:
        from compression import zstd
    except ImportError:
        return None
    if "w" in mode:
        options = {
            zstd.CompressionParameter.compression_level: _ZSTD_LEVEL,
            zstd.CompressionParameter.window_log: _ZSTD_WINDOW_LOG,
        }
        try:
            return zstd.ZstdFile(path, mode, options=options)
        except (TypeError, ValueError):
            return zstd.ZstdFile(path, mode, level=_ZSTD_LEVEL)
    return zstd.ZstdFile(path, mode)


def _zstd_available() -> bool:
    try:
        import compression.zstd  # noqa: F401
    except ImportError:
        return False
    return True



def preferred_suffix() -> str:
    return ".tar.zst" if _zstd_available() else ".tar.gz"


def is_archive(path: str | Path) -> bool:
    """True for ``<timestamp>.tar.zst`` / ``.tar.gz`` files."""
    p = Path(path)
    if not p.is_file():
        return False
    for suf in ARCHIVE_SUFFIXES:
        if p.name.endswith(suf):
            return SNAPSHOT_NAME_RE.match(p.name[: -len(suf)]) is not None
    return False


def stem_name(path: str | Path) -> str:
    """Snapshot name without any ``.tar.*`` suffix — the shared ordering
    key. ``<ts>-2`` sorts after the bare ``<ts>``, whereas comparing full
    archive names would order it *before* (``-`` < ``.``) and treat the
    newer same-second snapshot as the older one."""
    name = Path(path).name
    for suf in ARCHIVE_SUFFIXES:
        if name.endswith(suf):
            return name[: -len(suf)]
    return name


@contextmanager
def _open_writer(path: Path, suffix: str):
    """TarFile writer; the zstd fileobj is closed explicitly because
    tarfile does not own (or close) a caller-supplied fileobj — without
    it the zstd frame is never finalized and the archive is truncated."""
    if suffix == ".tar.zst":
        fobj = _zstd_fileobj(path, "wb")
        if fobj is None:
            raise SnapshotError(
                "cannot write .tar.zst: compression.zstd needs Python 3.14+"
            )
        try:
            with tarfile.open(fileobj=fobj, mode="w|") as tf:
                yield tf
        finally:
            fobj.close()
    else:
        with tarfile.open(path, "w:gz", compresslevel=_GZ_LEVEL) as tf:
            yield tf


@contextmanager
def _open_reader(path: Path):
    """Streaming tar reader; same fileobj ownership rule as the writer."""
    if path.name.endswith(".tar.zst"):
        if not _zstd_available():
            raise SnapshotError(
                f"{path}: .tar.zst needs compression.zstd (Python 3.14+)"
            )
        fobj = _zstd_fileobj(path, "rb")
        try:
            with tarfile.open(fileobj=fobj, mode="r|") as tf:
                yield tf
        finally:
            fobj.close()
    else:
        with tarfile.open(path, "r|gz") as tf:
            yield tf


def _is_sqlite_sidecar(path: Path) -> bool:
    """``-wal``/``-shm``/``-journal`` companions of a ``.db``/``.vscdb``.

    Snapshot dirs can carry these as runtime leftovers from opening the
    copied WAL-mode databases — they are never manifest content (store
    discovery skips them) and hold no data of their own.
    """
    return path.name.lower().endswith(tuple(SQLITE_SIDECAR_SUFFIXES))


def _iter_members(snap_dir: Path):
    """(arcname, fs_path) pairs: manifest.json first, then sorted files."""
    files = [
        p for p in snap_dir.rglob("*")
        if p.is_file()
        and p.name != MANIFEST_NAME
        and not _is_sqlite_sidecar(p)
    ]
    files.sort(key=lambda p: p.relative_to(snap_dir).as_posix())
    manifest = snap_dir / MANIFEST_NAME
    if manifest.is_file():
        yield MANIFEST_NAME, manifest
    for p in files:
        yield p.relative_to(snap_dir).as_posix(), p


def write_archive(snap_dir: str | Path, dest: str | Path | None = None) -> Path:
    """Write ``snap_dir``'s contents to ``<name>.<suffix>`` archive.

    The archive sits next to the snapshot dir unless ``dest`` is given.
    Partial output is removed on failure. Returns the archive path.
    """
    snap_dir = Path(snap_dir)
    suffix = preferred_suffix()
    out = Path(dest) if dest else snap_dir.with_name(snap_dir.name + suffix)
    if out.exists():
        raise SnapshotError(f"{out}: already exists — refusing to overwrite")
    tmp = out.with_name(out.name + ".tmp")
    # Snapshots can carry credentials — create the temp file 0600 upfront
    # so the archive is never world-readable mid-write (umask 022 would
    # otherwise leave it open until the post-rename chmod).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(fd)
    try:
        with _open_writer(tmp, suffix) as tf:
            for arcname, fs_path in _iter_members(snap_dir):
                tf.add(fs_path, arcname=arcname, recursive=False)
        tmp.replace(out)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    try:
        out.chmod(0o600)
    except OSError:
        pass
    return out


def _validate_manifest(manifest: dict, source: str) -> dict:
    if not isinstance(manifest, dict):
        raise SnapshotError(f"{source}: manifest is not a JSON object")
    if manifest.get("manifest_version") not in {1, MANIFEST_VERSION}:
        raise SnapshotError(
            f"{source}: unsupported manifest_version "
            f"{manifest.get('manifest_version')!r} "
            f"(supported: 1..{MANIFEST_VERSION})"
        )
    if not isinstance(manifest.get("files"), list):
        raise SnapshotError(f"{source}: manifest has no 'files' list")
    return manifest


def load_manifest_file(archive_path: str | Path) -> dict:
    """Read ``manifest.json`` from an archive without full extraction.

    The tar is streamed and reading stops at the first member — cheap
    even for large snapshots.
    """
    archive_path = Path(archive_path)
    if not is_archive(archive_path):
        raise SnapshotError(f"{archive_path}: not a snapshot archive")
    try:
        with _open_reader(archive_path) as tf:
            for member in tf:
                if member.name == MANIFEST_NAME and member.isfile():
                    fobj = tf.extractfile(member)
                    raw = fobj.read() if fobj else b""
                    break
            else:
                raise SnapshotError(
                    f"{archive_path}: no {MANIFEST_NAME} — not a snapshot?"
                )
    except SnapshotError:
        raise
    except Exception as exc:
        # OSError, tarfile.TarError, compression.zstd.ZstdError, EOFError…
        raise SnapshotError(f"{archive_path}: unreadable archive: {exc}") from exc
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(
            f"{archive_path}: unreadable manifest: {exc}"
        ) from exc
    return _validate_manifest(manifest, str(archive_path / MANIFEST_NAME))


def _safe_target(dest: Path, arcname: str) -> Path:
    target = (dest / arcname).resolve()
    if not target.is_relative_to(dest.resolve()):
        raise SnapshotError(f"archive member escapes destination: {arcname!r}")
    return target


def _extract_into(archive_path: Path, dest: Path) -> None:
    """Extract archive contents into ``dest`` (which becomes the snapshot dir)."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with _open_reader(archive_path) as tf:
            for member in tf:
                target = _safe_target(dest, member.name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    fd = os.open(
                        target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
                    )
                    with os.fdopen(fd, "wb") as out:
                        shutil.copyfileobj(src, out, length=1 << 20)
                # other member types (links, devices) are skipped
    except SnapshotError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise SnapshotError(f"{archive_path}: extraction failed: {exc}") from exc


def extract_archive(archive_path: str | Path, dest_parent: str | Path) -> Path:
    """Extract an archive into ``dest_parent/<snapshot-name>/``.

    Returns the extracted snapshot directory. Members with absolute or
    ``..`` paths are rejected.
    """
    archive_path = Path(archive_path)
    stem = archive_path.name
    for suf in ARCHIVE_SUFFIXES:
        if stem.endswith(suf):
            stem = stem[: -len(suf)]
            break
    dest = Path(dest_parent) / stem
    if dest.exists():
        raise SnapshotError(
            f"{dest}: already exists — refusing to overwrite"
        )
    _extract_into(archive_path, dest)
    return dest


@contextmanager
def materialized(path: str | Path) -> Iterator[Path]:
    """Yield a snapshot *directory* for ``path`` (dir or archive).

    Directories pass through unchanged. Archives are extracted into a
    temporary dir inside the archive's parent and the temp dir itself is
    yielded as the snapshot root — so ``snapshot_dir.parent`` stays the
    real backups dir and ``restore``'s ``pre-restore-*`` safety backups
    land next to the snapshots instead of inside the temp dir (which is
    removed on exit). On read-only media the parent is not writable —
    extraction then falls back to a private dir under the system temp and
    ``restore`` writes the safety backup next to the restore target
    instead.
    """
    p = Path(path).expanduser()
    if not is_archive(p):
        yield p
        return
    parent = p.resolve().parent
    tmp_parent = parent if os.access(parent, os.W_OK) else None
    with tempfile.TemporaryDirectory(
        prefix=".extract-", dir=tmp_parent, ignore_cleanup_errors=True
    ) as td:
        _extract_into(p, Path(td))
        yield Path(td)


def verify_archive(archive_path: str | Path) -> dict:
    """Hash-verify every member against the manifest, single pass.

    Returns a report shaped like ``verify_snapshot`` minus the sqlite
    ``integrity_check`` (that needs real files — use ``verify`` on the
    archive, which materializes first).
    """
    archive_path = Path(archive_path)
    manifest = load_manifest_file(archive_path)
    expected = {}
    for entry in manifest["files"]:
        sp = entry.get("snapshot_path") or entry.get("path")
        if sp:
            expected[sp] = (entry.get("size"), entry.get("sha256"))

    results = []
    seen = set()
    try:
        with _open_reader(archive_path) as tf:
            for member in tf:
                if not member.isfile() or member.name == MANIFEST_NAME:
                    continue
                sp = member.name
                seen.add(sp)
                exp = expected.get(sp)
                if exp is None:
                    results.append({"path": sp, "ok": False,
                                    "status": "unexpected"})
                    continue
                h = hashlib.sha256()
                size = 0
                fobj = tf.extractfile(member)
                if fobj is None:
                    results.append({"path": sp, "ok": False,
                                    "status": "unreadable"})
                    continue
                for chunk in iter(lambda f=fobj: f.read(1 << 20), b""):
                    h.update(chunk)
                    size += len(chunk)
                ok = (size == exp[0] and h.hexdigest() == exp[1])
                results.append({
                    "path": sp, "ok": ok,
                    "status": "ok" if ok else "hash-mismatch",
                    "size": size,
                })
    except SnapshotError:
        raise
    except Exception as exc:
        raise SnapshotError(f"{archive_path}: verify failed: {exc}") from exc

    for sp in expected:
        if sp not in seen:
            results.append({"path": sp, "ok": False, "status": "missing"})
    results.sort(key=lambda r: r["path"])
    failed = sum(1 for r in results if not r["ok"])
    return {
        "snapshot": str(archive_path),
        "checked": len(results),
        "failed": failed,
        "ok": failed == 0,
        "results": results,
    }


def compress_snapshot_dir(snap_dir: str | Path) -> Path:
    """Archive ``snap_dir`` in place: write, verify, then remove the dir.

    Returns the archive path. On any failure the original dir is kept.
    """
    snap_dir = Path(snap_dir)
    out = write_archive(snap_dir)
    try:
        report = verify_archive(out)
    except Exception:
        out.unlink(missing_ok=True)
        raise
    if not report["ok"]:
        out.unlink(missing_ok=True)
        raise SnapshotError(
            f"{out}: archive failed self-verification "
            f"({report['failed']}/{report['checked']} files)"
        )
    shutil.rmtree(snap_dir)
    return out
