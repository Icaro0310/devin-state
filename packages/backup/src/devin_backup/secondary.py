"""BK-2: copy a snapshot to a secondary destination and re-verify.

A secondary destination is a plain directory — an external drive, a mounted
NAS, a synced folder. The whole snapshot directory is copied verbatim and
then ``verify_snapshot`` runs **against the copy**: every file's sha256 is
re-hashed at the destination, so a corrupt transfer fails loudly instead of
silently archiving a bad backup.

Offloading to an ssh-style remote (``[user@]host:path`` via rsync) lives
in ``remote.py``, behind ``create --remote``; this command only guarantees
a byte-verified local/mounted copy. Encryption and cloud targets stay out
of scope — that's the personal-track P-8 concern.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from devin_backup import archive
from devin_backup.snapshot import SnapshotError, load_manifest
from devin_backup.verify import verify_snapshot


def _copy_archive(src: Path, dest_parent: Path) -> dict:
    """Copy a ``.tar.*`` snapshot file and re-verify the copy.

    The archive is copied verbatim, then materialized and run through
    ``verify_snapshot`` so every payload hash is checked at the
    destination — same guarantee as a directory copy.
    """
    dest = dest_parent / src.name
    try:
        shutil.copy2(src, dest)
        with archive.materialized(dest) as snap:
            report = verify_snapshot(snap)
        report["snapshot"] = str(dest)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    if not report["ok"]:
        dest.unlink(missing_ok=True)
        raise SnapshotError(
            f"{dest}: copied but FAILED re-verification "
            f"({report['failed']}/{report['checked']} files) — removed")
    return {"dest": str(dest), "verify": report, "compressed": True}


def copy_to(snapshot_dir: str | Path, dest_parent: str | Path) -> dict:
    """Copy ``snapshot_dir`` into ``dest_parent`` and verify the copy.

    ``snapshot_dir`` may be a snapshot directory or a ``.tar.*`` archive;
    archives are copied as files and verified by materializing the copy.

    Returns ``{"dest": ..., "verify": {...}}``. Raises ``SnapshotError`` on
    manifest/verification problems; a failed verification removes the
    partial copy.
    """
    src = Path(snapshot_dir).expanduser()
    load_manifest(src)  # validates it is a snapshot before copying
    dest_parent = Path(dest_parent).expanduser()
    if not dest_parent.is_dir():
        raise SnapshotError(
            f"{dest_parent}: not a directory — mount/create it first")
    if archive.is_archive(src):
        if (dest_parent / src.name).exists():
            raise SnapshotError(
                f"{dest_parent / src.name}: already exists — refusing to merge")
        return _copy_archive(src, dest_parent)
    dest = dest_parent / src.name
    if dest.exists():
        raise SnapshotError(f"{dest}: already exists — refusing to merge")

    try:
        shutil.copytree(src, dest)
        report = verify_snapshot(dest)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    if not report["ok"]:
        shutil.rmtree(dest, ignore_errors=True)
        raise SnapshotError(
            f"{dest}: copied but FAILED re-verification "
            f"({report['failed']}/{report['checked']} files) — removed")
    return {"dest": str(dest), "verify": report}
