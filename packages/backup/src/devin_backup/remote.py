"""Offload a snapshot to a remote or mounted destination (BK-3).

``create --remote <dest>`` re-verifies the fresh snapshot and ships it to
an rsync-style destination:

- **ssh target** — ``[user@]host:path`` — delegated to the system
  ``rsync`` (``rsync -a --protect-args``). Credentials never appear in
  argv; rsync uses its own mechanisms (ssh-agent, ``~/.ssh/config``).
  Effectively posix-only: Windows does not ship rsync, and a missing
  binary fails loudly instead of falling back silently.
- **local/mounted path** — an external drive, NAS mount or synced
  folder — copied through :func:`devin_backup.secondary.copy_to`, which
  re-verifies every sha256 at the destination and needs no rsync
  (Windows-safe).

The local snapshot is kept by default — a copy, not a move. It is only
deleted after a successful offload when ``move=True``
(``create --remote --move``), and never on failure.

Cloud backends (S3/rclone), encryption and remote-side re-verification
stay out of scope — this covers filesystem and ssh destinations only.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from devin_backup import secondary
from devin_backup.snapshot import SnapshotError, load_manifest
from devin_backup.verify import verify_snapshot

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


def is_remote_target(dest: str) -> bool:
    """True when ``dest`` is an rsync ssh-style target ``[user@]host:path``.

    The remote form has a ``:`` before the first path separator. A
    drive-letter prefix (``C:\\…``, ``C:/…``) is never a host — a
    one-letter "hostname" is not a real ssh target — and neither is
    anything whose first separator precedes the colon (``./a:b``,
    ``/x/y:z`` are local filenames).
    """
    if _DRIVE_PREFIX.match(dest):
        return False
    head = re.split(r"[/\\]", dest, maxsplit=1)[0]
    return ":" in head


def _remote_dest(src: Path, dest: str) -> str:
    """``dest`` resolved to the snapshot's final remote path."""
    if dest.endswith(":"):  # 'host:' — rsync home dir
        return f"{dest}{src.name}"
    return f"{dest.rstrip('/')}/{src.name}"


def _offload_rsync(src: Path, dest: str) -> dict:
    if shutil.which("rsync") is None:
        raise SnapshotError(
            "rsync not found on PATH — ssh-style targets "
            "('[user@]host:path') require rsync (posix); on Windows pass "
            "a mounted/local path instead"
        )
    remote_dest = _remote_dest(src, dest)
    cmd = [
        "rsync", "-a", "--protect-args", "--",
        f"{src}/", remote_dest,
    ]
    proc = subprocess.run(
        cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise SnapshotError(
            f"rsync to {remote_dest} failed (exit {proc.returncode})"
            + (f": {detail}" if detail else "")
        )
    return {"dest": remote_dest, "method": "rsync"}


def offload_snapshot(
    snapshot_dir: str | Path, dest: str | Path, *, move: bool = False
) -> dict:
    """Verify ``snapshot_dir`` and offload it to ``dest``.

    ``dest`` is either an ssh-style ``[user@]host:path`` (rsync) or a
    local/mounted directory (verified copy via
    :func:`devin_backup.secondary.copy_to`). The snapshot must pass
    ``verify_snapshot`` before anything is transferred — a corrupt
    bundle is never shipped.

    Returns ``{"dest": ..., "method": "rsync"|"copy", "bytes": int,
    "moved": bool}``, plus ``"verify"`` for local copies. With
    ``move=True`` the local snapshot is removed *after* a successful
    offload; on any failure nothing is deleted. Raises
    :class:`SnapshotError` on verification/transfer problems.
    """
    src = Path(snapshot_dir).expanduser()
    manifest = load_manifest(src)
    total = sum(f.get("size", 0) for f in manifest["files"])

    report = verify_snapshot(src)
    if not report["ok"]:
        raise SnapshotError(
            f"{src}: failed verification "
            f"({report['failed']}/{report['checked']} files) — not offloading"
        )

    dest_str = str(dest)
    if is_remote_target(dest_str):
        result = _offload_rsync(src, dest_str)
    else:
        result = secondary.copy_to(src, Path(dest_str).expanduser())
        result["method"] = "copy"
    result["bytes"] = total
    result["moved"] = False
    if move:
        shutil.rmtree(src)
        result["moved"] = True
    return result
