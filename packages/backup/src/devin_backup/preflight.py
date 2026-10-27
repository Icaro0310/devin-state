"""Pre-flight readiness checks for ``devin-backup create``.

Runs the same source/destination resolution as ``create`` and reports
each precondition as its own result — ``pass``, ``fail`` or ``unknown``
— instead of a single verdict, so a scheduled run can tell *what* would
break before it breaks:

- ``data-root`` — the Devin data dir exists and is a directory
  (``create`` aborts otherwise).
- ``config-root`` — the UI config root exists. Only evaluated when
  ``create`` would include it: an explicit ``--config-dir``, or the
  platform default when ``--data-dir`` is not given. A missing
  *explicit* root is a fail; a missing default is unknown — the backup
  would silently skip the UI stores.
- ``stores-found`` — discovery yields at least one store after the same
  ``--exclude``/``--exclude-secrets`` filters ``create`` applies, and
  every store can be stat'ed (an unreadable store aborts a copy
  mid-snapshot).
- ``dest-writable`` — the backups dir, or the nearest existing ancestor
  it would be created under, accepts a real write probe.
- ``free-space`` — free space at the destination is >= the summed size
  of the stores that would be copied (the documented threshold).
- ``tool-sqlite3`` — the stdlib ``sqlite3`` module and its online
  backup API work; without them SQLite stores fall back to plain file
  copies that can be corrupt on a live database.
- ``no-inflight-snapshot`` — no timestamp-named dir without
  ``manifest.json`` sits in the backups dir (a ``create`` still in
  progress or one that crashed mid-copy).
- ``latest-snapshot`` — the newest existing snapshot's manifest still
  parses; no snapshots at all passes (first backup).
- ``remote-dest`` / ``tool-rsync`` — only with ``--remote``: a mounted
  path must exist and be writable (``copy_to`` refuses otherwise); an
  ssh-style ``[user@]host:path`` needs ``rsync`` on PATH.

Fail-closed: a check that cannot be evaluated reports ``unknown``
rather than passing. ``ok`` in the report is true only when *every*
check passed; the CLI maps that to exit 0, any fail or unknown to
exit 1, and usage/spec errors to exit 2.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

from devin_backup import remote as _remote
from devin_backup.snapshot import (
    MANIFEST_NAME,
    SENSITIVE_PATTERNS,
    SNAPSHOT_NAME_RE,
    SnapshotError,
    _excluded,
    load_manifest,
)
from devin_backup.stores import Store, discover_stores

PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"


def _result(name: str, status: str, detail: str) -> dict:
    return {"name": name, "status": status, "detail": detail}


def _check_data_root(data_dir: Path) -> dict:
    name = "data-root"
    try:
        if data_dir.is_dir():
            return _result(name, PASS, f"exists: {data_dir}")
        if data_dir.exists():
            return _result(name, FAIL, f"{data_dir} is not a directory")
        return _result(name, FAIL, f"{data_dir} does not exist")
    except OSError as exc:
        return _result(name, UNKNOWN, f"cannot stat {data_dir}: {exc}")


def _check_config_root(config_dir: Path, explicit: bool) -> dict:
    name = "config-root"
    try:
        ok = config_dir.is_dir()
    except OSError as exc:
        return _result(name, UNKNOWN, f"cannot stat {config_dir}: {exc}")
    if ok:
        return _result(name, PASS, f"exists: {config_dir}")
    if explicit:
        return _result(
            name, FAIL,
            f"explicit --config-dir {config_dir} is not a directory",
        )
    return _result(
        name, UNKNOWN,
        f"default config root {config_dir} not found — UI stores "
        "(state.vscdb, acp-messages) would be skipped; pass --config-dir "
        "or set DEVIN_CONFIG_DIR",
    )


def _kept_stores(
    data_dir: Path,
    config_dir: Path | None,
    out_dir: Path,
    exclude: tuple[str, ...],
    exclude_secrets: bool,
) -> list[Store]:
    """Stores ``create`` would copy, exclusions applied. May raise."""
    stores = discover_stores(data_dir, config_dir=config_dir,
                             exclude=[out_dir])
    patterns = tuple(exclude) + (
        SENSITIVE_PATTERNS if exclude_secrets else ()
    )
    return [s for s in stores if not _excluded(s, patterns)]


def _size_stores(stores: list[Store]) -> tuple[int, int]:
    """``(total_bytes, unreadable_count)`` over the store source files."""
    total = 0
    unreadable = 0
    for store in stores:
        try:
            total += store.path.stat().st_size
        except OSError:
            unreadable += 1
    return total, unreadable


def _nearest_existing_dir(path: Path) -> Path:
    """``path`` itself when it is a dir, else its nearest ancestor that is."""
    cur = path
    while not cur.is_dir():
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return cur


def _writable_probe(directory: Path) -> str | None:
    """``None`` when a real temp-file write works, else the error text."""
    try:
        fd, probe = tempfile.mkstemp(
            prefix=".devin-backup-preflight-", dir=directory)
        try:
            os.close(fd)
        finally:
            Path(probe).unlink(missing_ok=True)
    except OSError as exc:
        return str(exc)
    return None


def _check_dest(out_dir: Path) -> dict:
    name = "dest-writable"
    try:
        if out_dir.exists():
            if not out_dir.is_dir():
                return _result(
                    name, FAIL,
                    f"{out_dir} exists but is not a directory")
            err = _writable_probe(out_dir)
            if err:
                return _result(name, FAIL,
                               f"{out_dir} not writable: {err}")
            return _result(name, PASS, f"writable: {out_dir}")
        base = _nearest_existing_dir(out_dir)
        err = _writable_probe(base)
        if err:
            return _result(
                name, FAIL,
                f"cannot create {out_dir}: {base} not writable: {err}")
        return _result(
            name, PASS,
            f"{out_dir} will be created under writable {base}")
    except OSError as exc:
        return _result(name, UNKNOWN, f"cannot evaluate {out_dir}: {exc}")


def _check_free_space(out_dir: Path, needed: int | None) -> dict:
    name = "free-space"
    if needed is None:
        return _result(name, UNKNOWN,
                       "store size unknown — cannot evaluate")
    try:
        base = _nearest_existing_dir(out_dir)
        free = shutil.disk_usage(base).free
    except OSError as exc:
        return _result(name, UNKNOWN, f"cannot statfs {out_dir}: {exc}")
    if free >= needed:
        return _result(name, PASS,
                       f"{free} B free >= {needed} B needed "
                       "(sum of store sizes)")
    return _result(name, FAIL,
                   f"{free} B free < {needed} B needed "
                   "(sum of store sizes)")


def _check_sqlite() -> dict:
    name = "tool-sqlite3"
    try:
        con = sqlite3.connect(":memory:")
        try:
            has_backup = hasattr(con, "backup")
        finally:
            con.close()
    except sqlite3.Error as exc:
        return _result(
            name, FAIL,
            f"stdlib sqlite3 unusable: {exc} — SQLite stores would "
            "fall back to unsafe file-copy")
    if not has_backup:
        return _result(
            name, FAIL,
            "sqlite3 lacks Connection.backup — SQLite stores would "
            "fall back to unsafe file-copy")
    return _result(
        name, PASS,
        f"sqlite3 {sqlite3.sqlite_version} — online backup API available")


def _snapshot_dirs(out_dir: Path, *, with_manifest: bool) -> list[Path]:
    return [
        d for d in out_dir.iterdir()
        if d.is_dir()
        and SNAPSHOT_NAME_RE.match(d.name)
        and (d / MANIFEST_NAME).is_file() == with_manifest
    ]


def _check_inflight(out_dir: Path) -> dict:
    name = "no-inflight-snapshot"
    try:
        if not out_dir.is_dir():
            return _result(name, PASS, "no backups dir yet")
        stale = sorted(d.name for d in _snapshot_dirs(
            out_dir, with_manifest=False))
    except OSError as exc:
        return _result(name, UNKNOWN, f"cannot scan {out_dir}: {exc}")
    if not stale:
        return _result(name, PASS, "none found")
    names = ", ".join(stale[:3]) + ("…" if len(stale) > 3 else "")
    return _result(
        name, FAIL,
        f"{names}: timestamp dir without manifest.json — a create is "
        "running or crashed; let it finish or remove the dir")


def _check_latest(out_dir: Path) -> dict:
    name = "latest-snapshot"
    try:
        if not out_dir.is_dir():
            return _result(name, PASS,
                           "no previous snapshot — first backup")
        snaps = sorted(_snapshot_dirs(out_dir, with_manifest=True))
    except OSError as exc:
        return _result(name, UNKNOWN, f"cannot scan {out_dir}: {exc}")
    if not snaps:
        return _result(name, PASS, "no previous snapshot — first backup")
    newest = snaps[-1]
    try:
        load_manifest(newest)
    except SnapshotError as exc:
        return _result(
            name, FAIL,
            f"{newest.name}: {exc} — last backup may be corrupt")
    return _result(name, PASS, f"{newest.name} manifest readable")


def _check_remote(dest: str) -> dict:
    if _remote.is_remote_target(dest):
        name = "tool-rsync"
        rsync = shutil.which("rsync")
        if rsync:
            return _result(name, PASS, f"{rsync} — needed for ssh target")
        return _result(
            name, FAIL,
            f"ssh target {dest!r} needs rsync on PATH (posix); "
            "use a mounted path instead")
    name = "remote-dest"
    dest_path = Path(dest).expanduser()
    try:
        if not dest_path.is_dir():
            return _result(
                name, FAIL,
                f"{dest_path}: not a directory — mount/create it first "
                "(copy_to refuses otherwise)")
        err = _writable_probe(dest_path)
        if err:
            return _result(name, FAIL, f"{dest_path} not writable: {err}")
        return _result(name, PASS, f"writable: {dest_path}")
    except OSError as exc:
        return _result(name, UNKNOWN,
                       f"cannot evaluate {dest_path}: {exc}")


def run_preflight(
    data_dir: str | Path,
    out_dir: str | Path,
    *,
    config_dir: str | Path | None = None,
    config_dir_explicit: bool = False,
    remote: str | None = None,
    exclude: tuple[str, ...] = (),
    exclude_secrets: bool = False,
) -> dict:
    """Evaluate every precondition for a ``create`` run.

    Args mirror ``create``'s resolution: ``config_dir`` should already be
    the default config root when ``create`` would include one (no
    explicit ``--data-dir``), and ``config_dir_explicit`` marks a
    user-passed ``--config-dir`` (missing → fail instead of unknown).

    Returns ``{"ok", "checks", "summary", "data_dir", "config_dir",
    "out", "estimated_bytes"}``. ``ok`` is true only when every check
    passed — a check that cannot be evaluated is ``unknown``, never
    silently passed.
    """
    data_dir = Path(data_dir).expanduser()
    out_dir = Path(out_dir).expanduser()
    config = Path(config_dir).expanduser() if config_dir else None

    checks = [_check_data_root(data_dir)]
    if config is not None:
        checks.append(_check_config_root(config, config_dir_explicit))

    stores: list[Store] | None = None
    discovery_err: Exception | None = None
    try:
        stores = _kept_stores(
            data_dir, config, out_dir, exclude, exclude_secrets)
    except Exception as exc:  # noqa: BLE001 - discovery failure → unknown, not silent
        discovery_err = exc
    if stores is None:
        checks.append(_result(
            "stores-found", UNKNOWN,
            f"cannot evaluate: {discovery_err}"))
        estimated = None
    else:
        total, unreadable = _size_stores(stores)
        estimated = total
        if not stores:
            checks.append(_result(
                "stores-found", FAIL,
                "no Devin stores found — create would abort"))
        elif unreadable:
            checks.append(_result(
                "stores-found", FAIL,
                f"{unreadable}/{len(stores)} store(s) unreadable — "
                "copy would fail mid-snapshot"))
        else:
            checks.append(_result(
                "stores-found", PASS,
                f"{len(stores)} store(s), {total} B"))

    checks.append(_check_dest(out_dir))
    checks.append(_check_free_space(out_dir, estimated))
    checks.append(_check_sqlite())
    checks.append(_check_inflight(out_dir))
    checks.append(_check_latest(out_dir))
    if remote is not None:
        checks.append(_check_remote(remote))

    summary = {PASS: 0, FAIL: 0, UNKNOWN: 0}
    for c in checks:
        summary[c["status"]] += 1
    return {
        "data_dir": str(data_dir),
        "config_dir": str(config) if config else None,
        "out": str(out_dir),
        "estimated_bytes": estimated,
        "checks": checks,
        "ok": summary[FAIL] == 0 and summary[UNKNOWN] == 0,
        "summary": summary,
    }
