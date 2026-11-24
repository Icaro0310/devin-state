"""Discovery of Devin's local stores under their platform-specific roots.

Known store patterns (see devin-internals-spec ``docs/SPEC.md``)::

    <data-dir>/cli/sessions.db                  session metadata + message tree
    <config-dir>/User/acp-messages/*.db         per-session ACP message logs
    <config-dir>/User/globalStorage/state.vscdb editor/workbench state
    <data-dir>/.devin/**                        user config (skills, memory, ...)

``*.db``/``*.vscdb`` files are treated as SQLite and copied through the
SQLite backup API; everything under ``.devin/`` is a plain file copy.
SQLite sidecars (``-wal``/``-shm``/``-journal``) are never copied directly —
``Connection.backup()`` already produces a consistent standalone file.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SQLITE_SUFFIXES = {".db", ".vscdb"}
SQLITE_SIDECAR_SUFFIXES = {".db-wal", ".db-shm", ".db-journal",
                           ".vscdb-wal", ".vscdb-shm", ".vscdb-journal"}
CONFIG_DIR_NAME = ".devin"
MANIFEST_NAME = "manifest.json"
PRE_RESTORE_PREFIX = "pre-restore-"
# ``pre-restore-<YYYYMMDDTHHMMSSZ>`` plus the ``-N`` collision suffix
# ``_unique_dir`` appends — the exact on-disk shape restore produces.
_PRE_RESTORE_DIR_RE = re.compile(
    rf"^{PRE_RESTORE_PREFIX}\d{{8}}T\d{{6}}Z(-\d+)?$"
)


class DataDirError(RuntimeError):
    """The data directory does not exist or is not a directory."""


@dataclass(frozen=True)
class Store:
    """A file worth snapshotting."""

    path: Path
    """Absolute source path."""
    rel_path: str
    """POSIX-style path relative to its source root (manifest key)."""
    kind: str
    """``"sqlite"`` (backup API) or ``"file"`` (plain copy)."""
    root: str = "data"
    """Source root label: ``data`` or ``config``."""


def default_data_dir(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> Path:
    """Best-effort location of Devin's session data root."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    override = env.get("DEVIN_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if plat == "nt" or plat.startswith("win"):
        appdata = env.get("APPDATA")
        if appdata:
            return Path(appdata) / "devin"
        return Path.home() / "AppData" / "Roaming" / "devin"
    if plat == "darwin":
        return Path.home() / "Library" / "Application Support" / "devin"
    data_home = Path(env.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    config_home = Path(env.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    candidates = [data_home / "devin", config_home / "devin", Path.home() / "devin"]
    return next(
        (root for root in candidates if (root / "cli" / "sessions.db").is_file()),
        candidates[0],
    )


def default_config_dir(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> Path:
    """Best-effort location of Devin Desktop's UI/config stores."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    override = env.get("DEVIN_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    if plat == "nt" or plat.startswith("win"):
        appdata = env.get("APPDATA")
        if appdata:
            return Path(appdata) / "Devin"
        return Path.home() / "AppData" / "Roaming" / "Devin"
    if plat == "darwin":
        return Path.home() / "Library" / "Application Support" / "devin"
    config_home = Path(env.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    candidates = [config_home / "Devin", config_home / "devin"]
    return next(
        (root for root in candidates if (root / "User").is_dir()),
        candidates[0],
    )


def default_backups_dir(data_dir: str | Path) -> Path:
    """``<data-dir>/backups`` — overridable via ``DEVIN_BACKUP_DIR``."""
    env = os.environ.get("DEVIN_BACKUP_DIR")
    if env:
        return Path(env).expanduser()
    return Path(data_dir) / "backups"


def is_sqlite_store(path: Path) -> bool:
    return path.suffix.lower() in SQLITE_SUFFIXES


def _is_under(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _pre_restore_dir_names(root: Path) -> set[str]:
    """Names of top-level dirs that are genuine ``pre-restore`` backups.

    A dir qualifies only when its name matches the full
    ``pre-restore-<timestamp>[-N]`` format *and* its manifest declares
    ``kind: pre-restore`` — a user folder merely sharing the prefix
    (``pre-restore-validation/`` etc.) keeps its stores in backups.
    """
    names: set[str] = set()
    try:
        children = list(root.iterdir())
    except OSError:
        return names
    for child in children:
        if not child.is_dir() or _PRE_RESTORE_DIR_RE.match(child.name) is None:
            continue
        try:
            manifest = json.loads(
                (child / MANIFEST_NAME).read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(manifest, dict) and manifest.get("kind") == "pre-restore":
            names.add(child.name)
    return names


def _discover_root(
    root: Path, root_name: str, excluded: list[Path]
) -> list[Store]:
    stores: list[Store] = []
    pre_restore = _pre_restore_dir_names(root)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        resolved = path.resolve()
        if any(_is_under(resolved, directory) for directory in excluded):
            continue
        rel_root = path.relative_to(root)
        # ``pre-restore-<ts>/`` safety backups can land inside the data
        # root itself when a restore runs on read-only media — they are
        # artifacts of ours, never live stores, so discovery skips them.
        if len(rel_root.parts) > 1 and rel_root.parts[0] in pre_restore:
            continue
        rel = rel_root.as_posix()
        if path.suffix.lower() in SQLITE_SIDECAR_SUFFIXES or path.name.endswith(
            ("-wal", "-shm", "-journal")
        ):
            continue
        if is_sqlite_store(path):
            stores.append(Store(path=path, rel_path=rel, kind="sqlite", root=root_name))
        elif rel_root.parts[0] == CONFIG_DIR_NAME:
            stores.append(Store(path=path, rel_path=rel, kind="file", root=root_name))
    return stores


def discover_stores(
    data_dir: str | Path,
    *,
    config_dir: str | Path | None = None,
    exclude: list[str | Path] | None = None,
) -> list[Store]:
    """Find snapshot-worthy files under the data root and optional config root.

    Args:
        data_dir: Devin session-data directory.
        config_dir: separate Devin Desktop UI/config directory, used on Linux.
        exclude: directories to skip (e.g. the backups dir itself).

    Raises:
        DataDirError: ``data_dir`` does not exist or is not a directory.
    """
    data_root = Path(data_dir).expanduser()
    if not data_root.is_dir():
        raise DataDirError(f"{data_root}: not a directory")
    excluded = [Path(e).expanduser().resolve() for e in (exclude or [])]
    stores = _discover_root(data_root, "data", excluded)
    if config_dir is not None:
        config_root = Path(config_dir).expanduser()
        if not config_root.is_dir():
            return stores
        if os.path.normcase(str(config_root.resolve())) != os.path.normcase(
            str(data_root.resolve())
        ):
            stores.extend(_discover_root(config_root, "config", excluded))
    return stores
