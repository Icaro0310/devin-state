"""devin-backup as an MCP server: the read-only snapshot surface.

Three tools — ``backup_verify``, ``backup_list``, ``backup_diff`` —
answer "is there a recent, intact backup and how stale is it?" with the
same reports the CLI prints. Read-only by design: writing snapshots,
pruning old ones and rolling data back are destructive, human-confirmed
operations and are deliberately NOT exposed here — an MCP client can
inspect and report, never change a store.

The logic lives in the ``do_*`` functions, unit-testable without a
running server or the ``mcp`` package. ``build_server()`` wraps them —
needs the ``mcp`` extra: ``pip install 'devin-backup[mcp]'``.
"""

from __future__ import annotations

from pathlib import Path

from devin_backup.diff import diff_snapshot
from devin_backup.rotate import list_snapshots
from devin_backup.stores import default_backups_dir, default_data_dir
from devin_backup.verify import verify_snapshot


def do_verify(snapshot_dir: str) -> dict:
    """Verify one snapshot against its manifest.

    Returns ``{"snapshot", "ok", "checked", "failed", "results"}`` — one
    result per manifest entry with exists/size/sha256/integrity checks.
    """
    return verify_snapshot(snapshot_dir)


def do_list(backups_dir: str = "") -> dict:
    """List snapshots under ``backups_dir``, newest first.

    Empty ``backups_dir`` resolves to the platform default
    (``<data-dir>/backups`` or ``DEVIN_BACKUP_DIR``). Returns
    ``{"backups_dir", "snapshots": [{name, path, kind, created_at,
    files, size, schema_versions}]}``.
    """
    root = (
        Path(backups_dir).expanduser()
        if backups_dir
        else default_backups_dir(default_data_dir())
    )
    return {"backups_dir": str(root), "snapshots": list_snapshots(root)}


def do_diff(snapshot_dir: str, data_dir: str = "", config_dir: str = "") -> dict:
    """Diff a snapshot against the live stores — read-only.

    Returns ``{"identical", "summary", "files", "live_only",
    "warnings"}``: per-file same/different/snapshot-only/live-only
    status (SQLite stores compare by logical content digest, not raw
    bytes) plus schema drift warnings. ``identical`` is true when there
    is no drift at all.
    """
    live = Path(data_dir).expanduser() if data_dir else default_data_dir()
    config = Path(config_dir).expanduser() if config_dir else None
    return diff_snapshot(snapshot_dir, live, config_dir=config)


def _err(error: Exception) -> dict:
    return {"error": type(error).__name__, "detail": str(error)[:500]}


def _make_app(name: str):
    """Return an MCP server app across SDK versions.

    mcp 2.x renamed FastMCP -> MCPServer; both expose the same .tool()
    decorator and .run(transport='stdio'). Support whichever is installed.
    """
    try:  # mcp 2.x
        from mcp.server.mcpserver import MCPServer
        return MCPServer(name)
    except ImportError:
        pass
    try:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP
        return FastMCP(name)
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "The MCP server needs the 'mcp' extra: "
            "pip install 'devin-backup[mcp]'"
        ) from e


def build_server():
    """Build the MCP server app with every devin-backup tool registered."""
    server = _make_app("devin-backup")

    @server.tool()
    def backup_verify(snapshot_dir: str) -> dict:
        """Check a snapshot's integrity against its manifest. Read-only —
        returns {snapshot, ok, checked, failed, results[]} where each
        result carries exists/size/sha256/integrity checks per file.
        """
        try:
            return do_verify(snapshot_dir)
        except Exception as error:  # noqa: BLE001 — tool boundary must not raise
            return _err(error)

    @server.tool()
    def backup_list(backups_dir: str = "") -> dict:
        """List known snapshots, newest first. Read-only — returns
        {backups_dir, snapshots[]} with name, kind, created_at, files,
        size and schema_versions per snapshot. Empty backups_dir uses
        the platform default location.
        """
        try:
            return do_list(backups_dir)
        except Exception as error:  # noqa: BLE001 — tool boundary must not raise
            return _err(error)

    @server.tool()
    def backup_diff(
        snapshot_dir: str, data_dir: str = "", config_dir: str = ""
    ) -> dict:
        """Compare a snapshot against the live Devin stores. Read-only —
        returns {identical, summary, files[], live_only, warnings}:
        which files are unchanged, changed, snapshot-only or live-only.
        """
        try:
            return do_diff(
                snapshot_dir, data_dir=data_dir, config_dir=config_dir
            )
        except Exception as error:  # noqa: BLE001 — tool boundary must not raise
            return _err(error)

    return server


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
