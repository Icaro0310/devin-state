"""devin-redact as an MCP server: the ``scan`` report exposed as a tool.

Two read-only tools: ``redact_scan`` scans files or a sessions.db for
secrets/PII and returns the same JSON report as ``devin-redact scan``;
``redact_verify_publish`` cross-references an export with its verdicts.
Read-only by design: the redaction engine's ``redact --apply`` path is a destructive,
human-confirmed operation and is deliberately NOT exposed here — an MCP
client can detect and report findings, never rewrite a store.

The logic lives in :func:`do_scan`, unit-testable without a running
server or the ``mcp`` package. ``build_server()`` wraps it — needs the
``mcp`` extra: ``pip install 'devin-redact[mcp]'``.
"""

from __future__ import annotations

from pathlib import Path

from devin_redact import engine, paths, publish


def do_scan(
    scan_paths: list[str] | None = None,
    sessions_db: str = "",
    session_id: str = "",
) -> dict:
    """Scan targets and return the ``scan --json`` report as a dict.

    ``session_id`` scopes the scan to one session's rows in a
    sessions.db (explicit ``sessions_db``, first ``scan_paths`` entry or
    auto-detected). Without it, ``scan_paths`` are scanned; with neither,
    the default sessions.db is the target — the same auto-detect the CLI
    hooks use.
    """
    if session_id:
        if sessions_db:
            db = Path(sessions_db).expanduser()
        elif scan_paths:
            db = Path(scan_paths[0]).expanduser()
        else:
            db = paths.default_sessions_db()
        if db is None or not db.is_file():
            return {"error": "no_store",
                    "detail": f"sessions.db not found: {db}"}
        if engine.session_exists(db, session_id) is False:
            return {"error": "no_session",
                    "detail": f"session {session_id!r} not found in {db}"}
        return engine.scan_session(db, session_id)

    targets = [Path(p).expanduser() for p in (scan_paths or [])]
    if not targets:
        db = Path(sessions_db).expanduser() if sessions_db else (
            paths.default_sessions_db())
        if db is None or not db.is_file():
            return {"error": "no_store",
                    "detail": f"sessions.db not found: {db} "
                    "(pass scan_paths or sessions_db)"}
        targets = [db]
    missing = [str(p) for p in targets if not p.exists()]
    existing = [p for p in targets if p.exists()]
    if not existing:
        return {"error": "no_targets",
                "detail": "none of the scan targets exist",
                "missing_paths": missing}
    report = engine.scan(existing)
    if missing:
        report["missing_paths"] = missing
    return report


def do_verify(export_dir: str, verdicts_dir: str = "") -> dict:
    """Cross-reference a store export with its redaction verdicts —
    ``publish.verify_publish`` semantics. Read-only."""
    ed = Path(export_dir).expanduser()
    if not ed.is_dir():
        return {"error": "no_export_dir",
                "detail": f"not a directory: {ed}"}
    vd = Path(verdicts_dir).expanduser() if verdicts_dir else None
    return publish.verify_publish(ed, verdicts_dir=vd)


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
            "pip install 'devin-redact[mcp]'"
        ) from e


def build_server():
    """Build the MCP server app with every devin-redact tool registered."""
    server = _make_app("devin-redact")

    @server.tool()
    def redact_scan(
        scan_paths: list[str] | None = None,
        sessions_db: str = "",
        session_id: str = "",
    ) -> dict:
        """Scan files or a sessions.db for secrets and PII (tokens, keys,
        emails, absolute paths, project names) and return the same JSON
        report as ``devin-redact scan``: findings per file/location with
        category and fingerprint, plus publication_status CLEAN / REVIEW /
        BLOCKED. Read-only — never modifies the store; applying redactions
        stays a human CLI action (``devin-redact redact --apply``).
        """
        try:
            return do_scan(
                scan_paths=scan_paths,
                sessions_db=sessions_db,
                session_id=session_id,
            )
        except Exception as error:  # noqa: BLE001 — tool boundary must not raise
            return _err(error)

    @server.tool()
    def redact_verify_publish(export_dir: str, verdicts_dir: str = "") -> dict:
        """Verify a store export against its redaction verdicts — the same
        result as ``devin-redact verify``. Read-only — reports whether the
        export is safe to publish, never rewrites anything.
        """
        try:
            return do_verify(export_dir, verdicts_dir)
        except Exception as error:  # noqa: BLE001 — tool boundary must not raise
            return _err(error)

    return server


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
