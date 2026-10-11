"""devin-janitor as an MCP server: the advisory surface only.

Two tools — ``janitor_dry_run`` and ``janitor_classify`` — answer "what
could be reclaimed?" and "which tier does each session fall in?" with
the same payloads the CLI's ``report --json`` / ``scan --json`` print.
Read-only by design: removing sessions, touching locks or stores, and
scheduling jobs are human-confirmed operations and are deliberately
NOT exposed here — an MCP client can report, never remove.

The logic lives in the ``do_*`` functions, unit-testable without a
running server or the ``mcp`` package. ``build_server()`` wraps them —
needs the ``mcp`` extra: ``pip install 'devin-janitor[mcp]'``.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from devin_janitor.config import JanitorConfig
from devin_janitor.execute import load_pending
from devin_janitor.inventory import load_inventory
from devin_janitor.paths import resolve
from devin_janitor.report import space_report
from devin_janitor.tiers import classify, load_keep_file

DEFAULT_KEEP_FILE = ".devin/janitor-keep.json"
DEFAULT_PENDING_FILE = ".devin/janitor-pending.json"


def _resolve_paths(
    data_dir: str = "",
    config_dir: str = "",
    sessions_db: str = "",
    acp_dir: str = "",
    locks_dir: str = "",
):
    """Empty strings resolve to the same platform defaults as the CLI."""
    return resolve(
        data_dir=data_dir or None,
        config_dir=config_dir or None,
        sessions_db=sessions_db or None,
        acp_messages_dir=acp_dir or None,
        session_locks_dir=locks_dir or None,
    )


def _cfg(config: str, keep_file: str):
    cfg = JanitorConfig.load(Path(config).expanduser() if config else None)
    keep_ids, keep_patterns = load_keep_file(
        Path(keep_file).expanduser() if keep_file else DEFAULT_KEEP_FILE
    )
    return cfg, keep_ids, keep_patterns


def _row_json(row, tier: str, reason: str) -> dict:
    d = asdict(row)
    d["tier"] = tier
    d["reason"] = reason
    return d


def do_dry_run(
    data_dir: str = "",
    config_dir: str = "",
    sessions_db: str = "",
    acp_dir: str = "",
    locks_dir: str = "",
    config: str = "",
    keep_file: str = "",
    pending_file: str = "",
    labels_file: str = "",
    exclude_labeled: bool = False,
) -> dict:
    """The ``report --json`` payload: advisory recoverable-space scan.

    Returns ``{"generated_at", "data_root", "classification",
    "stores", "cleanup_tiers", "automatic_sessions", "totals"}`` —
    per-store bytes and recoverable_bytes, tier summaries and totals.
    Reads everything, writes nothing. Like the CLI's ``report``
    (advisory — must never fail), an unreadable store degrades to
    ``classification: null`` + ``classification_error`` instead of
    raising.
    """
    paths = _resolve_paths(data_dir, config_dir, sessions_db, acp_dir, locks_dir)
    cfg, keep_ids, keep_patterns = _cfg(config, keep_file)
    pending = load_pending(
        Path(pending_file).expanduser() if pending_file
        else DEFAULT_PENDING_FILE
    )
    try:
        return space_report(
            paths,
            cfg,
            keep_ids=keep_ids,
            keep_patterns=keep_patterns,
            extra_delete_ids=set(pending),
            labels_path=Path(labels_file).expanduser()
            if labels_file else None,
            exclude_labeled=exclude_labeled,
        )
    except Exception as exc:  # noqa: BLE001 — advisory, same as the CLI
        return {
            "stores": [],
            "totals": {"bytes": 0, "recoverable_bytes": 0},
            "classification": None,
            "classification_error": str(exc),
        }


def do_classify(
    data_dir: str = "",
    config_dir: str = "",
    sessions_db: str = "",
    acp_dir: str = "",
    locks_dir: str = "",
    config: str = "",
    keep_file: str = "",
) -> dict:
    """The ``scan --json`` payload: per-session tier assignment.

    Returns ``{"total", "tiers": {"keep", "auto_delete", "judge":
    {"delete", "keep", "unresolved"}}}`` — every session lands in
    exactly one tier, with the reason it was kept or flagged. Like the
    CLI's ``scan`` (which never runs a judge either), the judge tiers
    stay empty and every ambiguous session lands in ``unresolved`` —
    judging is a pluggable advisory step, out of scope here.
    """
    paths = _resolve_paths(data_dir, config_dir, sessions_db, acp_dir, locks_dir)
    cfg, keep_ids, keep_patterns = _cfg(config, keep_file)
    rows = load_inventory(paths)
    classification = classify(
        rows, cfg, keep_ids=keep_ids, keep_patterns=keep_patterns
    )
    kept_ids = set(classification.kept)
    return {
        "total": len(rows),
        "tiers": {
            "keep": [
                _row_json(r, "keep", classification.kept[r.id])
                for r in rows
                if r.id in kept_ids
            ],
            "auto_delete": [
                _row_json(r, "auto_delete", why)
                for r, why in classification.auto_delete
            ],
            "judge": {
                "delete": [],
                "keep": [],
                "unresolved": [
                    _row_json(r, "judge", "judge unavailable")
                    for r in classification.judge
                ],
            },
        },
    }


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
            "pip install 'devin-janitor[mcp]'"
        ) from e


def build_server():
    """Build the MCP server app with every devin-janitor tool registered."""
    server = _make_app("devin-janitor")

    @server.tool()
    def janitor_dry_run(
        data_dir: str = "",
        config_dir: str = "",
        sessions_db: str = "",
        acp_dir: str = "",
        locks_dir: str = "",
        config: str = "",
        keep_file: str = "",
        pending_file: str = "",
        labels_file: str = "",
        exclude_labeled: bool = False,
    ) -> dict:
        """Recoverable-space report across every store the janitor
        manages. Read-only advisory — returns {classification, stores[],
        cleanup_tiers, automatic_sessions, totals} where totals carries
        bytes and recoverable_bytes. Removal stays a human decision;
        this tool only ever reports.
        """
        try:
            return do_dry_run(
                data_dir=data_dir,
                config_dir=config_dir,
                sessions_db=sessions_db,
                acp_dir=acp_dir,
                locks_dir=locks_dir,
                config=config,
                keep_file=keep_file,
                pending_file=pending_file,
                labels_file=labels_file,
                exclude_labeled=exclude_labeled,
            )
        except Exception as error:  # noqa: BLE001 — tool boundary must not raise
            return _err(error)

    @server.tool()
    def janitor_classify(
        data_dir: str = "",
        config_dir: str = "",
        sessions_db: str = "",
        acp_dir: str = "",
        locks_dir: str = "",
        config: str = "",
        keep_file: str = "",
    ) -> dict:
        """Tier every known session: keep / auto_delete / judge.
        Read-only — returns {total, tiers} with each session's id,
        origin, title, tier and reason. Ambiguous sessions come back as
        judge/unresolved; nothing is removed or queued.
        """
        try:
            return do_classify(
                data_dir=data_dir,
                config_dir=config_dir,
                sessions_db=sessions_db,
                acp_dir=acp_dir,
                locks_dir=locks_dir,
                config=config,
                keep_file=keep_file,
            )
        except Exception as error:  # noqa: BLE001 — tool boundary must not raise
            return _err(error)

    return server


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
