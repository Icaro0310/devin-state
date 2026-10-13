"""MCP adapter contract: do_scan mirrors `scan --json`; the tool layer
exposes scan only — no mutation surface exists to call."""

from pathlib import Path
import tomllib

import pytest

from devin_redact.mcp_server import do_scan

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = [
    FIXTURES / "sessions.db",
    FIXTURES / "memories.jsonl",
    FIXTURES / "export.md",
    FIXTURES / ".env",
]
BENIGN = FIXTURES / "benign.txt"


def test_do_scan_matches_engine_scan():
    from devin_redact import scan

    assert do_scan(scan_paths=[str(p) for p in CORPUS]) == scan(CORPUS)


def test_do_scan_reports_findings_and_status():
    out = do_scan(scan_paths=[str(p) for p in CORPUS])
    assert out["tool"] == "devin-redact"
    assert out["files_scanned"] == len(CORPUS)
    assert out["findings_total"] > 0
    assert out["publication_status"] in {"CLEAN", "REVIEW", "BLOCKED"}


def test_do_scan_clean_file():
    out = do_scan(scan_paths=[str(BENIGN)])
    assert out["publication_status"] == "CLEAN"
    assert out["findings_total"] == 0


def test_do_scan_session_scope():
    out = do_scan(
        sessions_db=str(FIXTURES / "sessions.db"),
        session_id="fixture-session-0001",
    )
    assert out["session_id"] == "fixture-session-0001"
    assert out["files_scanned"] == 1
    assert "publication_status" in out


def test_do_scan_session_missing_db_is_error(tmp_path):
    out = do_scan(
        sessions_db=str(tmp_path / "nope.db"), session_id="anything")
    assert out["error"] == "no_store"


def test_do_scan_session_db_via_scan_paths():
    out = do_scan(
        scan_paths=[str(FIXTURES / "sessions.db")],
        session_id="fixture-session-0001",
    )
    assert out["session_id"] == "fixture-session-0001"


def test_do_scan_session_unknown_is_error():
    out = do_scan(
        sessions_db=str(FIXTURES / "sessions.db"),
        session_id="no-such-session",
    )
    assert out["error"] == "no_session"


def test_do_scan_missing_targets_is_error(tmp_path):
    out = do_scan(scan_paths=[str(tmp_path / "gone.txt")])
    assert out["error"] == "no_targets"
    assert out["missing_paths"]


def test_do_scan_partial_missing_surfaces(tmp_path):
    out = do_scan(
        scan_paths=[str(BENIGN), str(tmp_path / "gone.txt")])
    assert out["missing_paths"]
    assert out["files_scanned"] == 1


def test_do_verify_missing_dir_is_error(tmp_path):
    from devin_redact.mcp_server import do_verify
    out = do_verify(str(tmp_path / "nope"))
    assert out["error"] == "no_export_dir"


def test_server_exposes_scan_only():
    """The module must not reference the mutation path at all."""
    src = (Path(__file__).parents[1] / "src" / "devin_redact"
           / "mcp_server.py").read_text(encoding="utf-8")
    assert "engine.redact" not in src
    assert "confirm_irreversible" not in src


def test_server_entrypoint_in_pyproject():
    meta = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"))
    assert (meta["project"]["scripts"]["devin-redact-mcp"]
            == "devin_redact.mcp_server:main")
    assert any(dep.startswith("mcp") for dep in
               meta["project"]["optional-dependencies"]["mcp"])


def test_build_server_registers_tool():
    pytest.importorskip("mcp")
    from devin_redact.mcp_server import build_server

    server = build_server()
    mgr = getattr(server, "_tool_manager", None) or getattr(
        server, "tools", None)
    assert mgr is not None
    tools = getattr(mgr, "_tools", mgr)
    if isinstance(tools, dict):
        assert set(tools) == {"redact_scan", "redact_verify_publish"}


def _registered_tool_names() -> set[str]:
    """Tools the MCP server registers — derived statically so this test
    runs without the optional ``mcp`` extra installed."""
    import ast
    from pathlib import Path

    src = (
        Path(__file__).parents[1] / "src" / "devin_redact" / "mcp_server.py"
    )
    tree = ast.parse(src.read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            isinstance(dec, ast.Call)
            and isinstance(dec.func, ast.Attribute)
            and dec.func.attr == "tool"
            for dec in node.decorator_list
        )
    }


def test_mcp_tool_surface_is_pinned():
    """Regression contract: the AI surface is exactly this set. Static by
    design so it runs without the ``mcp`` extra; the runtime registry is
    pinned separately by test_build_server_registers_tool. A new tool
    only lands after a deliberate edit here — check it stays read-only
    before widening."""
    assert _registered_tool_names() == {"redact_scan","redact_verify_publish"}
