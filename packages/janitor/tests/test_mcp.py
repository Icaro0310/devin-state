"""MCP adapter contract: do_* output mirrors `report --json` /
`scan --json` on the synthetic fixtures; failures the CLI maps to
exit 2 surface as {error, detail} — the tools never raise, and the
module never touches the mutation surface (no apply, no vacuum, no
pending-queue, no scheduling).
"""

import json
from pathlib import Path

import pytest
import tomllib
from conftest import add_gui_session, add_session
from devin_janitor.mcp_server import _err, do_classify, do_dry_run


def _call(fn, *args, **kwargs):
    """Same exception -> {error, detail} mapping the tool layer applies."""
    try:
        return fn(*args, **kwargs)
    except Exception as error:  # noqa: BLE001
        return _err(error)


def _cli_json(capsys, argv):
    from devin_janitor.cli import main

    rc = main(argv)
    assert rc == 0
    return json.loads(capsys.readouterr().out)


@pytest.fixture()
def noisy_dir(devin_dir):
    """One deletable noise session + one keeper + one GUI noise store."""
    add_session(devin_dir.sessions_db, "noise-1", title="billing",
                user_msgs=1, tool_calls=1)
    add_session(devin_dir.sessions_db, "work-1",
                title="real feature work", user_msgs=50, tool_calls=40)
    add_gui_session(devin_dir.acp_messages_dir, "gui-noise", title="inbox")
    return devin_dir


def test_do_classify_matches_scan_json(noisy_dir, tmp_path, capsys):
    expected = _cli_json(capsys, [
        "scan", "--data-dir", str(noisy_dir.root),
        "--keep-file", str(tmp_path / "keep.json"), "--json"])
    out = do_classify(data_dir=str(noisy_dir.root),
                      keep_file=str(tmp_path / "keep.json"))
    assert out == expected


def test_do_classify_tiers(noisy_dir, tmp_path):
    out = do_classify(data_dir=str(noisy_dir.root),
                      keep_file=str(tmp_path / "keep.json"))
    assert out["total"] == 3
    tiers = out["tiers"]
    assert {r["id"] for r in tiers["auto_delete"]} == {
        "noise-1", "gui-noise"}
    assert {r["id"] for r in tiers["keep"]} == {"work-1"}
    # the advisory surface never runs a judge — ambiguous sessions only
    # ever land in unresolved, same as `scan --json`
    assert tiers["judge"]["delete"] == []
    assert tiers["judge"]["keep"] == []


def test_do_dry_run_matches_report_json(noisy_dir, tmp_path, capsys):
    expected = _cli_json(capsys, [
        "report", "--data-dir", str(noisy_dir.root),
        "--keep-file", str(tmp_path / "keep.json"),
        "--pending-file", str(tmp_path / "pending.json"), "--json"])
    out = do_dry_run(data_dir=str(noisy_dir.root),
                     keep_file=str(tmp_path / "keep.json"))
    assert isinstance(out["generated_at"], int)
    # wall-clock field — the only piece allowed to drift between calls
    out.pop("generated_at")
    expected.pop("generated_at")
    assert out == expected


def test_do_dry_run_defaults_load_bundled_keep_and_pending_files(
        noisy_dir, tmp_path, capsys, monkeypatch):
    """With no keep_file/pending_file args, DEFAULT_KEEP_FILE /
    DEFAULT_PENDING_FILE (relative to cwd) feed the report exactly as
    `report --json` resolves them — and they must change the result:
    the keep file protects the deletable noise session, the pending
    queue marks the keeper's bytes recoverable."""
    monkeypatch.chdir(tmp_path)
    dotdevin = tmp_path / ".devin"
    dotdevin.mkdir()
    (dotdevin / "janitor-keep.json").write_text(
        json.dumps({"ids": ["noise-1"]}), encoding="utf-8")
    (dotdevin / "janitor-pending.json").write_text(
        json.dumps({"work-1": 1_700_000_000}), encoding="utf-8")

    expected = _cli_json(capsys, [
        "report", "--data-dir", str(noisy_dir.root), "--json"])
    out = do_dry_run(data_dir=str(noisy_dir.root))
    out.pop("generated_at")
    expected.pop("generated_at")
    assert out == expected
    # both defaults bit: noise-1 kept (not deletable), work-1 queued
    sess = next(s for s in out["stores"] if s["name"] == "sessions.db")
    assert sess["deletable_sessions"] == 1  # only the queued work-1


def test_do_dry_run_unreadable_store_degrades_like_cli(devin_dir):
    """`report` is advisory and must never fail: a corrupt store yields
    the same degraded payload the CLI prints, not an exception."""
    devin_dir.sessions_db.write_bytes(b"not sqlite")
    out = do_dry_run(data_dir=str(devin_dir.root))
    assert out["classification"] is None
    assert out["classification_error"]
    assert out["totals"]["recoverable_bytes"] >= 0


def test_do_classify_bad_store_maps_to_error(devin_dir):
    """scan failures (CLI exit 2) surface as {error, detail} dicts."""
    devin_dir.sessions_db.write_bytes(b"not sqlite")
    out = _call(do_classify, data_dir=str(devin_dir.root))
    assert out["error"]
    assert out["detail"]


def test_module_never_touches_mutation_surface():
    """Read-only contract: no reference — not even an import — to the
    modules whose only purpose is to delete, retry, export or schedule.

    Exception: ``execute.load_pending`` is the read side of the pending
    retry queue — the CLI's ``report`` folds those ids into recoverable
    bytes, so the MCP surface imports it for parity. Every other symbol
    in ``execute`` (and the whole mutation path) stays banned.
    """
    src = (Path(__file__).parents[1] / "src" / "devin_janitor"
           / "mcp_server.py").read_text(encoding="utf-8")
    for mod in ("cleanup", "install", "exporter", "judge"):
        assert f"devin_janitor.{mod}" not in src
        assert f"devin_janitor import {mod}" not in src
    import re
    assert not re.search(
        r"devin_janitor\.execute import (?!load_pending\b)", src)
    for banned in ("--apply", "--yes", "vacuum", "save_pending",
                   "apply_tier", "apply_deletions", "restore"):
        assert banned not in src


def test_server_entrypoint_in_pyproject():
    meta = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"))
    assert (meta["project"]["scripts"]["devin-janitor-mcp"]
            == "devin_janitor.mcp_server:main")
    assert any(dep.startswith("mcp") for dep in
               meta["project"]["optional-dependencies"]["mcp"])


def test_build_server_registers_tools():
    pytest.importorskip("mcp")
    from devin_janitor.mcp_server import build_server
    assert build_server() is not None


def _registered_tool_names() -> set[str]:
    """Tools the MCP server registers — derived statically so this test
    runs without the optional ``mcp`` extra installed."""
    import ast
    from pathlib import Path

    src = (
        Path(__file__).parents[1] / "src" / "devin_janitor" / "mcp_server.py"
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
    """Regression contract: the AI surface is exactly this set. A new
    tool only lands after a deliberate edit here — check it stays
    read-only before widening."""
    assert _registered_tool_names() == {"janitor_classify","janitor_dry_run"}
