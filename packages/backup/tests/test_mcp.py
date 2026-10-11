"""MCP adapter contract: the do_* functions mirror the core reports and
the tool layer exposes the read-only trio only — no mutation surface
exists to call."""

from pathlib import Path

import pytest
import tomllib
from devin_backup import snapshot
from devin_backup.mcp_server import _err, do_diff, do_list, do_verify


def _call(fn, *args, **kwargs):
    """Same exception -> {error, detail} mapping the tool layer applies."""
    try:
        return fn(*args, **kwargs)
    except Exception as error:  # noqa: BLE001
        return _err(error)


def test_do_verify_matches_core(data_dir, backups_dir):
    from devin_backup.verify import verify_snapshot

    snap = snapshot.create_snapshot(data_dir, backups_dir)
    assert do_verify(str(snap)) == verify_snapshot(snap)


def test_do_verify_reports_ok(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    out = do_verify(str(snap))
    assert out["ok"] is True
    assert out["failed"] == 0
    assert out["checked"] == len(out["results"]) > 0


def test_verify_missing_manifest_maps_to_error(tmp_path):
    """A bad snapshot dir (CLI exit 2) surfaces as {error, detail}."""
    from devin_backup.snapshot import SnapshotError

    with pytest.raises(SnapshotError):
        do_verify(str(tmp_path / "nope"))
    out = _call(do_verify, str(tmp_path / "nope"))
    assert out["error"]
    assert out["detail"]


def test_do_list_finds_snapshot(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    out = do_list(str(backups_dir))
    assert out["backups_dir"] == str(backups_dir)
    assert [s["name"] for s in out["snapshots"]] == [snap.name]
    assert out["snapshots"][0]["kind"] == "snapshot"
    assert out["snapshots"][0]["files"] > 0


def test_do_list_empty_dir(tmp_path):
    out = do_list(str(tmp_path / "nothing"))
    assert out["snapshots"] == []


def test_do_diff_identical(data_dir, backups_dir):
    from devin_backup.diff import diff_snapshot

    snap = snapshot.create_snapshot(data_dir, backups_dir)
    assert do_diff(str(snap), str(data_dir)) == diff_snapshot(
        snap, data_dir
    )
    out = do_diff(str(snap), str(data_dir))
    assert out["identical"] is True
    assert out["live_only"] == []


def test_do_diff_detects_drift(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    cfg = data_dir / ".devin" / "config.json"
    cfg.write_bytes(b'{"synthetic": false}\n')
    out = do_diff(str(snap), str(data_dir))
    assert out["identical"] is False
    assert out["summary"]["different"] >= 1


def test_diff_bad_manifest_maps_to_error(tmp_path, data_dir):
    out = _call(do_diff, str(tmp_path / "nope"), str(data_dir))
    assert out["error"]
    assert out["detail"]


def test_server_exposes_read_only_trio():
    """The module must not reference any mutation path — not even an
    import of the modules whose only purpose is to write."""
    src = (Path(__file__).parents[1] / "src" / "devin_backup"
           / "mcp_server.py").read_text(encoding="utf-8")
    for banned in ("create_snapshot", "rotate_snapshots",
                   "restore_snapshot", "copy_to", "--apply", "--yes",
                   "devin_backup.snapshot", "devin_backup.restore",
                   "devin_backup.secondary", "devin_backup.install",
                   "devin_backup import install"):
        assert banned not in src


def test_server_entrypoint_in_pyproject():
    meta = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"))
    assert (meta["project"]["scripts"]["devin-backup-mcp"]
            == "devin_backup.mcp_server:main")
    assert any(dep.startswith("mcp") for dep in
               meta["project"]["optional-dependencies"]["mcp"])


def test_build_server_registers_tools():
    pytest.importorskip("mcp")
    from devin_backup.mcp_server import build_server
    assert build_server() is not None


def _registered_tool_names() -> set[str]:
    """Tools the MCP server registers — derived statically so this test
    runs without the optional ``mcp`` extra installed."""
    import ast
    from pathlib import Path

    src = (
        Path(__file__).parents[1] / "src" / "devin_backup" / "mcp_server.py"
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
    assert _registered_tool_names() == {"backup_diff","backup_list","backup_verify"}
