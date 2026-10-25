import json
import sys

from conftest import add_gui_session, add_session
from devin_janitor.cli import main
from devin_janitor.inventory import SessionRow
from devin_janitor.paths import DevinPaths
from devin_janitor.report import (
    append_log,
    audit_entry,
    fmt_bytes,
    plan_summary,
    render_space_report,
    space_report,
)
from devin_janitor.tiers import Classification


def _row(sid: str) -> SessionRow:
    return SessionRow(
        id=sid, origin="cli", title="t", project="/p",
        created=1_700_000_000.0, last_activity=1_700_000_000.0,
    )


def test_audit_entry_shape():
    e = audit_entry(
        deleted=[(_row("d1"), "empty")],
        judged_keep=[_row("k1")],
        judged_delete=[(_row("j1"), "judge: no durable knowledge (p=0.1)")],
        judge_name="none",
        judge_down=2,
        pending_locked=["p1"],
        orphan_locks_removed=3,
        vacuumed=True,
    )
    assert e["judge"] == "none"
    assert e["deleted"][0]["id"] == "d1"
    assert e["deleted"][0]["tier"] == "auto_delete"
    assert e["deleted"][0]["reason"] == "empty"
    assert e["judged_delete"][0]["judge_verdict"].startswith("judge:")
    assert e["judged_keep"] == ["k1"]
    assert e["judge_down"] == 2
    assert e["pending_locked"] == ["p1"]
    assert e["orphan_locks_removed"] == 3
    assert e["vacuumed"] is True
    assert isinstance(e["ts"], int)


def test_append_log_writes_jsonl(tmp_path):
    log = tmp_path / "sub" / "janitor-log.jsonl"
    append_log(log, {"ts": 1, "a": "é"})
    append_log(log, {"ts": 2})
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["a"] == "é"  # ensure_ascii=False


def test_plan_summary_marks_dry_run():
    c = Classification()
    c.kept["k"] = "substantive work"
    out = plan_summary(
        apply=False, total=1, grace_hours=48, classification=c,
        judged_keep=[], judged_delete=[], judge_down=0,
        targets=[(_row("t"), "empty")],
    )
    assert "DRY-RUN" in out and "dry-run" in out
    assert "t" in out and "empty" in out


def _by_name(rep):
    return {s["name"]: s for s in rep["stores"]}


def test_fmt_bytes():
    assert fmt_bytes(0) == "0 B"
    assert fmt_bytes(512) == "512 B"
    assert fmt_bytes(2048) == "2.0 KB"
    assert fmt_bytes(3 * 1024**2) == "3.0 MB"


def test_space_report_totals_and_recoverable(devin_dir, tmp_path):
    add_session(devin_dir.sessions_db, "noise-1", title="billing",
                user_msgs=1, tool_calls=1)
    add_session(devin_dir.sessions_db, "work-1", title="real feature work",
                user_msgs=50, tool_calls=40)
    add_gui_session(devin_dir.acp_messages_dir, "gui-noise", title="inbox")
    rep = space_report(devin_dir, devin_dir=tmp_path / "no-devin")
    stores = _by_name(rep)
    assert set(stores) == {
        "sessions.db", "acp-messages", "state.vscdb", "session_locks",
        ".devin",
    }
    sdb = stores["sessions.db"]
    assert sdb["exists"] and sdb["sessions"] == 2
    assert sdb["deletable_sessions"] == 1
    assert sdb["est_bytes_by_tier"]["auto_delete"] > 0
    assert sdb["est_bytes_by_tier"]["keep"] > 0
    acp = stores["acp-messages"]
    assert acp["files"] == 1 and acp["deletable_files"] == 1
    assert rep["totals"]["bytes"] > 0
    assert rep["totals"]["recoverable_bytes"] > 0
    cls = rep["classification"]
    assert cls == {"keep": 1, "auto_delete": 2, "judge": 0, "sessions": 3}
    assert sdb["oldest"] and sdb["newest"] and sdb["oldest"] <= sdb["newest"]


def test_space_report_sidecars_and_orphan_lock(devin_dir):
    add_session(devin_dir.sessions_db, "keep-1", title="real feature work",
                user_msgs=30, tool_calls=30)
    (devin_dir.sessions_db.parent / "sessions.db-wal").write_bytes(b"w" * 1234)
    (devin_dir.session_locks_dir / "dead.lock").write_bytes(b"dead!")
    (devin_dir.session_locks_dir / "keep-1.lock").write_bytes(b"live!!")
    rep = space_report(devin_dir)
    stores = _by_name(rep)
    sdb = stores["sessions.db"]
    # opening the store may materialize a -shm next to the fake wal
    assert sdb["sidecar_bytes"] >= 1234
    assert sdb["recoverable_bytes"] >= sdb["sidecar_bytes"]
    locks = stores["session_locks"]
    assert locks["locks"] == 2 and locks["orphan_locks"] == 1
    assert locks["recoverable_bytes"] == len(b"dead!")


def test_space_report_pending_and_leftover_sidecar(devin_dir):
    acp = devin_dir.acp_messages_dir
    (acp / "gone.db-wal").write_bytes(b"w" * 100)
    rep = space_report(devin_dir, extra_delete_ids={"gone"})
    acp_e = _by_name(rep)["acp-messages"]
    assert acp_e["recoverable_bytes"] == 100
    assert acp_e["unmanaged_bytes"] == 0

    rep = space_report(devin_dir)
    acp_e = _by_name(rep)["acp-messages"]
    assert acp_e["recoverable_bytes"] == 0
    assert acp_e["unmanaged_bytes"] == 100


def test_space_report_state_vscdb(devin_dir):
    from devin_internals.fixtures import create_state_vscdb

    db = create_state_vscdb(
        devin_dir.root / "User" / "globalStorage" / "state.vscdb"
    )
    rep = space_report(devin_dir)
    v = _by_name(rep)["state.vscdb"]
    assert v["exists"] and v["path"] == str(db)
    assert v["items"] == 4
    assert v["recoverable_bytes"] == 0


def test_space_report_missing_everything(tmp_path):
    rep = space_report(
        DevinPaths.from_root(tmp_path / "nope"),
        devin_dir=tmp_path / "nope-devin",
    )
    assert rep["totals"] == {"bytes": 0, "recoverable_bytes": 0}
    assert all(not s["exists"] for s in rep["stores"])
    assert rep["classification"] == {
        "keep": 0, "auto_delete": 0, "judge": 0, "sessions": 0,
    }


def test_space_report_bad_db_still_reports(tmp_path):
    root = tmp_path / "devin"
    (root / "cli").mkdir(parents=True)
    (root / "cli" / "sessions.db").write_bytes(b"not sqlite at all")
    rep = space_report(DevinPaths.from_root(root))
    assert rep["classification"] is None
    assert rep["classification_error"]
    sdb = _by_name(rep)["sessions.db"]
    assert sdb["bytes"] > 0
    assert sdb["recoverable_bytes"] == 0


def test_render_space_report(devin_dir):
    add_session(devin_dir.sessions_db, "n1", title="billing", user_msgs=1)
    out = render_space_report(space_report(devin_dir))
    assert "REPORT" in out and "recoverable" in out
    assert "sessions.db" in out and "state.vscdb" in out
    assert "auto_delete 1" in out


def test_report_cli_json(devin_dir, tmp_path, capsys):
    add_session(devin_dir.sessions_db, "noise-1", title="billing",
                user_msgs=1, tool_calls=1)
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--keep-file", str(tmp_path / "k.json"),
        "--pending-file", str(tmp_path / "p.json"),
        "--json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["totals"]["recoverable_bytes"] > 0
    assert payload["classification"]["auto_delete"] == 1


def test_report_cli_human_missing_store(devin_dir, tmp_path, capsys):
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--pending-file", str(tmp_path / "p.json"),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "REPORT" in out and "state.vscdb" in out and "missing" in out

    rc = main(["report", "--data-dir", str(tmp_path / "empty")])
    assert rc == 0
    assert "missing" in capsys.readouterr().out


def test_report_cli_writes_nothing(devin_dir, tmp_path):
    before = sorted(
        p.name for p in devin_dir.acp_messages_dir.iterdir()
    )
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--pending-file", str(tmp_path / "p.json"),
    ])
    assert rc == 0
    assert sorted(
        p.name for p in devin_dir.acp_messages_dir.iterdir()
    ) == before
    assert not (tmp_path / "p.json").exists()


def test_report_cli_judge_counts_judged_bytes(devin_dir, tmp_path, capsys):
    script = tmp_path / "judge.py"
    script.write_text(
        "import sys, json\n"
        "json.loads(sys.stdin.read())\n"
        'print(json.dumps({"keep": False}))\n',
        encoding="utf-8",
    )
    add_session(devin_dir.sessions_db, "ambig", title="odd little session",
                user_msgs=2, tool_calls=2)
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--pending-file", str(tmp_path / "p.json"),
        "--judge", f'command:"{sys.executable}" "{script}"',
        "--json",
    ])
    assert rc == 0
    sdb = _by_name(json.loads(capsys.readouterr().out))["sessions.db"]
    assert sdb["deletable_sessions"] == 1


def test_report_cli_bad_judge_spec(devin_dir, tmp_path):
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--pending-file", str(tmp_path / "p.json"),
        "--judge", "bogus",
    ])
    assert rc == 2
