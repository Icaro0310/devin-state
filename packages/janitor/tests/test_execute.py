import sqlite3

from conftest import add_gui_session, add_session
from devin_janitor.execute import (
    delete_gui_files,
    delete_session_rows,
    load_pending,
    remove_orphan_locks,
    retry_pending,
    save_pending,
    vacuum_if_safe,
)
from devin_janitor.inventory import load_inventory


def test_delete_session_rows_removes_everything(devin_dir):
    add_session(devin_dir.sessions_db, "s1", user_msgs=1, tool_calls=1)
    con = sqlite3.connect(str(devin_dir.sessions_db))
    assert delete_session_rows(con, "s1") is True
    con.commit()
    for table in ("sessions", "message_nodes", "tool_call_state"):
        n = con.execute(
            f"SELECT COUNT(*) FROM {table} WHERE session_id='s1'"
            if table != "sessions"
            else "SELECT COUNT(*) FROM sessions WHERE id='s1'"
        ).fetchone()[0]
        assert n == 0
    con.close()
    con = sqlite3.connect(str(devin_dir.sessions_db))
    assert delete_session_rows(con, "nope") is False
    con.close()


def test_delete_gui_files_removes_db_and_lock(devin_dir, tmp_path):
    acp = devin_dir.acp_messages_dir
    add_gui_session(acp, "g1")
    (acp / "g1.db-wal").write_text("x")
    (acp / "g1.lock").write_text("x")
    pending = {}
    assert delete_gui_files(acp, "g1", pending) is True
    assert not list(acp.glob("g1.*"))
    assert pending == {}


def test_delete_gui_files_locked_goes_pending(devin_dir):
    acp = devin_dir.acp_messages_dir
    # a directory named like the .db can't be removed by os.remove
    (acp / "g2.db").mkdir()
    pending = {}
    assert delete_gui_files(acp, "g2", pending) is False
    assert "g2" in pending


def test_retry_pending_clears_queue(devin_dir):
    acp = devin_dir.acp_messages_dir
    add_gui_session(acp, "g3")
    pending = {"g3": 1}
    retry_pending(acp, pending)
    assert pending == {}
    assert not (acp / "g3.db").exists()


def test_pending_roundtrip(tmp_path):
    f = tmp_path / "pending.json"
    assert load_pending(f) == {}
    save_pending(f, {"a": 1})
    assert load_pending(f) == {"a": 1}
    save_pending(f, {})
    assert not f.exists()
    f.write_text("not json")
    assert load_pending(f) == {}


def test_remove_orphan_locks(devin_dir):
    add_session(devin_dir.sessions_db, "live")
    locks = devin_dir.session_locks_dir
    (locks / "live.lock").write_text("")
    (locks / "dead.lock").write_text("")
    removed = remove_orphan_locks(devin_dir, {"live"})
    assert removed == 1
    assert (locks / "live.lock").exists()
    assert not (locks / "dead.lock").exists()


def test_vacuum_skipped_when_locks_present(devin_dir):
    (devin_dir.session_locks_dir / "x.lock").write_text("")
    assert vacuum_if_safe(devin_dir, running=False) is False


def test_vacuum_skipped_when_devin_running(devin_dir):
    assert vacuum_if_safe(devin_dir, running=True) is False


def test_vacuum_runs_when_closed_and_unlocked(devin_dir):
    add_session(devin_dir.sessions_db, "s1")
    assert vacuum_if_safe(devin_dir, running=False) is True
    # db still readable after vacuum
    assert len(load_inventory(devin_dir)) == 1
