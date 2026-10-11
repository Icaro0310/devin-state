"""JA-1 install (F6 scheduling), JA-2 cleanup tiers, JA-4 automatic
sessions — extras on top of the core suite."""

import hashlib
import json
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from conftest import NOW_S, add_gui_session, add_session
from devin_install_scheduler import install as _sched
from devin_internals.fixtures import STATE_VSCDB_DDL
from devin_janitor import install
from devin_janitor.cleanup import (
    TOMBSTONE_PREFIX,
    CleanupRefused,
    apply_tier1,
    apply_tier3,
    gui_state_entries,
    parse_tiers,
    verify_snapshot,
    vscdb_path,
)
from devin_janitor.cli import main
from devin_janitor.labels import (
    automatic_sessions,
    bridge_state_dir,
    load_labels,
)
from devin_janitor.report import render_space_report, space_report


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_labels(path: Path, sessions: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "sessions": sessions}), encoding="utf-8"
    )
    return path


def _gui_key(backend: str, slug: str) -> str:
    return f"windsurfSpace.sessionWorkspace/{backend}/{slug}"


def _mk_vscdb(path: Path, entries: list[tuple[str, object]]) -> Path:
    """ItemTable store with controlled sessionWorkspace keys."""
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    with con:
        con.executescript(STATE_VSCDB_DDL)
        for key, value in entries:
            con.execute(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                (key, value if isinstance(value, str) else json.dumps(value)),
            )
    con.close()
    return path


def _mk_snapshot(tmp_path: Path, *, age_h: float = 1.0,
                 cover_vscdb: bool = True) -> Path:
    """A devin-backup-shaped snapshot dir: payload file + manifest.json."""
    snap = tmp_path / "snap"
    if cover_vscdb:
        rel = Path("config/User/globalStorage/state.vscdb")
        src_path = "User/globalStorage/state.vscdb"
    else:
        rel = Path("cli/sessions.db")
        src_path = "cli/sessions.db"
    target = snap / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"snapshot-bytes")
    created = datetime.now(timezone.utc) - timedelta(hours=age_h)
    manifest = {
        "manifest_version": 2,
        "tool": "devin-backup",
        "created_at": created.isoformat(timespec="seconds"),
        "files": [
            {
                "path": src_path,
                "snapshot_path": str(rel),
                "size": target.stat().st_size,
                "sha256": _sha(target),
            }
        ],
    }
    (snap / "manifest.json").write_text(json.dumps(manifest))
    return snap


# ------------------------------------------------------------- JA-1 install


def test_install_elapsed_writes_f6_registry(tmp_path):
    res = install.install_daily(config_dir=str(tmp_path / "cfg"),
                                backend="elapsed")
    assert res["backend"] == "elapsed"
    reg = json.loads(Path(res["registry"]).read_text())
    assert reg["version"] == 1
    job = reg["jobs"]["devin-janitor-daily"]
    assert "-m devin_janitor.cli report" in job["command"]
    assert "--apply" not in job["command"]  # never schedule deletion
    assert job["guarded_command"] == job["command"]
    assert job["interval_h"] == 24
    assert job["installed_at"] > 0 and job["last_run"] == 0


def test_install_bad_backend(tmp_path):
    with pytest.raises(ValueError):
        install.install_daily(config_dir=str(tmp_path), backend="bogus")


def test_install_cron_tagged_line(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(_sched.shutil, "which", lambda _c: "/usr/bin/crontab")

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(_sched.subprocess, "run", fake_run)
    res = install.install_daily(config_dir=str(tmp_path / "cfg"),
                                backend="cron")
    assert res["backend"] == "cron"
    stdin = calls[-1][1]["input"]
    assert "@daily" in stdin
    assert "# devin-ecosystem:devin-janitor-daily" in stdin
    assert "--apply" not in stdin


def test_install_cli(tmp_path, capsys):
    rc = main(["install", "--daily", "--backend", "elapsed",
               "--config-dir", str(tmp_path / "cfg")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "devin-janitor-daily" in out and "elapsed" in out

    rc = main(["install", "--daily", "--backend", "elapsed",
               "--config-dir", str(tmp_path / "cfg2"), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["job"] == "devin-janitor-daily"


def test_install_requires_daily_flag(tmp_path, capsys):
    rc = main(["install", "--backend", "elapsed",
               "--config-dir", str(tmp_path)])
    assert rc == 2
    assert "--daily" in capsys.readouterr().err
    assert not (tmp_path / ".devin-ecosystem").exists()


# ------------------------------------------------------------- JA-2 tiers --


def test_parse_tiers():
    assert parse_tiers(None) == {1, 2}
    assert parse_tiers("") == {1, 2}
    assert parse_tiers("3") == {3}
    assert parse_tiers("tier1,tier3") == {1, 3}
    assert parse_tiers("all") == {1, 2, 3}
    with pytest.raises(ValueError):
        parse_tiers("9")
    with pytest.raises(ValueError):
        parse_tiers("bogus")


def test_verify_snapshot_ok(tmp_path):
    snap = _mk_snapshot(tmp_path)
    res = verify_snapshot(snap)
    assert res["ok"] and res["checked"] == 1 and res["failed"] == 0
    # the manifest path itself also works
    assert verify_snapshot(snap / "manifest.json")["ok"]


def test_verify_snapshot_refuses(tmp_path):
    assert not verify_snapshot(None)["ok"]
    assert "no snapshot" in verify_snapshot(None)["reason"]

    missing = verify_snapshot(tmp_path / "nope")
    assert not missing["ok"] and "manifest" in missing["reason"]

    stale = verify_snapshot(_mk_snapshot(tmp_path / "a", age_h=25))
    assert not stale["ok"] and "old" in stale["reason"]

    uncovered = verify_snapshot(_mk_snapshot(tmp_path / "b",
                                           cover_vscdb=False))
    assert not uncovered["ok"] and "does not cover" in uncovered["reason"]

    tampered = _mk_snapshot(tmp_path / "d")
    f = tampered / "config" / "User" / "globalStorage" / "state.vscdb"
    f.write_bytes(b"tampered")
    res = verify_snapshot(tampered)
    assert not res["ok"] and "failed verification" in res["reason"]


def test_verify_snapshot_rejects_lookalike_filename(tmp_path):
    """`state.vscdb.old` must not satisfy tier-3 coverage."""
    snap = tmp_path / "snap"
    target = snap / "User" / "globalStorage" / "state.vscdb.old"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"old-bytes")
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (snap / "manifest.json").write_text(json.dumps({
        "manifest_version": 2,
        "tool": "devin-backup",
        "created_at": created,
        "files": [{
            "path": "User/globalStorage/state.vscdb.old",
            "snapshot_path": "User/globalStorage/state.vscdb.old",
            "size": target.stat().st_size,
            "sha256": _sha(target),
        }],
    }))
    res = verify_snapshot(snap)
    assert not res["ok"] and "does not cover" in res["reason"]


def test_verify_snapshot_custom_fragment_still_substring(tmp_path):
    """Custom fragments keep substring semantics; only the tier-3
    default is an exact filename match."""
    snap = _mk_snapshot(tmp_path)
    res = verify_snapshot(snap, required_fragment="globalStorage")
    assert res["ok"]


def test_gui_state_entries_staleness(tmp_path):
    db = _mk_vscdb(tmp_path / "state.vscdb", [
        (_gui_key("acp", "old"),
         {"lastUpdated": int((NOW_S - 90 * 86400) * 1000)}),
        (_gui_key("acp", "fresh"), {"lastUpdated": int(NOW_S * 1000)}),
        ("windsurfSpace.other/key", {"lastUpdated": 1}),
        (_gui_key("acp", "unparseable"), "not json"),
    ])
    entries = {e["key"]: e for e in
               gui_state_entries(db, stale_before=NOW_S - 48 * 3600)}
    # only sessionWorkspace keys are listed
    assert set(entries) == {
        _gui_key("acp", "old"), _gui_key("acp", "fresh"),
        _gui_key("acp", "unparseable"),
    }
    assert entries[_gui_key("acp", "old")]["stale"]
    assert not entries[_gui_key("acp", "fresh")]["stale"]
    assert entries[_gui_key("acp", "unparseable")]["stale"]


def test_apply_tier1_orphans_and_leftovers(devin_dir):
    db = devin_dir.sessions_db
    add_session(db, "live-1", title="real work", user_msgs=50)
    con = sqlite3.connect(str(db))
    with con:
        con.execute(
            "INSERT INTO message_nodes(session_id, node_id,"
            " parent_node_id, chat_message, created_at, metadata)"
            " VALUES ('ghost', 1, NULL, '{}', 1, NULL)"
        )
    con.close()
    acp = devin_dir.acp_messages_dir
    (acp / "dead.db-wal").write_bytes(b"x" * 10)
    (acp / "pend.db-wal").write_bytes(b"x" * 10)
    add_gui_session(acp, "live-gui")  # live-gui.db + sidecars stay
    (acp / "live-gui.db-wal").write_bytes(b"y")

    stats = apply_tier1(devin_dir, {"live-1", "live-gui"}, skip={"pend"})
    assert stats["orphan_rows"] == 1
    assert stats["leftover_files"] == 1 and stats["leftover_bytes"] == 10
    assert not (acp / "dead.db-wal").exists()
    assert (acp / "pend.db-wal").exists()      # pending queue owns it
    assert (acp / "live-gui.db-wal").exists()  # belongs to a live db
    con = sqlite3.connect(str(db))
    n = con.execute(
        "SELECT COUNT(*) FROM message_nodes WHERE session_id='ghost'"
    ).fetchone()[0]
    con.close()
    assert n == 0


def test_apply_tier3_gates(devin_dir, tmp_path):
    _mk_vscdb(vscdb_path(devin_dir), [
        (_gui_key("acp", "old"),
         {"lastUpdated": int((NOW_S - 90 * 86400) * 1000)}),
        (_gui_key("acp", "fresh"), {"lastUpdated": int(NOW_S * 1000)}),
    ])
    stale_before = NOW_S - 48 * 3600

    with pytest.raises(CleanupRefused, match="include-gui"):
        apply_tier3(devin_dir, stale_before=stale_before, running=False)
    with pytest.raises(CleanupRefused, match="no snapshot"):
        apply_tier3(devin_dir, stale_before=stale_before,
                    include_gui=True, running=False)
    with pytest.raises(CleanupRefused, match="state.vscdb"):
        apply_tier3(devin_dir, stale_before=stale_before, include_gui=True,
                    snapshot=_mk_snapshot(tmp_path / "unc",
                                          cover_vscdb=False),
                    running=False)
    with pytest.raises(CleanupRefused, match="running"):
        apply_tier3(devin_dir, stale_before=stale_before, include_gui=True,
                    snapshot=_mk_snapshot(tmp_path / "ok2"), running=True)


def test_apply_tier3_deletes_only_stale(devin_dir, tmp_path):
    vdb = _mk_vscdb(vscdb_path(devin_dir), [
        (_gui_key("acp", "old"),
         {"lastUpdated": int((NOW_S - 90 * 86400) * 1000)}),
        (_gui_key("acp", "fresh"), {"lastUpdated": int(NOW_S * 1000)}),
    ])
    snap = _mk_snapshot(tmp_path)
    stats = apply_tier3(devin_dir, stale_before=NOW_S - 48 * 3600,
                        include_gui=True, snapshot=snap, running=False)
    assert stats["keys"] == 1 and stats["bytes"] > 0
    assert stats["tombstoned"] == 1
    con = sqlite3.connect(str(vdb))
    rows = dict(con.execute("SELECT key, value FROM ItemTable"))
    con.close()
    stale_key = _gui_key("acp", "old")
    tomb_key = f"{TOMBSTONE_PREFIX}{stale_key}"
    assert stale_key not in rows
    assert _gui_key("acp", "fresh") in rows
    tomb = json.loads(rows[tomb_key])
    assert tomb["key"] == stale_key and tomb["slug"] == "old"
    assert tomb["backend"] == "acp" and tomb["tool"] == "devin-janitor"
    assert tomb["deleted_at"] > 0


def test_apply_tier3_tombstones_are_idempotent(devin_dir, tmp_path):
    """A second run sees no stale keys — tombstones are neither
    re-tombstoned nor treated as GUI session state."""
    vdb = _mk_vscdb(vscdb_path(devin_dir), [
        (_gui_key("acp", "old"),
         {"lastUpdated": int((NOW_S - 90 * 86400) * 1000)}),
    ])
    snap = _mk_snapshot(tmp_path)
    kw = dict(stale_before=NOW_S - 48 * 3600, include_gui=True,
              snapshot=snap, running=False)
    first = apply_tier3(devin_dir, **kw)
    assert first["tombstoned"] == 1
    second = apply_tier3(devin_dir, **kw)
    assert second["keys"] == 0 and second["tombstoned"] == 0
    con = sqlite3.connect(str(vdb))
    rows = list(con.execute("SELECT key FROM ItemTable"))
    con.close()
    assert rows == [(f"{TOMBSTONE_PREFIX}{_gui_key('acp', 'old')}",)]
    # tombstone markers are not picked up as stale GUI entries
    assert gui_state_entries(vdb, stale_before=NOW_S - 48 * 3600) == []


def test_report_cleanup_tiers(devin_dir):
    add_session(devin_dir.sessions_db, "noise-1", title="billing",
                user_msgs=1, tool_calls=1)
    _mk_vscdb(vscdb_path(devin_dir), [
        (_gui_key("acp", "old"),
         {"lastUpdated": int((NOW_S - 90 * 86400) * 1000)}),
    ])
    rep = space_report(devin_dir)
    tiers = rep["cleanup_tiers"]
    assert set(tiers) == {"tier1", "tier2", "tier3"}
    assert tiers["tier2"]["items"] >= 1 and tiers["tier2"]["bytes"] > 0
    assert tiers["tier3"]["items"] == 1 and tiers["tier3"]["gated"]
    out = render_space_report(rep)
    assert "cleanup tiers" in out and "tier3" in out and "gated" in out


def _run_args(devin_dir, tmp_path, *extra):
    return [
        "run",
        "--data-dir", str(devin_dir.root),
        "--keep-file", str(tmp_path / "keep.json"),
        "--pending-file", str(tmp_path / "pending.json"),
        "--log-file", str(tmp_path / "janitor-log.jsonl"),
        *extra,
    ]


def test_run_tier3_refused_without_gates(devin_dir, tmp_path, capsys):
    add_session(devin_dir.sessions_db, "n", title="billing", user_msgs=1)
    db_hash = _sha(devin_dir.sessions_db)
    rc = main(_run_args(devin_dir, tmp_path, "--apply", "--tiers", "3"))
    assert rc == 2
    assert "--include-gui" in capsys.readouterr().err

    rc = main(_run_args(devin_dir, tmp_path, "--apply", "--tiers", "3",
                        "--include-gui"))
    assert rc == 4
    assert "snapshot" in capsys.readouterr().err

    rc = main(_run_args(devin_dir, tmp_path, "--apply", "--tiers", "3",
                        "--include-gui", "--snapshot",
                        str(tmp_path / "nope")))
    assert rc == 4
    assert _sha(devin_dir.sessions_db) == db_hash  # nothing written


def test_run_tier3_full_gate_ok(devin_dir, tmp_path, monkeypatch):
    monkeypatch.setattr("devin_janitor.cli.devin_running", lambda: False)
    monkeypatch.setattr("devin_janitor.execute.devin_running",
                        lambda: False)
    _mk_vscdb(vscdb_path(devin_dir), [
        (_gui_key("acp", "old"),
         {"lastUpdated": int((NOW_S - 90 * 86400) * 1000)}),
    ])
    snap = _mk_snapshot(tmp_path)
    rc = main(_run_args(devin_dir, tmp_path, "--apply", "--tiers", "3",
                        "--include-gui", "--snapshot", str(snap)))
    assert rc == 0
    con = sqlite3.connect(str(vscdb_path(devin_dir)))
    keys = [r[0] for r in con.execute("SELECT key FROM ItemTable")]
    con.close()
    # the stale binding is gone; its tombstone marker remains
    assert keys == [f"{TOMBSTONE_PREFIX}{_gui_key('acp', 'old')}"]
    log = tmp_path / "janitor-log.jsonl"
    entry = json.loads(log.read_text().splitlines()[0])
    assert entry["tiers"] == [3] and entry["tier3"]["keys"] == 1


def test_run_tiers_restrict_scope(devin_dir, tmp_path, monkeypatch):
    monkeypatch.setattr("devin_janitor.cli.vacuum_if_safe",
                        lambda paths: False)
    add_session(devin_dir.sessions_db, "noise", title="billing",
                user_msgs=1, tool_calls=1)
    con = sqlite3.connect(str(devin_dir.sessions_db))
    with con:
        con.execute(
            "INSERT INTO message_nodes(session_id, node_id,"
            " parent_node_id, chat_message, created_at, metadata)"
            " VALUES ('ghost', 1, NULL, '{}', 1, NULL)"
        )
    con.close()

    # tier1 only: orphan row gone, the stale session is kept
    rc = main(_run_args(devin_dir, tmp_path, "--apply", "--tiers", "1"))
    assert rc == 0
    con = sqlite3.connect(str(devin_dir.sessions_db))
    ids = {r[0] for r in con.execute("SELECT id FROM sessions")}
    ghosts = con.execute(
        "SELECT COUNT(*) FROM message_nodes WHERE session_id='ghost'"
    ).fetchone()[0]
    con.close()
    assert ids == {"noise"} and ghosts == 0

    # tier2 only: session deleted, orphan locks NOT pruned (tier1's job)
    add_session(devin_dir.sessions_db, "noise2", title="billing",
                user_msgs=1)
    (devin_dir.session_locks_dir / "dead.lock").write_bytes(b"x")
    rc = main(_run_args(devin_dir, tmp_path, "--apply", "--tiers", "2"))
    assert rc == 0
    con = sqlite3.connect(str(devin_dir.sessions_db))
    ids = {r[0] for r in con.execute("SELECT id FROM sessions")}
    con.close()
    assert "noise2" not in ids
    assert (devin_dir.session_locks_dir / "dead.lock").exists()


def test_run_bad_tiers(devin_dir, tmp_path):
    assert main(_run_args(devin_dir, tmp_path, "--tiers", "bogus")) == 2


def test_run_tier3_only_without_sessions_db(tmp_path, capsys):
    # tier3 alone doesn't require sessions.db
    rc = main(["run", "--data-dir", str(tmp_path / "empty"),
               "--pending-file", str(tmp_path / "p.json"),
               "--keep-file", str(tmp_path / "k.json"),
               "--log-file", str(tmp_path / "l.jsonl"),
               "--tiers", "3"])
    assert rc == 0
    assert "tier3" in capsys.readouterr().out


# ------------------------------------------------- JA-4 automatic sessions


def test_bridge_state_dir_override():
    assert bridge_state_dir(
        {"DEVIN_BRIDGE_STATE_DIR": "/x/b"}, platform="linux"
    ) == Path("/x/b")
    assert bridge_state_dir(
        {"XDG_STATE_HOME": "/state"}, platform="linux"
    ) == Path("/state/devin-bridge")


def test_load_labels_fail_open(tmp_path):
    assert load_labels(tmp_path / "nope.json") == {}
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert load_labels(bad) == {}
    bad.write_text(json.dumps({"nope": 1}))
    assert load_labels(bad) == {}


def test_load_labels_roundtrip(tmp_path):
    f = _write_labels(tmp_path / "session-labels.json", {
        "s1": {"label": "bridge:digest", "origin": "bridge",
               "purpose": "digest", "createdAt": "2026-01-01T00:00:00Z"},
        "s2": {"origin": "bridge", "purpose": "scout"},  # label derived
        "s3": "junk",
    })
    labels = load_labels(f)
    assert labels["s1"]["label"] == "bridge:digest"
    assert labels["s2"]["label"] == "bridge:scout"  # synthesized
    assert "s3" not in labels  # non-dict entries are skipped


def test_automatic_sessions_marks_bridge_only():
    class Row:
        def __init__(self, sid):
            self.id, self.title, self.origin = sid, "t", "cli"
            self.last_activity = 1.0

    labels = {
        "a": {"label": "bridge:digest", "origin": "bridge",
              "purpose": "digest", "createdAt": None, "cwd": None},
        "b": {"label": "human:work", "origin": "human",
              "purpose": "work", "createdAt": None, "cwd": None},
    }
    auto = automatic_sessions([Row("a"), Row("b")], labels)
    assert [s["id"] for s in auto] == ["a"]
    assert auto[0]["label"] == "bridge:digest"


def test_report_automatic_sessions(devin_dir, tmp_path):
    add_session(devin_dir.sessions_db, "auto-1", title="billing",
                user_msgs=1)
    labels_f = _write_labels(tmp_path / "session-labels.json", {
        "auto-1": {"label": "bridge:digest", "origin": "bridge",
                   "purpose": "digest"},
        "ghost": {"label": "bridge:x", "origin": "bridge",
                  "purpose": "x"},  # not in inventory — not listed
    })
    rep = space_report(devin_dir, labels_path=labels_f)
    auto = rep["automatic_sessions"]
    assert auto["count"] == 1
    assert auto["sessions"][0]["id"] == "auto-1"
    assert auto["sessions"][0]["label"] == "bridge:digest"
    assert str(labels_f) == auto["labels_file"]
    out = render_space_report(rep)
    assert "automatic sessions: 1" in out and "bridge:digest" in out

    # missing sidecar → section present but empty, never fatal
    rep = space_report(devin_dir, labels_path=tmp_path / "none.json")
    assert rep["automatic_sessions"]["count"] == 0


def test_report_exclude_labeled(devin_dir, tmp_path):
    add_session(devin_dir.sessions_db, "auto-1", title="billing",
                user_msgs=1)
    labels_f = _write_labels(tmp_path / "session-labels.json", {
        "auto-1": {"label": "bridge:digest", "origin": "bridge",
                   "purpose": "digest"},
    })
    rep = space_report(devin_dir, labels_path=labels_f)
    assert rep["classification"]["auto_delete"] == 1

    rep = space_report(devin_dir, labels_path=labels_f,
                       exclude_labeled=True)
    assert rep["classification"]["auto_delete"] == 0
    auto = rep["automatic_sessions"]
    assert auto["count"] == 1 and auto["excluded_from_classification"]
    out = render_space_report(rep)
    assert "excluded from classification" in out


def test_report_cli_labels(devin_dir, tmp_path, capsys):
    add_session(devin_dir.sessions_db, "auto-1", title="billing",
                user_msgs=1)
    labels_f = _write_labels(tmp_path / "session-labels.json", {
        "auto-1": {"label": "bridge:digest", "origin": "bridge",
                   "purpose": "digest"},
    })
    rc = main(["report", "--data-dir", str(devin_dir.root),
               "--pending-file", str(tmp_path / "p.json"),
               "--keep-file", str(tmp_path / "k.json"),
               "--labels-file", str(labels_f), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["automatic_sessions"]["count"] == 1

    rc = main(["report", "--data-dir", str(devin_dir.root),
               "--pending-file", str(tmp_path / "p.json"),
               "--keep-file", str(tmp_path / "k.json"),
               "--labels-file", str(labels_f), "--exclude-labeled",
               "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["classification"]["auto_delete"] == 0
    assert payload["automatic_sessions"]["excluded_from_classification"]
