import hashlib
import json
import sqlite3
import sys

import pytest
from conftest import add_gui_session, add_session
from devin_janitor.cli import main


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scan_args(devin_dir, tmp_path, *extra):
    return [
        "scan",
        "--data-dir", str(devin_dir.root),
        "--keep-file", str(tmp_path / "keep.json"),
        *extra,
    ]


def _run_args(devin_dir, tmp_path, *extra):
    return [
        "run",
        "--data-dir", str(devin_dir.root),
        "--keep-file", str(tmp_path / "keep.json"),
        "--pending-file", str(tmp_path / "pending.json"),
        "--log-file", str(tmp_path / "janitor-log.jsonl"),
        *extra,
    ]


def _db_ids(db_path):
    con = sqlite3.connect(str(db_path))
    ids = {r[0] for r in con.execute("SELECT id FROM sessions")}
    con.close()
    return ids


@pytest.fixture()
def noisy_dir(devin_dir):
    """A data dir with one deletable noise session + one keeper."""
    add_session(devin_dir.sessions_db, "noise-1", title="billing",
                user_msgs=1, tool_calls=1)
    add_session(devin_dir.sessions_db, "work-1", title="real feature work",
                user_msgs=50, tool_calls=40)
    add_gui_session(devin_dir.acp_messages_dir, "gui-noise", title="inbox")
    return devin_dir


def test_scan_json(noisy_dir, tmp_path, capsys):
    rc = main(_scan_args(noisy_dir, tmp_path, "--json"))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == 3
    tiers = payload["tiers"]
    assert {r["id"] for r in tiers["auto_delete"]} == {"noise-1", "gui-noise"}
    assert {r["id"] for r in tiers["keep"]} == {"work-1"}


def test_dry_run_writes_nothing(noisy_dir, tmp_path, capsys):
    db_hash = _sha(noisy_dir.sessions_db)
    acp_listing = sorted(p.name for p in noisy_dir.acp_messages_dir.iterdir())

    rc = main(_run_args(noisy_dir, tmp_path))
    out = capsys.readouterr().out
    assert rc == 0
    assert "DRY-RUN" in out
    assert _sha(noisy_dir.sessions_db) == db_hash
    assert sorted(p.name for p in noisy_dir.acp_messages_dir.iterdir()) == acp_listing
    assert not (tmp_path / "pending.json").exists()
    assert not (tmp_path / "janitor-log.jsonl").exists()


def test_apply_deletes_and_logs(noisy_dir, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        "devin_janitor.cli.vacuum_if_safe", lambda paths: False
    )
    rc = main(_run_args(noisy_dir, tmp_path, "--apply"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "APPLY" in out

    ids = _db_ids(noisy_dir.sessions_db)
    assert ids == {"work-1"}
    assert not (noisy_dir.acp_messages_dir / "gui-noise.db").exists()

    log = tmp_path / "janitor-log.jsonl"
    entry = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert {d["id"] for d in entry["deleted"]} == {"noise-1", "gui-noise"}
    assert entry["judge"] == "none"


def test_export_failure_aborts(noisy_dir, tmp_path, capsys):
    rc = main(_run_args(
        noisy_dir, tmp_path, "--apply",
        "--export-cmd", f'"{sys.executable}" -c "import sys; sys.exit(9)"',
    ))
    assert rc == 3
    assert "noise-1" in _db_ids(noisy_dir.sessions_db)
    assert (noisy_dir.acp_messages_dir / "gui-noise.db").exists()
    assert not (tmp_path / "janitor-log.jsonl").exists()


def test_judge_none_keeps_ambiguous(devin_dir, tmp_path, capsys):
    add_session(devin_dir.sessions_db, "ambig", title="odd little session",
                user_msgs=2, tool_calls=2)
    rc = main(_run_args(devin_dir, tmp_path, "--apply"))
    assert rc == 0
    assert "ambig" in _db_ids(devin_dir.sessions_db)


def test_judge_command_deletes_ambiguous(devin_dir, tmp_path):
    script = tmp_path / "judge.py"
    script.write_text(
        "import sys, json\n"
        "json.loads(sys.stdin.read())\n"
        'print(json.dumps({"keep": False}))\n',
        encoding="utf-8",
    )
    add_session(devin_dir.sessions_db, "ambig", title="odd little session",
                user_msgs=2, tool_calls=2)
    rc = main(_run_args(
        devin_dir, tmp_path, "--apply",
        "--judge", f'command:"{sys.executable}" "{script}"',
    ))
    assert rc == 0
    assert _db_ids(devin_dir.sessions_db) == set()


def test_judge_fail_open_when_backend_down(devin_dir, tmp_path):
    add_session(devin_dir.sessions_db, "ambig", title="odd little session",
                user_msgs=2, tool_calls=2)
    rc = main(_run_args(
        devin_dir, tmp_path, "--apply",
        "--judge", f'command:"{sys.executable}" -c "import sys; sys.exit(1)"',
    ))
    assert rc == 0
    assert "ambig" in _db_ids(devin_dir.sessions_db)


def test_locked_gui_file_goes_pending(devin_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "devin_janitor.cli.vacuum_if_safe", lambda paths: False
    )
    acp = devin_dir.acp_messages_dir
    # stage a real acp db so "ghost" classifies, then swap in a directory
    # to simulate a file locked by a running Devin
    add_session(devin_dir.sessions_db, "ghost", title="inbox", user_msgs=1)
    add_gui_session(acp, "ghost", title="inbox")
    pending = tmp_path / "pending.json"

    real_db = acp / "ghost.db"
    blob = real_db.read_bytes()
    real_db.unlink()
    (acp / "ghost.db").mkdir()  # locked: deletion will fail
    (acp / "ghost.db" / "inside").write_bytes(blob)

    rc = main(_run_args(devin_dir, tmp_path, "--apply",
                        "--pending-file", str(pending)))
    assert rc == 0
    assert json.loads(pending.read_text())  # ghost is queued
    assert "ghost" in json.loads(pending.read_text())


def test_pending_list_and_retry(devin_dir, tmp_path, capsys):
    pending = tmp_path / "pending.json"
    add_gui_session(devin_dir.acp_messages_dir, "g9")
    pending.write_text(json.dumps({"g9": 1}))
    rc = main(["pending", "--data-dir", str(devin_dir.root),
               "--pending-file", str(pending), "--list"])
    assert rc == 0
    assert "g9" in capsys.readouterr().out

    rc = main(["pending", "--data-dir", str(devin_dir.root),
               "--pending-file", str(pending), "--retry"])
    assert rc == 0
    assert not (devin_dir.acp_messages_dir / "g9.db").exists()
    assert not pending.exists()  # queue cleared → file removed


class _DeleteAllJudge:
    """Scripted judge: votes 'delete' on every ambiguous session."""

    name = "devin-judge"

    def available(self):
        return True

    def judge(self, session, statement):
        from devin_janitor.judge import Verdict

        return Verdict(keep=False, reason="voted delete")

    def close(self):
        pass


def test_judged_delete_never_executes_without_apply(
    devin_dir, tmp_path, capsys, monkeypatch
):
    """Rule 1: a judge 'delete' verdict is a plan, not an execution —
    without --apply nothing may be mutated, whatever the judge said."""
    add_session(devin_dir.sessions_db, "ambig-1", title="quick question",
                user_msgs=1)
    db_hash = _sha(devin_dir.sessions_db)
    calls = []
    monkeypatch.setattr(
        "devin_janitor.cli.apply_deletions",
        lambda *a, **k: calls.append(1),
    )
    monkeypatch.setattr(
        "devin_janitor.cli.make_judge", lambda spec: _DeleteAllJudge()
    )
    rc = main(_run_args(devin_dir, tmp_path, "--judge", "devin-judge"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "DRY-RUN" in out
    assert "ambig-1" in out  # the judged delete is planned...
    assert calls == []       # ...but never executed without --apply
    assert _sha(devin_dir.sessions_db) == db_hash


def test_judged_delete_executes_only_with_apply(
    devin_dir, tmp_path, capsys, monkeypatch
):
    """Same verdict, with --apply: the judged delete is eligible."""
    monkeypatch.setattr(
        "devin_janitor.cli.vacuum_if_safe", lambda paths: False
    )
    add_session(devin_dir.sessions_db, "ambig-1", title="quick question",
                user_msgs=1)
    monkeypatch.setattr(
        "devin_janitor.cli.make_judge", lambda spec: _DeleteAllJudge()
    )
    rc = main(_run_args(devin_dir, tmp_path, "--apply",
                        "--judge", "devin-judge"))
    assert rc == 0
    assert "ambig-1" not in _db_ids(devin_dir.sessions_db)


def test_run_missing_db(tmp_path, capsys):
    rc = main([
        "run", "--data-dir", str(tmp_path / "nope"),
        "--pending-file", str(tmp_path / "p.json"),
        "--keep-file", str(tmp_path / "k.json"),
        "--log-file", str(tmp_path / "l.jsonl"),
    ])
    assert rc == 1
    assert "no sessions.db" in capsys.readouterr().err


def test_bad_judge_spec(devin_dir, tmp_path, capsys):
    rc = main(_run_args(devin_dir, tmp_path, "--judge", "bogus"))
    assert rc == 2
