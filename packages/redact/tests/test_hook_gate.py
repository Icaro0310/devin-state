"""RD-1 + RD-4: SessionEnd hook verdict line and the `gate` command.

``sessionend-scan`` is the handler-shaped invocation for the ecosystem
hook dispatcher: read-only, bounded to the default ``sessions.db``, prints
exactly one compact verdict line, exits 0 unless a hard error occurs.
``gate`` is the pipeline variant for ``devin-history``: it prints just the
status word and encodes it in the exit code (0=CLEAN/REVIEW, 1=BLOCKED,
2=error). Both rest on the top-level ``publication_status`` the JSON
report already emits.
"""

import re
import shutil
from pathlib import Path

import devin_redact
from devin_redact import cli, paths
from test_chunked import FAKE_AWS_KEY, _db, _node
from test_scan import FIXTURES, PLANTED

DB = FIXTURES / "sessions.db"

VERDICT = re.compile(
    r"^devin-redact: findings=\d+ publication_status=(CLEAN|REVIEW|BLOCKED)$"
)


def _isolate_env(tmp_path: Path, monkeypatch) -> None:
    """Point every path root the platform lookup may consult at tmp_path."""
    for var in (
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "APPDATA",
    ):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))


# --- RD-4: publication_status is the machine-readable verdict ------------


def test_publication_status_top_level_for_history():
    report = devin_redact.scan([DB])
    assert report["publication_status"] == "BLOCKED"
    assert report["publication_status"] in {"BLOCKED", "REVIEW", "CLEAN"}


def test_gate_blocked(capsys):
    # --no-baseline: this test asserts the raw gate verdict — the repo's
    # committed redact-baseline.json would otherwise suppress the
    # fixture's already-triaged findings (baseline coverage lives in
    # test_baseline.py).
    assert cli.main(["gate", "--no-baseline", str(DB)]) == 1
    assert capsys.readouterr().out.strip() == "BLOCKED"


def test_gate_clean(tmp_path, capsys):
    p = tmp_path / "note.md"
    p.write_text("all good here\n", encoding="utf-8")
    assert cli.main(["gate", str(p)]) == 0
    assert capsys.readouterr().out.strip() == "CLEAN"


def test_gate_review_exits_zero(tmp_path, capsys):
    p = tmp_path / "note.md"
    p.write_text("contact fake.user@example.com anytime\n", encoding="utf-8")
    assert cli.main(["gate", str(p)]) == 0
    assert capsys.readouterr().out.strip() == "REVIEW"


def test_gate_hard_error_exit_2(tmp_path, capsys):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"definitely not a sqlite database at all")
    assert cli.main(["gate", str(bad)]) == 2
    out = capsys.readouterr()
    assert out.out == ""  # stdout stays a clean status-word channel
    assert "devin-redact:" in out.err


def test_gate_binary_skip_is_not_an_error(tmp_path, capsys):
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\x89PNG\x00" + bytes(range(32)))
    assert cli.main(["gate", str(blob)]) == 0
    assert capsys.readouterr().out.strip() == "CLEAN"


# --- RD-1: sessionend-scan hook invocation -------------------------------


def test_sessionend_scan_explicit_path(capsys):
    assert cli.main(["sessionend-scan", str(DB)]) == 0
    line = capsys.readouterr().out.strip()
    assert VERDICT.match(line), line
    assert "publication_status=BLOCKED" in line


def test_sessionend_scan_blocked_still_exits_zero(capsys):
    # The hook must never block session teardown — a BLOCKED verdict is
    # still a successful scan.
    assert cli.main(["sessionend-scan", str(DB)]) == 0


def test_sessionend_scan_verdict_has_no_secret_text(capsys):
    assert cli.main(["sessionend-scan", str(DB)]) == 0
    out = capsys.readouterr().out
    for values in PLANTED.values():
        for v in values:
            assert v not in out


def test_sessionend_scan_clean_target(tmp_path, capsys):
    p = tmp_path / "clean.md"
    p.write_text("nothing sensitive\n", encoding="utf-8")
    assert cli.main(["sessionend-scan", str(p)]) == 0
    line = capsys.readouterr().out.strip()
    assert VERDICT.match(line)
    assert "publication_status=CLEAN" in line


def test_sessionend_scan_missing_explicit_path(tmp_path, capsys):
    assert cli.main(["sessionend-scan", str(tmp_path / "nope.db")]) == 2
    assert "devin-redact:" in capsys.readouterr().err


def test_sessionend_scan_corrupt_db_is_hard_error(tmp_path, capsys):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"definitely not a sqlite database at all")
    assert cli.main(["sessionend-scan", str(bad)]) == 2
    assert "devin-redact:" in capsys.readouterr().err


def test_sessionend_scan_no_db_is_clean(tmp_path, capsys, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    assert paths.default_sessions_db() is None
    assert cli.main(["sessionend-scan"]) == 0
    line = capsys.readouterr().out.strip()
    assert VERDICT.match(line)
    assert "findings=0" in line
    assert "publication_status=CLEAN" in line


def test_sessionend_scan_autodetects_default_db(tmp_path, capsys, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    # Plant the store under every candidate root so any platform's
    # resolution order finds it.
    for root in (
        tmp_path / "xdg_data_home",
        tmp_path / "appdata",
        tmp_path / "home" / ".local" / "share",
        tmp_path / "home" / ".config",
        tmp_path / "home" / "Library" / "Application Support",
    ):
        target = root / "devin" / "cli"
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy2(DB, target / "sessions.db")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data_home"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    assert paths.default_sessions_db() is not None
    assert cli.main(["sessionend-scan"]) == 0
    line = capsys.readouterr().out.strip()
    assert VERDICT.match(line)
    assert "publication_status=BLOCKED" in line


def test_sessionend_scan_session_id_bounds_scan(tmp_path, capsys):
    # The bounded hook mode audits only the just-ended session's rows.
    db, con = _db(tmp_path)
    _node(con, "s1", 0, "fake key " + FAKE_AWS_KEY)
    _node(con, "s2", 0, "totally benign content")
    con.commit()
    con.close()

    assert cli.main(
        ["sessionend-scan", str(db), "--session-id", "s2"]
    ) == 0
    line = capsys.readouterr().out.strip()
    assert "findings=0" in line
    assert "publication_status=CLEAN" in line

    assert cli.main(
        ["sessionend-scan", str(db), "--session-id", "s1"]
    ) == 0
    line = capsys.readouterr().out.strip()
    assert VERDICT.match(line)
    assert "publication_status=BLOCKED" in line
    assert "findings=0" not in line


def test_paths_candidates_explicit(tmp_path):
    env = {"XDG_DATA_HOME": str(tmp_path / "xdg")}
    assert paths.default_sessions_db(env, "linux") is None
    db = tmp_path / "xdg" / "devin" / "cli" / "sessions.db"
    db.parent.mkdir(parents=True)
    db.write_bytes(b"x")
    assert paths.default_sessions_db(env, "linux") == db

    env2 = {"APPDATA": str(tmp_path / "roam")}
    db2 = tmp_path / "roam" / "devin" / "cli" / "sessions.db"
    db2.parent.mkdir(parents=True)
    db2.write_bytes(b"x")
    assert paths.default_sessions_db(env2, "win32") == db2
