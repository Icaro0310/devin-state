"""Regression tests for ``gate --staged`` — the pre-commit hook path.

The working tree is not authoritative for what a commit records: a file
edited or deleted after ``git add`` still contributes its *staged* blob
to the commit. Scanning the file on disk therefore lets a secret staged
and then removed from the worktree slip through the gate. These tests
build real git indexes so the bypass is exercised end to end: the
staged blob is what gets scanned.
"""

import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from devin_redact import cli, engine, staged
from test_chunked import FAKE_AWS_KEY
from test_scan import FIXTURES

needs_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git binary required"
)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=False
    )
    assert proc.returncode == 0, proc.stderr
    return proc


@pytest.fixture
def repo(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    monkeypatch.chdir(repo)
    return repo


# --- engine.scan_blobs: blob dispatch (no git needed) --------------------


def test_scan_blobs_text_and_binary():
    report = engine.scan_blobs(
        [
            ("leak.env", f"API_KEY={FAKE_AWS_KEY}\n".encode()),
            ("img.bin", b"\x89PNG\x00" + bytes(range(32))),
        ]
    )
    assert report["publication_status"] == "BLOCKED"
    assert report["files_scanned"] == 1
    skipped = [e for e in report["errors"] if e["file"] == "img.bin"]
    assert skipped and skipped[0]["error"].startswith("skipped:")


def test_scan_blobs_sqlite():
    blob = (FIXTURES / "sessions.db").read_bytes()
    report = engine.scan_blobs([("sessions.db", blob)])
    assert report["publication_status"] == "BLOCKED"
    assert report["files_scanned"] == 1


def test_scan_blobs_seeds_errors():
    report = engine.scan_blobs(
        [("clean.txt", b"all good\n")],
        errors=[{"file": "gone.txt", "error": "skipped: no staged blob"}],
    )
    assert report["publication_status"] == "CLEAN"
    assert report["errors"] == [
        {"file": "gone.txt", "error": "skipped: no staged blob"}
    ]


# --- staged.staged_blobs + gate --staged over a real index ---------------


@needs_git
def test_staged_secret_worktree_deleted_blocks(repo, capsys):
    """`git add secret && rm secret` — the finding's exact vector: the
    worktree file is gone, but the staged blob still ships."""
    (repo / "secret.env").write_text(f"API_KEY={FAKE_AWS_KEY}\n")
    _git(repo, "add", "secret.env")
    (repo / "secret.env").unlink()
    assert cli.main(["gate", "--staged", "secret.env"]) == 1
    assert capsys.readouterr().out.strip() == "BLOCKED"


@needs_git
def test_staged_secret_worktree_overwritten_blocks(repo, capsys):
    """Staged secret, then the worktree file replaced with content that
    scans clean — the commit still contains the secret, so BLOCKED can
    only come from the staged blob."""
    f = repo / "app.env"
    f.write_text(f"API_KEY={FAKE_AWS_KEY}\n")
    _git(repo, "add", "app.env")
    f.write_text("# scrubbed\n")
    assert cli.main(["gate", "--staged", "app.env"]) == 1
    assert capsys.readouterr().out.strip() == "BLOCKED"


@needs_git
def test_worktree_only_secret_not_committed_is_clean(repo, capsys):
    """Inverse direction: a secret added to the worktree *after* the
    clean version was staged is not part of the commit — the staged
    blob is what the gate vouches for."""
    f = repo / "note.txt"
    f.write_text("nothing sensitive\n")
    _git(repo, "add", "note.txt")
    f.write_text(f"API_KEY={FAKE_AWS_KEY}\n")
    assert cli.main(["gate", "--staged", "note.txt"]) == 0
    assert capsys.readouterr().out.strip() == "CLEAN"


@needs_git
def test_unstaged_path_skips_not_errors(repo, capsys):
    """A path with no index entry has nothing staged for the commit —
    skipped (non-blocking), not a hard error."""
    (repo / "loose.txt").write_text("never staged\n")
    assert cli.main(["gate", "--staged", "loose.txt"]) == 0
    assert capsys.readouterr().out.strip() == "CLEAN"


@needs_git
def test_staged_blobs_subdirectory_path(repo, monkeypatch):
    """Paths resolve against the repo root even when invoked from a
    subdirectory (pre-commit passes root-relative names)."""
    sub = repo / "sub"
    sub.mkdir()
    (sub / "key.env").write_text(f"API_KEY={FAKE_AWS_KEY}\n")
    _git(repo, "add", "sub/key.env")
    monkeypatch.chdir(sub)
    blobs, errors = staged.staged_blobs(["key.env"])
    assert errors == []
    assert [name for name, _ in blobs] == ["sub/key.env"]


@needs_git
def test_gate_staged_outside_repo_fails_closed(tmp_path, monkeypatch, capsys):
    """No repository → the index cannot be consulted → exit 2."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "f.txt").write_text("x\n")
    assert cli.main(["gate", "--staged", "f.txt"]) == 2
    assert "devin-redact:" in capsys.readouterr().err


@needs_git
def test_gate_without_staged_scans_worktree(repo, capsys):
    """Plain `gate` keeps scanning the filesystem — `--staged` is the
    opt-in index mode. Same index/worktree split, opposite verdicts."""
    (repo / "dirty.env").write_text(f"API_KEY={FAKE_AWS_KEY}\n")
    _git(repo, "add", "dirty.env")
    (repo / "dirty.env").write_text("# scrubbed\n")
    assert cli.main(["gate", "dirty.env"]) == 0
    assert capsys.readouterr().out.strip() == "CLEAN"
    assert cli.main(["gate", "--staged", "dirty.env"]) == 1
    assert capsys.readouterr().out.strip() == "BLOCKED"


# --- staged_blobs: directory arguments expand to index descendants ------


@needs_git
def test_staged_blobs_directory_expands(repo):
    """staged_blobs returns one blob per index descendant for a
    directory argument — the index holds files, not directories."""
    sub = repo / "cfg"
    sub.mkdir()
    (sub / "a.txt").write_text("a\n")
    (sub / "b.txt").write_text("b\n")
    _git(repo, "add", "cfg")
    blobs, errors = staged.staged_blobs(["cfg"])
    assert errors == []
    assert sorted(name for name, _ in blobs) == ["cfg/a.txt", "cfg/b.txt"]


@needs_git
def test_gate_staged_directory_scans_descendants(repo, capsys):
    """`gate --staged <dir>` must expand to staged descendants instead
    of exiting 2 on the directory as an unreadable blob."""
    sub = repo / "cfg"
    sub.mkdir()
    (sub / "ok.txt").write_text("nothing sensitive\n")
    (sub / "leak.env").write_text(f"API_KEY={FAKE_AWS_KEY}\n")
    _git(repo, "add", "cfg")
    assert cli.main(["gate", "--staged", "cfg"]) == 1
    assert capsys.readouterr().out.strip() == "BLOCKED"


@needs_git
def test_gate_staged_directory_clean_descendants(repo, capsys):
    """Clean staged directory → CLEAN (exit 0, not the old error path)."""
    sub = repo / "cfg"
    sub.mkdir()
    (sub / "a.txt").write_text("fine\n")
    _git(repo, "add", "cfg")
    assert cli.main(["gate", "--staged", "cfg"]) == 0
    assert capsys.readouterr().out.strip() == "CLEAN"


# --- scan_blobs: SQLite sidecars replay with their primary --------------


def _wal_db_blobs(tmp_path: Path) -> tuple[bytes, bytes]:
    """``(db_blob, wal_blob)`` for a WAL-mode store whose committed row
    lives only in the uncheckpointed ``-wal``."""
    db = tmp_path / "s.db"
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE secrets(v TEXT)")
    con.execute("INSERT INTO secrets VALUES (?)", (f"key={FAKE_AWS_KEY}",))
    con.commit()
    wal = Path(str(db) + "-wal").read_bytes()  # read before close:
    blob = db.read_bytes()                     # closing checkpoints
    con.close()
    assert wal
    return blob, wal


def test_scan_blobs_sqlite_wal_sidecar(tmp_path):
    """Committed-but-uncheckpointed rows live in the WAL — a staged
    ``.db-wal`` must replay with its db or the scan misses them."""
    blob, wal = _wal_db_blobs(tmp_path)
    assert engine.scan_blobs([("s.db", blob)])["publication_status"] == "CLEAN"
    report = engine.scan_blobs([("s.db", blob), ("s.db-wal", wal)])
    assert report["publication_status"] == "BLOCKED"
    # the wal's rows are covered via replay into the temp db; the wal
    # blob itself then dispatches as binary → non-blocking skipped.
    assert report["files_scanned"] == 1
    assert any(e["file"] == "s.db-wal" for e in report["errors"])


def test_scan_blobs_orphan_wal_scans_alone():
    """A ``-wal`` blob with no staged ``.db`` dispatches as an ordinary
    binary blob — non-blocking ``skipped:``, never a hard error."""
    report = engine.scan_blobs(
        [("gone.db-wal", b"\x37\x7f\x06\x82" + b"\x00" * 16)]
    )
    skipped = [e for e in report["errors"] if e["file"] == "gone.db-wal"]
    assert skipped and skipped[0]["error"].startswith("skipped:")
    assert report["publication_status"] == "CLEAN"


def test_scan_blobs_attached_sidecar_content_scanned(tmp_path):
    """An attached ``-journal`` still has its own bytes scanned: a staged
    sidecar holding plaintext secrets must not pass attached-but-unread."""
    blob, _ = _wal_db_blobs(tmp_path)
    journal = f"journal header\nAPI_KEY={FAKE_AWS_KEY}\n".encode()
    report = engine.scan_blobs([("s.db", blob), ("s.db-journal", journal)])
    assert report["publication_status"] == "BLOCKED"
