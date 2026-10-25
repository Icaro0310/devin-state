"""BK-3: create --remote offload (rsync ssh targets + mounted paths)."""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devin_backup import cli, remote, snapshot


def _mk_snapshot(data_dir, tmp_path):
    return snapshot.create_snapshot(data_dir, tmp_path / "snaps")


@pytest.mark.parametrize("dest,expected", [
    ("user@host:backups", True),
    ("host:/abs/path", True),
    ("host:", True),                    # rsync home dir
    ("somehost:dir/sub", True),
    ("user@host:~/backups", True),
    ("/mnt/nas", False),
    ("./rel", False),
    ("~/backups", False),
    ("rel/path", False),
    ("./a:b", False),                   # ':' after a separator is a filename
    ("/x/y:z", False),
    ("C:\\backups", False),             # drive letter is never a host
    ("C:/backups", False),
    ("\\\\server\\share", False),       # UNC path
])
def test_is_remote_target(dest, expected):
    assert remote.is_remote_target(dest) is expected


def test_remote_dest_naming():
    src = Path("/snaps/20261029T120000Z")
    assert remote._remote_dest(src, "user@h:/bk") == \
        "user@h:/bk/20261029T120000Z"
    assert remote._remote_dest(src, "user@h:") == \
        "user@h:20261029T120000Z"
    assert remote._remote_dest(src, "h:trail/") == \
        "h:trail/20261029T120000Z"


def test_offload_local_path_real_copy(data_dir, tmp_path):
    snap = _mk_snapshot(data_dir, tmp_path)
    dest = tmp_path / "nas"
    dest.mkdir()
    res = remote.offload_snapshot(snap, dest)
    assert res["method"] == "copy" and res["moved"] is False
    assert res["bytes"] > 0 and res["verify"]["ok"]
    assert (Path(res["dest"]) / "manifest.json").is_file()
    assert snap.is_dir()  # local copy kept by default


def test_offload_rsync_command(data_dir, tmp_path, monkeypatch):
    snap = _mk_snapshot(data_dir, tmp_path)
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(remote.shutil, "which", lambda name: "/usr/bin/rsync")
    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    res = remote.offload_snapshot(snap, "user@host:/backups")
    assert res["method"] == "rsync" and res["moved"] is False
    assert res["dest"] == f"user@host:/backups/{snap.name}"
    cmd = calls[0]
    assert cmd[:4] == ["rsync", "-a", "--protect-args", "--"]
    assert cmd[-2] == f"{snap}/"          # contents of the snapshot dir
    assert cmd[-1] == f"user@host:/backups/{snap.name}"
    assert snap.is_dir()                  # copy, not move


def test_offload_rsync_failure_is_loud(data_dir, tmp_path, monkeypatch):
    snap = _mk_snapshot(data_dir, tmp_path)

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(
            cmd, 12, stdout="", stderr="rsync: link_stat failed")

    monkeypatch.setattr(remote.shutil, "which", lambda name: "/usr/bin/rsync")
    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    with pytest.raises(snapshot.SnapshotError, match="rsync.*exit 12"):
        remote.offload_snapshot(snap, "user@host:/backups")
    assert snap.is_dir()  # nothing deleted on failure


def test_offload_rsync_missing_binary(data_dir, tmp_path, monkeypatch):
    snap = _mk_snapshot(data_dir, tmp_path)
    monkeypatch.setattr(remote.shutil, "which", lambda name: None)
    with pytest.raises(snapshot.SnapshotError, match="rsync not found"):
        remote.offload_snapshot(snap, "user@host:/backups")
    assert snap.is_dir()


def test_offload_refuses_corrupt_snapshot(data_dir, tmp_path, monkeypatch):
    snap = _mk_snapshot(data_dir, tmp_path)
    victim = next(snap.rglob("*.db"))
    with open(victim, "ab") as fh:
        fh.write(b"junk")
    called = []
    monkeypatch.setattr(
        remote.subprocess, "run",
        lambda cmd, **kw: called.append(cmd))
    dest = tmp_path / "nas"
    dest.mkdir()
    with pytest.raises(snapshot.SnapshotError, match="verification"):
        remote.offload_snapshot(snap, dest)
    with pytest.raises(snapshot.SnapshotError, match="verification"):
        remote.offload_snapshot(snap, "user@host:/backups")
    assert not called and not list(dest.iterdir())


def test_offload_move_removes_local(data_dir, tmp_path):
    snap = _mk_snapshot(data_dir, tmp_path)
    dest = tmp_path / "nas"
    dest.mkdir()
    res = remote.offload_snapshot(snap, dest, move=True)
    assert res["moved"] is True
    assert not snap.exists()
    assert (Path(res["dest"]) / "manifest.json").is_file()


def test_offload_rsync_move_removes_local(data_dir, tmp_path, monkeypatch):
    snap = _mk_snapshot(data_dir, tmp_path)
    monkeypatch.setattr(remote.shutil, "which", lambda name: "/usr/bin/rsync")
    monkeypatch.setattr(
        remote.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0))
    res = remote.offload_snapshot(snap, "user@host:/backups", move=True)
    assert res["moved"] is True and not snap.exists()


def test_cli_create_remote_local(data_dir, backups_dir, tmp_path, capsys):
    dest = tmp_path / "mounted"
    dest.mkdir()
    rc = cli.main([
        "create", "--data-dir", str(data_dir), "--out", str(backups_dir),
        "--remote", str(dest),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "offloaded" in out and "copy" in out
    copied = [p for p in dest.iterdir()]
    assert len(copied) == 1 and (copied[0] / "manifest.json").is_file()
    assert len(list(backups_dir.iterdir())) == 1  # local kept


def test_cli_move_without_remote_errors(data_dir, backups_dir, capsys):
    rc = cli.main([
        "create", "--data-dir", str(data_dir), "--out", str(backups_dir),
        "--move",
    ])
    assert rc == 2
    assert "--remote" in capsys.readouterr().err
    assert not backups_dir.exists() or not list(backups_dir.iterdir())
