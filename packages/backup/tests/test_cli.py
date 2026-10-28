import os
from datetime import datetime, timedelta, timezone

import pytest
from devin_backup import cli, snapshot

T0 = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


def _create(data_dir, backups_dir):
    return cli.main(
        [
            "create",
            "--data-dir", str(data_dir),
            "--out", str(backups_dir),
        ]
    )


def test_cli_create(data_dir, backups_dir, capsys):
    assert _create(data_dir, backups_dir) == 0
    out = capsys.readouterr().out
    assert "snapshot" in out
    snaps = list(backups_dir.iterdir())
    assert len(snaps) == 1 and (snaps[0] / "manifest.json").is_file()


def test_cli_create_missing_data_dir(tmp_path, backups_dir, capsys):
    rc = cli.main(
        ["create", "--data-dir", str(tmp_path / "nope"), "--out", str(backups_dir)]
    )
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_cli_verify_ok_and_fail(data_dir, backups_dir, capsys):
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    capsys.readouterr()
    assert cli.main(["verify", str(snap)]) == 0
    assert "ok" in capsys.readouterr().out.lower()

    victim = next((snap / "User" / "acp-messages").glob("*.db"))
    with open(victim, "ab") as fh:
        fh.write(b"junk")
    assert cli.main(["verify", str(snap)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_cli_list(data_dir, backups_dir, capsys):
    assert _create(data_dir, backups_dir) == 0
    capsys.readouterr()
    assert cli.main(["list", "--out", str(backups_dir)]) == 0
    out = capsys.readouterr().out
    assert "snapshot" in out
    assert "v17" in out


def test_cli_list_empty(tmp_path, capsys):
    assert cli.main(["list", "--out", str(tmp_path / "nope")]) == 0
    assert "no snapshots" in capsys.readouterr().out.lower()


def test_cli_restore_dry_run_default(data_dir, backups_dir, tmp_path, capsys):
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    target = tmp_path / "restore-target"
    capsys.readouterr()
    assert cli.main(["restore", str(snap), "--to", str(target)]) == 0
    assert "dry-run" in capsys.readouterr().out.lower()
    assert not target.exists()


def test_cli_restore_apply(data_dir, backups_dir, tmp_path):
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    target = tmp_path / "restore-target"
    assert (
        cli.main(["restore", str(snap), "--to", str(target), "--apply"]) == 0
    )
    assert (target / "cli" / "sessions.db").is_file()
    assert (target / ".devin" / "config.json").is_file()


def test_cli_restore_no_backup_refuses(data_dir, backups_dir, tmp_path, capsys):
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    target = tmp_path / "restore-target"
    cli.main(["restore", str(snap), "--to", str(target), "--apply"])
    capsys.readouterr()
    rc = cli.main(
        ["restore", str(snap), "--to", str(target), "--apply", "--no-backup"]
    )
    assert rc == 2
    assert "refus" in capsys.readouterr().err.lower()


def test_cli_rotate_requires_yes(data_dir, backups_dir, capsys):
    for i in range(3):
        snapshot.create_snapshot(
            data_dir, backups_dir, now=T0 + timedelta(hours=i)
        )
    assert cli.main(["rotate", "--out", str(backups_dir), "--keep", "1"]) == 2
    assert "--yes" in capsys.readouterr().err
    assert len(list(backups_dir.iterdir())) == 3


def test_cli_rotate_with_yes(data_dir, backups_dir, capsys):
    snaps = [
        snapshot.create_snapshot(
            data_dir, backups_dir, now=T0 + timedelta(hours=i)
        )
        for i in range(3)
    ]
    rc = cli.main(
        ["rotate", "--out", str(backups_dir), "--keep", "1", "--yes"]
    )
    assert rc == 0
    assert "deleted" in capsys.readouterr().out.lower()
    assert [p.name for p in backups_dir.iterdir()] == [snaps[-1].name]


def _aged_snaps(data_dir, backups_dir, ages_days):
    now = datetime.now(timezone.utc)
    snaps = [
        snapshot.create_snapshot(
            data_dir, backups_dir, now=T0 + timedelta(hours=i)
        )
        for i in range(len(ages_days))
    ]
    for snap, age in zip(snaps, ages_days):
        ts = (now - timedelta(days=age)).timestamp()
        os.utime(snap, (ts, ts))
    return snaps


def test_cli_rotate_older_than_requires_yes(data_dir, backups_dir, capsys):
    _aged_snaps(data_dir, backups_dir, [60, 40])
    rc = cli.main(
        ["rotate", "--out", str(backups_dir), "--older-than", "30d"]
    )
    assert rc == 2
    assert "--yes" in capsys.readouterr().err
    assert len(list(backups_dir.iterdir())) == 2


def test_cli_rotate_older_than_with_yes(data_dir, backups_dir, capsys):
    snaps = _aged_snaps(data_dir, backups_dir, [60, 40, 10, 1])
    rc = cli.main(
        ["rotate", "--out", str(backups_dir), "--older-than", "30d", "--yes"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "deleted" in out.lower()
    remaining = sorted(p.name for p in backups_dir.iterdir())
    assert remaining == sorted(p.name for p in snaps[2:])


def test_cli_rotate_older_than_keep_floor(data_dir, backups_dir, capsys):
    snaps = _aged_snaps(data_dir, backups_dir, [60, 50, 40, 35])
    rc = cli.main(
        [
            "rotate", "--out", str(backups_dir),
            "--older-than", "30d", "--keep", "2", "--yes",
        ]
    )
    assert rc == 0
    capsys.readouterr()
    remaining = sorted(p.name for p in backups_dir.iterdir())
    assert remaining == sorted(p.name for p in snaps[2:])


def test_cli_rotate_older_than_bad_duration(data_dir, backups_dir, capsys):
    _aged_snaps(data_dir, backups_dir, [60])
    rc = cli.main(
        ["rotate", "--out", str(backups_dir), "--older-than", "bogus", "--yes"]
    )
    assert rc == 2
    assert "duration" in capsys.readouterr().err.lower()


def test_cli_no_command_errors(capsys):
    with pytest.raises(SystemExit):
        cli.main([])
