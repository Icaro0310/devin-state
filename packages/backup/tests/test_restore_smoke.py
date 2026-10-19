import sqlite3

from devin_backup import cli, restore, smoke, snapshot


def _create(data_dir, backups_dir):
    return cli.main(
        [
            "create",
            "--data-dir", str(data_dir),
            "--out", str(backups_dir),
        ]
    )


def _corrupt_db(path):
    """Break the schema SQL — integrity_check reports a malformed schema.

    Same trick as test_verify: the file still hashes fine, only
    ``PRAGMA integrity_check`` can see the damage.
    """
    con = sqlite3.connect(path)
    con.execute("PRAGMA writable_schema=ON")
    con.execute(
        "UPDATE sqlite_master SET sql='CREATE TABLE broken(' WHERE name='sessions'"
    )
    con.commit()
    con.close()


def test_smoke_snapshot_healthy(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    report = smoke.smoke_snapshot(snap)
    assert report["ok"] is True
    assert report["checked"] == 5
    assert report["failed"] == 0
    by_path = {r["path"]: r for r in report["results"]}
    assert by_path["cli/sessions.db"]["integrity"] == "ok"
    assert by_path["cli/sessions.db"]["schema_version"] == 17
    # not a sessions.db — detectable as sqlite but no Devin schema version
    assert by_path["User/globalStorage/state.vscdb"]["integrity"] == "ok"
    assert by_path["User/globalStorage/state.vscdb"]["schema_version"] is None
    # plain files are not opened as databases at all
    cfg = by_path[".devin/config.json"]
    assert cfg["sqlite"] is False
    assert cfg["integrity"] == "skipped"


def test_smoke_snapshot_catches_corrupt_source(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    _corrupt_db(snap / "cli" / "sessions.db")
    report = smoke.smoke_snapshot(snap)
    assert report["ok"] is False
    assert report["failed"] == 1
    result = {r["path"]: r for r in report["results"]}["cli/sessions.db"]
    assert result["ok"] is False
    assert result["integrity"].startswith("failed")


def test_smoke_restored_healthy(data_dir, backups_dir, tmp_path):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    restore.restore_snapshot(snap, target, dry_run=False)
    report = smoke.smoke_restored(snap, target)
    assert report["ok"] is True
    assert report["checked"] == 5
    assert all(r["ok"] for r in report["results"])


def test_smoke_restored_catches_corrupt_store(data_dir, backups_dir, tmp_path):
    """A snapshot whose source was already corrupt restores a corrupt file."""
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    _corrupt_db(snap / "cli" / "sessions.db")
    target = tmp_path / "restore-target"
    restore.restore_snapshot(snap, target, dry_run=False)
    report = smoke.smoke_restored(snap, target)
    assert report["ok"] is False
    result = {r["path"]: r for r in report["results"]}["cli/sessions.db"]
    assert result["integrity"].startswith("failed")


def test_smoke_restored_flags_missing_store(data_dir, backups_dir, tmp_path):
    """Smoke against a target the restore never reached reports missing."""
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    report = smoke.smoke_restored(snap, target)
    assert report["ok"] is False
    assert all(r["integrity"] == "missing" for r in report["results"])


def test_cli_restore_apply_smoke_ok(data_dir, backups_dir, tmp_path, capsys):
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    target = tmp_path / "restore-target"
    capsys.readouterr()
    rc = cli.main(
        ["restore", str(snap), "--to", str(target), "--apply", "--smoke"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "smoke" in out
    assert "restored stores" in out
    assert "schema v17" in out
    assert "FAIL" not in out


def test_cli_restore_apply_smoke_fails_on_corruption(
    data_dir, backups_dir, tmp_path, capsys
):
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    _corrupt_db(snap / "cli" / "sessions.db")
    target = tmp_path / "restore-target"
    capsys.readouterr()
    rc = cli.main(
        ["restore", str(snap), "--to", str(target), "--apply", "--smoke"]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "cli/sessions.db" in out


def test_cli_restore_dry_run_smoke_checks_sources(
    data_dir, backups_dir, tmp_path, capsys
):
    """--smoke without --apply previews the snapshot sources; nothing writes."""
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    target = tmp_path / "restore-target"
    capsys.readouterr()
    rc = cli.main(["restore", str(snap), "--to", str(target), "--smoke"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "snapshot sources" in out
    assert not target.exists()


def test_cli_restore_dry_run_smoke_fails_on_corrupt_source(
    data_dir, backups_dir, tmp_path, capsys
):
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    _corrupt_db(snap / "cli" / "sessions.db")
    target = tmp_path / "restore-target"
    capsys.readouterr()
    rc = cli.main(["restore", str(snap), "--to", str(target), "--smoke"])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out
    assert not target.exists()


def test_cli_restore_apply_without_smoke_unchanged(
    data_dir, backups_dir, tmp_path, capsys
):
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    target = tmp_path / "restore-target"
    capsys.readouterr()
    rc = cli.main(["restore", str(snap), "--to", str(target), "--apply"])
    assert rc == 0
    assert "smoke" not in capsys.readouterr().out


def _trash_db_header(path):
    """Overwrite with non-SQLite bytes — 'file is not a database'."""
    path.write_bytes(b"not a sqlite file at all" * 64)


def test_smoke_flags_db_that_is_not_a_database(data_dir, backups_dir):
    """A .db file with a destroyed header is corrupt, not 'skipped'."""
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    _trash_db_header(snap / "cli" / "sessions.db")
    report = smoke.smoke_snapshot(snap)
    assert report["ok"] is False
    result = {r["path"]: r for r in report["results"]}["cli/sessions.db"]
    assert result["ok"] is False
    assert result["integrity"] == "skipped"
    assert result["detail"] == "not a readable database"


def test_smoke_flags_hash_mismatch_on_restored_copy(
    data_dir, backups_dir, tmp_path
):
    """A restored file whose content diverges from the manifest hash
    fails smoke even when the database itself is healthy."""
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    restore.restore_snapshot(snap, target, dry_run=False)
    (target / ".devin" / "config.json").write_text('{"tampered": true}')
    report = smoke.smoke_restored(snap, target)
    assert report["ok"] is False
    result = {r["path"]: r for r in report["results"]}[
        ".devin/config.json"]
    assert result["hash"] == "mismatch"
    assert result["detail"] == "content hash differs from manifest"


def test_smoke_snapshot_expands_home(data_dir, backups_dir, tmp_path,
                                     monkeypatch):
    """'~/backups/x' works in dry-run smoke, like restore/verify."""
    monkeypatch.setenv("HOME", str(tmp_path))
    home_backups = tmp_path / "backups"
    home_backups.mkdir()
    snap = snapshot.create_snapshot(data_dir, home_backups)
    rel = snap.relative_to(tmp_path)
    report = smoke.smoke_snapshot(f"~/{rel}")
    assert report["ok"] is True
    assert report["checked"] == 5


def test_cli_smoke_missing_file_shows_real_cause(
    data_dir, backups_dir, tmp_path, capsys
):
    """A missing plain file must not report 'not a sqlite store'."""
    assert _create(data_dir, backups_dir) == 0
    snap = next(backups_dir.iterdir())
    (snap / ".devin" / "config.json").unlink()
    capsys.readouterr()
    rc = cli.main(
        ["restore", str(snap), "--to", str(tmp_path / "t"), "--smoke"]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "store is missing" in out
    assert "not a sqlite store" not in out
