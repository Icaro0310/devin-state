import json
import sqlite3
from pathlib import Path

import pytest
from devin_backup import restore, snapshot
from devin_internals import fixtures


def _manifest(snap):
    return json.loads((snap / "manifest.json").read_text(encoding="utf-8"))


def _rel_paths(data_dir):
    return [
        "cli/sessions.db",
        "User/globalStorage/state.vscdb",
        ".devin/config.json",
    ]


def test_restore_dry_run_writes_nothing(data_dir, backups_dir, tmp_path):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    plan = restore.restore_snapshot(snap, target, dry_run=True)
    assert plan["dry_run"] is True
    assert len(plan["would_write"]) == 5
    assert plan["would_overwrite"] == []
    assert not target.exists()


def test_restore_split_snapshot_routes_files_to_both_roots(
    data_dir, backups_dir, tmp_path
):
    config_source = tmp_path / "config-source" / "Devin"
    acp_db = config_source / "User" / "acp-messages" / "gui.db"
    acp_db.parent.mkdir(parents=True)
    with sqlite3.connect(acp_db) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")
    snap = snapshot.create_snapshot(data_dir, backups_dir, config_dir=config_source)
    data_target = tmp_path / "restore-data"
    config_target = tmp_path / "restore-config"

    plan = restore.restore_snapshot(
        snap, data_target, config_dir=config_target, dry_run=False
    )

    assert plan["dry_run"] is False
    assert (data_target / "cli" / "sessions.db").is_file()
    assert (config_target / "User" / "acp-messages" / "gui.db").is_file()
    assert "config/User/acp-messages/gui.db" in plan["written"]


def test_restore_apply_to_empty_target(data_dir, backups_dir, tmp_path):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    plan = restore.restore_snapshot(snap, target, dry_run=False)
    assert plan["dry_run"] is False
    assert len(plan["written"]) == 5
    assert plan["overwritten"] == []
    assert plan["pre_restore_backup"] is None
    for rel in _rel_paths(data_dir):
        assert (target / rel).is_file(), rel
    # restored sessions.db is a working database
    con = sqlite3.connect(target / "cli" / "sessions.db")
    assert con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] > 0
    con.close()


def test_restore_default_is_dry_run(data_dir, backups_dir, tmp_path):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    plan = restore.restore_snapshot(snap, target)
    assert plan["dry_run"] is True
    assert not target.exists()


def test_restore_overwrite_creates_pre_restore_backup(
    data_dir, backups_dir, tmp_path
):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    restore.restore_snapshot(snap, target, dry_run=False)

    # user edits the config and the db drifts
    cfg = target / ".devin" / "config.json"
    cfg.write_text('{"edited": true}\n', encoding="utf-8")
    old_cfg = cfg.read_bytes()

    plan = restore.restore_snapshot(snap, target, dry_run=False)
    assert plan["overwritten"]  # files existed
    pre = plan["pre_restore_backup"]
    assert pre is not None
    pre_dir = next(backups_dir.glob("pre-restore-*"))
    assert str(pre_dir) == pre
    assert (pre_dir / ".devin" / "config.json").read_bytes() == old_cfg
    # current files now match the snapshot again
    assert cfg.read_bytes() == (snap / ".devin" / "config.json").read_bytes()


def test_restore_refuses_to_overwrite_without_backup(
    data_dir, backups_dir, tmp_path
):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    restore.restore_snapshot(snap, target, dry_run=False)
    cfg = target / ".devin" / "config.json"
    cfg.write_text('{"edited": true}\n', encoding="utf-8")

    with pytest.raises(restore.RestoreError):
        restore.restore_snapshot(snap, target, dry_run=False, backup=False)
    # untouched
    assert cfg.read_text(encoding="utf-8") == '{"edited": true}\n'


def test_restore_warns_on_schema_version_mismatch(backups_dir, tmp_path):
    src = tmp_path / "old-data"
    fixtures.create_sessions_db(src / "cli" / "sessions.db", schema_version=15)
    snap = snapshot.create_snapshot(src, backups_dir)

    target = tmp_path / "new-data"
    fixtures.create_sessions_db(target / "cli" / "sessions.db", schema_version=17)

    plan = restore.restore_snapshot(snap, target, dry_run=True)
    assert any("15" in w and "17" in w for w in plan["warnings"])


def test_restore_no_schema_warning_when_versions_match(
    data_dir, backups_dir, tmp_path
):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    restore.restore_snapshot(snap, target, dry_run=False)
    plan = restore.restore_snapshot(snap, target, dry_run=True)
    assert plan["warnings"] == []
    assert plan["would_overwrite"]  # everything already exists


def test_restore_rejects_path_traversal(data_dir, backups_dir, tmp_path):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    manifest_path = snap / "manifest.json"
    manifest = _manifest(snap)
    manifest["files"].append(
        {"path": "../evil.txt", "kind": "file", "size": 1, "sha256": "x"}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(restore.RestoreError):
        restore.restore_snapshot(snap, tmp_path / "target", dry_run=False)
    # dry-run also refuses (planning stage validates paths)
    with pytest.raises(restore.RestoreError):
        restore.restore_snapshot(snap, tmp_path / "target", dry_run=True)


def test_restore_missing_manifest_raises(tmp_path):
    bogus = tmp_path / "not-a-snapshot"
    bogus.mkdir()
    with pytest.raises(snapshot.SnapshotError):
        restore.restore_snapshot(bogus, tmp_path / "t")


def test_restore_into_original_data_dir(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    (data_dir / ".devin" / "config.json").write_text(
        '{"drifted": 1}\n', encoding="utf-8"
    )
    plan = restore.restore_snapshot(snap, data_dir, dry_run=False)
    assert plan["pre_restore_backup"] is not None
    assert (data_dir / ".devin" / "config.json").read_bytes() == (
        snap / ".devin" / "config.json"
    ).read_bytes()


def test_pre_restore_inside_data_dir_not_resnapshotted(
    data_dir, backups_dir, tmp_path, monkeypatch
):
    """When the pre-restore safety copy falls back inside the data root
    (read-only media case), later snapshots must not pick up the stale
    databases it holds."""
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    target = tmp_path / "restore-target"
    restore.restore_snapshot(snap, target, dry_run=False)

    monkeypatch.setattr(
        restore, "_pre_restore_parent", lambda _snap, tgt: tgt
    )
    (target / ".devin" / "config.json").write_text(
        '{"edited": true}\n', encoding="utf-8"
    )
    plan = restore.restore_snapshot(snap, target, dry_run=False)
    pre_dir = Path(plan["pre_restore_backup"])
    assert pre_dir.parent == target
    assert (pre_dir / "cli" / "sessions.db").is_file()

    snap2 = snapshot.create_snapshot(target, backups_dir)
    paths = [f["path"] for f in _manifest(snap2)["files"]]
    assert "cli/sessions.db" in paths
    assert not any(p.startswith("pre-restore-") for p in paths)
