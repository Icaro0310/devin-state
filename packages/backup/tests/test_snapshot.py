import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from devin_backup import snapshot
from devin_backup.stores import discover_stores
from devin_internals import fixtures

EXPECTED_STORES = 5  # sessions.db + 2 acp-messages + state.vscdb + .devin/config.json


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_discover_stores_finds_all(data_dir):
    stores = discover_stores(data_dir)
    rels = sorted(s.rel_path for s in stores)
    assert "cli/sessions.db" in rels
    assert "User/globalStorage/state.vscdb" in rels
    assert ".devin/config.json" in rels
    acp = [r for r in rels if r.startswith("User/acp-messages/")]
    assert len(acp) == 2
    kinds = {s.rel_path: s.kind for s in stores}
    assert kinds["cli/sessions.db"] == "sqlite"
    assert kinds[".devin/config.json"] == "file"


def test_discover_stores_skips_genuine_pre_restore_backup(data_dir):
    """A ``pre-restore-<ts>`` dir with a ``kind: pre-restore`` manifest
    inside the data root is a restore artifact — its stale databases
    must not be discovered as live stores."""
    pre = data_dir / "pre-restore-20260101T000000Z"
    (pre / "cli").mkdir(parents=True)
    (pre / "manifest.json").write_text(
        json.dumps({"kind": "pre-restore", "files": []}), encoding="utf-8"
    )
    with sqlite3.connect(pre / "cli" / "sessions.db") as conn:
        conn.execute("CREATE TABLE t (v TEXT)")
    rels = {s.rel_path for s in discover_stores(data_dir)}
    assert "cli/sessions.db" in rels
    assert not any(r.startswith("pre-restore-") for r in rels)


def test_discover_stores_keeps_user_dir_sharing_pre_restore_prefix(
    data_dir,
):
    """A user folder that merely starts with ``pre-restore-`` but lacks
    the timestamped name/manifest shape is live data — it must be
    discovered, not silently skipped."""
    user_db = data_dir / "pre-restore-validation" / "state.vscdb"
    user_db.parent.mkdir(parents=True)
    with sqlite3.connect(user_db) as conn:
        conn.execute("CREATE TABLE t (v TEXT)")
    rels = {s.rel_path for s in discover_stores(data_dir)}
    assert "pre-restore-validation/state.vscdb" in rels


def test_snapshot_leaves_no_sqlite_sidecars_and_preserves_wal(
    data_dir, backups_dir, tmp_path
):
    """The copied db is converted to rollback journal — no
    ``-wal``/``-shm``/``-journal`` leftovers — while data committed to
    the source's WAL (not yet checkpointed) still lands in the snapshot."""
    src = tmp_path / "wal-data" / "cli"
    src.mkdir(parents=True)
    con = sqlite3.connect(src / "sessions.db")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t (v TEXT)")
    con.execute("INSERT INTO t VALUES ('in-wal')")
    con.commit()  # committed but not checkpointed — lives only in -wal
    snap = snapshot.create_snapshot(tmp_path / "wal-data", backups_dir)
    con.close()
    leftovers = [
        p
        for p in snap.rglob("*")
        if p.name.endswith(("-wal", "-shm", "-journal"))
    ]
    assert leftovers == []
    check = sqlite3.connect(snap / "cli" / "sessions.db")
    try:
        assert check.execute("SELECT v FROM t").fetchall() == [("in-wal",)]
    finally:
        check.close()


def test_snapshot_copies_all_stores_with_manifest(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    manifest = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["manifest_version"] == 2
    files = {f["path"]: f for f in manifest["files"]}
    assert len(files) == EXPECTED_STORES

    for rel, entry in files.items():
        copied = snap / rel
        assert copied.is_file(), rel
        assert entry["size"] == copied.stat().st_size
        assert entry["sha256"] == sha256(copied)

    # plain files are byte-identical to the source
    assert (snap / ".devin" / "config.json").read_bytes() == (
        data_dir / ".devin" / "config.json"
    ).read_bytes()


def test_snapshot_includes_stores_from_a_separate_config_root(
    data_dir, backups_dir, tmp_path
):
    from devin_backup.verify import verify_snapshot

    config_root = tmp_path / "config" / "Devin"
    acp_db = config_root / "User" / "acp-messages" / "gui.db"
    state_db = config_root / "User" / "globalStorage" / "state.vscdb"
    for db in (acp_db, state_db):
        db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE sample (value TEXT)")

    snap = snapshot.create_snapshot(data_dir, backups_dir, config_dir=config_root)
    manifest = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    config_files = {f["path"]: f for f in manifest["files"] if f["root"] == "config"}

    assert set(config_files) == {
        "User/acp-messages/gui.db",
        "User/globalStorage/state.vscdb",
    }
    assert (snap / "config" / "User" / "acp-messages" / "gui.db").is_file()
    assert verify_snapshot(snap)["ok"]


def test_snapshot_uses_sqlite_backup_api(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    manifest = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    entry = {f["path"]: f for f in manifest["files"]}["cli/sessions.db"]
    assert entry["copied_via"] == "sqlite-backup"

    # the copy is a real, consistent database with the same rows
    src = sqlite3.connect(data_dir / "cli" / "sessions.db")
    dst = sqlite3.connect(snap / "cli" / "sessions.db")
    n_src = src.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    n_dst = dst.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    assert n_dst == n_src and n_src > 0
    src.close()
    dst.close()


def test_snapshot_records_schema_version(data_dir, backups_dir):
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    manifest = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_versions"]["cli/sessions.db"] == 17
    entry = {f["path"]: f for f in manifest["files"]}["cli/sessions.db"]
    assert entry["schema_version"] == 17


def test_snapshot_records_older_schema_version(tmp_path, backups_dir):
    root = tmp_path / "data"
    fixtures.create_sessions_db(root / "cli" / "sessions.db", schema_version=15)
    snap = snapshot.create_snapshot(root, backups_dir)
    manifest = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_versions"]["cli/sessions.db"] == 15


def test_snapshot_falls_back_to_file_copy(tmp_path, backups_dir):
    root = tmp_path / "data"
    (root / "cli").mkdir(parents=True)
    fake = root / "cli" / "sessions.db"
    fake.write_bytes(b"this is not a sqlite database")
    snap = snapshot.create_snapshot(root, backups_dir)
    manifest = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    entry = {f["path"]: f for f in manifest["files"]}["cli/sessions.db"]
    assert entry["copied_via"] == "file-copy"
    assert entry["schema_version"] is None
    assert (snap / "cli" / "sessions.db").read_bytes() == fake.read_bytes()


def test_snapshot_excludes_backups_dir_inside_data_dir(data_dir):
    out = data_dir / "backups"
    snap1 = snapshot.create_snapshot(data_dir, out)
    snap2 = snapshot.create_snapshot(data_dir, out)
    m1 = json.loads((snap1 / "manifest.json").read_text(encoding="utf-8"))
    m2 = json.loads((snap2 / "manifest.json").read_text(encoding="utf-8"))
    assert len(m2["files"]) == len(m1["files"]) == EXPECTED_STORES


def test_snapshot_timestamped_and_unique(data_dir, backups_dir):
    now = datetime(2026, 9, 29, 20, 30, 0, tzinfo=timezone.utc)
    snap = snapshot.create_snapshot(data_dir, backups_dir, now=now)
    assert snap.name == "20260929T203000Z"
    snap2 = snapshot.create_snapshot(data_dir, backups_dir, now=now)
    assert snap2.name != snap.name
    snap3 = snapshot.create_snapshot(
        data_dir, backups_dir, now=now + timedelta(seconds=1)
    )
    assert snap3.name == "20260929T203001Z"


def test_snapshot_exclude_pattern_skips_stores(data_dir, backups_dir):
    snap = snapshot.create_snapshot(
        data_dir, backups_dir, exclude=("acp-messages",)
    )
    manifest = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    paths = [f["path"] for f in manifest["files"]]
    assert not any("acp-messages" in p for p in paths)
    assert "cli/sessions.db" in paths
    excluded = [e["path"] for e in manifest["excluded"]]
    assert len(excluded) == 2 and all("acp-messages" in p for p in excluded)


def test_snapshot_exclude_secrets_skips_vscdb(data_dir, backups_dir):
    snap = snapshot.create_snapshot(
        data_dir, backups_dir, exclude_secrets=True
    )
    manifest = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    paths = [f["path"] for f in manifest["files"]]
    assert "User/globalStorage/state.vscdb" not in paths
    assert not (snap / "User" / "globalStorage" / "state.vscdb").exists()
    excluded = [e["path"] for e in manifest["excluded"]]
    assert "User/globalStorage/state.vscdb" in excluded


@pytest.mark.skipif(os.name == "nt", reason="posix mode bits")
def test_snapshot_dir_is_owner_only(data_dir, backups_dir):
    import stat
    snap = snapshot.create_snapshot(data_dir, backups_dir)
    assert stat.S_IMODE(snap.stat().st_mode) == 0o700
    assert stat.S_IMODE(
        (snap / "manifest.json").stat().st_mode) == 0o600
    copied = snap / "cli" / "sessions.db"
    assert stat.S_IMODE(copied.stat().st_mode) == 0o600


def test_snapshot_empty_data_dir_raises(tmp_path, backups_dir):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(snapshot.SnapshotError):
        snapshot.create_snapshot(empty, backups_dir)
    assert not list(backups_dir.iterdir()) if backups_dir.exists() else True


def test_snapshot_missing_data_dir_raises(tmp_path, backups_dir):
    with pytest.raises(snapshot.SnapshotError):
        snapshot.create_snapshot(tmp_path / "nope", backups_dir)
