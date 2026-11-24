"""Tests for compressed snapshot archives (.tar.zst / .tar.gz)."""

import json

import pytest
from devin_backup import archive, restore, rotate, snapshot, verify
from devin_backup.snapshot import SnapshotError, load_manifest


def _make_snapshot(data_dir, backups_dir, **kwargs):
    return snapshot.create_snapshot(data_dir, backups_dir, **kwargs)


def test_create_compress_returns_archive(data_dir, backups_dir):
    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    assert archive.is_archive(snap)
    assert snap.name.endswith(archive.preferred_suffix())
    # the plain dir is gone — only the archive remains
    assert not (backups_dir / snap.name.split(".")[0]).is_dir()
    manifest = load_manifest(snap)
    assert manifest["manifest_version"] == snapshot.MANIFEST_VERSION
    assert manifest["files"]


def test_manifest_is_first_member(data_dir, backups_dir):
    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    with archive._open_reader(snap) as tf:
        first = tf.next()
    assert first.name == "manifest.json"


def test_verify_archive_ok_and_manifest(data_dir, backups_dir):
    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    report = archive.verify_archive(snap)
    assert report["ok"], report["results"]
    assert report["checked"] == len(load_manifest(snap)["files"])


def test_verify_archive_detects_corruption(data_dir, backups_dir):
    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    data = bytearray(snap.read_bytes())
    data[len(data) // 2] ^= 0xFF  # flip a byte mid-payload
    snap.write_bytes(bytes(data))
    # either the stream fails to decode (raise) or a hash mismatches
    try:
        report = archive.verify_archive(snap)
    except SnapshotError:
        return
    assert not report["ok"]


def test_materialized_roundtrip(data_dir, backups_dir):
    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    with archive.materialized(snap) as snap_dir:
        assert snap_dir.is_dir()
        assert (snap_dir / "manifest.json").is_file()
        # every manifest file exists in the extraction
        manifest = load_manifest(snap_dir)
        for entry in manifest["files"]:
            sp = entry.get("snapshot_path") or entry["path"]
            assert (snap_dir / sp).is_file()
    # temp dir is cleaned up
    assert not list(backups_dir.glob(".extract-*"))


def test_verify_command_path_works_on_archive(data_dir, backups_dir):
    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    with archive.materialized(snap) as snap_dir:
        report = verify.verify_snapshot(snap_dir)
    assert report["ok"], report["results"]


def test_restore_dry_run_from_archive(data_dir, backups_dir, tmp_path):
    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    target = tmp_path / "restore-target"
    with archive.materialized(snap) as snap_dir:
        plan = restore.restore_snapshot(snap_dir, target, dry_run=True)
    assert plan["dry_run"] is True
    assert plan["would_write"]


def test_list_and_rotate_include_archives(data_dir, backups_dir):
    for _ in range(3):
        _make_snapshot(data_dir, backups_dir, compress=True)
    listed = rotate.list_snapshots(backups_dir)
    arch_entries = [s for s in listed if s["compressed"]]
    assert len(arch_entries) == 3
    assert all(s["kind"] == "snapshot" for s in arch_entries)

    deleted = rotate.rotate_snapshots(backups_dir, keep=1)
    assert len(deleted) == 2
    remaining = rotate.list_snapshots(backups_dir)
    assert len([s for s in remaining if s["compressed"]]) == 1
    # archives are unlinked, not rmtree'd
    for d in deleted:
        assert not d.exists()


def test_copy_to_archive(data_dir, backups_dir, tmp_path):
    from devin_backup.secondary import copy_to

    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    dest_parent = tmp_path / "secondary"
    dest_parent.mkdir()
    result = copy_to(snap, dest_parent)
    dest = dest_parent / snap.name
    assert dest.is_file()
    assert result["verify"]["ok"]
    assert result["compressed"] is True


def test_extract_rejects_traversal(data_dir, backups_dir, tmp_path):
    import tarfile

    _make_snapshot(data_dir, backups_dir)
    evil = backups_dir / "20260101T000000Z.tar.zst"
    # craft a tar.zst with a .. member using the same suffix machinery
    suffix = archive.preferred_suffix()
    evil = backups_dir / ("20260101T000000Z" + suffix)
    with archive._open_writer(evil, suffix) as tf:
        import io
        data = b"x"
        ti = tarfile.TarInfo("../escape.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    with pytest.raises(SnapshotError):
        archive.extract_archive(evil, tmp_path)
    assert not (tmp_path.parent / "escape.txt").exists()
    assert not (backups_dir / "escape.txt").exists()


def test_compress_cmd_keep(data_dir, backups_dir, tmp_path, capsys):
    from devin_backup import cli

    snap = _make_snapshot(data_dir, backups_dir)
    args = cli.build_parser().parse_args(
        ["compress", str(snap), "--keep"])
    assert args.func(args) == 0
    out = backups_dir / (snap.name + archive.preferred_suffix())
    assert out.is_file()
    assert snap.is_dir()  # --keep preserved it


def test_compress_cmd_replaces(data_dir, backups_dir):
    from devin_backup import cli

    snap = _make_snapshot(data_dir, backups_dir)
    args = cli.build_parser().parse_args(["compress", str(snap)])
    assert args.func(args) == 0
    assert not snap.exists()
    assert archive.is_archive(
        backups_dir / (snap.name + archive.preferred_suffix()))


def test_compress_cmd_rejects_nontimestamp(data_dir, backups_dir, tmp_path):
    from devin_backup import cli

    weird = backups_dir / "pre-restore-20260101T000000Z"
    weird.mkdir(parents=True)
    (weird / "manifest.json").write_text(json.dumps({
        "manifest_version": 2, "files": []}))
    args = cli.build_parser().parse_args(["compress", str(weird)])
    assert args.func(args) == 2
    assert weird.is_dir()


def test_write_archive_creates_private_file(data_dir, backups_dir):
    """The finished archive (and the temp file it renames from) is 0600 —
    snapshots can carry credentials."""
    import os

    snap = _make_snapshot(data_dir, backups_dir)
    out = archive.write_archive(snap)
    if os.name == "posix":
        assert out.stat().st_mode & 0o777 == 0o600


def test_extract_archive_refuses_existing_dest(
    data_dir, backups_dir, tmp_path
):
    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    dest = tmp_path / archive.stem_name(snap)
    dest.mkdir()
    with pytest.raises(SnapshotError):
        archive.extract_archive(snap, tmp_path)
    assert not list(dest.iterdir())


def test_materialized_readonly_parent(data_dir, backups_dir):
    import os

    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    backups_dir.chmod(0o555)
    try:
        if os.access(backups_dir, os.W_OK):
            pytest.skip("parent stays writable (e.g. running as root)")
        with archive.materialized(snap) as snap_dir:
            assert snap_dir.is_dir()
            assert snap_dir.parent != backups_dir
            report = verify.verify_snapshot(snap_dir)
        assert report["ok"], report["results"]
    finally:
        backups_dir.chmod(0o755)


def test_restore_from_readonly_media_backups_land_by_target(
    data_dir, backups_dir, tmp_path
):
    """Pre-restore safety copies must be persistent — when the snapshot
    had to be materialized in system temp (read-only media) they go next
    to the restore target, not into the temp dir."""
    import os
    from pathlib import Path

    snap = _make_snapshot(data_dir, backups_dir, compress=True)
    target = tmp_path / "restore-target"
    backups_dir.chmod(0o555)
    try:
        if os.access(backups_dir, os.W_OK):
            pytest.skip("parent stays writable (e.g. running as root)")
        with archive.materialized(snap) as snap_dir:
            assert snap_dir.parent != backups_dir
            first = restore.restore_snapshot(
                snap_dir, target, dry_run=False
            )
            assert first["pre_restore_backup"] is None
            second = restore.restore_snapshot(
                snap_dir, target, dry_run=False
            )
    finally:
        backups_dir.chmod(0o755)
    pre = Path(second["pre_restore_backup"])
    assert pre.parent == target.parent
    assert pre.is_dir()
    assert (pre / "manifest.json").is_file()


def test_restore_pre_restore_inside_target_when_parents_ro(
    data_dir, backups_dir, tmp_path
):
    """Chain: snapshot parent unwritable → target parent unwritable →
    the safety backup lands *inside* the writable target."""
    import os
    from pathlib import Path

    ro_backups = tmp_path / "ro-backups"
    ro_backups.mkdir()
    snap = _make_snapshot(data_dir, ro_backups, compress=True)
    target = tmp_path / "tgt"
    target.mkdir()  # the writable mount point exists before parents lock
    ro_backups.chmod(0o555)
    tmp_path.chmod(0o555)
    try:
        if os.access(ro_backups, os.W_OK) or os.access(tmp_path, os.W_OK):
            pytest.skip("parents stay writable (e.g. running as root)")
        with archive.materialized(snap) as snap_dir:
            first = restore.restore_snapshot(
                snap_dir, target, dry_run=False
            )
            assert first["pre_restore_backup"] is None
            second = restore.restore_snapshot(
                snap_dir, target, dry_run=False
            )
    finally:
        tmp_path.chmod(0o755)
        ro_backups.chmod(0o755)
    pre = Path(second["pre_restore_backup"])
    assert pre.parent == target
    assert pre.is_dir()
    assert (pre / "manifest.json").is_file()
