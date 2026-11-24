import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from devin_backup import archive, rotate, snapshot

T0 = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)


def _make_snapshots(data_dir, backups_dir, n):
    return [
        snapshot.create_snapshot(
            data_dir, backups_dir, now=T0 + timedelta(hours=i)
        )
        for i in range(n)
    ]


def _set_mtime(path, moment):
    ts = moment.timestamp()
    os.utime(path, (ts, ts))


def _aged_snapshots(data_dir, backups_dir, ages_days):
    """Snapshots whose dir mtimes are staggered ``ages_days`` into the past
    relative to ``NOW``."""
    snaps = _make_snapshots(data_dir, backups_dir, len(ages_days))
    for snap, age in zip(snaps, ages_days):
        _set_mtime(snap, NOW - timedelta(days=age))
    return snaps


def test_rotate_keeps_newest_n(data_dir, backups_dir):
    snaps = _make_snapshots(data_dir, backups_dir, 4)
    deleted = rotate.rotate_snapshots(backups_dir, keep=2)
    assert sorted(p.name for p in deleted) == sorted(p.name for p in snaps[:2])
    remaining = sorted(p.name for p in backups_dir.iterdir())
    assert remaining == sorted(p.name for p in snaps[2:])
    for d in snaps[2:]:
        assert (d / "manifest.json").is_file()


def test_rotate_noop_when_at_or_below_keep(data_dir, backups_dir):
    _make_snapshots(data_dir, backups_dir, 2)
    assert rotate.rotate_snapshots(backups_dir, keep=5) == []
    assert len(list(backups_dir.iterdir())) == 2


def test_rotate_never_touches_pre_restore_backups(data_dir, backups_dir):
    _make_snapshots(data_dir, backups_dir, 2)
    pre = backups_dir / "pre-restore-20990101T000000Z"
    pre.mkdir()
    (pre / "manifest.json").write_text(
        json.dumps({"manifest_version": 1, "kind": "pre-restore", "files": []}),
        encoding="utf-8",
    )
    rotate.rotate_snapshots(backups_dir, keep=1)
    assert pre.is_dir()
    assert len(list(backups_dir.iterdir())) == 2  # 1 kept snapshot + pre-restore


def test_rotate_never_touches_foreign_dirs(data_dir, backups_dir):
    _make_snapshots(data_dir, backups_dir, 2)
    foreign = backups_dir / "some-other-tool"
    foreign.mkdir()
    rotate.rotate_snapshots(backups_dir, keep=1)
    assert foreign.is_dir()


def test_rotate_requires_keep_at_least_one(backups_dir):
    with pytest.raises(ValueError):
        rotate.rotate_snapshots(backups_dir, keep=0)


def test_rotate_requires_a_criterion(backups_dir):
    with pytest.raises(ValueError):
        rotate.rotate_snapshots(backups_dir)


def test_rotate_missing_backups_dir(tmp_path):
    assert rotate.rotate_snapshots(tmp_path / "nope", keep=3) == []
    assert (
        rotate.rotate_snapshots(
            tmp_path / "nope", older_than=timedelta(days=30)
        )
        == []
    )


@pytest.mark.parametrize(
    "text,expected",
    [
        ("30d", timedelta(days=30)),
        ("12h", timedelta(hours=12)),
        ("4w", timedelta(weeks=4)),
        ("7D", timedelta(days=7)),
        (" 2w ", timedelta(weeks=2)),
    ],
)
def test_parse_duration(text, expected):
    assert rotate.parse_duration(text) == expected


@pytest.mark.parametrize("bad", ["", "30", "d", "30x", "1.5d", "-3d", "abc"])
def test_parse_duration_rejects_garbage(bad):
    with pytest.raises(ValueError):
        rotate.parse_duration(bad)


def test_rotate_older_than_deletes_only_aged(data_dir, backups_dir):
    snaps = _aged_snapshots(data_dir, backups_dir, [60, 40, 10, 1])
    deleted = rotate.rotate_snapshots(
        backups_dir, older_than=timedelta(days=30), now=NOW
    )
    assert sorted(p.name for p in deleted) == sorted(
        p.name for p in snaps[:2]
    )
    remaining = sorted(p.name for p in backups_dir.iterdir())
    assert remaining == sorted(p.name for p in snaps[2:])


def test_rotate_older_than_can_delete_everything(data_dir, backups_dir):
    _aged_snapshots(data_dir, backups_dir, [60, 40])
    deleted = rotate.rotate_snapshots(
        backups_dir, older_than=timedelta(days=30), now=NOW
    )
    assert len(deleted) == 2
    assert list(backups_dir.iterdir()) == []


def test_rotate_older_than_keep_is_a_floor(data_dir, backups_dir):
    snaps = _aged_snapshots(data_dir, backups_dir, [60, 50, 40, 35])
    deleted = rotate.rotate_snapshots(
        backups_dir, keep=2, older_than=timedelta(days=30), now=NOW
    )
    # all four are aged, but the keep floor protects the two newest
    assert sorted(p.name for p in deleted) == sorted(
        p.name for p in snaps[:2]
    )
    remaining = sorted(p.name for p in backups_dir.iterdir())
    assert remaining == sorted(p.name for p in snaps[2:])


def test_rotate_older_than_floor_means_noop(data_dir, backups_dir):
    _aged_snapshots(data_dir, backups_dir, [60, 50])
    assert (
        rotate.rotate_snapshots(
            backups_dir, keep=5, older_than=timedelta(days=30), now=NOW
        )
        == []
    )
    assert len(list(backups_dir.iterdir())) == 2


def test_rotate_older_than_never_touches_pre_restore(data_dir, backups_dir):
    _aged_snapshots(data_dir, backups_dir, [60])
    pre = backups_dir / "pre-restore-20990101T000000Z"
    pre.mkdir()
    (pre / "manifest.json").write_text(
        json.dumps({"manifest_version": 1, "kind": "pre-restore", "files": []}),
        encoding="utf-8",
    )
    _set_mtime(pre, NOW - timedelta(days=90))
    rotate.rotate_snapshots(
        backups_dir, older_than=timedelta(days=30), now=NOW
    )
    assert pre.is_dir()


def test_list_snapshots_sorted_newest_first(data_dir, backups_dir):
    snaps = _make_snapshots(data_dir, backups_dir, 3)
    listed = rotate.list_snapshots(backups_dir)
    assert [s["name"] for s in listed] == [s.name for s in reversed(snaps)]
    first = listed[0]
    assert first["files"] == 5
    assert first["size"] > 0
    assert first["kind"] == "snapshot"
    assert first["schema_versions"]["cli/sessions.db"] == 17


def test_list_snapshots_marks_pre_restore(data_dir, backups_dir):
    _make_snapshots(data_dir, backups_dir, 1)
    pre = backups_dir / "pre-restore-20990101T000000Z"
    pre.mkdir()
    (pre / "manifest.json").write_text(
        json.dumps({"manifest_version": 1, "kind": "pre-restore", "files": []}),
        encoding="utf-8",
    )
    kinds = {s["name"]: s["kind"] for s in rotate.list_snapshots(backups_dir)}
    assert kinds["pre-restore-20990101T000000Z"] == "pre-restore"


def test_list_snapshots_empty(tmp_path):
    assert rotate.list_snapshots(tmp_path / "nope") == []


def test_rotate_ignores_unreadable_archives(data_dir, backups_dir):
    """A ``.tar.*``-looking file with no readable manifest is neither
    counted in the keep quota nor deleted — only real snapshots compete."""
    snaps = _make_snapshots(data_dir, backups_dir, 2)
    garbage = backups_dir / "20990101T000000Z.tar.gz"
    garbage.write_bytes(b"not a tar at all")
    deleted = rotate.rotate_snapshots(backups_dir, keep=1)
    assert [p.name for p in deleted] == [snaps[0].name]
    assert snaps[1].is_dir()
    assert garbage.is_file()


def test_rotate_same_second_archive_orders_by_stem(
    data_dir, backups_dir
):
    """Two archives created in the same second get ``<ts>`` and
    ``<ts>-2`` — the ``-2`` one is newer and must survive keep=1."""
    first = snapshot.create_snapshot(
        data_dir, backups_dir, now=T0, compress=True
    )
    second = snapshot.create_snapshot(
        data_dir, backups_dir, now=T0, compress=True
    )
    assert "-2." in second.name
    deleted = rotate.rotate_snapshots(backups_dir, keep=1)
    assert [p.name for p in deleted] == [first.name]
    assert second.is_file()


def test_rotate_compress_keep_counts_as_one_point(data_dir, backups_dir):
    """``compress --keep`` leaves dir + archive — one recovery point,
    not two snapshots in the keep quota."""
    snap = snapshot.create_snapshot(data_dir, backups_dir, now=T0)
    arc = archive.write_archive(snap)  # dir kept, same manifest
    newer = snapshot.create_snapshot(
        data_dir, backups_dir, now=T0 + timedelta(hours=1)
    )
    assert rotate.rotate_snapshots(backups_dir, keep=2) == []
    deleted = rotate.rotate_snapshots(backups_dir, keep=1)
    assert sorted(p.name for p in deleted) == sorted(
        [snap.name, arc.name]
    )
    assert newer.is_dir()


def test_rotate_differing_manifest_same_stem_counts_twice(
    data_dir, backups_dir
):
    """Same stem but different manifests → two different snapshots
    sharing a name, counted separately."""
    snap = snapshot.create_snapshot(data_dir, backups_dir, now=T0)
    arc = archive.write_archive(snap)
    # same name, different content — hand-edited manifest in the dir
    manifest = snap / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["files"].append({"path": "extra.db", "size": 0})
    manifest.write_text(json.dumps(data), encoding="utf-8")
    newer = snapshot.create_snapshot(
        data_dir, backups_dir, now=T0 + timedelta(hours=1)
    )
    # 3 distinct recovery points → keep=2 drops exactly one path: one of
    # the same-stem twins. If the pair were wrongly merged into a single
    # point there would be only 2 points and zero deletions.
    deleted = rotate.rotate_snapshots(backups_dir, keep=2)
    assert len(deleted) == 1
    assert deleted[0].name in {snap.name, arc.name}
    assert newer.is_dir()
    surviving = {p.name for p in (snap, arc) if p.exists()}
    assert len(surviving) == 1


def test_list_snapshots_orders_same_second_archives(
    data_dir, backups_dir
):
    first = snapshot.create_snapshot(
        data_dir, backups_dir, now=T0, compress=True
    )
    second = snapshot.create_snapshot(
        data_dir, backups_dir, now=T0, compress=True
    )
    names = [s["name"] for s in rotate.list_snapshots(backups_dir)]
    assert names == [second.name, first.name]


def test_rotate_skips_archive_with_nonobject_manifest(
    data_dir, backups_dir
):
    """A ``.tar.*`` whose manifest.json is valid JSON but not an object
    (``[]``) must not crash rotation — it is skipped like any other
    unidentifiable file."""
    import io
    import tarfile

    snaps = _make_snapshots(data_dir, backups_dir, 2)
    bad = backups_dir / "20990101T000000Z.tar.gz"
    payload = b"[]"
    with tarfile.open(bad, "w:gz") as tf:
        ti = tarfile.TarInfo("manifest.json")
        ti.size = len(payload)
        tf.addfile(ti, io.BytesIO(payload))
    deleted = rotate.rotate_snapshots(backups_dir, keep=1)
    assert [p.name for p in deleted] == [snaps[0].name]
    assert snaps[1].is_dir()
    assert bad.is_file()


def test_rotate_dir_with_nonobject_manifest(data_dir, backups_dir):
    """A snapshot dir whose manifest.json is ``[]`` keeps the dir-only
    semantics: it counts for rotation but must not crash."""
    _make_snapshots(data_dir, backups_dir, 2)
    weird = backups_dir / "20990101T000000Z"
    weird.mkdir()
    (weird / "manifest.json").write_text("[]", encoding="utf-8")
    deleted = rotate.rotate_snapshots(backups_dir, keep=1)
    assert len(deleted) == 2
