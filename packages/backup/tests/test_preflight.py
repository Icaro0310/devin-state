"""Tests for ``devin-backup preflight`` and ``preflight.run_preflight``."""

import json
import stat
import sys

import pytest
from devin_backup import cli, preflight, snapshot


def _run(data_dir, backups_dir, *extra):
    return cli.main(
        ["preflight", "--data-dir", str(data_dir), "--out", str(backups_dir),
         *extra]
    )


def _check(report, name):
    return next(c for c in report["checks"] if c["name"] == name)


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------

def test_preflight_all_pass(data_dir, backups_dir, capsys):
    rc = _run(data_dir, backups_dir)
    out = capsys.readouterr().out
    assert rc == 0
    assert "PASS" in out and "FAILED" not in out
    for name in ("data-root", "stores-found", "dest-writable", "free-space",
                 "tool-sqlite3", "no-inflight-snapshot", "latest-snapshot"):
        line = next(l for l in out.splitlines() if name in l)
        assert "PASS" in line
    # --data-dir without --config-dir → config check out of scope
    assert "config-root" not in out


def test_run_preflight_report_shape(data_dir, backups_dir):
    report = preflight.run_preflight(data_dir, backups_dir)
    assert report["ok"] is True
    assert report["config_dir"] is None
    assert report["estimated_bytes"] > 0
    statuses = {c["status"] for c in report["checks"]}
    assert statuses == {preflight.PASSED}
    assert report["summary"]["pass"] == len(report["checks"])
    assert all({"name", "status", "detail"} <= set(c)
               for c in report["checks"])


def test_preflight_config_root_pass_and_unknown(data_dir, backups_dir,
                                                tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    report = preflight.run_preflight(
        data_dir, backups_dir, config_dir=cfg, config_dir_explicit=True)
    assert _check(report, "config-root")["status"] == preflight.PASSED

    # a missing *default* root degrades to unknown — fail-closed, not pass
    report = preflight.run_preflight(
        data_dir, backups_dir, config_dir=tmp_path / "nope")
    assert _check(report, "config-root")["status"] == preflight.UNKNOWN
    assert report["ok"] is False

    # an explicitly requested root that does not exist is a hard fail
    report = preflight.run_preflight(
        data_dir, backups_dir, config_dir=tmp_path / "nope",
        config_dir_explicit=True)
    assert _check(report, "config-root")["status"] == preflight.FAIL


# ---------------------------------------------------------------------------
# per-check failures
# ---------------------------------------------------------------------------

def test_preflight_missing_data_dir(tmp_path, backups_dir, capsys):
    rc = _run(tmp_path / "nope", backups_dir)
    out = capsys.readouterr().out
    assert rc == 1
    assert "data-root" in out and "FAIL" in out


def test_preflight_data_dir_is_file(tmp_path, backups_dir):
    f = tmp_path / "file"
    f.write_text("x")
    report = preflight.run_preflight(f, backups_dir)
    assert _check(report, "data-root")["status"] == preflight.FAIL


def test_preflight_no_stores(tmp_path, backups_dir, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = _run(empty, backups_dir)
    out = capsys.readouterr().out
    assert rc == 1
    assert "stores-found" in out
    assert "FAIL" in out


def test_preflight_unreadable_store(data_dir, backups_dir, monkeypatch):
    monkeypatch.setattr(
        preflight, "_size_stores", lambda stores: (10, 1))
    report = preflight.run_preflight(data_dir, backups_dir)
    check = _check(report, "stores-found")
    assert check["status"] == preflight.FAIL
    assert "unreadable" in check["detail"]
    assert report["ok"] is False


def test_preflight_dest_is_file(data_dir, tmp_path):
    f = tmp_path / "not-a-dir"
    f.write_text("x")
    report = preflight.run_preflight(data_dir, f)
    check = _check(report, "dest-writable")
    assert check["status"] == preflight.FAIL
    assert "not a directory" in check["detail"]


def test_preflight_dest_not_writable(data_dir, backups_dir, monkeypatch):
    monkeypatch.setattr(
        preflight, "_writable_probe", lambda d: "simulated denial")
    report = preflight.run_preflight(data_dir, backups_dir)
    assert _check(report, "dest-writable")["status"] == preflight.FAIL
    assert report["ok"] is False


@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX mode bits are advisory on Windows")
def test_preflight_dest_readonly_dir(data_dir, backups_dir):
    backups_dir.mkdir()
    backups_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        report = preflight.run_preflight(data_dir, backups_dir)
    finally:
        backups_dir.chmod(stat.S_IRWXU)
    assert _check(report, "dest-writable")["status"] == preflight.FAIL


def test_preflight_free_space_fail(data_dir, backups_dir, monkeypatch):
    class _Usage:
        total = 10
        used = 9
        free = 1

    monkeypatch.setattr(
        preflight.shutil, "disk_usage", lambda p: _Usage())
    report = preflight.run_preflight(data_dir, backups_dir)
    check = _check(report, "free-space")
    assert check["status"] == preflight.FAIL
    assert "<" in check["detail"]


def test_preflight_free_space_unknown_when_estimate_unknown(
        tmp_path, backups_dir):
    report = preflight.run_preflight(tmp_path / "nope", backups_dir)
    assert _check(report, "free-space")["status"] == preflight.UNKNOWN


def test_preflight_inflight_snapshot(data_dir, backups_dir):
    backups_dir.mkdir(parents=True)
    stale = backups_dir / "20260101T000000Z"  # timestamp dir, no manifest
    stale.mkdir()
    report = preflight.run_preflight(data_dir, backups_dir)
    check = _check(report, "no-inflight-snapshot")
    assert check["status"] == preflight.FAIL
    assert stale.name in check["detail"]


def test_preflight_inflight_ignores_complete_snapshots(
        data_dir, backups_dir):
    snapshot.create_snapshot(data_dir, backups_dir)
    report = preflight.run_preflight(data_dir, backups_dir)
    assert _check(report, "no-inflight-snapshot")["status"] == preflight.PASSED
    assert _check(report, "latest-snapshot")["status"] == preflight.PASSED


def test_preflight_latest_corrupt_manifest(data_dir, backups_dir):
    backups_dir.mkdir(parents=True)
    snap = backups_dir / "20260101T000000Z"
    snap.mkdir()
    (snap / "manifest.json").write_text("{not json")
    report = preflight.run_preflight(data_dir, backups_dir)
    check = _check(report, "latest-snapshot")
    assert check["status"] == preflight.FAIL
    assert "corrupt" in check["detail"]


def test_preflight_exclude_filters_estimate(data_dir, backups_dir):
    full = preflight.run_preflight(data_dir, backups_dir)
    reduced = preflight.run_preflight(
        data_dir, backups_dir, exclude=("sessions.db", "*.vscdb"))
    assert reduced["estimated_bytes"] < full["estimated_bytes"]
    assert _check(reduced, "stores-found")["status"] == preflight.PASSED


def test_preflight_exclude_everything_fails(data_dir, backups_dir):
    report = preflight.run_preflight(data_dir, backups_dir, exclude=("*",))
    assert _check(report, "stores-found")["status"] == preflight.FAIL
    assert report["ok"] is False


# ---------------------------------------------------------------------------
# --remote checks
# ---------------------------------------------------------------------------

def test_preflight_remote_local_dir(data_dir, backups_dir, tmp_path):
    dest = tmp_path / "nas"
    dest.mkdir()
    report = preflight.run_preflight(data_dir, backups_dir, remote=str(dest))
    assert _check(report, "remote-dest")["status"] == preflight.PASSED

    report = preflight.run_preflight(
        data_dir, backups_dir, remote=str(tmp_path / "unmounted"))
    assert _check(report, "remote-dest")["status"] == preflight.FAIL


def test_preflight_remote_ssh_needs_rsync(data_dir, backups_dir,
                                          monkeypatch):
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)
    report = preflight.run_preflight(
        data_dir, backups_dir, remote="me@nas.example:/backups")
    check = _check(report, "tool-rsync")
    assert check["status"] == preflight.FAIL
    assert "rsync" in check["detail"]

    monkeypatch.setattr(
        preflight.shutil, "which", lambda name: "/usr/bin/rsync")
    report = preflight.run_preflight(
        data_dir, backups_dir, remote="me@nas.example:/backups")
    assert _check(report, "tool-rsync")["status"] == preflight.PASSED


# ---------------------------------------------------------------------------
# exit codes + --json
# ---------------------------------------------------------------------------

def test_preflight_json_ok(data_dir, backups_dir, capsys):
    rc = _run(data_dir, backups_dir, "--json")
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["summary"]["pass"] == len(payload["checks"])
    for check in payload["checks"]:
        assert {"name", "status", "detail"} <= set(check)
        assert check["status"] in {"pass", "fail", "unknown"}
    assert payload["data_dir"] == str(data_dir)
    assert payload["out"] == str(backups_dir)


def test_preflight_json_failure_still_prints(data_dir, backups_dir,
                                             capsys):
    backups_dir.mkdir(parents=True)
    (backups_dir / "20260101T000000Z").mkdir()
    rc = _run(data_dir, backups_dir, "--json")
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["summary"]["fail"] >= 1


def test_preflight_exit_1_on_unknown(data_dir, backups_dir, tmp_path):
    # an unevaluable check (default config root missing) must not pass
    # silently — ok is False even with no hard FAIL.
    report = preflight.run_preflight(
        data_dir, backups_dir, config_dir=tmp_path / "no-config")
    assert _check(report, "config-root")["status"] == preflight.UNKNOWN
    assert report["ok"] is False


def test_preflight_usage_error_is_2(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["preflight", "--no-such-flag"])
    assert exc.value.code == 2


def test_preflight_help_documents_exit_codes(capsys):
    with pytest.raises(SystemExit):
        cli.main(["preflight", "--help"])
    out = capsys.readouterr().out
    assert "0 = all checks pass" in out
    assert "usage" in out.lower()
