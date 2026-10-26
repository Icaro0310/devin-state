"""``report --project`` — linear growth projection from the observation
window each store carries (first-seen → now).

Determinism comes from ``space_report(now=...)`` plus fixtures whose
timestamps are pinned ``OLD_S`` (10 days before ``NOW_S``).
"""

import json
import os

import pytest
from conftest import NOW_S, OLD_S, add_gui_session, add_session
from devin_janitor.cli import main
from devin_janitor.report import (
    growth_projection,
    parse_horizon,
    render_space_report,
    space_report,
)

# --------------------------------------------------------------- parse ----


def test_parse_horizon_units():
    assert parse_horizon("90d") == 90.0
    assert parse_horizon("90") == 90.0  # bare number = days
    assert parse_horizon("2w") == 14.0
    assert parse_horizon("48h") == 2.0
    assert parse_horizon("1.5d") == 1.5
    assert parse_horizon(" 30D ") == 30.0  # spaces + case tolerated


@pytest.mark.parametrize(
    "bad", ["", "abc", "-5d", "0d", "0", "d", "1.5x", "3m", "90 d!"]
)
def test_parse_horizon_invalid(bad):
    with pytest.raises(ValueError, match="--project"):
        parse_horizon(bad)


# -------------------------------------------------------------- model ----


def _by_name(proj):
    return {s["name"]: s for s in proj["stores"]}


def test_growth_projection_linear_rate(devin_dir):
    """Rate = bytes ÷ days-since-first-seen; projected = bytes + rate·N."""
    add_session(devin_dir.sessions_db, "s1", title="real work",
                user_msgs=10, tool_calls=5)
    add_gui_session(devin_dir.acp_messages_dir, "g1", title="gui")
    proj = growth_projection(
        space_report(devin_dir, now=NOW_S)["stores"], 10.0, now=NOW_S
    )
    assert proj["model"] == "linear" and proj["horizon_days"] == 10.0
    assert "estimate" in proj["caveat"]

    stores = _by_name(proj)
    sdb = stores["sessions.db"]
    assert sdb["ok"]
    # sessions are pinned OLD_S → 10-day window (mtime granularity stays
    # well inside this tolerance even on FAT-era filesystems)
    assert sdb["window_days"] == pytest.approx(10.0, abs=0.01)
    assert sdb["rate_bytes_per_day"] == pytest.approx(
        sdb["bytes"] / 10.0, rel=0.01
    )
    assert sdb["delta_bytes"] == pytest.approx(sdb["bytes"], rel=0.01)
    assert sdb["projected_bytes"] == pytest.approx(2 * sdb["bytes"],
                                                 rel=0.01)

    acp = stores["acp-messages"]
    assert acp["ok"]
    assert acp["window_days"] == pytest.approx(10.0, abs=0.01)
    assert acp["projected_bytes"] > acp["bytes"]


def test_growth_projection_scales_with_horizon(devin_dir):
    add_session(devin_dir.sessions_db, "s1", title="real work",
                user_msgs=10, tool_calls=5)
    stores = space_report(devin_dir, now=NOW_S)["stores"]
    p30 = _by_name(growth_projection(stores, 30.0, now=NOW_S))
    p90 = _by_name(growth_projection(stores, 90.0, now=NOW_S))
    s30, s90 = p30["sessions.db"], p90["sessions.db"]
    assert s90["delta_bytes"] == pytest.approx(3 * s30["delta_bytes"],
                                             rel=1e-6)


def test_growth_projection_insufficient_window(devin_dir):
    """A store created today has no rate — insufficient, not a fake."""
    add_session(devin_dir.sessions_db, "fresh", title="new",
                user_msgs=3, created=NOW_S, last_activity=NOW_S)
    proj = growth_projection(
        space_report(devin_dir, now=NOW_S)["stores"], 30.0, now=NOW_S
    )
    sdb = _by_name(proj)["sessions.db"]
    assert not sdb["ok"]
    assert "insufficient data" in sdb["reason"]


def test_growth_projection_no_first_seen(devin_dir):
    """Empty sessions.db → no session span → no honest rate."""
    proj = growth_projection(
        space_report(devin_dir, now=NOW_S)["stores"], 30.0, now=NOW_S
    )
    stores = _by_name(proj)
    assert stores["sessions.db"]["ok"] is False
    assert stores["sessions.db"]["reason"] == "no first-seen timestamp"
    # state.vscdb missing in the fixture; session_locks empty → no span
    assert stores["state.vscdb"]["ok"] is False
    assert stores["session_locks"]["ok"] is False


def test_growth_projection_missing_store(tmp_path):
    proj = growth_projection(
        [{"name": "x", "exists": False, "bytes": 0}], 10.0, now=NOW_S
    )
    assert proj["stores"][0]["reason"] == "store missing"


def test_growth_projection_standalone_newest_does_not_leak(devin_dir):
    """The window is first-seen→now, not first-seen→last-seen."""
    add_session(devin_dir.sessions_db, "s1", title="real work",
                user_msgs=5, created=OLD_S, last_activity=NOW_S)
    proj = growth_projection(
        space_report(devin_dir, now=NOW_S)["stores"], 10.0, now=NOW_S
    )
    sdb = _by_name(proj)["sessions.db"]
    assert sdb["window_days"] == pytest.approx(10.0, abs=0.01)


def test_space_report_embeds_projection(devin_dir):
    add_session(devin_dir.sessions_db, "s1", title="real work",
                user_msgs=10, tool_calls=5)
    rep = space_report(devin_dir, now=NOW_S, project_days=90.0)
    assert rep["projection"]["horizon_days"] == 90.0
    assert _by_name(rep["projection"])["sessions.db"]["ok"]
    # absent without the flag — report shape unchanged
    assert "projection" not in space_report(devin_dir)


# ------------------------------------------------------------- render ----


def test_render_space_report_projection(devin_dir):
    add_session(devin_dir.sessions_db, "s1", title="real work",
                user_msgs=10, tool_calls=5)
    out = render_space_report(
        space_report(devin_dir, now=NOW_S, project_days=90.0)
    )
    assert "growth projection +90d" in out
    assert "estimate" in out
    assert "sessions.db" in out and "/d over" in out
    # honesty: stores without a window say so instead of printing a number
    assert "insufficient data" in out

    out = render_space_report(
        space_report(devin_dir, now=NOW_S, project_days=12.0)
    )
    assert "growth projection +12h" not in out  # 12d stays days
    assert "growth projection +12d" in out


def test_render_projection_short_horizon_in_hours(devin_dir):
    add_session(devin_dir.sessions_db, "s1", title="real work",
                user_msgs=10, tool_calls=5)
    out = render_space_report(
        space_report(devin_dir, now=NOW_S, project_days=0.5)
    )
    assert "growth projection +12h" in out


# ---------------------------------------------------------------- cli ----


def test_report_cli_project_human(devin_dir, tmp_path, capsys):
    add_session(devin_dir.sessions_db, "s1", title="real work",
                user_msgs=10, tool_calls=5, created=OLD_S)
    add_gui_session(devin_dir.acp_messages_dir, "g1")
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--pending-file", str(tmp_path / "p.json"),
        "--project", "90d",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "growth projection +90d" in out
    assert "insufficient data" in out  # state.vscdb has no span


def test_report_cli_project_json(devin_dir, tmp_path, capsys):
    add_session(devin_dir.sessions_db, "s1", title="real work",
                user_msgs=10, tool_calls=5)
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--pending-file", str(tmp_path / "p.json"),
        "--project", "2w", "--json",
    ])
    assert rc == 0
    proj = json.loads(capsys.readouterr().out)["projection"]
    assert proj["horizon_days"] == 14.0
    assert proj["model"] == "linear"
    sdb = _by_name(proj)["sessions.db"]
    assert sdb["ok"] and sdb["rate_bytes_per_day"] > 0


def test_report_cli_project_invalid(devin_dir, tmp_path):
    for bad in ("bogus", "0d"):
        rc = main([
            "report", "--data-dir", str(devin_dir.root),
            "--pending-file", str(tmp_path / "p.json"),
            "--project", bad,
        ])
        assert rc == 2, bad


def test_report_cli_project_negative_exits_2(devin_dir, tmp_path):
    # "-3d" fails loudly either way: on Python <3.14 it looks like a flag
    # so argparse exits 2 itself; on 3.14+ argparse consumes it as the
    # value, parse_horizon rejects it and main() returns 2 — same CLI
    # contract, different mechanism.
    try:
        rc = main([
            "report", "--data-dir", str(devin_dir.root),
            "--pending-file", str(tmp_path / "p.json"),
            "--project", "-3d",
        ])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        assert rc == 2


def test_report_cli_project_writes_nothing(devin_dir, tmp_path):
    before = sorted(p.name for p in devin_dir.acp_messages_dir.iterdir())
    mtime = os.stat(devin_dir.sessions_db).st_mtime_ns
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--pending-file", str(tmp_path / "p.json"),
        "--project", "90d",
    ])
    assert rc == 0
    assert sorted(
        p.name for p in devin_dir.acp_messages_dir.iterdir()
    ) == before
    assert os.stat(devin_dir.sessions_db).st_mtime_ns == mtime
    assert not (tmp_path / "p.json").exists()
