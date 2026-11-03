import time

from conftest import OLD_S, add_session
from devin_janitor.config import JanitorConfig
from devin_janitor.inventory import SessionRow, load_inventory
from devin_janitor.tiers import Tier, classify, norm_title


def mkrow(sid, **kw) -> SessionRow:
    defaults = {
        "id": sid, "origin": "cli", "title": "", "project": "/p",
        "created": OLD_S, "last_activity": OLD_S,
    }
    return SessionRow(**{**defaults, **kw})


def test_empty_session_auto_delete():
    r = mkrow("s1")
    c = classify([r])
    assert c.tier_of("s1") is Tier.AUTO_DELETE
    assert c.auto_delete[0][1] == "empty"


def test_grace_window_keeps_recent():
    # Robot/judge classes bypass grace (deleted regardless of age); the grace
    # window only protects substantive recent work — so this row must have
    # real activity metrics, not the mkrow defaults that match the judge tier.
    recent = mkrow("new", last_activity=time.time() - 3600, user_msgs=100)
    old = mkrow("old", last_activity=OLD_S, user_msgs=100)
    c = classify([recent, old])
    assert c.kept["new"] == "grace window"
    assert c.tier_of("old") is Tier.KEEP


def test_robot_sessions_skip_grace_window():
    # Directive 2026-11-03: robot/judge sessions are deleted with no grace
    # period even when last_activity is inside the window.
    recent_noise = mkrow("bot", last_activity=time.time() - 3600)
    c = classify([recent_noise])
    assert c.tier_of("bot") is Tier.AUTO_DELETE or "bot" in [r.id for r in c.judge]


def test_keep_ids_and_patterns():
    rows = [
        mkrow("keep-id", user_msgs=100),
        mkrow("keep-title", title="KICKOFF notes", user_msgs=100),
        mkrow("keep-nao", title="não apagar isto", user_msgs=100),
        mkrow("other", user_msgs=100),
    ]
    c = classify(rows, keep_ids={"keep-id"}, keep_patterns=["KICKOFF"])
    assert c.kept["keep-id"] == "allowlist/marked"
    assert c.kept["keep-title"] == "allowlist/marked"
    assert c.kept["keep-nao"] == "allowlist/marked"  # built-in pattern
    assert c.kept["other"] == "substantive work"


def test_noise_pattern_auto_delete():
    r = mkrow("n", title="billing", user_msgs=2, tool_calls=3)
    c = classify([r])
    assert c.tier_of("n") is Tier.AUTO_DELETE
    assert c.auto_delete[0][1] == "automation/eval noise"


def test_noise_pattern_with_many_tool_calls_not_noise():
    # Lots of tool calls ⇒ not pure noise; falls through to JUDGE/KEEP.
    r = mkrow("n", title="billing", user_msgs=2, tool_calls=20,
              files_touched=3)
    c = classify([r])
    assert c.tier_of("n") is Tier.KEEP


def test_ephemeral_cycle_auto_delete():
    r = mkrow("e", title="slack-bridge inbox", user_msgs=10, tool_calls=5)
    c = classify([r])
    assert c.tier_of("e") is Tier.AUTO_DELETE
    assert c.auto_delete[0][1] == "ephemeral heartbeat/mailbox cycle"


def test_ephemeral_over_threshold_not_deleted():
    r = mkrow("e", title="slack-bridge inbox", user_msgs=200, tool_calls=100)
    c = classify([r])
    assert c.tier_of("e") is Tier.KEEP


def test_duplicates_keep_most_active_sibling():
    loser = mkrow("dup-a", title="Same Task!", user_msgs=1, tool_calls=1,
                  project="/p")
    winner = mkrow("dup-b", title="same task", user_msgs=9, tool_calls=9,
                   project="/p")
    other_proj = mkrow("dup-c", title="Same Task", user_msgs=1, tool_calls=1,
                       project="/other")
    c = classify([loser, winner, other_proj])
    assert (loser, "duplicate") in [
        (r, w) for r, w in c.auto_delete
    ]
    assert "dup-b" not in {r.id for r, _ in c.auto_delete}
    # different project ⇒ not a duplicate group
    assert "dup-c" not in {r.id for r, _ in c.auto_delete}


def test_ambiguous_goes_to_judge():
    r = mkrow("j", title="hmm", user_msgs=2, tool_calls=3, files_touched=0)
    c = classify([r])
    assert c.tier_of("j") is Tier.JUDGE


def test_files_touched_escapes_judge():
    r = mkrow("j", title="hmm", user_msgs=2, tool_calls=3, files_touched=2)
    c = classify([r])
    assert c.tier_of("j") is Tier.KEEP


def test_config_overrides_noise(tmp_path):
    cfg = JanitorConfig(noise_patterns=[r"mynoise"], keep_title_patterns=[])
    r = mkrow("x", title="mynoise job", user_msgs=1, tool_calls=1)
    assert classify([r], cfg).tier_of("x") is Tier.AUTO_DELETE
    # default rules don't match "mynoise" ⇒ ambiguous ⇒ JUDGE
    assert classify([r]).tier_of("x") is Tier.JUDGE


def test_norm_title():
    assert norm_title("Hello, World! 123") == "helloworld123"


def test_inventory_roundtrip(devin_dir):
    add_session(devin_dir.sessions_db, "s1", title="t", user_msgs=2,
                assistant_msgs=3, tool_calls=4, prompt="do the thing",
                files=["/a/b.py", "/a/c.py"])
    rows = load_inventory(devin_dir)
    assert len(rows) == 1
    r = rows[0]
    assert r.id == "s1" and r.origin == "cli"
    assert r.user_msgs == 2 and r.assistant_msgs == 3
    assert r.tool_calls == 4 and r.files_touched == 2
    assert r.prompt == "do the thing"
    # ms → s conversion
    assert abs(r.last_activity - OLD_S) < 2
