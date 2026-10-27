"""Reaper tests — fake process table only.

The unit tests NEVER touch the real ``/proc``: every spec is decided
over an injected table. The single live-process test is marked
``integration`` and only ever signals the child it spawned itself.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from devin_janitor.reap import (
    ProcInfo,
    ReapCandidate,
    _key,
    _managed_by_unit,
    _parse_stat,
    _redact,
    append_ledger,
    load_reap_state,
    reap,
    save_reap_state,
    scan,
)

UID = os.getuid() if hasattr(os, "getuid") else 1000
NOW = 1_800_000_000.0


def mkproc(pid, ppid=1, *, uid=UID, comm="python3",
           cmdline="python3 -", state="S", starttime=1000,
           age_s=3600.0, managed=False) -> ProcInfo:
    return ProcInfo(pid=pid, ppid=ppid, uid=uid, comm=comm,
                    cmdline=cmdline, state=state, starttime=starttime,
                    age_s=age_s, managed=managed)


class FakeTable:
    """In-memory ProcTable — drives scan/reap without /proc."""

    def __init__(self, procs, cpu_map=None, adopters={1}):
        self.procs = {p.pid: p for p in procs}
        self.cpu_map = cpu_map or {}
        self._adopters = set(adopters)

    def adopter_pids(self, uid):
        return set(self._adopters)

    def iter_procs(self):
        return list(self.procs.values())

    def sample_cpu(self, pid, seconds):
        if pid not in self.procs:
            return None
        return self.cpu_map.get(pid, 0.0)

    def read_starttime(self, pid):
        p = self.procs.get(pid)
        return p.starttime if p else None

    def read_uid(self, pid):
        p = self.procs.get(pid)
        return p.uid if p else None

    def alive(self, pid):
        p = self.procs.get(pid)
        return p is not None and p.state != "Z"

    # -- test helpers -------------------------------------------------
    def die(self, pid):
        self.procs.pop(pid, None)

    def zombie(self, pid):
        if pid in self.procs:
            self.procs[pid].state = "Z"


def mkstate(first_seen=None, pidmap=None):
    return {"first_seen": dict(first_seen or {}),
            "pidmap": dict(pidmap or {})}


def run_scan(table, *, pid_map=None, state=None, **kw):
    kw.setdefault("uid", UID)
    kw.setdefault("now", NOW)
    return scan(table, locks_dir=Path("/nonexistent-locks"),
                sessions_db=Path("/nonexistent.db"),
                state=mkstate() if state is None else state,
                pid_map=pid_map or {}, **kw)


# ------------------------------------------------------------- scan ----


class TestScanGates:
    """Every gate in isolation — each skip reason is asserted."""

    def test_unparented_normal_child_ignored(self):
        t = FakeTable([mkproc(10, ppid=5)])  # ppid not an adopter
        res = run_scan(t)
        assert res.orphans == 0 and not res.candidates

    def test_wrong_uid_ignored(self):
        t = FakeTable([mkproc(10, uid=0)])
        res = run_scan(t)
        assert res.orphans == 0 and not res.candidates

    def test_zombie_skipped(self):
        p = mkproc(10, state="Z")
        res = run_scan(FakeTable([p]))
        assert res.skipped[0][1] == "zombie — init reaps it"

    def test_keep_comm_skipped(self):
        res = run_scan(FakeTable([mkproc(10, comm="tmux")]))
        assert "keep-listed" in res.skipped[0][1]

    def test_managed_unit_skipped(self):
        res = run_scan(FakeTable([mkproc(10, managed=True)]))
        assert "managed" in res.skipped[0][1]

    def test_unattributed_orphan_skipped(self):
        res = run_scan(FakeTable([mkproc(10)]), pid_map={})
        assert res.skipped[0][1] == "not attributed to a Devin session"

    def test_first_sighting_watched_not_killed(self):
        p = mkproc(10)
        key = _key(10, p.starttime)
        state = mkstate(pidmap={key: "dead-sess"})
        res = run_scan(FakeTable([p]), state=state)
        assert "first sighting" in res.skipped[0][1]

    def test_grace_not_yet_met(self):
        p = mkproc(10)
        key = _key(10, p.starttime)
        state = mkstate(first_seen={key: NOW - 60}, pidmap={key: "s"})
        res = run_scan(FakeTable([p]), state=state, grace_min=10)
        assert "grace" in res.skipped[0][1]

    def test_idle_process_survives(self):
        p = mkproc(10)
        key = _key(10, p.starttime)
        state = mkstate(first_seen={key: NOW - 7200},
                        pidmap={key: "dead-sess"})
        res = run_scan(FakeTable([p], cpu_map={10: 5.0}), state=state)
        assert "idle" in res.skipped[0][1]
        assert not res.candidates

    def test_gone_during_sampling(self):
        p = mkproc(10)
        key = _key(10, p.starttime)
        state = mkstate(first_seen={key: NOW - 7200},
                        pidmap={key: "dead-sess"})
        t = FakeTable([p])
        t.cpu_map[10] = None  # sample returns None → vanished
        t.sample_cpu = lambda pid, s: None
        res = run_scan(t, state=state)
        assert "exited during sampling" in res.skipped[0][1]

    def test_fully_eligible_candidate(self):
        p = mkproc(10, cmdline="python3 -m pytest tests")
        key = _key(10, p.starttime)
        state = mkstate(first_seen={key: NOW - 7200},
                        pidmap={key: "dead-sess"})
        res = run_scan(FakeTable([p], cpu_map={10: 99.0}), state=state)
        assert len(res.candidates) == 1
        assert res.candidates[0].session_slug == "dead-sess"

    def test_adoption_via_systemd_user(self):
        p = mkproc(10, ppid=4242)
        key = _key(10, p.starttime)
        state = mkstate(first_seen={key: NOW - 7200},
                        pidmap={key: "dead-sess"})
        t = FakeTable([p], cpu_map={10: 99.0}, adopters={1, 4242})
        res = run_scan(t, state=state)
        assert len(res.candidates) == 1

    def test_pid_reuse_breaks_attribution(self):
        """Same pid, different starttime = recycled → unattributed."""
        p = mkproc(10, starttime=9999)
        old_key = _key(10, 1111)  # saved for the OLD process
        state = mkstate(first_seen={_key(10, 9999): NOW - 7200},
                        pidmap={old_key: "dead-sess"})
        res = run_scan(FakeTable([p], cpu_map={10: 99.0}), state=state)
        assert "not attributed" in res.skipped[0][1]

    def test_circuit_breaker(self):
        procs = [mkproc(100 + i) for i in range(6)]
        state = mkstate(
            first_seen={_key(p.pid, p.starttime): NOW - 7200 for p in procs},
            pidmap={_key(p.pid, p.starttime): "s" for p in procs})
        t = FakeTable(procs, cpu_map={p.pid: 99.0 for p in procs})
        res = run_scan(t, state=state, max_kill=5)
        assert res.circuit is True
        assert res.candidates == []  # NOTHING is eligible when it trips

    def test_attribution_persisted_for_next_run(self):
        """A live session child is recorded so its orphanhood is provable."""
        p = mkproc(10, ppid=777)  # still parented right now
        state = mkstate()
        run_scan(FakeTable([p]), pid_map={10: "live-sess"}, state=state)
        assert state["pidmap"][_key(10, p.starttime)] == "live-sess"

    def test_stale_pidmap_entries_pruned(self):
        state = mkstate(pidmap={_key(999, 1): "gone"})
        run_scan(FakeTable([]), state=state)
        assert _key(999, 1) not in state["pidmap"]


# ------------------------------------------------------------- reap ----


class FakeKill:
    def __init__(self, table):
        self.calls = []
        self.table = table

    def __call__(self, pid, sig):
        self.calls.append((pid, sig))
        if pid not in self.table.procs:
            raise ProcessLookupError(pid)
        if sig == 15:
            self.table.zombie(pid)  # well-behaved proc dies on TERM
        elif sig == 9:
            self.table.die(pid)


def mkcand(pid, starttime=1000, cpu=99.0):
    return ReapCandidate(proc=mkproc(pid, starttime=starttime),
                         session_slug="dead-sess", cpu_pct=cpu)


class TestReap:
    def test_term_then_done(self):
        t = FakeTable([mkproc(10)])
        kill = FakeKill(t)
        res = reap(t, [mkcand(10)], term_wait=0.01, uid=UID, kill_sig=kill)
        assert [c.proc.pid for c in res.killed] == [10]
        assert kill.calls == [(10, 15)]  # KILL not needed

    def test_sigkill_when_term_ignored(self):
        t = FakeTable([mkproc(10)])
        def stubborn(pid, sig):
            if pid not in t.procs:
                raise ProcessLookupError(pid)
            if sig == 9:
                t.die(pid)  # only KILL works
        res = reap(t, [mkcand(10)], term_wait=0.01, uid=UID,
                   kill_sig=stubborn)
        assert [c.proc.pid for c in res.killed] == [10]

    def test_starttime_recheck_aborts_reused_pid(self):
        """PID recycled between scan and kill → no signal is sent."""
        t = FakeTable([mkproc(10, starttime=2222)])  # NEW proc on old pid
        sent = []
        res = reap(t, [mkcand(10, starttime=1000)], term_wait=0.01,
                   uid=UID, kill_sig=lambda p, s: sent.append((p, s)))
        assert sent == []
        assert res.survivors == [10]

    def test_wrong_uid_never_signalled(self):
        t = FakeTable([mkproc(10, uid=0)])
        sent = []
        res = reap(t, [mkcand(10)], term_wait=0.01, uid=UID,
                   kill_sig=lambda p, s: sent.append((p, s)))
        assert sent == []
        assert res.survivors == [10]

    def test_vanished_process_is_fine(self):
        t = FakeTable([])
        res = reap(t, [mkcand(10)], term_wait=0.01, uid=UID,
                   kill_sig=FakeKill(t))
        assert len(res.killed) == 1  # already gone = goal achieved


# ------------------------------------------------------------ state ----


def test_state_roundtrip(tmp_path):
    f = tmp_path / "reap.json"
    state = {"first_seen": {"10:100": 123}, "pidmap": {"10:100": "sess"}}
    save_reap_state(f, state)
    assert load_reap_state(f) == state


def test_state_tolerates_damage(tmp_path):
    f = tmp_path / "reap.json"
    f.write_text("{corrupt", encoding="utf-8")
    assert load_reap_state(f) == {"first_seen": {}, "pidmap": {}}


# ----------------------------------------------------------- parsing ----


def test_parse_stat_comm_with_parens_and_spaces():
    # fields after comm: state=S ppid=9 … utime=30 stime=20 … starttime=999
    text = "10 (weird )name) S 9 10 10 0 -1 4194304 100 0 0 0 30 20 0 0 20 0 1 0 999 0 0 0"
    ppid, comm, state, work, starttime = _parse_stat(text)
    assert (ppid, comm, state, work, starttime) == (9, "weird )name", "S", 50, 999)


def test_managed_by_unit():
    assert _managed_by_unit("0::/user.slice/user-1000.slice/user@1000.service/app.service/foo.service")
    assert not _managed_by_unit("0::/user.slice/user-1000.slice/session-3.scope")
    assert not _managed_by_unit("0::/init.scope")


# ---------------------------------------------------------- redaction ----


def test_redact_fallback_never_emits_raw(monkeypatch):
    """No engine → fingerprint only; the raw cmdline never reaches a log."""
    import devin_janitor.reap as mod
    monkeypatch.setitem(sys.modules, "devin_redact.engine", None)
    secret = "abc123def456ghi"
    out = mod._redact(f"cmd --token={secret} --other ok")
    assert secret not in out
    assert "sha256:" in out and "len=" in out
    assert "--token" not in out and "--other" not in out


# ------------------------------------------------------------ ledger ----


class TestLedger:
    def test_append_creates_jsonl(self, tmp_path):
        f = tmp_path / "ledger.jsonl"
        append_ledger(f, [{"ts": 100, "decision": "would_kill", "pid": 5}])
        import json as _json
        rows = [_json.loads(l) for l in f.read_text().splitlines()]
        assert rows == [{"ts": 100, "decision": "would_kill", "pid": 5}]

    def test_retention_prunes_old_entries(self, tmp_path):
        f = tmp_path / "ledger.jsonl"
        now = 1_800_000_000.0
        f.write_text(
            '{"ts": %d, "decision": "would_kill", "pid": 1}\n'
            '{"ts": %d, "decision": "killed", "pid": 2}\n'
            % (now - 31 * 86400, now - 10 * 86400),
            encoding="utf-8")
        append_ledger(f, [{"ts": now, "decision": "would_kill", "pid": 3}],
                      retain_days=30, now=now)
        import json as _json
        pids = [_json.loads(l)["pid"] for l in f.read_text().splitlines()]
        assert 1 not in pids and 2 in pids and 3 in pids

    def test_empty_is_noop(self, tmp_path):
        f = tmp_path / "ledger.jsonl"
        append_ledger(f, [])
        assert not f.exists()

    def test_corrupt_lines_dropped_on_rewrite(self, tmp_path):
        f = tmp_path / "ledger.jsonl"
        f.write_text('{"ts": 1}\n{corrupt\n', encoding="utf-8")
        append_ledger(f, [{"ts": 2, "decision": "survivor", "pid": 9}],
                      retain_days=30, now=2)
        assert "{corrupt" not in f.read_text()


# --------------------------------------------------------- kill-switch ----


@pytest.mark.skipif(not sys.platform.startswith("linux"),
                    reason="Linux-only feature")
def test_disable_file_skips_sweep(tmp_path, capsys):
    """reap.disabled next to the state file → no-op before any /proc work."""
    from devin_janitor.cli import main
    state = tmp_path / "state.json"
    (tmp_path / "reap.disabled").touch()
    rc = main(["reap", "--state-file", str(state)])
    assert rc == 0
    assert "disabled" in capsys.readouterr().out
    assert not state.exists()  # nothing was written


# ----------------------------------------------------- live integration ----


@pytest.mark.integration
@pytest.mark.skipif(not sys.platform.startswith("linux"),
                    reason="Linux-only feature")
def test_reap_kills_real_spawned_child():
    """The only test touching real processes — and only its own child."""
    import subprocess
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        assert proc.poll() is None
        cand = ReapCandidate(
            proc=ProcInfo(pid=proc.pid, ppid=os.getpid(), uid=os.getuid(),
                          comm="python3", cmdline="python3 -c sleep",
                          state="S", starttime=0, age_s=1.0,
                          managed=False),
            session_slug="test", cpu_pct=0.0)

        class RealChildTable:
            def read_starttime(self, pid):
                return 0
            def read_uid(self, pid):
                return os.getuid()
            def alive(self, pid):
                return proc.poll() is None

        res = reap(RealChildTable(), [cand], term_wait=1.0, uid=os.getuid())
        assert [c.proc.pid for c in res.killed] == [proc.pid]
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()


@pytest.mark.integration
@pytest.mark.skipif(not sys.platform.startswith("linux"),
                    reason="Linux-only feature")
def test_e2e_orphaned_busy_child_becomes_candidate(tmp_path):
    """Sandbox e2e over the REAL /proc: a fake session's busy child
    outlives its parent → reparented to a subreaper → after the grace
    window the reaper flags exactly that PID as would_kill.

    Session attribution is injected ({child_pid: slug}) — the office
    procmap mapping itself is exercised elsewhere; everything else is
    real: adopter detection, /proc stat reads, CPU sampling. The child
    is SIGKILLed in teardown so no busy-loop survives the test.
    """
    import subprocess

    from devin_janitor.reap import ProcFsTable

    # the "session": a parent that spawns a CPU-burning child, prints
    # the child's pid, then sleeps — killing it orphans the child
    parent = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess,sys,time\n"
         "c=subprocess.Popen([sys.executable,'-c','while True: pass'])\n"
         "print(c.pid,flush=True)\n"
         "time.sleep(120)"],
        stdout=subprocess.PIPE, text=True)
    child_pid = int(parent.stdout.readline().strip())
    table = ProcFsTable()
    state = {"first_seen": {}, "pidmap": {}}
    try:
        kw = dict(locks_dir=tmp_path, sessions_db=tmp_path / "none.db",
                  state=state, grace_min=0, sample_sec=0.05)
        # sweep 1 — session alive: child recorded as its descendant
        scan(table, pid_map={child_pid: "fake-session"}, **kw)
        assert state["pidmap"], "child was not attributed on live sweep"

        parent.kill()
        parent.wait()
        time.sleep(0.2)  # reparenting is synchronous; settle anyway

        # sweep 2 — session dead: child is now a seen orphan
        res2 = scan(table, pid_map={}, **kw)
        assert child_pid in {p.pid for p, _ in res2.skipped}, \
            "orphaned child vanished between sweeps"
        # sweep 3 — grace (0) already met by first_seen: candidate
        res3 = scan(table, pid_map={}, **kw)
        pids = [c.proc.pid for c in res3.candidates]
        assert pids == [child_pid], \
            f"expected exactly the orphaned child, got {pids}"
        assert res3.candidates[0].session_slug == "fake-session"
    finally:
        # kill the busy child directly — never left running
        try:
            os.kill(child_pid, 9)
        except (ProcessLookupError, PermissionError):
            pass
        if parent.poll() is None:
            parent.kill()
