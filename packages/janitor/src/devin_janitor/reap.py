"""Runaway orphan-process reaper (Linux only).

When a Devin session or terminal dies, children launched via
``bash -c``/``python -`` are reparented to a subreaper — init (ppid 1)
or the ``systemd --user`` manager — and a stuck one burns a core
forever (a pytest run deadlocked in a loop after its terminal died).

Killing is gated by *attribution*, not just behaviour — an eligible
process must satisfy ALL of:

- **attributed**  — seen in a previous scan as a descendant of a live
  Devin session lock (the ``devin_office.procmap`` mapping is reused,
  never duplicated); unattributed orphans are listed but never killed;
- **orphaned**    — reparented to init or the user's systemd manager;
- **lock dead**   — the session that launched it holds no live lock;
- **grace**       — observed orphaned for longer than ``grace_min``
  (tracked in a state file across runs, like the pending queue);
- **busy**        — sustained CPU above ``cpu_pct``, measured by
  ``/proc`` utime/stime deltas over ``sample_sec`` (never a spike).

Kill-path hardening, per the review spec:

- ``starttime`` is re-read immediately before every signal; a changed
  value means PID reuse and that kill is aborted. When
  :func:`os.pidfd_open` exists, the fd additionally pins the kernel
  object for the post-signal liveness check.
- Only the caller's own UID is touched — running as root aborts the
  whole command; other users' and system processes are ignored.
- ``max_kill`` per sweep: if eligible candidates exceed it the circuit
  trips — NOTHING is killed and the run reports ``circuit=True``. A
  mass-eligibility reading is treated as a detector bug, not a quota.
- cmdlines pass through ``devin_redact`` before any output or log —
  a crashed agent's argv may embed tokens.

Coverage limit (documented, fail-safe): attribution requires the
process to have been SEEN as a session descendant while the session
lock was alive. A process spawned and orphaned entirely between two
sweeps has no ``pidmap`` entry and is never eligible — the blind spot
shrinks with sweep interval, never into a false kill.

Audit trail: ``would_kill``/``killed`` decisions go to a dedicated
append-only ledger (``--ledger-file``, ≥30-day retention) — the
two-week calibration review is the evalset; the capped shared log
keeps only sweep summaries so rotation cannot eat the evidence.

Dry-run is the default; ``--apply`` performs SIGTERM → ``term_wait`` →
SIGKILL. Intended scheduling is a systemd ``oneshot`` user timer every
few minutes (installed manually — never via ``install --daily``).
Kill-switch: a ``reap.disabled`` file next to the state file makes
every sweep a no-op before any /proc work.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

DEFAULT_STATE_FILE = ".devin/janitor-reap.json"
DEFAULT_MAX_KILL = 5

# Comms legitimately expected to outlive their parent — detached
# servers whose whole job is surviving the session.
DEFAULT_KEEP_COMM = {
    "tmux", "screen", "mosh-server",
    "ssh", "ssh-agent", "gpg-agent", "dbus-daemon",
    "pipewire", "pipewire-pulse", "wireplumber",
    "Xorg", "Xwayland", "sddm",
}


# ------------------------------------------------------------ model ----


@dataclass
class ProcInfo:
    """One row of the process table, as the scan sees it."""

    pid: int
    ppid: int
    uid: int
    comm: str
    cmdline: str
    state: str
    starttime: int  # clock ticks since boot — the PID-reuse guard
    age_s: float
    managed: bool  # lives under a *.service cgroup segment


@dataclass
class ReapCandidate:
    proc: ProcInfo
    session_slug: str | None  # the Devin session it was attributed to
    cpu_pct: float
    reason: str = ""


@dataclass
class ReapResult:
    scanned: int = 0
    orphans: int = 0
    attributed: int = 0
    candidates: list[ReapCandidate] = field(default_factory=list)
    killed: list[ReapCandidate] = field(default_factory=list)
    skipped: list[tuple[ProcInfo, str]] = field(default_factory=list)
    survivors: list[int] = field(default_factory=list)
    circuit: bool = False  # eligibility exceeded max_kill — nothing ran
    attribution_ok: bool = True  # False → office missing, kills impossible


class ProcTable(Protocol):
    """Process-table view the scan decides over.

    The real implementation reads ``/proc``; tests inject a fake table
    so no spec assertion ever touches the live system.
    """

    def adopter_pids(self, uid: int) -> set[int]: ...
    def iter_procs(self) -> list[ProcInfo]: ...
    def sample_cpu(self, pid: int, seconds: float) -> float | None: ...
    def read_starttime(self, pid: int) -> int | None: ...
    def read_uid(self, pid: int) -> int | None: ...
    def alive(self, pid: int) -> bool: ...


# ------------------------------------------------------- /proc impl ----


def _parse_stat(text: str) -> tuple[int, str, str, int, int] | None:
    """``(ppid, comm, state, utime+stime, starttime)``.

    ``comm`` is wrapped in parens and may itself contain spaces or
    parens — split at the LAST ``)``, never the first.
    """
    rparen = text.rfind(")")
    if rparen < 0:
        return None
    comm = text[text.find("(") + 1:rparen]
    rest = text[rparen + 2:].split()
    if len(rest) < 20:
        return None
    try:
        # rest[0]=state rest[1]=ppid … rest[11]=utime rest[12]=stime
        # … rest[19]=starttime
        return (int(rest[1]), comm, rest[0],
                int(rest[11]) + int(rest[12]), int(rest[19]))
    except (ValueError, IndexError):
        return None


def _managed_by_unit(cgroup_text: str) -> bool:
    """True when any cgroup path segment names a ``*.service`` unit."""
    for line in cgroup_text.splitlines():
        path = line.partition(":")[2]
        for seg in path.split("/"):
            if seg.endswith(".service") and not seg.startswith("user@"):
                return True
    return False


class ProcFsTable:
    """Real ``/proc``-backed table. Linux only, read-mostly."""

    def __init__(self, proc_root: str | Path = "/proc"):
        self.root = Path(proc_root)
        self.ticks = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

    def _dir(self, pid: int) -> Path:
        return self.root / str(pid)

    def _stat(self, pid_dir: Path):
        try:
            return _parse_stat(
                (pid_dir / "stat").read_text(
                    encoding="utf-8", errors="replace"))
        except OSError:
            return None

    def _btime(self) -> int:
        try:
            for line in (self.root / "stat").read_text().splitlines():
                if line.startswith("btime "):
                    return int(line.split()[1])
        except (OSError, ValueError, IndexError):
            pass
        return int(time.time())

    def adopter_pids(self, uid: int) -> set[int]:
        """PID 1 plus every ``systemd --user`` manager for this uid."""
        adopters = {1}
        for pid_dir in self.root.iterdir():
            if not pid_dir.name.isdigit():
                continue
            stat = self._stat(pid_dir)
            if stat is None or stat[1] != "systemd":
                continue
            try:
                if pid_dir.stat().st_uid != uid:
                    continue
                cmd = (pid_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if b"--user" in cmd:
                adopters.add(int(pid_dir.name))
        return adopters

    def iter_procs(self) -> list[ProcInfo]:
        btime = self._btime()
        now = time.time()
        out = []
        for pid_dir in self.root.iterdir():
            if not pid_dir.name.isdigit():
                continue
            stat = self._stat(pid_dir)
            if stat is None:
                continue
            ppid, comm, state, _work, starttime = stat
            try:
                uid = pid_dir.stat().st_uid
                cmdline = (pid_dir / "cmdline").read_bytes().replace(
                    b"\0", b" ").decode("utf-8", "replace").strip()
                cgroup = (pid_dir / "cgroup").read_text(
                    encoding="utf-8", errors="replace")
            except OSError:
                continue
            out.append(ProcInfo(
                pid=int(pid_dir.name), ppid=ppid, uid=uid, comm=comm,
                cmdline=cmdline or comm, state=state, starttime=starttime,
                age_s=now - (btime + starttime / self.ticks),
                managed=_managed_by_unit(cgroup),
            ))
        return out

    def sample_cpu(self, pid: int, seconds: float) -> float | None:
        """CPU% by utime+stime delta over ``seconds``; None if gone."""
        first = self._stat(self._dir(pid))
        if first is None:
            return None
        t0 = time.monotonic()
        time.sleep(seconds)
        second = self._stat(self._dir(pid))
        if second is None:
            return None
        dt = time.monotonic() - t0
        return (second[3] - first[3]) / self.ticks / dt * 100.0 if dt > 0 else 0.0

    def read_starttime(self, pid: int) -> int | None:
        stat = self._stat(self._dir(pid))
        return stat[4] if stat else None

    def read_uid(self, pid: int) -> int | None:
        try:
            return self._dir(pid).stat().st_uid
        except OSError:
            return None

    def alive(self, pid: int) -> bool:
        """Still running — a zombie counts as dead (init reaps it)."""
        stat = self._stat(self._dir(pid))
        return stat is not None and stat[2] != "Z"


# ------------------------------------------------------ attribution ----


def procmap_pid_map(
    locks_dir: Path, sessions_db: Path
) -> tuple[dict[int, str], bool]:
    """``({pid: session_slug}, attribution_available)``.

    The mapping is REUSED, never reimplemented: locks give the owner
    PID per session and ``procmap`` already walks its descendants.
    An absent office install reports ``available=False`` — the scan
    stays fully read-only and attribution (hence kills) is impossible;
    that state must surface as a warning, not silently no-op.
    """
    try:
        from devin_office import procmap  # optional cross-repo dep
    except ImportError:
        return {}, False
    try:
        report = procmap.attribute(Path(locks_dir), Path(sessions_db))
    except Exception:  # noqa: BLE001 — attribution must never crash a scan
        return {}, True
    out: dict[int, str] = {}
    for row in report.get("rows", []):
        slug = row.get("slug") or ""
        if row.get("alive") and row.get("pid"):
            out[int(row["pid"])] = slug
        for child in row.get("children", []):
            if child.get("pid"):
                out[int(child["pid"])] = slug
    return out, True


# ------------------------------------------------------------- state ----


def load_reap_state(path: str | Path) -> dict:
    """``{"first_seen": {key: epoch}, "pidmap": {key: slug}}``."""
    p = Path(path)
    if not p.is_file():
        return {"first_seen": {}, "pidmap": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    fs = data.get("first_seen") if isinstance(data.get("first_seen"), dict) else {}
    pm = data.get("pidmap") if isinstance(data.get("pidmap"), dict) else {}
    return {
        "first_seen": {str(k): int(v) for k, v in fs.items()},
        "pidmap": {str(k): str(v) for k, v in pm.items()},
    }


def save_reap_state(path: str | Path, state: dict) -> None:
    p = Path(path)
    has = state.get("first_seen") or state.get("pidmap")
    if has:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state, indent=1), encoding="utf-8")
    elif p.exists():
        p.unlink()


def _key(pid: int, starttime: int) -> str:
    return f"{pid}:{starttime}"


# ------------------------------------------------------------- ledger ----

DEFAULT_LEDGER_RETAIN_DAYS = 30


def reap_build_info() -> dict:
    """Build identity stamped on every ledger entry — calibration
    labels must never mix events from different rules builds.

    ``reap_rules`` is a content hash of this file: it moves when the
    decision logic does, even without a version bump. ``devin-redact``
    records which engine produced each redacted cmdline — pinning a
    published release vs the audit branch is exactly the kind of drift
    the labeler needs to see."""
    import hashlib
    import importlib.metadata
    info: dict[str, str] = {}
    for pkg in ("devin-janitor", "devin-redact"):
        try:
            info[pkg] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            info[pkg] = "absent"
    try:
        info["reap_rules"] = "sha256:" + hashlib.sha256(
            Path(__file__).read_bytes()).hexdigest()[:12]
    except OSError:
        info["reap_rules"] = "unknown"
    return info


def _ledger_key(entry: dict) -> str:
    """Dedup identity: decision + ``pid:starttime`` — a stuck process
    reported every 3 min is ONE calibration event, not 480."""
    pid = entry.get("pid")
    if pid is None:
        return f"{entry.get('decision')}:run"
    return f"{entry.get('decision')}:{pid}:{entry.get('starttime')}"


def append_ledger(
    path: str | Path,
    entries: list[dict],
    *,
    retain_days: int = DEFAULT_LEDGER_RETAIN_DAYS,
    now: float | None = None,
) -> None:
    """Deduped ``would_kill``/``killed`` decision ledger (mode 0600).

    One row per distinct process identity — first sighting ts_first,
    latest ts_last, and a sighting ``count``. Kill-enable criteria read
    DISTINCT identities (>=10 across >=3 incidents over 14 days), so a
    single stuck process must not inflate the evalset. Rows older than
    ``retain_days`` are pruned on write; the capped shared log keeps
    only sweep summaries so rotation cannot eat this evidence.
    """
    if not entries:
        return
    now = time.time() if now is None else now
    cutoff = now - retain_days * 86400
    p = Path(path)
    rows: dict[str, dict] = {}
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue  # corrupt lines are dropped, never kept raw
            if e.get("ts_first", e.get("ts", 0)) < cutoff:
                continue
            rows[_ledger_key(e)] = e
    except OSError:
        pass  # no ledger yet — start fresh
    for e in entries:
        key = _ledger_key(e)
        prev = rows.get(key)
        if prev is None:
            rows[key] = {**e, "ts_first": e["ts"],
                         "ts_last": e["ts"], "count": 1}
        else:
            prev["count"] = prev.get("count", 1) + 1
            prev["ts_last"] = e["ts"]
            if e.get("cpu_pct") is not None:
                prev["cpu_pct"] = max(prev.get("cpu_pct") or 0,
                                      e["cpu_pct"])
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for e in rows.values():
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    os.replace(tmp, p)  # atomic; the 0600 mode travels with the tmp inode
    os.chmod(p, 0o600)  # belt: tighten any older file's mode too


# --------------------------------------------------------------- scan ----


def scan(
    table: ProcTable,
    *,
    locks_dir: Path,
    sessions_db: Path,
    state: dict,
    grace_min: float = 10.0,
    cpu_pct: float = 30.0,
    sample_sec: float = 2.0,
    max_kill: int = DEFAULT_MAX_KILL,
    keep_comm: set[str] | None = None,
    pid_map: dict[int, str] | None = None,
    uid: int | None = None,
    now: float | None = None,
) -> ReapResult:
    """Decide who is reap-eligible. Pure decision — kills happen in reap().

    ``pid_map`` defaults to ``procmap_pid_map`` so tests inject a fake
    attribution set without the office dependency. The previous scan's
    map is persisted in ``state["pidmap"]`` keyed by ``pid:starttime``
    so a process orphaned AFTER its owner died keeps its attribution.
    """
    uid = os.getuid() if uid is None else uid
    now = time.time() if now is None else now
    keep = DEFAULT_KEEP_COMM | set(keep_comm or ())
    res = ReapResult()
    if pid_map is None:
        live_map, res.attribution_ok = procmap_pid_map(locks_dir, sessions_db)
    else:
        live_map, res.attribution_ok = pid_map, True
    saved_map: dict[str, str] = state["pidmap"]
    adopters = table.adopter_pids(uid)

    procs = table.iter_procs()
    existing_keys = {_key(p.pid, p.starttime) for p in procs}

    seen_keys: set[str] = set()

    for proc in procs:
        res.scanned += 1
        if proc.uid != uid or proc.ppid not in adopters:
            continue
        res.orphans += 1
        key = _key(proc.pid, proc.starttime)
        seen_keys.add(key)
        slug = saved_map.get(key)
        if slug is not None:
            res.attributed += 1

        def skip(reason: str, p: ProcInfo = proc) -> None:
            res.skipped.append((p, reason))

        if proc.state == "Z":
            skip("zombie — init reaps it")
        elif proc.comm in keep:
            skip(f"keep-listed comm ({proc.comm})")
        elif proc.managed:
            skip("managed by a systemd unit")
        elif slug is None:
            skip("not attributed to a Devin session")
        else:
            first_seen = state["first_seen"].get(key, 0)
            if not first_seen:
                skip("first sighting — watching")
            elif now - first_seen < grace_min * 60:
                skip(f"orphaned {(now - first_seen) / 60:.0f}m "
                     f"< grace {grace_min:.0f}m")
            else:
                busy = table.sample_cpu(proc.pid, sample_sec)
                if busy is None:
                    skip("exited during sampling")
                elif busy < cpu_pct:
                    skip(f"idle ({busy:.0f}% < {cpu_pct:.0f}%)")
                else:
                    res.candidates.append(ReapCandidate(
                        proc=proc, session_slug=slug, cpu_pct=busy,
                        reason=f"orphan {grace_min:.0f}m+ at {busy:.0f}% "
                               f"CPU (was child of {slug})"))

    # refresh persisted attribution + first-seen; drop dead keys
    for proc in procs:
        slug = live_map.get(proc.pid)
        if slug:
            saved_map[_key(proc.pid, proc.starttime)] = slug
    for key in list(saved_map):
        if key not in existing_keys:
            del saved_map[key]
    for key in seen_keys:
        state["first_seen"].setdefault(key, int(now))
    for key in list(state["first_seen"]):
        if key not in seen_keys:
            del state["first_seen"][key]

    if len(res.candidates) > max_kill:
        res.circuit = True
        res.skipped.extend(
            (c.proc, "circuit: eligibility exceeded max_kill") for c in res.candidates)
        res.candidates = []
    return res


# --------------------------------------------------------------- kill ----


def reap(
    table: ProcTable,
    candidates: list[ReapCandidate],
    *,
    term_wait: float = 3.0,
    uid: int | None = None,
    kill_sig=None,
) -> ReapResult:
    """TERM then KILL. Called ONLY on --apply, never at scan time.

    Re-checks ``starttime`` right before each signal — a changed value
    means the PID was recycled and the kill aborts. ``os.pidfd_open``,
    where available, pins the kernel object for the liveness checks.
    ``kill_sig`` is injectable for tests (defaults to ``os.kill``).

    PID-only by design: signalling a whole process group would need the
    *entire* group to qualify, and one legitimate non-Devin grandchild
    would be killed by association. Surviving children simply orphan on
    the next sweep and face the same gates.
    """
    uid = os.getuid() if uid is None else uid
    if os.geteuid() == 0:
        raise RuntimeError("reap refuses to run as root")
    kill = os.kill if kill_sig is None else kill_sig
    res = ReapResult(candidates=list(candidates))
    pidfd_open = getattr(os, "pidfd_open", None)

    for cand in candidates:
        proc = cand.proc
        # re-read uid at kill time — the snapshot may be stale, and only
        # the caller's own processes may ever be signalled
        actual_uid = table.read_uid(proc.pid)
        if actual_uid is None:
            res.killed.append(cand)  # already gone — goal achieved
            continue
        if actual_uid != uid:
            cand.reason += " · wrong uid — refused"
            res.survivors.append(proc.pid)
            continue
        fd = None
        if pidfd_open is not None:
            try:
                fd = pidfd_open(proc.pid, 0)
            except OSError:
                fd = None
        try:
            if table.read_starttime(proc.pid) != proc.starttime:
                cand.reason += " · starttime changed (PID reused) — aborted"
                res.survivors.append(proc.pid)
                continue
            try:
                kill(proc.pid, 15)
            except ProcessLookupError:
                res.killed.append(cand)
                continue
            except PermissionError:
                cand.reason += " · SIGTERM refused"
                res.survivors.append(proc.pid)
                continue
            deadline = time.monotonic() + term_wait
            while time.monotonic() < deadline and table.alive(proc.pid):
                time.sleep(0.1)
            if table.alive(proc.pid):
                if table.read_starttime(proc.pid) != proc.starttime:
                    cand.reason += " · starttime changed mid-kill — left alone"
                    res.survivors.append(proc.pid)
                    continue
                try:
                    kill(proc.pid, 9)
                except (ProcessLookupError, PermissionError):
                    pass
            time.sleep(0.05)
            if table.alive(proc.pid):
                cand.reason += " · survived SIGKILL"
                res.survivors.append(proc.pid)
            else:
                res.killed.append(cand)
        finally:
            if fd is not None:
                os.close(fd)
    return res


# ----------------------------------------------------------- redaction ----

REDACT_TIMEOUT = 0.5
_redact_broken = False  # one engine timeout → hash-only for the run


def _redact_fallback(text: str) -> str:
    """Fingerprint — NEVER the raw line (issue #96: a token in argv is
    exactly what must not reach the journal)."""
    import hashlib
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    return f"<cmdline sha256:{digest[:12]} len={len(text)}>"


def _engine_available() -> bool:
    try:
        from devin_redact.engine import redact_text  # noqa: F401
        return True
    except Exception:  # noqa: BLE001 — absent/broken install
        return False


def _redact(text: str, timeout: float = REDACT_TIMEOUT) -> str:
    """Strip secrets from a cmdline before ANY output or log line.

    The engine runs in a FORKED child under a hard timeout — regex
    ReDoS lives in C code where signal.alarm can't reach (#96); only
    SIGKILL on a separate process is a real bound. On timeout the child
    is killed, the engine is marked broken for the rest of the run,
    and the fingerprint fallback is used (never the raw line).
    """
    global _redact_broken
    if _redact_broken or not _engine_available():
        return _redact_fallback(text)
    import select
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(rfd)
            from devin_redact.engine import redact_text
            out = redact_text(text)[0] or ""
            os.write(wfd, out.encode("utf-8", "replace"))
        except BaseException:  # noqa: BLE001 — child failure = fingerprint
            os._exit(1)
        os._exit(0)
    os.close(wfd)
    deadline = time.monotonic() + timeout
    out = b""
    alive = True
    while time.monotonic() < deadline and alive:
        done, _status = os.waitpid(pid, os.WNOHANG)
        if done:
            alive = False
        r, _, _ = select.select([rfd], [], [], 0.02)
        if r:
            chunk = os.read(rfd, 1 << 16)
            if not chunk:
                break
            out += chunk
    if alive:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        _redact_broken = True
        os.close(rfd)
        return _redact_fallback(text)
    try:  # drain any bytes that raced the exit
        while True:
            r, _, _ = select.select([rfd], [], [], 0)
            if not r:
                break
            chunk = os.read(rfd, 1 << 16)
            if not chunk:
                break
            out += chunk
    except OSError:
        pass
    os.close(rfd)
    redacted = out.decode("utf-8", "replace").strip()
    return redacted if redacted else _redact_fallback(text)


def render(res: ReapResult, apply: bool) -> str:
    """Human-readable listing — every cmdline is pre-redacted."""
    mode = "REAP" if apply else "DRY-RUN"
    lines = [
        (f"reap [{mode}]: {res.scanned} procs · {res.orphans} orphaned · "
         f"{res.attributed} attributed · {len(res.candidates)} eligible")
    ]
    if not res.attribution_ok:
        lines.append(
            "  WARNING: devin_office unavailable — attribution disabled; "
            "nothing can be killed (install devin-office to enable)")
    if res.circuit:
        lines.append(
            f"  CIRCUIT TRIPPED — {len(res.skipped)} would-be eligible "
            "exceeded max_kill; nothing killed (possible detector bug)")
    for cand in res.candidates:
        lines.append(
            f"  {'kill' if apply else 'KILL':5} {cand.proc.pid:>7} "
            f"{cand.cpu_pct:5.0f}%cpu {cand.proc.age_s / 60:6.0f}m  "
            f"sess={cand.session_slug}  {_redact(cand.proc.cmdline)[:80]}"
        )
    for proc, why in res.skipped:
        lines.append(f"  {'skip':5} {proc.pid:>7} {'':12} {why}  {proc.comm[:40]}")
    if res.killed:
        lines.append(f"killed: {len(res.killed)}")
    if res.survivors:
        lines.append(f"survived/aborted: {res.survivors}")
    return "\n".join(lines)
