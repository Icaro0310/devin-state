# janitor reap — handoff for owner review

Destructive-path feature. Status: **dry-run calibration**, awaiting
owner review. Not merged, not applied, not published.

Related: PR #97 (this branch) · issue #96 (ReDoS root cause) ·
PR #92 (audit branch, draft-blocked by #96).

## a) Owner review checklist — read in this order

All in `packages/janitor/src/devin_janitor/`:

1. **`reap.py` kill path** (`reap()`) — TERM → wait → KILL;
   PID-only by design (no group kill).
2. **starttime/pidfd checks** — `read_starttime` re-read before every
   signal; `pidfd_open` pin where available; abort on change.
3. **UID/root refusal** — `geteuid()==0` aborts the command; uid
   re-read per target before signalling; `read_uid` in `ProcTable`.
4. **Circuit breaker** — `len(candidates) > max_kill` → `circuit=True`,
   everything skipped, nothing signalled.
5. **Redaction subprocess** — `_redact` forks per call, hard timeout,
   SIGKILL on overruns, `_redact_broken` flag → sha256+len fingerprint
   (never the raw line). `signal.alarm` is *not* a bound for C-level
   regex ReDoS — the fork is.
6. **Ledger writes** — `append_ledger` dedups by
   `decision:pid:starttime`, keeps `ts_first/ts_last/count`, writes
   mode 0600 via tmp+rename; retention 30 days.
7. **Unit hardening** — `devin-janitor-reap.service` (user unit):
   oneshot, `TimeoutStartSec=60`, `RuntimeMaxSec=90`, `CPUQuota=50%`,
   `NoNewPrivileges`, `PrivateTmp`, `PrivateNetwork`,
   `ProtectSystem=strict` + `ReadWritePaths` (state dir + ledger dir).

Tests to read alongside: `packages/janitor/tests/test_reap.py` —
`TestScanGates`, `TestReap`, `TestLedger`, kill-switch test, the
mysql-budget test, and the `integration`-marked e2e (real `/proc`,
only ever signals the test's own child).

## b) Calibration protocol

Source of truth: the ledger at `--ledger-file` (default
`.devin/memory/janitor-reap-ledger.jsonl`; the timer writes to
`devin-state/.devin/memory/janitor-reap-ledger.jsonl`).

Export events:

```bash
jq -c 'select(.decision=="would_kill")' \
  devin-state/.devin/memory/janitor-reap-ledger.jsonl
```

Each event is one **distinct identity** (`decision` + `pid` +
`starttime`) with `ts_first`, `ts_last`, `count`, `session`,
`cpu_pct` (max), `comm`, redacted `cmdline`.

Labels (per identity):

- **TP** — the process was attributed to a dead Devin session *and*
  was truly runaway (busy loop, no useful work, owner gone).
- **FP** — anything else: misattributed, still wanted, would have
  finished, or wrong session.

Labeling sheet (one row per identity):

```
pid:starttime | session | first_seen | last_seen | count | cpu_max | verdict(TP|FP) | note
```

Enable criteria (all required, agreed with owner):

- ≥10 distinct `pid:starttime` `would_kill` events
- across ≥3 separate incidents (different sessions/times)
- observed over ≥14 days
- zero unexplained FPs (each FP needs a written reason + a rule fix)
- then: **manual `--apply` only**; `install --reap` only after that

## c) Runbook

- **Day 0** (done): timer `devin-janitor-reap.timer` active, dry-run
  only, every ~3 min, writes ledger + summary log under full
  sandboxing. Installed binary is the stable copy under
  `~/.local/share/uv/tools/devin-janitor` (with `devin-office`,
  `devin-redact==0.2.5` pinned from the published tag — repin on
  release after #96 closes).
- **Day 7 — interim review**: export ledger; label every
  `would_kill`; check `count` inflation vs distinct identities; if
  FPs appear, fix rules *before* day 14 rather than lowering the bar.
- **Day 14 — decision**: criteria in §b met → enable `--apply` on the
  timer (edit ExecStart) and keep logging `killed`; not met → extend
  dry-run or disable.

Disable instantly (either works):

```bash
touch ~/.local/share/devin/reap.disabled          # kill-switch: sweeps no-op
systemctl --user disable --now devin-janitor-reap.timer
```

Uninstall:

```bash
systemctl --user disable --now devin-janitor-reap.timer
rm ~/.config/systemd/user/devin-janitor-reap.{service,timer}
systemctl --user daemon-reload
# ledger/state/logs kept for postmortem — delete manually if unwanted
```

## d) Coverage limits & known blind spots

- **Between-sweep gap**: a process spawned *and* orphaned between two
  sweeps is never attributed → never eligible. Fail-safe by design;
  shrinks with sweep interval. The launch-time fix (devin-control
  scopes) is what closes it for real.
- **Attribution requires procmap**: without `devin_office` the reaper
  is inert — WARNING is emitted and eligibility is impossible.
- **Linux only**: reads `/proc`; Windows would need Job Objects at
  launch (prevention) rather than a reaper.
- **PID-only kills**: no process-group signalling — surviving
  grandchildren orphan on the next sweep and face the same gates.
- **CPU gate**: sustained load only; a runaway that idles most of the
  window can evade one sweep but not many (first_seen persists).
