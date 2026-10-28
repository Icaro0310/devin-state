<div align="center">

<img src="assets/banner.svg" alt="devin-janitor" width="100%"/>

<a href="https://github.com/Icaro0310/devin-state/actions/workflows/test-janitor.yml"><img src="https://github.com/Icaro0310/devin-state/actions/workflows/test-janitor.yml/badge.svg" alt="ci"/></a>
<a href="https://scorecard.dev/viewer/?uri=github.com/Icaro0310/devin-state"><img src="https://api.scorecard.dev/projects/github.com/Icaro0310/devin-state/badge" alt="OpenSSF Scorecard"/></a>

<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"/></a>
<a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"/></a>
<a href="https://github.com/Icaro0310/devin-state"><img src="https://img.shields.io/github/stars/Icaro0310/devin-state" alt="GitHub stars"/></a>
<a href="https://github.com/Icaro0310/devin-state/commits/main"><img src="https://img.shields.io/github/last-commit/Icaro0310/devin-state" alt="Last commit"/></a>
<a href="https://github.com/Icaro0310/awesome-devin"><img src="https://img.shields.io/badge/part%20of-devin--*-ecosystem-7c3aed" alt="devin-* ecosystem"/></a>
<a href="https://github.com/Icaro0310/devin-state/issues"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome"/></a>
</div>

<!-- DEVIN-ECO:BEGIN -->
> **Part of the [DEVIN ecosystem](https://github.com/Icaro0310/awesome-devin)**  
> Track: Control · Nature: product  
> For: Local-first ops, Security engineers  
> Interface: CLI / Automation  
> Path: Local-first ops · step 5/5 — after `devin-backup`
<!-- DEVIN-ECO:END -->

# devin-janitor

> **Unofficial community project.** Not affiliated with, endorsed by, or
> sponsored by Cognition AI. "Devin" is a trademark of Cognition AI.

**[Linux](README.linux.md)** · **[Personal Windows](README.windows.md)** · **[Corporate Windows](README.corporate-windows.md)**

Part of the [awesome-devin](https://github.com/Icaro0310/awesome-devin) ecosystem: the curated hub for the devin-* tools.

The lifecycle janitor for Devin sessions: **export first, classify in tiers,
delete only the safe tiers, retry locked files, vacuum only when Devin is
closed** — so `sessions.db` and `acp-messages/` never bloat with
empty/automation noise again.

## The problem

Daily Devin Desktop use accumulates session pollution: empty sessions,
automation/eval noise (classification probes, judge calls, JSON payloads),
one-shot heartbeat/mailbox cycles, and duplicates of the same task. On a real
install this noise was ~55% of all sessions — drowning out actual work in the
session list and growing `sessions.db` + `User/acp-messages/` without bound.
Devin ships no built-in lifecycle management, and deleting rows blindly is
dangerous: locked files, open databases and ambiguous sessions all need
handling.

## Prior art

Generic SQLite cleanup scripts and browser-history cleaners exist for many
tools, but none know Devin's layout. This project ports a proven
battle-tested script (`legacy/session-janitor.py`, run daily via Task
Scheduler against a production install) into a maintainable package — it
adapts that pipeline; it does not reinvent deletion.

## What makes it Devin-native

- Knows the real stores via
  [`devin-internals-spec`](https://github.com/Icaro0310/devin-internals-spec):
  `sessions.db` rows (schema-version gated), GUI `acp-messages/*.db` files,
  and `session_locks/` — no guessing at foreign-key graphs or file naming.
- Exports transcripts **before** deleting (`--export-cmd` hook, aborts the
  whole run on failure).
- **Pluggable judge** for ambiguous sessions — `--judge devin-judge` calls
  [poordjaevin](https://github.com/Icaro0310/devin-judge)'s local typed-answer
  CLI directly, and `--judge command:<cmd>` pipes a JSON payload to any local
  script you trust (e.g. a Devin ACP helper). The default `none` is purely
  rules-based and keeps everything ambiguous (fail-open). No external model
  or service is required.
- Retries locked deletions via a pending queue instead of force-killing
  Devin; `VACUUM` only runs when Devin is closed.

## Install

Requires Python ≥ 3.10 and `pipx` or `uv`. Per-OS setup lives in the platform guides: [Linux](README.linux.md) · [Personal Windows](README.windows.md) · [Corporate Windows](README.corporate-windows.md).

## Usage

```bash
devin-janitor scan                 # classification preview (+ .devin/ artifacts)
devin-janitor scan --json          # machine-readable
devin-janitor run                  # dry-run: prints the exact plan, writes nothing
devin-janitor run --apply          # execute the pipeline
devin-janitor run --apply --grace-hours 72 \
    --export-cmd "devin-history export"   # safe recipe: export first
devin-janitor run --judge "command:python my_judge.py"   # plug your own judge
devin-janitor run --apply --notify-cmd "my-notifier"     # post-run JSON summary on its stdin
devin-janitor pending --list       # locked files queued for retry
devin-janitor pending --retry      # retry them now
devin-janitor report               # recoverable-space report (advisory)
devin-janitor report --json        # machine-readable
devin-janitor report --project 90d # estimated store sizes in 90 days (linear
                                   # rate since first-seen; 'insufficient data'
                                   # when a store has no honest rate)
devin-janitor report --exclude-labeled    # drop bridge-labeled sessions from the counts
devin-janitor run --apply --tiers 1,2     # default scope: orphans/cache + stale sessions
devin-janitor run --apply --tiers all --include-gui \
    --snapshot /path/to/devin-backup-snapshot   # tier3 requires a fresh verified snapshot
devin-janitor install --daily      # schedule a daily read-only 'report' job (F6)
```

### Cleanup tiers

Everything the janitor can reclaim falls into three tiers, reported per-tier
by `report` and selectable via `run --tiers`:

- **tier1 — orphans & cache** (default): checkpoint sidecars, message-table
  rows whose session is gone, stale `session_locks/*.lock`, dead-session
  leftovers in `acp-messages/`. No session content is lost.
- **tier2 — stale sessions** (default): sessions past `--grace-hours` the
  classifier marks `auto_delete` (plus judge deletes / pending-queue ids).
- **tier3 — GUI session state** (opt-in): `windsurfSpace.sessionWorkspace/*`
  keys in `state.vscdb`. Destructive — `run --apply --tiers 3` refuses
  unless you pass `--include-gui` **and** `--snapshot PATH` pointing at a
  verified [`devin-backup`](https://github.com/Icaro0310/devin-state)
  snapshot manifest younger than 24h that covers `state.vscdb`, and Devin
  must be closed. `--apply` is never scheduled — deletion stays manual.
  Each deleted key leaves a metadata-only `devin.janitor.tombstone/…`
  marker (original key, slug, backend, size, timestamps) so the removal
  stays auditable; the verified snapshot owns payload restoration.

### Orphan reaper (Linux)

`devin-janitor reap` hunts runaway orphan processes — devin/bridge/agent
children whose parent session died. Dry-run is the default; nothing dies
without `--apply`.

```bash
devin-janitor reap              # report candidates only
devin-janitor reap --apply      # SIGTERM, wait, then SIGKILL eligible ones
```

Killing is gated by **attribution**, not just behaviour — a process only
becomes eligible when it maps to a Devin session lock that is already
dead (via the `devin_office.procmap` mapping). If the office map is
unavailable, attribution fails and **no kill happens** (fail-safe).
Identity is `(PID, starttime)`, so PID reuse can never mislabel a newer
process, and targets must also clear a grace period (`--grace-min 10`)
plus a sustained CPU threshold (`--cpu-pct 30` over `--sample-sec`).

Safety rails: `--max-kill 5` is a circuit breaker — if eligible
candidates exceed it, NOTHING is killed. `--term-wait` paces TERM → KILL.
Every `would_kill`/`killed` decision is appended to a dedicated
append-only ledger (`--ledger-file`, ≥30-day retention) so reaping stays
auditable. The reaper never runs unattended: like tier3, `--apply` is a
manual decision and is not scheduled by `install --daily`.

### `.devin/` runtime artifacts

The PAS learning loop and the janitor itself accumulate runtime state in
the project's `.devin/` dir. `scan` and `report` tier every file there
with the same KEEP / AUTO_DELETE / JUDGE enum (`--devin-dir` points at
another `.devin/`; default `./.devin`):

- **auto_delete** — regenerable caches (`search.db`, `graph.db`), sqlite
  sidecars, transient leftovers (`*.tmp`, `__pycache__`, OS droppings),
  and bounded append logs (`*.jsonl`/`*.log` like
  `memory/hook-fires.jsonl` — prune/rotate candidates)
- **keep** — durable state: `*.json` state files (`learning-state.json`,
  `janitor-keep.json`, the pending queue), docs, config, everything under
  `rules/` and `skills/`
- **judge** — unrecognized files: unknown sqlite stores, possible live
  `*.lock` files, anything else — fail-open kept, flagged for review

`report` shows per-artifact tiers and counts AUTO_DELETE bytes as
recoverable; `run` still deletes sessions only — `.devin/` is reported,
never touched. An unreadable or malformed artifact is an error (`scan`
exits 2); a missing `.devin/` is fine.

### Automatic sessions (bridge labels)

Sessions created by automation (devin-bridge and friends) carry
`origin:purpose` labels recorded in `<bridge-state>/session-labels.json`.
`report` reads that sidecar (`--labels-file` to override), lists the
labeled sessions in an **automatic sessions** section, and marks them
deterministically — `--exclude-labeled` drops them from the
classification so the report reflects only non-automation sessions.

### Scheduled daily report

`devin-janitor install --daily` registers a **read-only** daily
`devin-janitor report` using the F6 scheduling pattern shared across the
devin-* ecosystem: a tagged `@daily` crontab line
(`# devin-ecosystem:devin-janitor-daily`), a Task Scheduler entry on
Windows, or an elapsed-time job record in
`<config-dir>/.devin-ecosystem/scheduled.json` ticked by the
`UserPromptSubmit` hook when neither scheduler exists. Pin a backend with
`--backend auto|tasksch|cron|elapsed`. Only `report` is ever scheduled —
`--apply` stays a manual decision.

### Post-run notification

`run --notify-cmd "<command>"` (or `JANITOR_NOTIFY_CMD` when the flag is
absent) pipes a compact JSON summary to the command's stdin after every
run — the mirror of `--export-cmd`, which runs before deletion instead:

```json
{"apply": true, "total": 12, "planned": 3, "deleted": 3,
 "retained": 9, "pending": 0, "rc": 0}
```

`planned` is what the plan selected for deletion (a dry-run reports it
with `apply: false` and `deleted: 0`); `retained` counts sessions the
run leaves alone (keepers plus deletes outside `--tiers`/`--max-delete`);
`deleted` counts unique sessions actually removed — a session spanning
both stores counts once; `rc` is the run's exit code, so a failed purge
notifies too.
Notification is **fail-open**: a missing command, non-zero exit or the
10s timeout prints a stderr warning and never changes the exit code.
The janitor ships no notifier — point the flag at any local command (a
slack-webhook wrapper, `mail`, a devin-bridge helper). The flag beats the
env var; an explicit `--notify-cmd ""` disables notification entirely.

Session data defaults to `%APPDATA%\devin` on Windows and
`$XDG_DATA_HOME/devin` (normally `~/.local/share/devin`) on Linux. UI ACP files
use `$XDG_CONFIG_HOME/Devin` (normally `~/.config/Devin`). Override with
`--data-dir`/`DEVIN_DATA_DIR` and `--config-dir`/`DEVIN_CONFIG_DIR`; the
bridge labels sidecar follows `DEVIN_BRIDGE_STATE_DIR`. Protect
sessions in `.devin/janitor-keep.json`
(`{"ids": [...], "title_patterns": [...]}`); tune classification rules via
`--config file.json`. `report` reads every store (`sessions.db`,
`acp-messages/`, `state.vscdb`, `session_locks/`, `.devin/` artifacts) and
estimates what the
janitor's own rules would free — it never writes and always exits 0. Full
details: [docs/SPEC.md](docs/SPEC.md).

## Works with Devin alone (Devin-only mode)

devin-janitor needs nothing but Devin itself: it reads Devin's own session
stores and writes only a local audit log. No VM, no tunnel, no message queue,
no model server. The default `--judge none` keeps the whole pipeline
rules-based and fully offline.

Two honest caveats for restricted machines:

- `run` is a **dry-run by default**; only `--apply` deletes. Always preview
  first, and consider `--export-cmd "devin-history export"` so transcripts are
  archived before removal.
- If you want a semantic judge for ambiguous sessions, `--judge devin-judge`
  shells `poordjaevin ask` locally (or `--judge command:<cmd>` for your own
  script). Both stay fail-open: any backend error, timeout or unclear
  verdict keeps the session.

## Adapters (MCP server, Devin skill, plugin)

`devin_janitor.mcp_server` exposes the read-only surface as MCP tools — `janitor_dry_run` (same payload as `report --json`) and
`janitor_classify` (same as `scan --json`)
— via the `devin-janitor-mcp` entry point (`pip install 'devin-janitor[mcp]'`). The
`adapters/` directory is a self-contained Devin plugin root
(`adapters/.devin-plugin/plugin.json` + `adapters/skills/devin-janitor/SKILL.md`),
installable with `devin plugins install
Icaro0310/devin-state#packages/janitor/adapters`. Removing sessions stays a
human-confirmed CLI action and is deliberately not exposed through any
adapter.

The same stdio server registers in other MCP hosts:

**Zed** — `context_servers` in `settings.json`:

```json
{
  "context_servers": {
    "devin-janitor": { "command": { "path": "devin-janitor-mcp", "args": [] } }
  }
}
```

**JetBrains** — Settings → Tools → AI Assistant → Model Context Protocol → Add:

```json
{ "mcpServers": { "devin-janitor": { "command": "devin-janitor-mcp" } } }
```

**Antigravity** — `~/.gemini/config/mcp_config.json`:

```json
{ "mcpServers": { "devin-janitor": { "command": "devin-janitor-mcp" } } }
```

## Platform support

Tested on **Windows and Linux** (`windows-latest` + `ubuntu-latest` in CI).
Session data uses `%APPDATA%/devin` on Windows and `$XDG_DATA_HOME/devin` on
Linux (default `~/.local/share/devin`). ACP files use the separate
`$XDG_CONFIG_HOME/Devin` root on Linux (default `~/.config/Devin`). Explicit
`--data-dir`, `--config-dir`, `--sessions-db`, `--acp-dir`, `--locks-dir`,
and `--devin-dir` overrides are available.

## Limitations

- With the default `--judge none`, classification is purely rules-based:
  ambiguous low-activity sessions are always kept (fail-open), so some noise
  survives unless you opt into a judge backend.
- Devin's stores are private internals; schema versions beyond v17 make the
  tool stop loudly rather than misparse.
- By default it deletes sessions only — `state.vscdb` GUI keys are tier3,
  gated behind `--include-gui` + a verified <24h `devin-backup` snapshot —
  and it never touches anything without a dry-run preview first.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## When to use this

- Your session list is drowning in noise — empty sessions, automation/eval
  probes, one-shot heartbeat cycles, duplicates (~55% of sessions on a real
  install).
- You want cleanup that archives first: `--export-cmd` (e.g.
  `devin-history export`) saves transcripts before anything is deleted,
  and aborts the whole run if the export fails.
- You want a reviewable plan, not blind deletion — `run` is a dry-run until
  `--apply`, with tiered classification you can inspect via `scan`.
- You want locked files handled gracefully — they go to a pending queue for
  retry instead of force-killing Devin, and `VACUUM` only runs when Devin
  is closed.

## When NOT to use this

- You expect ambiguous sessions to be auto-judged — the default
  `--judge none` keeps everything ambiguous (fail-open); plug in a judge
  command if you want semantic calls.
- You need unattended deletion — only `report` is schedulable
  (`install --daily`); `--apply` always requires a human in the loop.
- You want tier3 GUI-state cleanup without a verified `devin-backup`
  snapshot — the guard refuses on purpose.
- You cannot review a dry-run first — that review is the safety model, and
  `--apply` without reading the plan defeats it.

## FAQ

**What is devin-janitor?** A lifecycle manager for Devin's session stores.
It classifies sessions into tiers (safe noise vs keep vs ambiguous),
exports transcripts before deleting, retries locked files through a
pending queue, and vacuums only when Devin is closed.

**Is it safe? Will it delete real work?** `run` is a dry-run by default —
it prints the exact plan and writes nothing until `--apply`. Classification
is rules-based and fail-open: ambiguous sessions are kept unless you opt
into a `--judge command:<cmd>` backend. Protect specific sessions in
`.devin/janitor-keep.json` and use `--export-cmd` so nothing is lost.

**What happens to locked or in-use files?** They are not force-deleted.
Locked deletions go into a pending queue (`devin-janitor pending --list`,
`--retry`) and are retried later; `VACUUM` runs only when Devin is closed.

**Does it need an external service or model?** No. The default pipeline is
purely rules-based and fully offline — it reads Devin's own stores and
writes a local audit log. A semantic judge for ambiguous sessions is
opt-in via `--judge command:<cmd>` (for example a poordjaevin ACP script).

## License

MIT — see [LICENSE](LICENSE).
