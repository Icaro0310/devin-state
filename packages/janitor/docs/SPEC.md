# devin-janitor — Spec (canonical, EN)

The lifecycle janitor for Devin sessions: a safety-ordered pipeline —
**export first, classify in tiers, delete only the safe tiers, retry locked
files, vacuum only when Devin is closed** — so `sessions.db` and
`acp-messages/` never bloat with empty/automation noise again.

Ported from `legacy/session-janitor.py` (proven in daily production use on a
real Devin Desktop install). Semantics preserved; hardcoded paths replaced by
detection, hardcoded rules replaced by config, and the Djævin-specific judge
replaced by pluggable backends.

## Stores

All knowledge of Devin's internals comes from
[`devin-internals-spec`](https://github.com/Icaro0310/devin-internals-spec)
(v0.2.0). Data root auto-detection (`DEVIN_DATA_DIR` overrides):

| OS      | root                                        |
|---------|---------------------------------------------|
| Windows | `%APPDATA%\devin`                           |
| macOS   | `~/Library/Application Support/devin`       |
| Linux   | `$XDG_DATA_HOME/devin` (see detection below) |

Inside the root:

- `cli/sessions.db`        — sessions + message forest (schema v15–v17 gated
  by `detect_schema_version`; unknown versions are refused)
- `User/acp-messages/*.db` — one store per GUI session (`meta` + `messages`)
- `cli/session_locks/*.lock` — live-session locks; presence ⇒ Devin active

## Environment overrides

Every root is env-overridable. Precedence per root is explicit CLI flag
(`--data-dir`, `--config-dir`, `--labels-file`) > `DEVIN_*` env var >
platform convention — with one coupling to know: when `--data-dir` is
given but `--config-dir` is not, the ACP store resolves *under that
data root* (`<data-dir>/User/acp-messages`) and `DEVIN_CONFIG_DIR` is
not consulted. An explicit data dir is treated as a self-contained
Devin home.

| env var                  | overrides                                        | platform default |
|--------------------------|--------------------------------------------------|------------------|
| `DEVIN_DATA_DIR`         | data root (`cli/sessions.db`, `cli/session_locks/`) | `%APPDATA%\devin` · `~/Library/Application Support/devin` · `$XDG_DATA_HOME/devin` |
| `DEVIN_CONFIG_DIR`       | UI-config root (`User/acp-messages/`)            | `%APPDATA%\Devin` · `~/Library/Application Support/Devin` · `$XDG_CONFIG_HOME/Devin` |
| `DEVIN_BRIDGE_STATE_DIR` | bridge state dir (`session-labels.json`, JA-4)   | `%LOCALAPPDATA%\devin-bridge` · `~/Library/Application Support/devin-bridge` · `$XDG_STATE_HOME/devin-bridge` |

`APPDATA`, `LOCALAPPDATA` and the `XDG_*` variables are honoured as
platform conventions whenever the matching `DEVIN_*` override is unset.
On Linux the data root is the first of `$XDG_DATA_HOME/devin`,
`$XDG_CONFIG_HOME/devin`, `~/devin` that already holds a
`cli/sessions.db` file (so migrated installs keep working).

The archived legacy script (`legacy/session-janitor.py`) had its own
env contract for the parts the port replaced; each knob maps to a
package equivalent:

| legacy var              | legacy purpose                         | package equivalent |
|-------------------------|----------------------------------------|--------------------|
| `JANITOR_EXPORTER`      | history-export script run before delete | `--export-cmd CMD` |
| `JANITOR_JUDGE_PYTHON`  | interpreter for the judge subprocess   | `devin-judge:<bin>` — role equivalent only: the legacy var held a Python *interpreter*, the package flag takes the `poordjaevin` *binary*; values are not interchangeable |
| `JANITOR_JUDGE_MODULE`  | private bridge module to shell         | `--judge command:<cmd>` (any backend spec) |
| `JANITOR_JUDGE_BACKEND` | backend selector exported to the judge | chosen by the `--judge` spec |

The legacy script also hardcoded `~/AppData/Roaming/devin` roots; the
package replaces them with the detection + overrides table above.

One behavior knob (not a path) is also env-configurable:
`JANITOR_NOTIFY_CMD` supplies `run`'s post-run notification command when
`--notify-cmd` is absent — flag > env, and an explicit empty flag
disables it (see *Pipeline (`run`)* step 8).

## Inventory

`inventory.load_inventory(paths)` merges both stores into `SessionRow`s:

- `origin`: `cli` (sessions.db) or `gui` (acp-messages files with no
  sessions.db row)
- counters: `user_msgs`, `assistant_msgs`, `tool_calls`, `files_touched`
  (distinct path-like values in tool-call payloads — heuristic)
- `prompt`: first user message text (feeds the judge)
- timestamps normalized ms → s; GUI rows use file mtime as `last_activity`

## Tiers (`tiers.classify`)

Evaluated in order; first match wins:

1. **KEEP** — `keep_ids` (keep-file), `keep_re` title match (defaults:
   `n[ãa]o apagar`, `SLACK-BRAIN`, plus keep-file `title_patterns`), or
   `last_activity` inside `--grace-hours` (default 48h)
2. **AUTO_DELETE** —
   - `empty`: zero user/assistant/tool activity
   - `duplicate`: same normalized title in same project; sibling with the
     highest `score = user_msgs*3 + tool_calls` survives
   - `automation/eval noise`: `noise_re` matches title AND
     `tool_calls <= 5`
   - `ephemeral heartbeat/mailbox cycle`: `ephemeral_re` matches AND
     `user_msgs <= 75` AND `tool_calls <= 60`
3. **JUDGE** — weak/ambiguous: `user_msgs <= 6`, `tool_calls <= 15`,
   `files_touched == 0`, `score < 20`
4. everything else → **KEEP** (`substantive work`)

All patterns and thresholds come from `JanitorConfig` (`--config file.json`,
merged over defaults). An empty pattern list matches nothing.

Keep-file format (default `.devin/janitor-keep.json`):

```json
{"ids": ["session-id"], "title_patterns": ["KICKOFF"]}
```

## Judge (`judge.make_judge`)

Ambiguous sessions ask a pluggable backend whether they hold durable
knowledge (`judge_statement`, also configurable). **Every backend is
fail-open**: unavailable/error/timeout/unclear verdict ⇒ keep.

| spec                        | behavior                                            |
|-----------------------------|-----------------------------------------------------|
| `none` (default)            | abstains on all — purely rules-based, nothing deleted without a tier rule |
| `devin-judge[:<bin>]`       | shells `poordjaevin ask` per session (local, typed answers with calibrated confidence). Only a decided `delete` deletes; abstained/low-confidence/error keeps. `poordjaevin`, `judge` are aliases; `<bin>` overrides the binary. |
| `command:<cmd>`             | JSON payload on stdin; stdout parsed as verdict (`{"keep": bool}` or bare keep/delete token). Plug in any local CLI (e.g. a Devin ACP helper). |

## Pipeline (`run`)

1. classify → judge ambiguous → `targets = (auto_delete + judged_delete)`
   capped at `max_delete` (100)
2. print plan; without `--apply` exit 0 having written nothing
3. `--export-cmd` (if given) runs **before** any deletion; non-zero exit
   aborts with rc=3. Recommended recipe:
   `devin-history export` (M2 will make this a real dependency)
4. delete rows in `message_nodes`, `tool_call_state`, `rendered_commits`,
   `subagent_heads`, `prompt_history` + the `sessions` row; delete
   `acp-messages/<id>.db*` + `<id>.lock`. Files that fail (locked by a
   running Devin) go to `janitor-pending.json` and are retried every run
   (`pending --retry` retries on demand)
5. remove `session_locks/*.lock` whose session no longer exists
6. `wal_checkpoint(TRUNCATE)` + `VACUUM` **only** when no lock files exist
   AND no Devin process is detected (`tasklist`/`pgrep`; detection failure
   counts as running — fail-safe)
7. append one JSON object to `janitor-log.jsonl` (id, origin, tier, reason,
   judge verdict, pending, orphans, vacuumed) and persist the pending queue
8. `--notify-cmd`/`JANITOR_NOTIFY_CMD` (if set) receives a compact JSON
   run summary on its stdin — after both the dry-run and `--apply` paths,
   and after aborts too, so the payload's `rc` carries the outcome:

   ```json
   {"apply": true, "total": 12, "planned": 3, "deleted": 3,
    "retained": 9, "pending": 0, "rc": 0}
   ```

   `planned` is the deletion plan (a dry-run reports it with
   `apply: false`, `deleted: 0`); `retained` counts sessions the run
   leaves alone — keepers plus deletes outside `--tiers`/`--max-delete`;
   `deleted` counts unique sessions actually removed (a session holding
   both a `sessions.db` row and `acp-messages` files counts once).
   The printed plan's `keep:` line and the payload's `retained` measure
   different things on purpose: the console figure counts *classified
   keepers* (allowlist/grace/substantive + judged-kept + judge-down),
   while `retained` counts *sessions the run leaves alone* — the two
   diverge exactly when `--tiers` or `--max-delete` leaves selected-able
   deletes untouched. Notification is
   **fail-open** — an unrunnable command, non-zero exit or the 10s
   timeout prints a stderr warning and never changes the exit code.
   Flag beats env; an explicit `--notify-cmd ""` disables it. The janitor
   ships no notifier — the hook expects a local command (slack/mail
   wrapper, devin-bridge helper).

## CLI

```
devin-janitor scan [--data-dir D] [--sessions-db F] [--acp-dir D]
                   [--locks-dir D] [--config F] [--keep-file F]
                   [--grace-hours N] [--json] [-v]
devin-janitor run  [path flags...] [--config F] [--grace-hours N]
                   [--max-delete N] [--judge SPEC] [--export-cmd CMD]
                   [--notify-cmd CMD]
                   [--keep-file F] [--pending-file F] [--log-file F]
                   [--tiers 1,2|all] [--include-gui] [--snapshot PATH]
                   [--apply]
devin-janitor pending [path flags...] [--pending-file F] [--list] [--retry]
devin-janitor report  [path flags...] [--config F] [--keep-file F]
                      [--pending-file F] [--grace-hours N] [--judge SPEC]
                      [--labels-file F] [--exclude-labeled]
                      [--project N[h|d|w]] [--json]
devin-janitor install --daily [--config-dir D]
                      [--backend auto|tasksch|cron|elapsed] [--json]
```

Dry-run is always the default. `run` without `--apply` prints the exact plan
and exits 0 without writing anything (no db writes, no pending file, no log).

`report` is advisory: it exits 0 always, writes nothing, and estimates
recoverable bytes from the same classification rules as `run` —
AUTO_DELETE + judged deletes + pending-queue ids, the `-wal`/`-shm` sidecars
that a safe vacuum truncates, stale acp-messages leftovers, and orphan
`session_locks/*.lock`. Per-session byte figures are payload estimates
(`SUM(LENGTH(...))` per message table), not exact page accounting.

`report --project N[h|d|w]` adds a **growth projection** section (and a
`projection` object in `--json`): each store's estimated size `N` hours,
days or weeks ahead (bare number = days). The janitor keeps **no size
history** — the report is read-only and the audit log records deletions,
not sizes — so the model is the simplest defensible one:

    rate      = current bytes ÷ days since first-seen
    projected = current bytes + rate × horizon

where *first-seen* is the store's `oldest` timestamp already reported
(session span for `sessions.db`, oldest `*.db` mtime for `acp-messages`,
oldest `*.lock` mtime for `session_locks`). It is an **average
accumulation rate**, not a trend fit — the output prints the rate and
the window it came from, and the payload carries the caveat, because an
estimate that hides its assumptions is a fake. Stores with no honest
rate report `insufficient data` instead of a number: missing stores,
stores with no first-seen timestamp (e.g. `state.vscdb`, or a
`sessions.db` holding zero sessions), and observation windows shorter
than 24h — a store created today has no rate. Invalid horizons
(non-numeric, zero/negative, unknown units) exit 2 before any report is
printed.

## Cleanup tiers (JA-2)

`run --tiers` selects what `--apply` may touch; `report` shows per-tier
sizes:

- **tier1 — orphans & cache**: `sessions.db` checkpoint sidecars (reclaimed
  by the safe vacuum), message rows whose session is gone, dead-session
  `acp-messages` leftovers, orphan locks. No session content.
- **tier2 — stale sessions** (default with tier1): the auto_delete/judged
  pipeline above.
- **tier3 — GUI state** (opt-in): stale `windsurfSpace.sessionWorkspace/*`
  keys in `state.vscdb`. `--apply` refuses tier3 unless `--include-gui`
  **and** `--snapshot PATH` verifies a `devin-backup` manifest <24h old
  covering `state.vscdb` — and Devin must be closed. Refusals exit 4
  (missing `--include-gui` exits 2). Each deleted key leaves a
  `devin.janitor.tombstone/<original key>` marker in `ItemTable` — metadata
  only (`key`, `slug`, `backend`, `bytes`, `last_updated`, `deleted_at`),
  never the payload; the verified snapshot owns restoration. Tombstones
  live outside `GUI_STATE_PREFIX`, so they are never re-scanned as stale
  entries and re-runs stay idempotent.

## Automatic sessions (JA-4)

The bridge sidecar `<bridge-state>/session-labels.json`
(`DEVIN_BRIDGE_STATE_DIR` or platform default) maps session ids to
`origin:purpose` labels. `report` lists matching inventory sessions in an
`automatic_sessions` section (origin `bridge` ⇒ automation); labeling is
advisory and fail-open. `--labels-file` overrides the sidecar path;
`--exclude-labeled` excludes labeled sessions from classification.

## Scheduled report (JA-1)

`install --daily` registers a read-only daily `report` via the F6
scheduling pattern — tagged `@daily` crontab line, a `schtasks` daily
entry on Windows, or an elapsed job record in
`<config-dir>/.devin-ecosystem/scheduled.json` ticked by a
`UserPromptSubmit` hook. `--apply` is never scheduled.

## Safety invariants

- export precedes deletion; export failure aborts
- notify follows the run; notify failure only warns — never fails a run
- judge abstention keeps; there is no fail-closed path
- locked files are never force-deleted — they queue for retry
- VACUUM never runs while Devin may have the db open
- schema versions outside the spec's known range abort loudly

## Limitations

- `--project` is a straight-line estimate, not a forecast: it assumes the
  average accumulation rate since first-seen continues unchanged, so it
  ignores inactivity gaps, bursts, cleanups and vacuums, and it has no
  signal for stores that expose no start-of-accumulation timestamp.
- Default `judge=none` is purely rules-based: ambiguous low-activity sessions
  are always kept, so the db may retain some noise that a judge would catch.
- `files_touched` is a heuristic over tool-call payloads; a session that
  touched files via an unrecognized payload shape may fall to JUDGE.
- GUI (`acp-messages`) rows have weaker signals than CLI rows (no rich
  message roles); `last_activity` is file mtime.
- Devin's internals are private and versioned; a schema bump beyond v17
  stops the tool rather than misparse.
