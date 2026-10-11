# STATUS

## M1 — done (2026-09-29)

Ported `legacy/session-janitor.py` into `src/devin_janitor/`:

- `paths.py` — OS-aware Devin data-root detection (`DEVIN_DATA_DIR`,
  `--data-dir`, per-store flags)
- `config.py` — `JanitorConfig`: all tier patterns/thresholds
  config-driven via `--config`
- `inventory.py` — unified `SessionRow`s over `sessions.db` +
  `acp-messages/` via `devin-internals-spec` v0.2.0
- `tiers.py` — KEEP / AUTO_DELETE / JUDGE classifier (legacy semantics)
- `judge.py` — pluggable `none` | `devin-judge[:<bin>]` | `command:<cmd>`,
  fail-open
- `exporter.py` — `--export-cmd` hook, aborts run on failure
- `execute.py` — row + gui-file deletion, `janitor-pending.json` retry
  queue, orphan-lock pruning, VACUUM only when Devin closed and no locks
- `report.py` — `janitor-log.jsonl` audit + human plan/summary
- `cli.py` — `scan` / `run` (dry-run default) / `pending`

54 tests green (`python -m pytest`), fixtures-first on
`devin_internals.fixtures`; dry-run verified to write nothing;
`run --apply` verified end-to-end on a fabricated data dir.

## M2 — in progress

- [x] JA-1 `install --daily` — daily `report` job via F6 scheduling
      (cron tag `# devin-ecosystem:devin-janitor-daily` / schtasks /
      elapsed registry in `.devin-ecosystem/scheduled.json`); only
      `report` is ever scheduled
- [x] JA-2 cleanup tiers — tier1 orphans & cache, tier2 stale sessions,
      tier3 `state.vscdb` GUI keys gated behind `--include-gui` + a
      verified devin-backup snapshot (<24h); `report` shows per-tier sizes
- [x] JA-4 automatic sessions — `report` marks bridge-labeled sessions
      from `session-labels.json`; `--labels-file` / `--exclude-labeled`

## M2 queue
- [ ] Depend on `devin-history` package instead of a free-form
      `--export-cmd` string
- [ ] Slack digest of janitor runs
- [ ] PyPI release
