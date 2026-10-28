# SPEC — `devin-backup`

## 1. Problem

Everything Devin keeps about your work lives in a handful of local files:
`cli/sessions.db` (session metadata + message tree), `User/acp-messages/*.db`
(per-session ACP logs), `User/globalStorage/state.vscdb` (workbench state) and
`.devin/` (skills, memory, config). Losing that directory means losing every
session you ever ran.

Two failure modes make naive backups dangerous:

1. **Live SQLite files.** Copying `sessions.db` while Devin is running can
   produce a corrupt copy (mid-write pages, unmerged WAL). The copy *looks*
   fine until you restore it.
2. **Silent schema drift.** `sessions.db` has already had **17 migrations**
   (per `devin-internals-spec`). Restoring a v15 backup over a v17 install
   silently downgrades the data — nothing warns you.

## 2. Devin extra (and the 3 tests)

**Extra:** it knows *which* stores matter, snapshots them *consistently* via
the SQLite backup API, and stamps every snapshot with `schema_version` from
`devin-internals-spec` — so restore warns "backup is v15, current is v17".

- **Side-by-side:** `robocopy`/`restic`/File History copy bytes; they cannot
  produce a consistent copy of a live SQLite file, do not know which files in
  a data dir are worth keeping, and have no concept of schema versions.
- **No-Devin:** remove Devin and there are no stores to discover — the extra
  disappears.
- **One sentence:** *"Time Machine for Devin's local brain — one that warns
  you when the brain format changed underneath you."*

## 3. Scope (M1)

`src/devin_backup/`:

- `stores.py` — discovers `**/*.db`, `**/*.vscdb` (minus WAL/SHM/journal
  sidecars) and `.devin/**` under a data dir; resolves default dirs.
- `snapshot.py` — `create_snapshot()` → `backups/<timestamp>/` + `manifest.json`;
  SQLite files copied via `sqlite3.Connection.backup()` with file-copy
  fallback; sha256/size/schema_version per file.
- `verify.py` — re-checks sha256 and runs `PRAGMA integrity_check` on DBs
  (catches sources that were already corrupt at backup time).
- `rotate.py` — `list_snapshots()` +
  `rotate_snapshots(keep=N, older_than=dur)`; only timestamp-named
  manifest dirs are ever deleted.
- `restore.py` — dry-run by default; pre-restore backup of files it would
  overwrite; refuses to overwrite with `backup=False`; schema-drift warnings.
- `cli.py` — thin argparse wrapper.

## 4. Non-scope

- Scheduling (Windows Task Scheduler / cron) — M2.
- Compression, remote/cloud targets, encryption — M2.
- Reading or exporting session content — that is `devin-history`.
- Whole-disk backups — this only covers Devin's stores.

## 5. Interfaces

| Interface | Description |
|---|---|
| Library `devin_backup` | `create_snapshot`, `verify_snapshot`, `list_snapshots`, `rotate_snapshots`, `restore_snapshot` |
| CLI `devin-backup` | `create` · `verify` · `list` · `restore` (dry-run default, `--apply` to write) · `rotate` (requires `--yes`) |
| Dependency | `devin-internals-spec` — `fixtures` for tests, `schema.detect_schema_version` for the manifest |

## 6. Data contract — `manifest.json`

```json
{
  "manifest_version": 1,
  "tool": "devin-backup",
  "tool_version": "0.1.0",
  "created_at": "2026-09-29T19:31:25+00:00",
  "source_data_dir": "C:/.../data",
  "files": [
    {
      "path": "cli/sessions.db",
      "kind": "sqlite",
      "copied_via": "sqlite-backup",
      "size": 81920,
      "sha256": "…",
      "schema_version": 17
    }
  ],
  "schema_versions": {"cli/sessions.db": 17}
}
```

`schema_version` is `null` for stores without a `refinery_schema_history`
ledger (`acp-messages`, `state.vscdb`) — detection semantics come from
`devin_internals.schema`. Snapshot dirs are `YYYYMMDDTHHMMSSZ` (UTC);
safety backups made by `restore` are `pre-restore-<ts>` and are exempt from
rotation.

## 7. Fixtures and tests (TDD — fixtures first)

`devin_internals.fixtures.create_devin_data_dir()` fabricates the store tree;
tests add a synthetic `.devin/config.json` on top. Covered: store discovery,
full snapshot + manifest correctness, SQLite-backup consistency, file-copy
fallback, backups-dir exclusion, schema_version recorded (v15/v17), verify
catches corruption/missing files/DB-internal corruption, rotation keep-N and
safety-dir exemption, restore dry-run/apply/refusal/path-traversal/schema
warning, CLI exit codes. 48 tests, Windows + Linux (CI matrix).

## 8. Risks and mitigation

| Risk | Mitigation |
|---|---|
| Locked DB while Devin runs | `Connection.backup()` is designed for live DBs; file-copy fallback flagged in manifest |
| Schema change between backup and restore | `schema_versions` in manifest + restore warning via `devin-internals-spec` |
| Restore clobbers current data | dry-run default; pre-restore backup; `backup=False` refuses outright |
| Rotate deletes something it shouldn't | only `^\d{8}T\d{6}Z` dirs *with* a manifest qualify; `--yes` required at the CLI |
| Terms of use | reads local files only; restores only behind explicit `--apply`; no network |

## 9. Definition of done

- [x] `pytest` green (48 tests)
- [x] `devin-backup create/verify/list/restore/rotate` runs on a fixture dir
- [x] `docs/SPEC.md` + shared README and Windows/Linux guides with Prior art / Limitations
- [x] CHANGELOG + STATUS updated, pushed

## 10. M2 queue

1. Scheduled backups (Windows Task Scheduler integration; cron on Linux).
2. Compression (`zip`/`.tar.zst`) and remote targets (S3/rclone).
3. PyPI publish (`pipx install devin-backup`).
4. `verify --deep`: row-count diff between snapshot and live store.
