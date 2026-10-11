<div align="center">

<img src="assets/banner.svg" alt="devin-backup" width="100%"/>

<a href="https://github.com/Icaro0310/devin-state/actions/workflows/test-backup.yml"><img src="https://github.com/Icaro0310/devin-state/actions/workflows/test-backup.yml/badge.svg" alt="ci"/></a>


<a href="https://scorecard.dev/viewer/?uri=github.com/Icaro0310/devin-backup"><img src="https://api.scorecard.dev/projects/github.com/Icaro0310/devin-backup/badge" alt="OpenSSF Scorecard"/></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"/></a>
<a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"/></a>
<a href="https://github.com/Icaro0310/devin-state"><img src="https://img.shields.io/github/stars/Icaro0310/devin-backup" alt="GitHub stars"/></a>
<a href="https://github.com/Icaro0310/devin-state/commits/main"><img src="https://img.shields.io/github/last-commit/Icaro0310/devin-backup" alt="Last commit"/></a>
<a href="https://github.com/Icaro0310/awesome-devin"><img src="https://img.shields.io/badge/part%20of-devin--*-ecosystem-7c3aed" alt="devin-* ecosystem"/></a>
<a href="https://github.com/Icaro0310/devin-state/issues"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome"/></a>
</div>

<!-- DEVIN-ECO:BEGIN -->
> **Part of the [DEVIN ecosystem](https://github.com/Icaro0310/awesome-devin)**  
> Track: Control · Nature: product  
> For: Local-first ops, Security engineers  
> Interface: CLI  
> Path: Local-first ops · step 4/5 — after `devin-office`, before `devin-janitor`
<!-- DEVIN-ECO:END -->


# devin-backup

> **Unofficial community project.** Not affiliated with, endorsed by, or
> sponsored by Cognition AI. "Devin" is a trademark of Cognition AI.

**[Linux](README.linux.md)** · **[Personal Windows](README.windows.md)** · **[Corporate Windows](README.corporate-windows.md)**

Part of the [awesome-devin](https://github.com/Icaro0310/awesome-devin) ecosystem: the curated hub for the devin-* tools.

Safe backup & restore for Devin Desktop stores: timestamped snapshots of
`sessions.db`, `acp-messages/`, `state.vscdb` and `.devin/` config — with
SQLite-consistent copies, integrity verification and rotation.

## The problem

Everything Devin keeps about your work lives in a handful of local SQLite
databases and config files. Two failure modes make naive `copy`/`robocopy`
backups dangerous:

1. **Live SQLite files.** Copying `sessions.db` while Devin is running can
   produce a corrupt copy — mid-write pages, unmerged WAL. It *looks* fine
   until you restore it.
2. **Silent schema drift.** `sessions.db` has already had **17 migrations**.
   Restoring an old backup over a newer install silently downgrades your
   data; nothing warns you.

## Prior art

General-purpose backup tools — `restic`, `borg`, `robocopy`, Windows File
History — copy bytes faithfully, but they know nothing about SQLite
consistency or about which files under a Devin data dir actually matter.
This project adapts the standard practice (`sqlite3`'s online backup API +
checksum manifests + retention rotation); it does not reinvent it.

## What makes it Devin-native

*It knows which stores are Devin's brain — and warns you when the brain's
format changed underneath a backup.*

1. **Side-by-side:** snapshots are made through `sqlite3.Connection.backup()`
   (consistent even while Devin runs, with file-copy fallback), and every
   manifest records `schema_version` via
   [`devin-internals-spec`](https://github.com/Icaro0310/devin-internals-spec).
2. **No-Devin:** remove Devin and there is nothing to discover — the extra
   disappears.
3. **One sentence:** on restore you get *"backup is v15, current is v17"*
   instead of a silent downgrade.

## Install

Requires Python ≥ 3.10. Install with `pipx install devin-backup`, `uv tool install devin-backup` or `pip install devin-backup`. Per-OS setup lives in the platform guides: [Linux](README.linux.md) · [Personal Windows](README.windows.md) · [Corporate Windows](README.corporate-windows.md).


## Usage

```bash
devin-backup create  [--data-dir <session-data-root>] [--config-dir <ui-config-root>] [--out <backups-dir>]
devin-backup verify  <snapshot-dir>
devin-backup diff    <snapshot-dir> [--data-dir <session-data-root>] [--config-dir <ui-config-root>] [--json]
devin-backup list    [--out <backups-dir>]
devin-backup restore <snapshot-dir> --to <session-data-root> [--config-to <ui-config-root>] [--apply] [--no-backup]
devin-backup rotate  [--keep N] --yes
```

- `create` snapshots `sessions.db`, ACP message databases, `state.vscdb` and
  `.devin/` files when present. A v2 manifest records which source root each
  file came from; old v1 snapshots remain readable.
- On Linux, the CLI data root and UI config root are separate. The default
  `create` detects both. If you pass `--data-dir`, also pass `--config-dir`
  to include the UI stores.
- `verify` re-checks every hash and runs `PRAGMA integrity_check` on DBs;
  exit code 1 on failure.
- `diff` compares a snapshot against the live stores — same/different per
  file, size deltas, files present on only one side — and never writes
  anything (exit 0 even on differences). For SQLite stores it compares a
  logical content digest plus per-table row counts, because
  `sqlite3.Connection.backup()` copies are not byte-identical.
- `restore` is a **dry-run by default**. It restores data-root files to
  `--to` and config-root files to `--config-to` (default: detected UI config
  root). Pass `--apply` to write. Existing files are saved to a
  `pre-restore-<ts>` backup first; `--no-backup` refuses overwrites.
- `rotate` keeps the newest N snapshots (default `$DEVIN_BACKUP_KEEP` or 10)
  and is a no-op until `--yes`. `pre-restore-*` dirs are never rotated.
- **A snapshot is a copy of every secret the stores hold.** Snapshot dirs
  are created owner-only (`0700` dirs, `0600` files — make sure the
  backups dir you pick is too). `create --exclude <PATTERN>` skips stores
  by path substring/glob (repeatable); `create --exclude-secrets` skips
  the stores a live audit found carrying OAuth tokens and PII:
  `globalStorage/state.vscdb`, `credentials.toml`, `*.pem`, `*.key`.
  Exclusions are listed in the manifest under `"excluded"`.

Defaults: the session data root is `$DEVIN_DATA_DIR` or
`%APPDATA%\\devin` on Windows and `$XDG_DATA_HOME/devin` (normally
`~/.local/share/devin`) on Linux. The UI config root is `%APPDATA%\\Devin`
on Windows and `$XDG_CONFIG_HOME/Devin` (normally `~/.config/Devin`) on Linux.
`--out` defaults to `$DEVIN_BACKUP_DIR` or `<data-root>/backups`.

```python
from devin_backup import diff, snapshot, verify, restore

snap = snapshot.create_snapshot(data_dir, backups_dir, config_dir=config_dir)
verify.verify_snapshot(snap)                       # {"ok": True, ...}
diff.diff_snapshot(snap, data_dir, config_dir=config_dir)  # read-only report
restore.restore_snapshot(snap, data_dir, config_dir=config_dir)  # dry-run
```

## Works with Devin alone (Devin-only mode)

devin-backup copies Devin's local stores to a destination folder you pick —
an external drive, a synced folder, anywhere on disk. No cloud account, VM or
network service is required.

Snapshots contain real session data (prompts, paths, commands). Treat the
backup destination as sensitive: keep it on a private/encrypted volume and
apply the same care you give the original stores.

## Adapters (MCP server, Devin skill, plugin)

`devin_backup.mcp_server` exposes the read-only surface as MCP tools — `backup_verify`, `backup_list` and
`backup_diff` (same payloads as the corresponding `--json` CLI
commands)
— via the `devin-backup-mcp` entry point (`pip install 'devin-backup[mcp]'`). The
`adapters/` directory is a self-contained Devin plugin root
(`adapters/.devin-plugin/plugin.json` + `adapters/skills/devin-backup/SKILL.md`),
installable with `devin plugins install
Icaro0310/devin-state#packages/backup/adapters`. Restoring a snapshot stays a
human-confirmed CLI action and is deliberately not exposed through any
adapter.

## Platform support

Tested on **Windows and Linux** (`windows-latest` + `ubuntu-latest` in CI).
Windows stores share the `%APPDATA%\\Devin` root. Linux stores are discovered
separately under `XDG_DATA_HOME/devin` and `XDG_CONFIG_HOME/Devin`. Use
`--data-dir` and `--config-dir` for non-default locations.

### `devin-backup copy-to` — verified secondary destination (BK-2)

Copies a whole snapshot into a secondary directory (mounted drive, NAS
mount, synced folder) and **re-verifies every sha256 at the destination** —
a corrupt copy is removed and reported instead of silently archived.
Encryption/remote sync is intentionally out of scope (personal-track P-8).

### `devin-backup install` — daily scheduled snapshots (BK-1)

`devin-backup install [--out DIR] [--backend auto|tasksch|cron|elapsed]`
registers a daily `devin-backup create` job using the F6 scheduling
foundation (shared `.devin-ecosystem/scheduled.json` registry): Task
Scheduler on Windows, a tagged crontab line elsewhere, and — where
schedulers are banned — the `elapsed` backend ticked by a `UserPromptSubmit`
hook (see devin-powerups `tools/schedule.py`). Opt-in; nothing is scheduled
unless you run it.

## Limitations

- **Private, volatile internals.** These stores are Devin implementation
  details; paths and schemas can change in any release. Store discovery is
  pattern-based (`*.db`, `*.vscdb`, `.devin/`) and best-effort.
- **Schema versions only exist where Devin keeps a ledger** —
  `sessions.db` gets a real `schema_version`; `acp-messages`/`state.vscdb`
  do not have one to record.
- **Not a scheduler.** M1 takes snapshots when you run it; Task Scheduler /
  cron integration is queued for M2 (see `docs/SPEC.md` §10).
- **Writes only on `--apply`.** Backup never touches Devin's databases except
  through the read-only backup API. `restore --apply` is the only write path
  and is always guarded by a pre-restore backup.
- Tested only against **synthetic fixtures** — no real session content is
  ever copied, by design.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

Ground rules in [CONTRIBUTING.md](CONTRIBUTING.md): fixtures before code,
small commits, a shared README and Windows/Linux platform guides. Canonical
spec: [docs/SPEC.md](docs/SPEC.md).

## When to use this

- You want point-in-time, restorable snapshots of everything Devin keeps
  locally — `sessions.db`, `acp-messages/`, `state.vscdb`, `.devin/` config.
- You need copies that are consistent even while Devin is running — the
  SQLite online backup API avoids corrupt mid-write copies.
- You want integrity guarantees: hash manifests plus
  `PRAGMA integrity_check` on `verify`, and a schema-version warning on
  restore instead of a silent downgrade.
- You want bounded retention — `rotate --keep N` prunes old snapshots
  without touching `pre-restore-*` safety copies.

## When NOT to use this

- You need scheduled backups — M1 only runs when you run it; wrap
  `devin-backup create` in cron/Task Scheduler yourself for now.
- You need encrypted or offsite/cloud backup — snapshots are plain files in
  a folder you pick; put that folder on an encrypted volume or sync it with
  your own tool.
- You only want the session text, not restorable state —
  [`devin-history`](https://github.com/Icaro0310/devin-explore) export may
  be all you need.

## FAQ

**What is devin-backup?** A CLI that takes consistent, verifiable snapshots
of Devin's local stores and can restore them safely. Every snapshot carries
a manifest with checksums and the `sessions.db` schema version, so restores
warn you before downgrading your data.

**Can I back up while Devin is running?** Yes. Snapshots go through
`sqlite3.Connection.backup()`, which is consistent on live databases, with
a file-copy fallback for non-SQLite files. You do not need to close Devin
to `create` or `verify`.

**Is restore destructive?** Not by default. `restore` is a dry-run until
you pass `--apply`, and even then every existing file is moved to a
`pre-restore-<timestamp>` backup first; `--no-backup` refuses overwrites
entirely.

**Does it encrypt or upload my backups?** No. Snapshots are plain copies in
a local folder. They contain real session data (prompts, paths, commands),
so keep the destination on a private or encrypted volume and apply the same
care you give the original stores.

## License

MIT — see [LICENSE](LICENSE).
