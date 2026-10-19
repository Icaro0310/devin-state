# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `devin-backup-mcp` exits with a one-line install hint when the `mcp`
  extra is missing instead of dumping a traceback; startup
  `ImportError`s from `.run()` keep their traceback.


### Added

- `restore --smoke` + `devin_backup.smoke`: post-restore integrity
  verification. With `--apply` it runs `PRAGMA integrity_check` and
  `devin-internals-spec` schema-version detection on every restored
  SQLite store and reports per store; in dry-run it smoke-checks the
  snapshot sources instead (read-only preview, nothing written).
  Exit code 1 if any store fails integrity.

- Daemon adapters for the daily snapshot (`adapters/daemon/`):
  `devin-backup-daily.{service,timer}` user-level systemd units and a
  Windows `task.xml` + `install-task.ps1`/`remove-task.ps1` pair —
  native-scheduler faces of the same `devin-backup create` job
  `devin-backup install` registers. The installer runs the canonical
  `devin-backup install --backend tasksch` for the registry entry, then
  overlays the XML task (logon + daily triggers, `StartWhenAvailable`,
  resolved absolute exe path — Task Scheduler's PATH lacks
  `%USERPROFILE%\.local\bin`); removal also cleans the job's
  `scheduled.json` record. `verify.sh` + `tests/test_daemon_adapter.py`
  cover the artifacts.

- Read-only adapters: `devin_backup.mcp_server` MCP server
  (`backup_verify` + `backup_list` + `backup_diff`,
  `devin-backup-mcp` entry point, `mcp` extra), Devin skill and
  `adapters/` plugin root; setup documented in the OS guides.

- README gains the generated `Part of the DEVIN ecosystem` block
  (track/nature/audience/interface rendered from the registry).

- `diff <snapshot>` subcommand + `diff_snapshot()`: read-only comparison of
  a snapshot against the live stores — per-file same/different via sha256
  plus a logical SQLite content digest (backup copies are not
  byte-identical), size deltas, per-table row counts on drift, and
  snapshot-only/live-only files. Always exits 0; `--json` supported.

### Changed


- Docs: guias de plataforma regenerados; o job agendado documentado usa wrapper `.cmd` em `%USERPROFILE%\devin-tasks` (cross-shell cmd.exe/PS5.1).
- Docs: export da raiz Zscaler no guia corporate-windows agora pede PEM — "Base-64 encoded X.509" no wizard de export ou `certutil -encode` após `Export-Certificate` (que gera DER) — e distingue `certmgr.msc` (store do usuário) de `certlm.msc` (store da máquina); a receita offline instala `setuptools`+`wheel` antes do `--no-build-isolation`.
- `labeler.yml` is now a thin caller of the shared reusable workflow in `devin-powerups` (`@v1`); PR labeling behavior is unchanged.

- Published to PyPI; the README install section prescribes `uv tool install`/`pip install` from the index and the source-only `DIST-STATUS` banner is gone.

- `llms.txt` no longer states a hard-coded ecosystem size; the registry owns the count.

## [0.1.0] - 2026-09-29

### Added

- Initial scaffold from `devin-repo-template`.
- Store discovery (`stores.py`): `*.db`/`*.vscdb` under the data dir
  (sidecars skipped) plus `.devin/` config; env-var dir resolution.
- `create_snapshot()`: timestamped snapshot dirs, SQLite-consistent copies
  via `sqlite3.Connection.backup()` with file-copy fallback, `manifest.json`
  with per-file size/sha256/`schema_version` (via `devin-internals-spec`).
- `verify_snapshot()`: sha256 + `PRAGMA integrity_check` per entry.
- `list_snapshots()` / `rotate_snapshots(keep)`: keep-N rotation that never
  touches `pre-restore-*` dirs or foreign directories.
- `restore_snapshot()`: dry-run by default, pre-restore backup of
  overwritten files, refusal without backup, manifest path-traversal guard,
  schema-version drift warnings.
- `devin-backup` CLI: `create`, `verify`, `list`, `restore`
  (`--dry-run`/`--apply`), `rotate --yes`.
- `docs/SPEC.md` (EN) and real bilingual READMEs.
