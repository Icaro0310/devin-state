# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
