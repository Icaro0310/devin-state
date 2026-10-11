# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Read-only adapters: `devin_janitor.mcp_server` MCP server
  (`janitor_dry_run` + `janitor_classify`, `devin-janitor-mcp` entry
  point, `mcp` extra), Devin skill and `adapters/` plugin root; setup
  documented in the OS guides. Dry-run reports now fold the pending
  retry queue into recoverable bytes like the CLI's `report`, and honor
  the default keep allowlist when `keep_file` is unset.

- README gains the generated `Part of the DEVIN ecosystem` block
  (track/nature/audience/interface rendered from the registry).

- Initial scaffold from `devin-repo-template`.
- M1: ported `legacy/session-janitor.py` into `src/devin_janitor/` —
  OS-aware path detection (`paths.py`), config-driven tier rules
  (`config.py`), unified session inventory over `sessions.db` +
  `acp-messages/` via `devin-internals-spec` (`inventory.py`),
  KEEP/AUTO_DELETE/JUDGE classifier (`tiers.py`), pluggable fail-open
  judge backends `none|command:<cmd>` (`judge.py`), pre-delete
  export hook (`exporter.py`), deletion engine with pending-retry queue,
  orphan-lock pruning and closed-Devin-only VACUUM (`execute.py`), JSONL
  audit log + plan rendering (`report.py`), and the `scan`/`run`/`pending`
  CLI (`cli.py`) — dry-run by default.
- `docs/SPEC.md` (canonical EN), bilingual READMEs, STATUS.md.
- `devin-janitor report`: advisory recoverable-space report over
  `sessions.db`, `acp-messages/`, `state.vscdb` and `session_locks/` —
  per-store bytes, age span and estimated recoverable bytes from the
  janitor's own rules; `--json`, optional `--judge`, always exits 0.

### Changed

- `labeler.yml` is now a thin caller of the shared reusable workflow in `devin-powerups` (`@v1`); PR labeling behavior is unchanged.

- README install section replaced by a generated `DIST-STATUS` banner stating the tool is source-only (no PyPI release yet) and offering both `pipx` and `uv` source installs.

- `llms.txt` no longer states a hard-coded ecosystem size; the registry owns the count.
