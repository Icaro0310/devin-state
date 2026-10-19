# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `devin-janitor-mcp` exits with a one-line install hint when the `mcp`
  extra is missing instead of dumping a traceback; startup
  `ImportError`s from `.run()` keep their traceback.
- `docs/SPEC.md` documents the full environment-override contract
  (`DEVIN_DATA_DIR`/`DEVIN_CONFIG_DIR`/`DEVIN_BRIDGE_STATE_DIR`, platform
  vars, flag > env > detection precedence, Linux detection order) and
  maps the archived legacy script's `JANITOR_*` vars to their package
  equivalents; the Stores table now shows the real Linux data root
  (`$XDG_DATA_HOME/devin`). README.linux.md now also documents the
  data-root detection fallback for migrated installs (first of
  `$XDG_DATA_HOME`, `$XDG_CONFIG_HOME`, `~/devin` containing
  `cli/sessions.db`), the `--data-dir` self-contained coupling, and
  that `JANITOR_JUDGE_PYTHON` maps by role only, not by value.


### Added

- `devin-judge` judge backend (`--judge devin-judge`, aliases
  `poordjaevin`/`judge`, `devin-judge:<bin>` for a custom binary): shells
  `poordjaevin ask` per ambiguous session and maps the typed answer onto
  the fail-open verdict contract — only a decided `delete` deletes.
- Tier3 GUI-state deletion now leaves a `devin.janitor.tombstone/<key>`
  metadata marker per removed binding (original key, slug, backend,
  bytes, timestamps) for auditability; the verified snapshot still owns
  payload restoration. Tombstones are idempotent and never re-scanned.

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


- Docs: guias de plataforma regenerados (Zscaler, flags reais de paths, cadência fiel).
- Docs: export da raiz Zscaler no guia corporate-windows agora pede PEM — "Base-64 encoded X.509" no wizard de export ou `certutil -encode` após `Export-Certificate` (que gera DER) — e distingue `certmgr.msc` (store do usuário) de `certlm.msc` (store da máquina); a receita offline instala `setuptools`+`wheel` antes do `--no-build-isolation`.
- `labeler.yml` is now a thin caller of the shared reusable workflow in `devin-powerups` (`@v1`); PR labeling behavior is unchanged.

- README install section replaced by a generated `DIST-STATUS` banner stating the tool is source-only (no PyPI release yet) and offering both `pipx` and `uv` source installs.

- `llms.txt` no longer states a hard-coded ecosystem size; the registry owns the count.
