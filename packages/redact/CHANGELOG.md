# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-10-11

### Added

- `ghcr.io/icaro0310/devin-redact` container image: the `devin-redact`
  CLI on `python:3.12-slim` running as a non-root user, published after
  each `redact-v*` release.
- `devin_redact.paths`: default `sessions.db` discovery matching the
  ecosystem convention (`%APPDATA%\devin\cli\sessions.db`,
  `~/Library/Application Support/…`, `$XDG_DATA_HOME`/`$XDG_CONFIG_HOME`/`~`
  fallbacks) — same candidate order as `devin-history`.
- CLI `sessionend-scan`: the `scan` invocation shaped for the
  `SessionEnd` hook (RD-1). Scan-only, bounded to the auto-detected
  default `sessions.db` (optional explicit path), prints one compact
  verdict line (`devin-redact: findings=N publication_status=X`), exits
  0 even on `BLOCKED` — non-zero (2) only on hard error. Registration
  documented in `docs/HOOKS.md` with the `hooks.json` entry for the
  planned `devin-powerups` hook dispatcher.
- CLI `gate`: machine gate for pipelines like `devin-history` (RD-4).
  Prints just the `publication_status` word; exits 0 for CLEAN/REVIEW,
  1 for BLOCKED, 2 on error.
- Cross-chunk scan pass (RD-2): on `sessions.db`-shaped stores, re-scans
  concatenations of adjacent same-session payloads —
  `tool_call_json`+`tool_call_update_json` of the same `tool_call_state`
  row, adjacent `tool_call_state`/`message_nodes` rows, and streaming
  parts inside one payload — so secrets split across two chunks are
  reassembled and reported at the earlier rowid with
  `kind="cross-chunk"`. Bounded: adjacent pairs only, same session only,
  full pattern matching only after a cheap boundary pre-filter.
  Detection-only: `redact` does not rewrite split secrets back into two
  halves.
- CLI `session-end`: per-session SessionEnd hook (RD-1). Resolves the
  just-ended session — `--session-id` → `{"session_id": …}` on stdin →
  `DEVIN_SESSION_ID` → most recently active in `sessions.db` — scans only
  that session's rows via `engine.scan_session()` and writes the verdict
  to a side file (`<data-dir>/redact/<session-id>.json`; `--data-dir`,
  `DEVIN_REDACT_DATA_DIR` and `--out` override). Never writes into any
  Devin store or transcript; fail-soft — unresolvable sessions produce a
  `SKIPPED` verdict and exit 0, only usage errors exit 2.
- CLI `verify-publish`: publication gate for `devin-history` export
  directories (RD-4). Enumerates exported sessions from `index.json`/
  `index.md` or the `<YYYY-MM-DD>_<session-id>.<ext>` layout, extracts
  each `session_id`, scans every file read-only and reports per-session
  verdicts. Cross-references `session-end` side files — a `BLOCKED` hook
  verdict beside a `CLEAN` export is a warning that holds the overall
  verdict at `REVIEW`. Exits 0 only when the overall verdict is `CLEAN`.
- Session-scoped scanning: `engine.scan_session(db, session_id)` filters
  every session-attributed table (`session_id` column, or `sessions.id`),
  including the cross-chunk pass; the `sessions` metadata row itself is
  excluded so clean sessions stay `CLEAN`.
- Cross-chunk pre-filter hardened (RD-2): a token-run of secret length
  spanning a payload boundary now triggers the reassembly scan, so a
  secret split at *any* byte offset — including 1-char fragments on
  either side — is detected; context pre-filters relaxed to catch
  `Bearer`/`KEY=`/`pairing code` hugging the edge.
- Tests: split-secret fixtures (adjacent message nodes, adjacent and
  within-row tool calls, streamed content parts), cross-session and
  non-adjacent negatives, every-offset split sweep, `sessionend-scan`/
  `gate`/`session-end` exit codes and verdict contracts, `verify-publish`
  over md/json export layouts, path auto-detection. 100 tests green.

### Changed

- README gains the generated `Part of the DEVIN ecosystem` block
  (track/nature/audience/interface rendered from the registry).
- Test fixtures are allowlisted via `.secrets-scan-allow`
  (`path sha256=<hash>` entries) now that the shared secrets-scan drops
  its blanket `fixtures` directory exclusion.

- `labeler.yml` is now a thin caller of the shared reusable workflow in `devin-powerups` (`@v1`); PR labeling behavior is unchanged.

- Install section now recommends pypi `uv tool install devin-redact` as the primary route, with `pipx`/source installs documented as alternatives.

- `llms.txt` no longer states a hard-coded ecosystem size; the registry owns the count.
- Platform guides and the README install command no longer pin a release; they install the latest published version.

### Fixed

- `__version__` now matches the published artifact: the 0.2.1 wheel on
  PyPI self-reports 0.2.0 (built from an unmerged branch before the
  verify gate existed). This release exists so the index carries a
  wheel whose metadata and self-report agree.

- `gate --staged` + published pre-commit hook: the hook now runs
  `devin-redact gate --staged`, which scans each path's blob in the git
  index (`:0:<path>`) via the new `devin_redact.staged` /
  `engine.scan_blobs` path. Previously the hook scanned working-tree
  files, so a secret staged and then edited or deleted out of the
  worktree bypassed the gate while still shipping in the commit. Paths
  with no staged blob (staged deletions, never-added files) are skipped;
  an unreadable index entry fails closed (exit 2).
- `env_assignment` literal detection now parses the right-hand side with
  `ast.literal_eval` instead of a quote-prefix heuristic — the bare
  `("secret")` fix from 0.2.1 now also covers nested parens, `r`/`b`/`u`
  prefixes, triple quotes, implicit concatenation (`("a" "b")`),
  trailing `#` comments and one-element tuples (`("x",)`). Dynamic
  expressions — calls, f-strings, comprehensions, conditionals and real
  containers — stay suppressed.

## [0.2.1] - 2026-10-10

### Fixed

- `env_assignment` no longer fires when the matched name is bound to a
  code expression — `_STRUCTURAL_KEYS = frozenset({...})`,
  `TOKEN_RE = re.compile(...)`, `SECRET_PATTERNS = [...]`. The pattern
  anchors on KEY/SECRET/TOKEN-carrying names, which made any repo
  holding scanner configs, env parsers or policy generators (including
  this package's own source and devin-janitor's regexes) gate BLOCKED.
  Suppression covers only right-hand sides that are container literals
  or calls — shapes an env value can never take; bare and quoted values
  still flag, so private constants holding real secrets remain caught.
  Applies to scan and redact identically via `_iter_matches`.

- `__version__` now matches the package version (the 0.2.1 wheel had shipped self-reporting 0.2.0).
- PyPI publish workflow verifies the wheel's self-reported `__version__` against `pyproject.toml` before upload (`--no-deps` install into an isolated target).
- Release workflow passes `github.ref_name` through `env:` instead of interpolating it into `run:` shell source.

### Added

- GHCR image `ghcr.io/icaro0310/devin-redact` tagged `<version>` + `latest` (linux/amd64 + linux/arm64); the image installs the published wheel, never the checkout.

## [0.2.0] - 2026-09-29

### Added

- `devin_redact.semantic`: tool-call semantic layer. Parses
  `tool_call_state.tool_call_json` `rawInput` and flags the associated
  `tool_call_update_json` output for redaction when the command/read
  targets a known-sensitive file (`.env*`, `credentials*`, `*.pem`,
  `~/.ssh`, `~/.aws`, …) — even when no pattern matches the output.
  Findings carry `kind="semantic-context"`.
- `engine.redact()` real implementation: replaces secret spans with
  `<REDACTED:sha256prefix>` (keeping `KEY=` prefixes for `.env`
  assignments), decodes/rewrites JSON cells leaf-wise so structure stays
  valid, and wholesale-redacts output payloads of sensitive reads while
  preserving structural keys (`type`, `mimeType`, `toolCallId`, …).
- Write path safety: dry-run by default; in-place requires
  `--apply --i-know-this-is-irreversible`; mandatory `.bak` sibling
  backups; DB updates in a single transaction; post-redact open +
  `integrity_check` with backup restore on failure.
- CLI `verify`: exits 0 only when `CLEAN`, 1 otherwise with
  `PUBLICATION STATUS: …` + per-category summary; `--json` for the full
  report.
- Idempotent redaction: `<REDACTED:…>` tags are never re-matched or
  re-redacted; `scan` ignores already-redacted values.
- Fixture corpus extended with a semantic-layer case (`cat .env` output
  with no pattern-shaped secret) and a benign `ls -la` negative control.
- Tests: redact-on-copy (DB still opens, planted fingerprints gone,
  edits logged), transaction rollback on induced failure, semantic
  flagging, `verify` exit codes both ways, text/JSON redaction
  idempotency. 23 tests green.

## [0.1.0] - 2026-09-29

### Added

- `devin_redact.patterns`: detection patterns for API keys (OpenAI/Stripe/
  AWS/Google/Slack), bearer tokens and JWTs, GitHub tokens (`ghp_`, `gho_`,
  `ghu_`, `ghs_`, `ghr_`, `github_pat_`), PEM private keys, `.env`-style
  assignments, Devin pairing codes, emails and absolute user paths.
- `devin_redact.engine.scan()`: read-only scan over text files and SQLite
  session stores, decoding JSON cells (including `tool_call_json`,
  `tool_call_update_json`, `chat_message`) so secrets in tool-call inputs
  *and* outputs are found. Returns the deterministic JSON report contract
  from `docs/SPEC.md` §6 (`files_scanned`, `secrets`, `emails`,
  `absolute_paths`, `project_names`, `publication_status`, `findings`).
- `devin_redact.engine.redact()`: dry-run only stub for M1 (`apply` raises
  `NotImplementedError`).
- CLI `devin-redact` with `scan` (prints/`--report` JSON) and `redact`
  (dry-run); `verify` stubbed for M2.
- Fixture corpus under `tests/fixtures/` with planted synthetic secrets:
  `sessions.db` (generated by `generate_sessions_db.py`, mirrors the real
  schema), `memories.jsonl`, `export.md`, `.env`, `benign.txt`.
- Tests: recall over the planted corpus (sha256 fingerprints), benign text
  produces zero findings, scan idempotency/read-only guarantees, DB opens
  after scan, CLI smoke.
- `docs/SPEC.md`: canonical English translation of `SPEC.pt-BR.md`.
- Initial scaffold from `devin-repo-template`.
