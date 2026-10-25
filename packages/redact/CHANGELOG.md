# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Detection coverage expansion (adversarial audit of the privacy
  boundary): GitLab (`glpat-`/`gldt-`/`glrt-`/`glcbt-`/`glagent-`),
  npm (`npm_`), PyPI (`pypi-`), DigitalOcean (`dop_v1_`), SendGrid
  (`SG.`), Square (`sq0atp-`/`sq0csp-`), Shopify
  (`shpat_`/`shpca_`/`shppa_`/`shpss_`), Google OAuth (`ya29.`),
  Hugging Face (`hf_`), Stripe webhook secrets (`whsec_`), Slack app
  tokens (`xapp-`) and age secret keys (`AGE-SECRET-KEY-`); JWTs with
  short payload/signature and `alg:none` empty signatures; PGP
  `PRIVATE KEY BLOCK` and unterminated PEM blocks;
  `Authorization: Basic <b64>`; case-insensitive `Bearer` with
  `[\s:=]` separators.
- New secret categories `connection_uri` (`scheme://user:pass@host`,
  any scheme) and `webhook_url` (Slack, Discord, Office365) — both
  hold `publication_status` at `BLOCKED`.
- `env_assignment` learns `:` (YAML) separators, JSON/dict/JS pairs
  anywhere on a line, escaped JSON quotes and camelCase/lowercase
  names; machine prefixes match unanchored so `api_key%3D<token>`
  still lands.
- Encoding coverage: UTF-8 with stray NUL, UTF-16 (BOM or NUL-parity
  BOM-less), lossy `surrogateescape` decode for text with a few
  invalid bytes, and a printable projection (`kind=binary-projection`)
  that rejoins secrets split by control bytes or ANSI escapes —
  detection-only.
- JSON dict *keys* scanned for secret-shaped content and now rewritten
  on redact (`{"sk-…": "enabled"}` → `{"<REDACTED:…>": "enabled"}`).
- `verify-publish` hardening: `index.json`/`index.md` enumerate but
  never limit coverage — on-disk session files are unioned into the
  scan set so a crafted/stale index omitting a dirty session cannot
  report `CLEAN`; entries resolving outside the export dir warn.
- `redact --apply` on a text-marked file with a few undecodable bytes
  rewrites through `surrogateescape`, byte-exact for the
  undecodable regions.
- `devin-redact diff <paths> [-o report.html]` — self-contained HTML
  before/after report for human review of sensitive exports. Renders the
  `scan` report as summary cards, category chips and a per-finding table
  (file, `table.column#rowid`/`line` location, category, masked *before*
  preview, `<REDACTED:sha256prefix>` *after* tag, fingerprint) and joins
  the dry-run `redact()` plan so each row is marked `planned` or
  `detection-only` (cross-chunk secrets the per-cell rewrite cannot
  cover). Same secrecy contract as the JSON/SARIF outputs: secret text
  never appears, and every dynamic value is HTML-escaped. Unreadable
  targets fail loudly (exit 2, no report); a clean input still produces
  a valid "no findings" page. Output is always written utf-8.
- Tests: adversarial-instruction corpus proving scanner input is
  content, not configuration — `scan_text` still reports a planted
  secret and `redact_text` still masks it when the surrounding free
  text says "don't mask", "do not redact", "never apply", "skip this"
  or "avoid applying", or injects an "IGNORE PREVIOUS" line
  (devin-state#91).

### Added

- `connection_uri` category — database/service URIs with embedded
  credentials (`postgres://user:pw@host`, `mongodb+srv://`, AMQP,
  Redis `redis://:pw@`) are detected and masked (devin-state#92).
- `webhook_url` category — Slack `hooks.slack.com`, Discord
  `discord.com/api/webhooks`, Google Chat and Teams/Office webhook
  endpoints are secrets in the URL itself and are masked
  (devin-state#92).
- Vendor-prefix coverage widened: GitLab `glpat-`, npm `npm_`,
  SendGrid `SG.`, OpenAI `sk-`, Stripe `sk_live`/`rk_`, Hugging Face
  `hf_`, DigitalOcean `dop_v1_`, Google `AIza`, and lowercase
  `password=`/`api_secret=` env names and YAML `name: value` pairs
  (devin-state#92).
- Unterminated PEM blocks (`-----BEGIN ... PRIVATE KEY-----` with no
  matching `END`) are detected and removed — a truncated capture no
  longer ships the key body (devin-state#92).

### Fixed

- Fail-closed decode gate (devin-state#92): a *text-named* blob
  (`.env`, `.txt`, `.json`, `.pem`, `id_rsa`, …) whose bytes fail
  every codec is now scanned lossy (surrogateescape + printable
  projection) instead of skipped — one invalid byte can no longer hide
  a credential from the staged-file gate. Binary-named blobs still
  skip.
- UTF-16 handling (devin-state#92): BOM'd input keeps its original
  endianness on write (`FE FF` stays big-endian), and a surrogate pair
  crossing the 8192-byte sniff boundary no longer flips the file to
  "binary, skip".
- JSON redaction preserves validity (devin-state#92): quoted
  `"key":"secret"` pairs keep their quotes (or gain them) so exports
  stay parseable; escape-aware value bodies mean `\"` inside a value
  no longer leaks the suffix, `=` inside a quoted value no longer
  suppresses detection, and an anchored pair cannot eat later
  same-line properties.
- JSON-object *keys* carrying credentials are rewritten on apply, not
  just values — `_key_strings` detections no longer survive
  `redact --apply` (devin-state#92).
- Type annotations (`api_key: str`, `token: Optional[str]`) are no
  longer flagged or redacted as secret assignments — quoted/YAML
  scalars with the same shape still are (devin-state#92).
- Dotted annotations whose terminal segment is lowercase by
  convention (`numpy.ndarray`, `collections.deque`, `socket.socket`)
  are suppressed like any other type, but only under the module
  namespace that owns them — `weakref.proxy` is an annotation while
  `password: customer.proxy` still flags and blocks the gate
  (devin-state#92).
- Import aliases are resolved from the scanned text itself —
  `import numpy as n` makes `n.ndarray` an annotation and
  `from collections import deque` binds the bare name, while an
  unbound alias (`api_key: n.ndarray` with no import) still flags.
  Relative (`from .x import y`) and wildcard (`from x import *`)
  imports bind the same way — `weakref`'s starred `ref` suppresses,
  `os`'s `environ` does not (devin-state#92).
- Parenthesized from-imports (`from collections import (deque)`),
  including the multi-line form and inline comments inside the parens,
  bind names like the plain form (devin-state#92).
- Alias resolution only applies where `x: T` can be an annotation —
  Python-typed files. An `import` line inside a `.env`/`.yaml` blob is
  inert text, so `api_key: n.ndarray` there still blocks the gate
  (devin-state#92).
- An annotated default no longer hides a hardcoded value —
  `api_key: str = "hunter2"` flags while `x: str = None` and
  `x: T = call()` stay annotations, and the rewrite scopes to the
  literal (`api_key: str = "<REDACTED:…>"`, still parseable)
  (devin-state#92).
- Import bindings only suppress outside string literals — a
  `name: value` line inside `'''`/`"""` is string content and always
  flags, so a docstring cannot launder a credential through a
  wildcard or relative import (devin-state#92).
- The parenthesized-import matcher is per-character now — an
  unclosed `from x import (` scans linearly instead of
  exponentially partitioning the file (ReDoS; devin-state#92).
- A complete PEM block is reported once, not once per matching
  pattern — `scan_text` dedupes overlapping findings so one key no
  longer inflates the count (devin-state#92).
- `redact --apply` no longer silently truncates a UTF-16 file whose
  final code point is incomplete (devin-state#92). The truncated-tail
  tolerance that lets the bounded binary sniff and read-only scans
  judge the decodable head used to reach the rewrite too: only the
  decoded prefix was written while success was reported. The rewrite
  now re-verifies the whole file under the detected codec and carries
  the undecodable tail bytes through `_apply_text`, re-appending them
  verbatim — and a mid-content decode failure skips with a loud error
  instead of dropping bytes.
- Type-shaped credentials no longer bypass scanning (devin-state#92):
  `api_key: abc.def` matched the *dotted type* escape hatch in the
  annotation guard and reported CLEAN. A dotted path now only counts
  as an annotation when it is well-formed *and* its terminal segment
  is a builtin/typing name or a CapWords class (`pathlib.Path`,
  `datetime.datetime`, `models.User`, `typing.Any`) — the same check
  applies inside generics/unions, so `list[abc.def]` cannot smuggle a
  credential either. Real type annotations stay suppressed.

## [0.2.5] - 2026-10-23

### Fixed

- The tag-gap fragment rescan no longer inherits the `env_assignment`
  `^` anchor (devin-state#82). After a closed `<REDACTED:…>` tag split a
  greedy match, a fragment beginning with non-key text —
  `API_KEY=<tag>suffix OTHER_TOKEN=raw` — left the tail assignment raw.
  The rescan now uses a de-anchored variant (`\s*` + `(?<!\w)`
  lookbehind) scoped to fragment rescanning only; the anchored pattern
  is unchanged for ordinary matching. Reunifies behavior with the
  TypeScript port, which shipped the equivalent fix in
  devin-powerups#223 — the port-only divergence case can now join the
  parity corpus.

## [0.2.4] - 2026-10-21

### Fixed

- `redact_text`/`scan_text` no longer drop a whole match when it
  contains a `<REDACTED:…>` tag (devin-state#66). Greedy patterns reach
  past the tag — `env_assignment` swallows the rest of the line — so
  `API_KEY=<REDACTED:x> OTHER_TOKEN=raw` previously left `OTHER_TOKEN`'s
  value raw and unreported (it can never match separately: the pattern
  is `^`-anchored). Only the tag's own span is now treated as prior
  output: each tag-free fragment of the match is re-scanned with the
  same pattern. Rescan stays safe inside code: `env_assignment`
  candidates keep the `_looks_like_code_assignment` suppression per
  fragment and are dropped when an unclosed bracket or dangling quote
  shows they sit inside a literal/container — so
  `KEY=["<tag> TAIL=v"]` and `KEY='abc<tag>def'` are left untouched
  rather than having their delimiters eaten. A `<REDACTED:` prefix with
  no closing `>` is malformed, not a real tag, and keeps the old
  whole-match skip.

### Added

- `devin-redact cflite-promote`: promotes ClusterFuzzLite minimized crash
  artifacts into the checked-in regression corpus at `fuzz/corpus/`
  (`new devin_redact.cflite` module). Sources: `--crashes-dir` for an
  already-unpacked artifact dir (recursive discovery), or `--run-id` to
  fetch a workflow run's artifacts via `gh run download` (`--artifact`
  narrows to named artifacts). Each crash is stored as
  `crash-<sha256>` — the name is the dedup key — and provenance (source
  artifact, run id, size, timestamp) is recorded in `manifest.json`.
  Validation is bounds-only but fail-loud: non-regular, empty or
  oversized (>1 MiB, `--max-bytes`) artifacts land in `rejected` and
  exit 1 rather than being silently skipped; usage/hard errors exit 2.
  `--dry-run` reports without writing. `tests/test_fuzz_corpus.py`
  replays every corpus entry through the atheris consumption the fuzz
  target uses and enforces manifest/disk integrity.
- `cflite-promote` review hardening (devin-state#78): the corpus
  manifest records the artifact-relative `source` (e.g.
  `fuzz-crashes-linux/crash-123`) instead of a dead temp path;
  dedup counts only validated `crash-<sha256>` entries so seed/notes
  files can't swallow a crash; on-disk crash entries missing from the
  manifest are reconciled into it; candidates are scanned with
  `engine.scan_text` and credential-shaped crashes are rejected unless
  `--allow-sensitive`; `--max-bytes` above the corpus bound exits 2
  instead of creating a corpus its own integrity check rejects. The
  `atheris` dev extra (linux marker) lets standard CI replay the
  corpus instead of import-skipping it.

## [0.2.3] - 2026-10-20

### Fixed

- Ship the `devin-redact-mcp` console script in the wheel: the entry
  point has been declared in `[project.scripts]` since the MCP server
  landed, but the published 0.2.2 wheel predates it (its
  `entry_points.txt` ships only `devin-redact`, and the metadata has
  no `mcp` extra). This release also publishes the `mcp` extra the
  plugin manifest's `uvx --from 'devin-redact[mcp]'` launch needs.
- `devin-redact-mcp` exits with a one-line install hint when the `mcp`
  extra is missing instead of dumping a traceback; startup
  `ImportError`s from `.run()` keep their traceback.
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

### Changed

- README gains the generated `Part of the DEVIN ecosystem` block
  (track/nature/audience/interface rendered from the registry).
- Test fixtures are allowlisted via `.secrets-scan-allow`
  (`path sha256=<hash>` entries) now that the shared secrets-scan drops
  its blanket `fixtures` directory exclusion.

- `labeler.yml` is now a thin caller of the shared reusable workflow in `devin-powerups` (`@v1`); PR labeling behavior is unchanged.

- Docs: export da raiz Zscaler no guia corporate-windows agora pede PEM — "Base-64 encoded X.509" no wizard de export ou `certutil -encode` após `Export-Certificate` (que gera DER) — e distingue `certmgr.msc` (store do usuário) de `certlm.msc` (store da máquina); a receita offline instala `setuptools`+`wheel` antes do `--no-build-isolation`.

- Install section now recommends pypi `uv tool install devin-redact` as the primary route, with `pipx`/source installs documented as alternatives.
- `llms.txt` no longer states a hard-coded ecosystem size; the registry owns the count.
- Platform guides and the README install command no longer pin a release; they install the latest published version.

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
- Read-only adapters: `devin_redact.mcp_server` MCP server
  (`redact_scan` + `redact_verify_publish`, `devin-redact-mcp` entry
  point, `mcp` extra), Devin skill and `adapters/` plugin root. Session
  scans honor a `sessions.db` passed via `scan_paths`, report absent
  sessions as `no_session` instead of `CLEAN`, and surface missing scan
  targets as `missing_paths`/`no_targets` rather than silently scanning
  zero files.
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

## [0.2.2] - 2026-10-11

### Fixed

- `__version__` now matches the published artifact: the 0.2.1 wheel on
  PyPI self-reports 0.2.0 (built from an unmerged branch before the
  verify gate existed). This release exists so the index carries a
  wheel whose metadata and self-report agree.

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
