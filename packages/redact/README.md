<div align="center">

<img src="assets/banner.svg" alt="devin-redact" width="100%"/>

<a href="https://github.com/Icaro0310/devin-state/actions/workflows/ci.yml"><img src="https://github.com/Icaro0310/devin-state/actions/workflows/ci.yml/badge.svg" alt="ci"/></a>
<a href="https://pypi.org/project/devin-redact/"><img src="https://img.shields.io/pypi/v/devin-redact" alt="PyPI"/></a>


<a href="https://scorecard.dev/viewer/?uri=github.com/Icaro0310/devin-state"><img src="https://api.scorecard.dev/projects/github.com/Icaro0310/devin-state/badge" alt="OpenSSF Scorecard"/></a>
<a href="https://deepwiki.com/Icaro0310/devin-state"><img src="https://deepwiki.com/badge.svg" alt="DeepWiki"/></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"/></a>
<a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"/></a>
<a href="https://github.com/Icaro0310/devin-state"><img src="https://img.shields.io/github/stars/Icaro0310/devin-state" alt="GitHub stars"/></a>
<a href="https://github.com/Icaro0310/devin-state/commits/main"><img src="https://img.shields.io/github/last-commit/Icaro0310/devin-state" alt="Last commit"/></a>
<a href="https://github.com/Icaro0310/awesome-devin"><img src="https://img.shields.io/badge/part%20of-devin--*-ecosystem-7c3aed" alt="devin-* ecosystem"/></a>
<a href="https://github.com/Icaro0310/devin-state/issues"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome"/></a>
</div>

<!-- DEVIN-ECO:BEGIN -->
> **Part of the [DEVIN ecosystem](https://github.com/Icaro0310/awesome-devin)**  
> Track: Control · Nature: product  
> For: Security engineers, Developers  
> Interface: CLI / Python library
<!-- DEVIN-ECO:END -->


# devin-redact

> **Renamed (Oct 2026):** this repository moved from `Icaro0310/devin-redact` to `Icaro0310/devin-state`. The PyPI package and console script stay `devin-redact`; stars, issues and history are preserved by the redirect.

> **Unofficial community project.** Not affiliated with, endorsed by, or
> sponsored by Cognition AI. "Devin" is a trademark of Cognition AI.

**[Linux](README.linux.md)** · **[Personal Windows](README.windows.md)** · **[Corporate Windows](README.corporate-windows.md)**

Part of the [awesome-devin](https://github.com/Icaro0310/awesome-devin) ecosystem: the curated hub for the devin-* tools.

Secret and PII redaction that understands Devin tool-call semantics —
in-place in `sessions.db`, not just flat text.

## The problem

Agent transcripts accumulate secrets: `cat .env` in a tool's output, keys
pasted into chat, tokens inside error messages. Publishing or sharing those
sessions leaks credentials. This is not hypothetical: during the audit that
motivated this project, a **real Devin CLI pairing code** was found sitting
inside a prompt in the local history.

## Prior art

- **geheim** — redacts secrets from Claude Code transcripts before sharing.
- **agent-leaks** — audits agent session logs (JSONL) for leaked credentials.
- **AgentLogs** — tooling around inspecting/exporting agent session logs.

These tools target Claude Code / Codex-style **JSONL files**. None of them
reads Devin's `sessions.db`, and none of them knows that a `cat .env` tool
call and its output are the same event. `devin-redact` adapts the idea; it
does not reinvent it.

## What makes it Devin-native

1. **Side-by-side:** it reads *and* will write the SQLite session store
   (`sessions.db`, `acp-messages/*.db`) — the tools above can only chew on
   flat files and cannot tell a command (`rawInput`) from its output.
2. **No-Devin:** remove Devin and the extra disappears — there is no
   `tool_call_state`, no `message_nodes`, no pairing codes.
3. **One sentence:** *it's the only cleaner that understands which commands
   ran and cleans the database, not just the text.*

`scan` opens the DB read-only, decodes `tool_call_json` /
`tool_call_update_json` / `chat_message` payloads and finds secrets inside
tool inputs *and* outputs. On top of pattern matching, the semantic layer
reads `tool_call_state.rawInput`: when the command touched a known-sensitive
file (`cat .env`, `type credentials.toml`, a read tool pointing at
`~/.ssh/…`), its output is flagged as `kind="semantic-context"` even when
the output matches no pattern. `redact` rewrites those cells in place —
masked as `<REDACTED:sha256prefix>` — keeping the JSON valid, inside a
single transaction with a mandatory `.bak` backup and a post-redact open
test.

## Install

Python ≥ 3.10 required; install with `uv` (recommended) or `pipx`.

```bash
uv tool install devin-redact
```

or with `pipx` (alternative):

```bash
pipx install devin-redact
```

For development:

```bash
pip install -e ".[dev]"
pytest
```

## Usage

```bash
# Read-only scan — prints the JSON report (SPEC §6 contract)
devin-redact scan path/to/sessions.db exports/ .env

# Same, plus write the report to a file
devin-redact scan sessions.db --report report.json

# SARIF 2.1.0 for CI / code-scanning ingestion (never contains secret text)
devin-redact scan sessions.db --format sarif > scan.sarif

# Dry-run redact — shows exactly what would change, modifies nothing
devin-redact redact sessions.db

# In-place redact (long flag on purpose; writes .bak backups first)
devin-redact redact sessions.db --apply --i-know-this-is-irreversible

# Publication gate: exit 0 only when CLEAN, else 1
devin-redact verify sessions.db exports/
devin-redact verify sessions.db --json

# Machine gate for pipelines (e.g. devin-history export): prints just the
# status word; exits 0 for CLEAN/REVIEW, 1 for BLOCKED, 2 on error
devin-redact gate sessions.db exports/

# Pre-commit mode: scan the staged index blobs instead of the working
# tree — what the commit will record, even if the file was edited or
# deleted after `git add` (this is what .pre-commit-hooks.yaml runs)
devin-redact gate --staged file1.py path/to/file2.env

# SessionEnd hook handler: read-only scan of the default sessions.db,
# one compact verdict line, exit 0 unless a hard error occurs
devin-redact sessionend-scan
# → devin-redact: findings=7 publication_status=BLOCKED

# SessionEnd hook (per-session verdict): resolves the just-ended session,
# scans only its messages and writes a verdict side file to
# <data-dir>/redact/<session-id>.json — fail-soft, exits 0 even on SKIPPED
devin-redact session-end                       # auto-resolves the session
echo '{"session_id": "abc"}' | devin-redact session-end
devin-redact session-end --session-id abc --out verdict.json

# Gate a devin-history export dir before publishing: per-session verdicts
# cross-referenced with session-end side files; exit 0 only when CLEAN
devin-redact verify-publish exports/
devin-redact verify-publish exports/ --json
```

No Devin installed? Try it on a synthetic fixture:

```bash
pipx install "devin-internals-spec"
devin-inspect make-fixture /tmp/fx
devin-redact scan /tmp/fx/cli/sessions.db
```

Report shape (deterministic — same input, same output):

```json
{"files_scanned": 4, "secrets": 20, "emails": 3,
 "absolute_paths": 5, "project_names": 1,
 "publication_status": "BLOCKED", "findings": [...]}
```

`publication_status` is `BLOCKED` when any secret-class finding exists,
`REVIEW` when only PII/hygiene findings exist, `CLEAN` when nothing was
found. Findings carry a masked `preview` and a `fingerprint`
(sha256, first 16 hex) — the report itself never contains the secret.

Detection categories: API keys (OpenAI/Stripe/AWS/Google/Slack shapes),
bearer tokens and JWTs, GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`,
`ghr_`, `github_pat_`), PEM private keys, `.env`-style assignments to
sensitive variable names, Devin pairing codes, email addresses, and absolute
user paths (`C:\Users\…`, `/home/…`, `/Users/…`).

`scan --format sarif` emits a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
log instead of the JSON report: one rule descriptor per detection category,
one result per finding with its file location (`region.startLine` for text
files; the `table.column#rowid` SQLite locator is preserved in
`properties.location`), a masked message like `match: aws access key id`,
and the sha256 fingerprint as `partialFingerprints` for deduplication.
Secret-class categories map to `level: error`, PII/hygiene to `warning`.
The log never contains the matched secret text, so it is safe to upload to
code-scanning dashboards or archive as a CI artifact.

## SessionEnd hook

`devin-redact sessionend-scan` is the `scan` invocation shaped for the
ecosystem hook dispatcher (`tools/hooks_dispatch.py` in `devin-powerups`,
which runs registered handlers on Devin hook events). It is **scan only**:
read-only, bounded to the auto-detected default `sessions.db`, prints one
compact verdict line (`findings=N publication_status=X`) and exits 0 even
when the verdict is `BLOCKED` — non-zero only on a hard error, so it can
never stall session teardown. Registration entry for `hooks.json`:

```json
{
  "SessionEnd": [
    {
      "matcher": "",
      "hooks": [
        {
          "type": "command",
          "command": "devin-redact sessionend-scan",
          "timeout": 30
        }
      ]
    }
  ]
}
```

See [`docs/HOOKS.md`](docs/HOOKS.md) for the full contract.

`devin-redact session-end` is the per-session variant: it resolves **the
just-ended session** — `--session-id` flag → `{"session_id": …}` JSON
payload on stdin → `DEVIN_SESSION_ID` → most recently active in
`sessions.db` — and scans only that session's rows (messages, tool-call
state, prompt history; the `sessions` metadata row itself is excluded).
The verdict is written to a **side file** —
`<data-dir>/redact/<session-id>.json` by default (`--data-dir`,
`DEVIN_REDACT_DATA_DIR` or `--out` override; `<data-dir>` is the resolved
store's `devin/` root) — never into any Devin store or transcript. It is
fail-soft: an unresolvable session produces a `SKIPPED` verdict and the
command still exits 0; only usage errors exit 2. `sessionend-scan` (the
whole-store verdict line) and `session-end` (the per-session side file)
complement each other — pick the shape your hook needs.

## Publication gate for exports

`devin-redact verify-publish <export-dir>` cross-references redaction
findings with [`devin-history`](https://github.com/Icaro0310/devin-explore)
export state before anything is published. It enumerates the exported
sessions — `index.json` (`{"sessions": [{"file": …}]}`) or `index.md`
wikilinks when present, else the `<YYYY-MM-DD>_<session-id>.{md,json}`
layout — extracts each `session_id` (JSON field, note frontmatter or
filename), scans every exported file read-only and reports per-session
verdicts. When a `session-end` side file exists for an exported session
(`<verdicts-dir>/<session-id>.json`, default `<data-dir>/redact`) it is
cross-referenced: a `BLOCKED` hook verdict beside a `CLEAN` export is
flagged as a warning (the export was redacted since — or dropped the
flagged content) and holds the overall verdict at `REVIEW`. Index entries
pointing at missing files are flagged too. Exit 0 only when the overall
verdict is `CLEAN`.

## What gets scanned

Targets can be files or directories; directories are walked recursively.
Every file is dispatched by type — detected by extension **or** by content:

- **SQLite stores** (`.db`/`.sqlite`/`.sqlite3`, *or any file starting with
  the `SQLite format 3` magic header*) are opened read-only and every text
  column of every table is scanned. This covers Devin's `sessions.db` and
  `User/acp-messages/*.db`, plus the derived stores that inherit session
  text: [`devin-graph`](https://github.com/Icaro0310/devin-explore)'s
  `graph.db`, [`devin-search`](https://github.com/Icaro0310/devin-explore)'s
  `search.db` (FTS5 `docs` included) and
  [`devin-memory`](https://github.com/Icaro0310/devin-brain)'s
  `memory.db`. On `sessions.db`-shaped data the tool-call semantic layer,
  `project_name` extraction and the cross-chunk pass also apply; other
  stores get the generic text-column scan.
- **Text files** — `.md` notes (including a `devin-history` export dir,
  whose notes are named `<YYYY-MM-DD>_<session-id>.md`), `.json`/`.jsonl`
  exports, `.env`, logs — are scanned whole; findings carry a line number.
- **Binary files** are skipped and reported under `errors`.

On `sessions.db`-shaped stores a bounded **cross-chunk pass** also runs:
secrets split across two adjacent payloads (half an AWS key at the end of
one tool output, the rest at the start of the next message) reassemble
when the payloads are concatenated. The pass re-scans concatenations of
`tool_call_json`+`tool_call_update_json` of the same `tool_call_state`
row, adjacent `tool_call_state`/`message_nodes` rows **of the same
session**, and streaming parts inside one payload — reporting the finding
at the earlier rowid with `kind="cross-chunk"`.

`redact` uses the same dispatch: derived SQLite stores are rewritable under
`--apply` with the same `.bak` + transaction + integrity-check guarantees
as `sessions.db`.

## Works with Devin alone (Devin-only mode)

The default `scan` is read-only and fully offline. `--apply` rewrites Devin's
SQLite store in place — it writes `.bak` backups first, and running
[`devin-backup`](https://github.com/Icaro0310/devin-state) beforehand is the
recommended extra safety net. Detection is heuristic: review the report
before applying.

## Adapters (MCP server, Devin skill, plugin)

`devin_redact.mcp_server` exposes the read-only half of the CLI as MCP
tools — `redact_scan` (same JSON `scan` prints by default) and
`redact_verify_publish` (same as `verify-publish --json`) — via the
`devin-redact-mcp` entry point (`pip install 'devin-redact[mcp]'`). The
`adapters/` directory is a self-contained Devin plugin root
(`adapters/.devin-plugin/plugin.json` + `adapters/skills/devin-redact/SKILL.md`),
installable with `devin plugins install Icaro0310/devin-state#packages/redact/adapters`.
Applying redactions stays a human CLI action and is deliberately not
exposed through any adapter.

## Platform support

Pure stdlib Python — identical behavior on Windows, Linux and macOS. CI runs
the suite on `windows-latest` + `ubuntu-latest`; the target database is
always an explicit argument, so there are no platform-specific paths.

## Limitations

- **False negatives exist.** This is a pattern-based scanner, not a guarantee.
  Secrets in unusual formats or encodings will be missed. Splits across
  chunks are caught only for *adjacent* same-session payloads — a secret
  spread over non-adjacent rows, across sessions, or in three or more
  pieces still slips through. Run `gitleaks`/`trufflehog` too — this
  complements them, it does not replace them.
- **False positives exist.** Keyword-based `.env` matching can flag benign
  assignments; pairing codes are only flagged with explicit context.
- **Private internals.** `sessions.db` schema and the `chisel`/`acp` JSON
  shapes are undocumented and can change between Devin CLI versions. The
  scanner reads cells generically to be resilient, but a schema change can
  still reduce recall.
- **Not preventive.** It finds secrets *after* they landed in the transcript.
  Stopping the agent from reading secrets is policy work, not redaction work.
- **Redaction is destructive by design.** `--apply` always writes a `.bak`
  sibling first and DB updates run in one transaction with a post-redact
  open test — but once you publish/share a `.bak`-less tree, the secrets
  that were in it are the only copy. Keep backups safe.
- **Semantic layer is heuristic.** The sensitive-file table covers common
  names (`.env*`, `credentials*`, `*.pem`, `~/.ssh`, `~/.aws`, …); a
  secret-bearing file with an unusual name read via `cat` will not be
  flagged — pattern matching still applies to its output.
- **M2 scope.** `scan`, `redact`, `verify`, `gate`, `sessionend-scan`,
  `session-end` and `verify-publish` work; the package is available on PyPI.
  Still out: the `/redact` skill. Cross-chunk findings are detection-only —
  `redact` masks per-cell matches and cannot rewrite a reassembled split
  secret back into two halves; review those findings manually.

## When to use this

- You are about to share or publish Devin session data — an export, a bug
  report, a demo database — and need to scrub secrets and PII first.
- You want a pre-publish gate: `devin-redact verify` exits 0 only when the
  target is `CLEAN`, so it drops straight into CI — or `devin-redact gate`
  when only secrets should block (exits 1 on `BLOCKED`, 0 on
  `CLEAN`/`REVIEW`), which is what `devin-history` can consume via the
  report's top-level `publication_status`.
- You need redaction inside `sessions.db` itself, not just in exported
  text — it rewrites the SQLite cells in place.
- You want findings a flat regex scanner misses: a `cat .env` tool call
  flags its output as sensitive via `tool_call_state.rawInput` even when
  the output matches no pattern.

## When NOT to use this

- You need a guarantee that no secret survives — pattern-based scanning has
  false negatives; run `gitleaks`/`trufflehog` alongside it.
- You want to stop secrets from entering transcripts in the first place —
  that is agent policy work, not redaction work.
- You cannot accept a destructive write — `--apply` rewrites cells in
  place; run [`devin-backup`](https://github.com/Icaro0310/devin-state)
  first and review the dry-run.

## FAQ

**What is devin-redact?** A scanner and redactor for Devin's session
stores. `scan` reads `sessions.db` (and export files) read-only and reports
secrets, emails, absolute paths and project names; `redact --apply` masks
findings in place as `<REDACTED:sha256prefix>`; `verify` gates publication
with an exit code.

**Is scanning safe to run against my live database?** Yes — `scan` opens
the database read-only and never modifies it. Only `redact --apply` writes,
and it creates a `.bak` sibling first inside a single transaction with a
post-redact open test.

**What does the publication verdict mean?** `publication_status` is
`BLOCKED` when any secret-class finding exists, `REVIEW` when only
PII/hygiene findings exist, and `CLEAN` when nothing was found. `verify`
exits 0 only on `CLEAN`. The report carries masked previews and sha256
fingerprints — never the secret itself.

**Will it catch every secret?** No. It is a heuristic, pattern-based
scanner plus a semantic layer for sensitive-file reads — unusual formats
or encodings will be missed, and secrets split across chunks are caught
only when they land in adjacent same-session payloads. Treat it as a
strong complement to `gitleaks`/`trufflehog`, not a replacement.

## License

MIT — see [LICENSE](LICENSE).
