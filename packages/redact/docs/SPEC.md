# SPEC 02 — `devin-redact` (Slot 0)

> Canonical English translation of [`SPEC.pt-BR.md`](SPEC.pt-BR.md) (authoritative).

## 1. Problem

Agent transcripts accumulate secrets: `cat .env` in a tool's output, keys pasted
into chat, tokens in error messages. Publishing or sharing sessions leaks
credentials. **Direct evidence:** today's audit found a **real Devin CLI pairing
code** inside a prompt in the history.

Existing tools (geheim, agent-leaks, AgentLogs) do this for Claude Code/Codex —
**none of them reads `sessions.db`**.

## 2. Devin extra (and the 3 tests)

**Extra:** understands **tool-call semantics** — it knows that `cat .env` was
executed (reads `tool_call_state.rawInput`) and redacts the *associated output*;
and it redacts **in-place in SQLite**, not just text.

- **Side-by-side competitor:** geheim/agent-leaks operate on JSONL files;
  **they can neither read nor write a SQLite DB** nor distinguish the command
  from its output.
- **No-Devin:** without Devin, the extra (tool-call semantics + relational
  store) disappears.
- **One sentence:** *"It's the only one that understands which commands ran and
  cleans the database, not just the text."*

## 3. Scope

- `scan` (read-only), `redact` (dry-run by default), `verify` (blocks
  publication), `diff` (self-contained masked HTML before/after report).
- Targets: `sessions.db`, `acp-messages/*.db`, `.devin/memory/memories.jsonl`,
  Markdown/CSV exports, `.env`/`mcp_config.json`.
- Detection: patterns (keys, tokens, cookies, credentials), known sensitive
  files, **and** tool semantics (`rawInput` → redact output of `cat`/`grep`
  over sensitive files).
- **On by default** in `devin-history` (the exporter always redacts).
- Blocking report: counts per category and `PUBLICATION STATUS: BLOCKED`.

## 4. Non-scope

- Not preventive (does not stop the agent from reading secrets — that is
  `devin-policy`).
- Does not upload or share anything.
- Does not promise 100% detection (false negatives exist — stated in the
  README).
- Does not replace `gitleaks` in CI (it complements it).

## 5. Interfaces

| Interface | Description |
|---|---|
| **Library** `devin_redact` | Detection + redaction engine (reusable by other repos) |
| **CLI** `devin-redact` | `scan` · `redact` · `verify` · `diff` · `--report` |
| **Hook** (optional) | `SessionEnd` → automatic scan of the day |
| **Skill** | `/redact` for use inside Devin |
| **PyPI** | `pipx install devin-redact` |

## 6. Output format / data contract

```json
{"files_scanned": 247, "secrets": 12, "emails": 38,
 "absolute_paths": 91, "project_names": 7,
 "publication_status": "BLOCKED", "findings": [...]}
```

Irreversible flags in long form only (`--apply --i-know-this-is-irreversible`),
like `geheim` does — avoids accidental keystrokes.

`diff` renders the same report as self-contained HTML (inline CSS, no
external assets, utf-8): summary counts, per-finding before/after table.
The secrecy contract is identical to the JSON/SARIF outputs — *before* is
the lossy masked preview, *after* is the `<REDACTED:sha256prefix>` tag; a
*Plan* column joins the dry-run `redact()` edit plan so rows the
per-cell rewrite cannot cover (e.g. cross-chunk secrets) read
`detection-only`. Every dynamic value is HTML-escaped; unreadable targets
exit non-zero without writing a report, and a legitimately clean input
still produces a valid "no findings" page.

## 7. Fixtures and tests (TDD — fixtures first)

1. Test corpus with **planted secrets** (synthetic) in: DB, JSONL, Markdown,
   `.env`.
2. Golden files: `scan` output is stable.
3. Tests: `redact` on a **copy** never corrupts the DB (opens afterwards with
   the parser) · `verify` blocks · false positives on benign text ·
   Unicode/encoding · Windows paths · idempotency (redacting twice does not
   break anything).
4. CI: Windows + Linux.

## 8. Risks and mitigation

| Risk | Mitigation |
|---|---|
| Corrupting the DB while redacting | Mandatory backup + SQLite transaction + post-redaction open test |
| False negatives | State it in the README; integrate `trufflehog`/`gitleaks` as an optional layer |
| Irreversibility | Dry-run by default + long flags + report before applying |
| False sense of security | Mandatory "Limitations" section + recommendation of gitleaks pre-commit |

## 9. Definition of done

- [ ] `scan` detects the test corpus (declared recall)
- [ ] `redact` on a copy leaves the DB able to open and parse (dedicated test)
- [ ] `verify` returns BLOCKED when secrets are present
- [ ] `devin-history` exports with `--redact` by default
- [ ] Green tests on Windows + Linux · README (EN) with Prior art and
      Limitations
- [ ] `pipx install devin-redact` works

## 10. Tasks (in order)

1. Fixture corpus with planted secrets + golden files.
2. Detection engine (patterns + sensitive files).
3. Tool-call semantic layer (`rawInput` → output).
4. In-place SQLite writing (with backup + transaction).
5. CLI `scan/redact/verify` + report.
6. Integrate into `devin-history-export.py` as default.
7. Publish PyPI + repo + CI.
