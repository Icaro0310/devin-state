# Hooks — SessionEnd scan

`devin-redact sessionend-scan` is the handler-shaped `scan` invocation for
the ecosystem hook dispatcher (the planned `tools/hooks_dispatch.py` in
`devin-powerups`, which runs registered commands on Devin hook events).
It also works standalone.

## Contract

- **SCAN ONLY** — strictly read-only (the database is opened `mode=ro`).
  It never writes; redaction stays manual via
  `redact --apply --i-know-this-is-irreversible`.
- **Bounded** — scans only one target: the auto-detected default
  `sessions.db` (`%APPDATA%\devin\cli\sessions.db` on Windows,
  `~/Library/Application Support/devin/cli/sessions.db` on macOS,
  `$XDG_DATA_HOME/devin/cli/sessions.db` → `~/.local/share` on Linux, then
  `$XDG_CONFIG_HOME`/`~` fallbacks). An explicit path can be passed as the
  optional argument to scan a different store.
- **Compact output** — prints exactly one line to stdout:

  ```
  devin-redact: findings=<N> publication_status=<BLOCKED|REVIEW|CLEAN>
  ```

  No matched secret text is ever printed (same guarantee as `scan`).
- **Exit codes** — `0` always, *including* when the verdict is `BLOCKED`:
  a SessionEnd handler must never block session teardown. Non-zero (`2`)
  only on a hard error: an explicitly passed path that is not a file, or a
  target that could not be scanned at all (e.g. a corrupt store). A
  machine with no `sessions.db` is not an error — the verdict is
  `findings=0 publication_status=CLEAN`.

## Registration with the hook dispatcher

Add the handler to `hooks.json` under the `SessionEnd` event:

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

The dispatcher invokes the command at session end; the single verdict
line is safe to log or surface as a hook annotation. To gate on the
verdict inside a pipeline (e.g. before a `devin-history` export), use
`devin-redact gate` instead — see below.

## `session-end` — the per-session variant

`devin-redact session-end` resolves **which session just ended** and
writes a verdict side file instead of printing one line:

- **Session resolution** — `--session-id` flag → `{"session_id": …}`
  JSON payload on stdin → `DEVIN_SESSION_ID` → most recently active in
  `sessions.db`.
- **Scoped scan** — only that session's rows (`message_nodes`,
  `tool_call_state`, `prompt_history`, any `session_id`-keyed table);
  the `sessions` metadata row itself is excluded so clean sessions stay
  `CLEAN`.
- **Side file** — the verdict JSON lands in
  `<data-dir>/redact/<session-id>.json` (`--data-dir`,
  `DEVIN_REDACT_DATA_DIR` or `--out` override; `<data-dir>` is the
  resolved store's `devin/` root). It **never** writes into any Devin
  store or transcript.
- **Fail-soft** — an unresolvable session, a missing store or a corrupt
  DB produces a `SKIPPED` verdict and still exits `0`; only usage errors
  (e.g. a `--sessions-db` path that is not a file) exit `2`.

```json
{
  "SessionEnd": [
    {
      "matcher": "",
      "hooks": [
        {
          "type": "command",
          "command": "devin-redact session-end",
          "timeout": 30
        }
      ]
    }
  ]
}
```

The side files double as the verdict source `verify-publish`
cross-references when gating a `devin-history` export dir.

## Related: `gate`, `verify` and `verify-publish`

| Command | Output | Exit 0 | Exit 1 | Exit 2 |
|---|---|---|---|---|
| `sessionend-scan [db]` | `devin-redact: findings=N publication_status=X` | always (incl. BLOCKED) | — | hard error |
| `session-end` | side file `<data-dir>/redact/<id>.json` (+ summary line) | always (incl. SKIPPED/BLOCKED) | — | usage error |
| `gate <targets…>` | `CLEAN` / `REVIEW` / `BLOCKED` | CLEAN or REVIEW | BLOCKED | hard error |
| `gate --staged <paths…>` | same, but scans the *staged index blobs* | CLEAN or REVIEW | BLOCKED | unreadable index |
| `verify <targets…>` | human summary (`--json` for the report) | CLEAN only | any finding | — |
| `verify-publish <export-dir>` | per-session verdicts for a `devin-history` export | CLEAN only | any session not CLEAN | usage error |

`gate` is the machine-readable publication gate other tools consume —
`devin-history` can run it before export and skip/flag exports that are
`BLOCKED`. The same verdict is available as the top-level
`publication_status` field of `scan --format json` (the SPEC §6 report).

With `--staged`, each path is resolved to its blob in the git index
(`git cat-file blob :0:<path>`) and *that* content is scanned — the
mode the published `devin-redact-gate` pre-commit hook runs in. The
working tree is not authoritative for a commit: content staged and then
edited or deleted still ships, so the gate reads the index rather than
the file on disk. A path with no staged blob (staged deletion, never
`git add`ed) is skipped — nothing staged means nothing is committed.
