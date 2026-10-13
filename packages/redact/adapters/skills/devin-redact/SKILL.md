---
name: devin-redact
description: "Scan files or a sessions.db for secrets and PII (tokens, keys, emails, absolute paths, project names) before sharing session content. Read-only scan — reports findings, never rewrites the store."
triggers: [model, user]
allowed-tools:
  - exec
  - read
---

# devin-redact

Before sharing session content, a transcript, or a store export, scan it
first and report what was found:

```bash
devin-redact scan <path> [<path>...]
```

Or, when this plugin's MCP server is connected, call `redact_scan` with
the same targets — it returns the same JSON report. Pass `session_id`
(optionally with `sessions_db`) to scan just one session's rows.

## Reading the result

- `publication_status` is `CLEAN` (nothing found), `REVIEW` (findings a
  human should look at) or `BLOCKED` (secret-class findings — do not
  share until reviewed).
- `findings[]` carries `file`, `location`, `category` and a
  `fingerprint` — never the secret value itself.
- `errors[]` lists targets that could not be scanned (unreadable,
  binary) — `skipped: binary file` is informational.

## Rules

- Read-only by design. This skill scans and reports — it never modifies
  the store or any file.
- If findings exist, surface them to the user and let them decide what
  to do next. Rewriting the store is a human operation, run manually by
  the user from the CLI — the agent only ever scans.
- Scope with `session_id` when the user asks about one session instead
  of rescanning the whole store.
