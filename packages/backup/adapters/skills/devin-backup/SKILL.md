---
name: devin-backup
description: "Answer whether a recent, intact backup of Devin's local stores exists — list snapshots, verify integrity, diff one against the live data. Read-only: reports only, never writes."
triggers: [model, user]
allowed-tools:
  - exec
  - read
---

# devin-backup

When the user asks whether a recent, intact backup exists — or how far
the live stores have drifted from one — inspect what is already on
disk:

```bash
devin-backup list                        # snapshots, newest first
devin-backup verify <snapshot-dir>       # integrity vs manifest
devin-backup diff <snapshot-dir> --json  # drift vs live stores
```

Or, when this plugin's MCP server is connected, call `backup_list`,
`backup_verify` and `backup_diff` — same reports as JSON.

## Reading the result

- `list` rows carry `name`, `kind` (regular snapshot vs safety backup),
  `created_at`, `files`, `size` and `schema_versions`.
- `verify` returns `ok`, `checked`, `failed` and per-file `results[]`
  (exists / size / sha256 / SQLite integrity). `ok: true` means the
  snapshot is intact.
- `diff` returns `identical`, a `summary` of per-status counts,
  `files[]` (same / different / snapshot-only / live-only) and
  `warnings`. SQLite stores compare by logical content, so a byte diff
  alone does not mean the data changed.

## Rules

- Read-only by design. This skill inspects what exists — it never
  writes to the live stores or the backups dir.
- If the user needs a fresh snapshot or data rolled back, say so and
  let them run the CLI themselves — taking and consuming backups is a
  human decision.
- An `error` payload or `ok: false` means "report it", not "fix it" —
  never invent a verdict.
