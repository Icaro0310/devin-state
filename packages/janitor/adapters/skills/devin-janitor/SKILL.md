---
name: devin-janitor
description: "Report what can be cleaned safely from Devin's session stores — run the advisory dry-run and the tier classification, then report. Read-only: never removes anything."
triggers: [model, user]
allowed-tools:
  - exec
  - read
---

# devin-janitor

When the user asks what can be cleaned safely — how much space is
recoverable, which sessions are noise — run the advisory surfaces and
report the answer:

```bash
devin-janitor report --json   # recoverable-space report
devin-janitor scan --json     # per-session tier classification
```

Or, when this plugin's MCP server is connected, call `janitor_dry_run`
and `janitor_classify` — same payloads.

## Reading the result

- `report` returns `stores[]` (per-store `bytes`, `recoverable_bytes`,
  `note`), `cleanup_tiers` (tier1 orphans & cache / tier2 stale
  sessions / tier3 gated GUI state), `automatic_sessions` and
  `totals.recoverable_bytes` — the headline number.
- `scan` returns `tiers.keep`, `tiers.auto_delete` and
  `tiers.judge.unresolved` — each row carries `id`, `origin`, `title`,
  `tier` and `reason` (grace window, allowlist, empty, noise,
  ephemeral, duplicate, substantive work).
- `classification` may be `null` with a `classification_error` when a
  store is unreadable — report that, don't guess.

## Rules

- Read-only by design. This skill reports what the janitor's own rules
  would free — it never removes a session, a file or a lock.
- Removal is a human decision. If the user wants the plan carried out,
  tell them the CLI exists and let them run it — the agent only ever
  reports.
- `auto_delete` rows are what the rules flag as safe-to-free candidates,
  not an instruction — surface them, don't act on them.
