# Changelog

## Unreleased

- **CI/publish** — the wheel gate in `pypi-publish.yml` no longer crashes
  with `StopIteration` on wheels without `entry_points.txt` (the
  install-scheduler shape, which ships no console scripts). Scriptless
  wheels now pass the script/extra coverage check honestly while
  declared-but-missing scripts still fail; the gate's python block is
  exercised by tests against fixture wheels.
- **Docs/janitor-legacy** — archived script fixes from Devin Review on
  the scrub PR: `EXPORTER` is now `JANITOR_EXPORTER`-overridable with
  the historical script name as default, the judge bridge module is
  `JANITOR_JUDGE_MODULE`-configurable (scrubbed name is a placeholder),
  and SKILL.md no longer implies cron support for the Windows-only
  script.
- **CI** — `actions/checkout` bumped to 7.0.1 across `ci.yml`,
  `docker-publish.yml`, `pypi-publish.yml` and `redact-action.yml` (dependabot).
- **CI** — `pr-approve` caller bumped from v1.1 to v1.3 in
  `auto-approve.yml` (devin-powerups reusable; the referenced workflow
  file is identical at both tags, so no caller-visible change).
- **Docker** — `docker-publish.yml` builds and pushes
  `ghcr.io/icaro0310/devin-redact` after `redact-v*` releases; PRs
  smoke-build against the latest published PyPI wheel.
- **Docs** — refreshed the generated `Part of the DEVIN ecosystem` block: journey recuration v2 (six paths, zero repeats, `Local-first ops` label, `devin-bridge` in DevOps).
- **Docs** — ecosystem journey recuration applied (six curated audiences); stale `Path:` line removed from the devin-redact eco-block, which is not a registry entry.
- **CI** — Ruff lint job added (`astral-sh/ruff-action`, pinned); codebase now
  lints clean with documented fail-soft ignores on legacy scripts.
- **Publish** — consolidated `pypi-publish.yml` builds and uploads
  `devin-redact`, `devin-backup`, `devin-janitor` and
  `devin-install-scheduler` via PyPI Trusted Publishing (OIDC), tag
  `*-v*` or manual dispatch.

## 2026-10 (F4 consolidation)

- Packages consolidated into this repo:
  `devin-redact` 0.2.0, `devin-backup` 0.1.0, `devin-janitor` 0.1.0,
  `devin-install-scheduler` 0.1.0.
- Prior per-repo history lives in each package's git history.
