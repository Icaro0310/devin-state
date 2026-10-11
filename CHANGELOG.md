# Changelog

## Unreleased

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
