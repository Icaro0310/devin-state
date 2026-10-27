# devin-state

<div align="center">

<a href="https://github.com/Icaro0310/devin-state/actions/workflows/ci.yml"><img src="https://github.com/Icaro0310/devin-state/actions/workflows/ci.yml/badge.svg" alt="ci"/></a>
<a href="https://www.bestpractices.dev/projects/15339"><img src="https://www.bestpractices.dev/projects/15339/badge" alt="OpenSSF Best Practices"/></a>
<a href="https://scorecard.dev/viewer/?uri=github.com/Icaro0310/devin-state"><img src="https://api.scorecard.dev/projects/github.com/Icaro0310/devin-state/badge" alt="OpenSSF Scorecard"/></a>
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
> For: Security engineers, Developers, DevOps engineers  
> Interface: CLI / Python library  
> Path: DevOps engineers · step 1/3 — before `devin-bridge`
<!-- DEVIN-ECO:END -->

<!-- DEVIN-WHERE:BEGIN -->
## Where this fits

- **Job:** Control
- **Product:** [`devin-state`](https://github.com/Icaro0310/devin-state)
- **Packages:** `redact` · `backup` · `janitor`
- **Mode:** mixed
- **Foundation:** [`devin-internals-spec`](https://github.com/Icaro0310/devin-internals-spec)
- **Ecosystem:** [`awesome-devin`](https://github.com/Icaro0310/awesome-devin) · registry: [`devin-powerups`](https://github.com/Icaro0310/devin-powerups)
<!-- DEVIN-WHERE:END -->

State safety for Devin Desktop: redact secrets from session stores, back
them up verifiably, and prune sessions behind an export-then-delete
pipeline.

| Package | PyPI | What it does |
|---|---|---|
| [`packages/redact`](packages/redact) | [![devin-redact](https://img.shields.io/pypi/v/devin-redact)](https://pypi.org/project/devin-redact/) | Secret and PII redaction with Devin tool-call semantics |
| [`packages/backup`](packages/backup) | [![devin-backup](https://img.shields.io/pypi/v/devin-backup)](https://pypi.org/project/devin-backup/) | Snapshots, rotation, integrity checks for Devin stores |
| [`packages/janitor`](packages/janitor) | [![devin-janitor](https://img.shields.io/pypi/v/devin-janitor)](https://pypi.org/project/devin-janitor/) | Session lifecycle janitor with tiered classification |
| [`shared/install-scheduler`](shared/install-scheduler) | `devin-install-scheduler` | Shared cron / Task Scheduler / elapsed install logic |

> **Renamed (Oct 2026):** this repository moved from `Icaro0310/devin-redact` to `Icaro0310/devin-state` when it became the `devin-state` product workspace. PyPI packages and console scripts keep their names; stars, issues and history are preserved by the redirect.

## Layout

```
packages/<name>/   one installable package each (src layout, own tests)
shared/<name>/     internal libraries shared by the packages
tests/integration/ cross-package contract tests
```

Each package ships independently: a tag `redact-vX.Y.Z` (same for
`backup`, `janitor`, `install-scheduler`) publishes only that package.
CI is scoped per path — a change under `packages/backup/` runs only the
backup suite.

## Platform support

All packages support Linux, macOS and Windows; scheduling falls back to
a config-file registry where neither cron nor Task Scheduler exists.
Per-package guides live under `packages/<name>/`.

> **Unofficial community project.** Not affiliated with, endorsed by, or
> sponsored by Cognition AI. "Devin" is a trademark of Cognition AI.
<!-- pipeline e2e smoke test -->
