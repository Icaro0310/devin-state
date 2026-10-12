# devin-backup — daemon adapters

Scheduled faces of `devin-backup create`, the daily snapshot of every
Devin store. These are the **native scheduler** faces of the SAME job
that `devin-backup install` registers (job name `devin-backup-daily`,
the canonical cross-platform installer — cron / Task Scheduler / elapsed
hook, and it writes the `.devin-ecosystem/scheduled.json` registry
entry). Pick one: `devin-backup install` if you want the shared
scheduling foundation, or these units if you specifically want a systemd
user timer / a hand-imported task XML. Both run the identical package
command, so the scheduled logic is never duplicated.

| Platform | Files |
| --- | --- |
| Linux (systemd user) | `devin-backup-daily.service` + `.timer` |
| Windows | `devin-backup-daily.task.xml` + `install-task.ps1` / `remove-task.ps1` |

Guides: [Linux](README.linux.md) ·
[Windows](README.windows.md) ·
[Corporate Windows](README.corporate-windows.md)

What runs: `devin-backup create` — snapshots Devin's stores under
`<data-dir>/backups` (autodetected; `DEVIN_BACKUP_DIR` or
`devin-backup create --out DIR` overrides). The units only schedule the
package's own CLI; rotation stays a separate, manual `devin-backup
rotate` decision.

> **Status:** these units are new — the 7-day no-silent-failure observation
> window started **2026-10-12** and has **not** completed. They are
> validated (unit syntax, XML parse, documented smoke checks) but not yet
> burn-in proven; if you enable them early, verify with the smoke-check
> section of your platform guide.

> Unofficial community project. Not affiliated with, endorsed by, or
> sponsored by Cognition AI. "Devin" is a trademark of Cognition AI.
