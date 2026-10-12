# devin-backup daily — Scheduled Task (Windows)

> New task — the 7-day no-silent-failure observation window started
> 2026-10-12 and has not completed; see [README.md](README.md).

`devin-backup-daily.task.xml` registers a **user-scope** task running
`devin-backup create` at logon and once daily, with
`StartWhenAvailable` — a machine suspended at the clock slot catches up
at next wake instead of skipping a backup silently.

## Install

```powershell
cd adapters\daemon
powershell -ExecutionPolicy Bypass -File .\install-task.ps1
```

`install-task.ps1` prefers the canonical path: when `devin-backup` is on
`PATH` it runs `devin-backup install --backend tasksch`, which registers
the same `devin-backup-daily` job **and** writes the
`.devin-ecosystem\scheduled.json` registry entry. Without the CLI it
imports the XML via `Register-ScheduledTask` — same command, same
schedule, minus the registry entry. Neither path needs admin.

Equivalent one-liner without the script:

```powershell
schtasks /create /tn "devin-backup-daily" /xml devin-backup-daily.task.xml /f
```

Do not combine this task with `devin-backup install` defaults — two
registrations of the same job name overwrite each other (`/f`), but a
manually renamed copy would double-run.

## Smoke check — did it run without silent failure?

```powershell
Start-ScheduledTask -TaskName 'devin-backup-daily'
Get-ScheduledTask -TaskName 'devin-backup-daily' | Get-ScheduledTaskInfo
# LastTaskResult 0 = create exited clean.

devin-backup list     # newest snapshot should carry today's date
```

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\remove-task.ps1
# or: schtasks /delete /tn "devin-backup-daily" /f
```

Existing snapshots and the `scheduled.json` job record (if the canonical
installer wrote one) are left in place.
