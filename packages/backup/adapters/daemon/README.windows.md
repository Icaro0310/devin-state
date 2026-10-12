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

`install-task.ps1` does a two-step registration when `devin-backup` is
on `PATH`: first `devin-backup install --backend tasksch` (the canonical
installer — writes the `.devin-ecosystem\scheduled.json` registry entry),
then it imports this XML with `-Force`, overwriting the daily-only task
with this adapter's triggers (logon + daily + `StartWhenAvailable`) and
an action pointing at the **resolved absolute exe path**. That last bit
matters: Task Scheduler's environment lacks `%USERPROFILE%\.local\bin`,
where `uv tool install` puts the shim — a bare `devin-backup` name is
not found at run time. Without the CLI it still imports the XML, falling
back to that documented default location and skipping the registry
entry. Neither path needs admin.

Equivalent one-liner without the script — replace the `__BACKUP_EXE__`
token in the XML with your exe path first:

```powershell
schtasks /create /tn "devin-backup-daily" /xml devin-backup-daily.task.xml /f
```

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

`remove-task.ps1` also deletes the job's record from
`%APPDATA%\Devin\.devin-ecosystem\scheduled.json` when present (the
schtasks fallback leaves it behind — delete the job key by hand).
Existing snapshots are left in place either way.
