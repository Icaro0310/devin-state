# devin-backup daily — Corporate Windows

> New task — the 7-day no-silent-failure observation window started
> 2026-10-12 and has not completed; see [README.md](README.md).

Same scheduled task as [README.windows.md](README.windows.md), plus the
constraints of a managed machine.

## User scope, no admin

The task registers under the current user with `InteractiveToken` /
`LeastPrivilege` — it only runs while you are logged on and never writes
outside your profile (snapshots land under `%APPDATA%\devin\backups` or
your `DEVIN_BACKUP_DIR`). If `install-task.ps1` fails with **0x80070005
(access denied)**, a GPO is blocking Task Scheduler or "Log on as a batch
job" was revoked — ask IT for a user-scope scheduling exception; do not
work around it by requesting admin.

## Trigger choice under suspend

The XML ships a **logon trigger plus a daily calendar trigger** with
`StartWhenAvailable` — the `-AtLogOn`-style catch-up matters on machines
that sleep through the 03:30 slot (nearly every corporate laptop). A
fixed-time-only task on a suspended machine is a backup that quietly
never happens.

If Task Scheduler is fully blocked by policy, the canonical installer
still has a fallback: `devin-backup install --backend elapsed` writes
only the `.devin-ecosystem\scheduled.json` job record (under
`%APPDATA%\Devin`), ticked by a `UserPromptSubmit` hook — no Task
Scheduler involved.

## Secrets in snapshots

`devin-backup create` copies every readable Devin store, **including
credentials-bearing ones**. On a managed machine that syncs or scans
your profile (OneDrive-known-folder-move, DLP agents), point the
snapshots at a dir you trust: `setx DEVIN_BACKUP_DIR "D:\backups"` or use
`--exclude-secrets` — decide before enabling, not after the first sync.

## Network: none

The backup is local file I/O — no proxy or TLS-inspection configuration
is needed for the task itself. Install-time proxy notes live in the
package's [README.corporate-windows.md](../../README.corporate-windows.md).

## Smoke check

```powershell
Get-ScheduledTask -TaskName 'devin-backup-daily' | Get-ScheduledTaskInfo
devin-backup list
```
