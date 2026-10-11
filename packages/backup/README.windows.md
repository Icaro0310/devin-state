# devin-backup, Personal Windows guide

This guide covers unrestricted Windows setup. For restricted machines, see [README.corporate-windows.md](README.corporate-windows.md); for features, shared commands, limitations, and the safety model, see [README.md](README.md).

Personal Windows uses the extended runtime: local execution plus optional Devin VM/QwenPaw delegation when this artifact supports it.

## Prerequisites

- `uv` and Python 3.10 or newer; `uv` can manage Python.

## Install

Install the isolated Python CLI:

```powershell
uv tool install "devin-backup"
```

## Devin paths

Session data normally lives under `%APPDATA%\devin\cli\`; UI state and ACP stores under `%APPDATA%\Devin\User\`.
Use `--data-dir`/`--config-dir` for non-default locations.

## Environment notes

- Delegated runtime is optional; this guide installs local tooling only.
- Corporate Windows is a separate local-only environment.
- macOS is planned but not claimed as tested.

## Personal Windows specifics

- **Python:** `uv` manages its own Python, which also avoids the Microsoft Store `python.exe` alias stub (it opens the Store instead of running). If you install Python from python.org anyway, tick "Add python.exe to PATH".
- **Shell:** PowerShell 7 + Windows Terminal is the recommended setup; every command also works in `cmd.exe` and Windows PowerShell 5.1, none require admin.
- **Install location:** executables live under `%USERPROFILE%\.local\bin`; data under `%APPDATA%\devin`. Nothing touches `Program Files` or the registry.
- **WSL:** treat it as a Linux machine, follow [README.linux.md](README.linux.md) inside it.
- **Uninstall:** `uv tool uninstall <package>` (or `npm uninstall -g` for a Node.js tool) removes the CLI; delete `%APPDATA%\devin` to remove local data. No services or scheduled tasks are left behind.

## Recurring runs (optional)

_Nightly snapshot; pair with a weekly `devin-backup rotate --keep 10 --yes`. Or let the tool self-schedule with `devin-backup install` (cron / Task Scheduler / elapsed backends)._

Quoted path arguments inside `/tr` fail differently in cmd.exe and PowerShell 5.1, so this job goes through a wrapper `.cmd` file in your own profile directory (quoting inside the file works normally, and no other user can replace it). The task inherits your user `PATH`, so the wrapper first prepends the standard tool directory (`%USERPROFILE%\.local\bin`); if the tool lives elsewhere, write its full path inside the `.cmd`. Register from PowerShell with the `ScheduledTask` cmdlets, which take the path literally and replace cleanly on rerun (`-Force`):

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\devin-tasks"   # cmd.exe: mkdir "%USERPROFILE%\devin-tasks"
```

Save this as `%USERPROFILE%\devin-tasks\devin-backup.cmd`:

```batch
set "PATH=%USERPROFILE%\.local\bin;%PATH%"
devin-backup create --out "%USERPROFILE%\backups"
```

```powershell
$action  = New-ScheduledTaskAction -Execute "$env:USERPROFILE\devin-tasks\devin-backup.cmd"
$trigger = New-ScheduledTaskTrigger -Daily -At 3:15AM
Register-ScheduledTask -TaskName "devin-backup" -Action $action -Trigger $trigger -Force
```

_cmd.exe users: the same registration works from Task Scheduler's GUI (Action = the .cmd path)._

Runs under your account, no admin needed. Adjust the `New-ScheduledTaskTrigger` arguments (or `-AtLogOn` for daemons) to taste.


## Adapters (MCP / Devin skill / plugin)

- MCP server: `pip install 'devin-backup[mcp]'` then run `devin-backup-mcp` (stdio).
  Read-only tools only.
- Devin plugin + skill: `devin plugins install
  Icaro0310/devin-state#packages/backup/adapters`. The manifest
  launches the server through `uvx --from 'devin-backup[mcp]' devin-backup-mcp`, which
  resolves once the next PyPI release ships. Until then, an
  editable install does not change what `uvx --from` resolves —
  either run the source-installed `devin-backup-mcp` directly, or
  point a local manifest copy at the checkout:
  `uvx --from './packages/backup[mcp]' devin-backup-mcp`.


## Troubleshooting

- If a command is not found, reopen PowerShell and run `uv tool update-shell`.
