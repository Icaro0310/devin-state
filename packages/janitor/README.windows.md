# devin-janitor — Personal Windows guide

This guide covers unrestricted Windows setup. For restricted machines, see [README.corporate-windows.md](README.corporate-windows.md); for features, shared commands, limitations, and the safety model, see [README.md](README.md).

Personal Windows uses the extended runtime: local execution plus optional Devin VM/QwenPaw delegation when this artifact supports it.

## Prerequisites

- `uv` and Python 3.10 or newer; `uv` can manage Python.

## Install

Install the isolated Python CLI:

```powershell
uv tool install "devin-janitor"
```

## Devin paths

Session data normally lives under `%APPDATA%\devin\cli\`; UI state and ACP stores under `%APPDATA%\Devin\User\`.
Use the tool's documented `--data-dir` or `--config-dir` flags for non-default locations.

## Environment notes

- Delegated runtime is optional; this guide installs local tooling only.
- Corporate Windows is a separate local-only environment.
- macOS is planned but not claimed as tested.

## Personal Windows specifics

- **Python:** `uv` manages its own Python, which also avoids the Microsoft Store `python.exe` alias stub (it opens the Store instead of running). If you install Python from python.org anyway, tick "Add python.exe to PATH".
- **Shell:** PowerShell 7 + Windows Terminal is the recommended setup; every command also works in `cmd.exe` and Windows PowerShell 5.1 — none require admin.
- **Install location:** executables live under `%USERPROFILE%\.local\bin`; data under `%APPDATA%\devin`. Nothing touches `Program Files` or the registry.
- **WSL:** treat it as a Linux machine — follow [README.linux.md](README.linux.md) inside it.
- **Uninstall:** `uv tool uninstall <package>` (or `npm uninstall -g` for a Node.js tool) removes the CLI; delete `%APPDATA%\devin` to remove local data. No services or scheduled tasks are left behind.

## Recurring runs (optional)

_Daily cleanup. `devin-janitor install` registers the built-in daily report job (cron / Task Scheduler / elapsed hook) — prefer it over hand-rolled entries._

```powershell
schtasks /create /tn "devin-janitor" /tr "devin-janitor run --apply" /sc daily /st 04:00 /f
```

Runs under your account — no admin needed. Adjust `/sc`/`/st` (or `/sc onlogon` for daemons) to taste.


## Adapters (MCP / Devin skill / plugin)

- MCP server: `pip install 'devin-janitor[mcp]'` then run `devin-janitor-mcp` (stdio).
  Read-only tools only.
- Devin plugin + skill: `devin plugins install
  Icaro0310/devin-state#packages/janitor/adapters`. The manifest
  launches the server through `uvx --from 'devin-janitor[mcp]' devin-janitor-mcp`, which
  resolves once the next PyPI release ships. Until then, an
  editable install does not change what `uvx --from` resolves —
  either run the source-installed `devin-janitor-mcp` directly, or
  point a local manifest copy at the checkout:
  `uvx --from './packages/janitor[mcp]' devin-janitor-mcp`.

## Troubleshooting

- If a command is not found, reopen PowerShell and run `uv tool update-shell`.
