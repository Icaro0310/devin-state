# devin-janitor — Corporate Windows guide

This guide covers restricted Windows setup only. For unrestricted Windows, see [README.windows.md](README.windows.md); for features, shared commands, limitations, and the safety model, see [README.md](README.md).

Corporate Windows is a local-only environment: no Devin VM, QwenPaw, Slack dependency, external compute, workload delegation or required external integration.

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

- Keep execution local; do not configure VM, QwenPaw, external compute or workload delegation.
- Registry-declared external integrations remain optional and are not installed by this guide.
- macOS is planned but not claimed as tested.

## Corporate Windows specifics

- **No admin rights needed:** `uv` and every tool install under `%LOCALAPPDATA%`/`%APPDATA%` — nothing writes to `Program Files`, the registry, or requires elevation.
- **Proxy:** set `HTTPS_PROXY`/`HTTP_PROXY` before installing. Per session: `$env:HTTPS_PROXY="http://proxy:port"`; persistently: `setx HTTPS_PROXY "http://proxy:port"`. `uv`, `pip` and `npm` honor them.
- **TLS inspection:** if the corporate proxy intercepts TLS, point the installer at the company CA bundle: `$env:REQUESTS_CA_BUNDLE="C:\path\corp-root.pem"`. Certificate errors at install time mean the proxy, not the package.
- **Execution policy:** installed CLIs are real executables — `Set-ExecutionPolicy` only matters for `.ps1` scripts from a checkout; `-Scope CurrentUser RemoteSigned` suffices, no admin.
- **Blocked installers:** if winget/Store are disabled by policy, `uv` installs as a standalone binary — download the GitHub release zip, extract to `%LOCALAPPDATA%\bin`, add it to PATH.
- **Long paths:** keep checkout/install roots short (`C:\dev`) — MAX_PATH (260 chars) can still bite inside virtualenvs; `LongPathsEnabled` needs admin, short roots do not.
- **EDR/antivirus:** if a scan kills the install, retry with an exclusion or ask IT to allowlist `%LOCALAPPDATA%\uv` and `%USERPROFILE%\.local\bin`. These tools never elevate or listen on the network by default.
- **Offline/air-gapped:** `pip download <package> -d wheels\` on a connected machine, copy the folder, then `pip install --no-index --find-links wheels\` on the target (pure-Python tools; native deps need a matching platform wheel). For `source_only` tools installed from a copied checkout, stage the build backend too (`pip download setuptools wheel`), then install with `pip install --no-index --find-links wheels\ --no-build-isolation .` inside the checkout.
- **Fully local runtime:** installed tools make no required network calls — they read `sessions.db` and local stores only. The single exception is devin-doctor's optional update check (fetches the DevKit manifest); it self-skips when the registry is unreachable, or force it off with `DEVIN_DOCTOR_OFFLINE=1`.

## Recurring runs (optional)

_Daily cleanup. `devin-janitor install` registers the built-in daily report job (cron / Task Scheduler / elapsed hook) — prefer it over hand-rolled entries._

```powershell
schtasks /create /tn "devin-janitor" /tr "devin-janitor run --apply" /sc daily /st 04:00 /f
```

User-scope `schtasks` needs no admin. If Group Policy disables Task Scheduler, run the command manually or use the tool's own `install` subcommand where available.


## Adapters (MCP / Devin skill / plugin)

- MCP server: `pip install 'devin-janitor[mcp]'` then run `devin-janitor-mcp` (stdio).
  Read-only tools only.
- Devin plugin + skill: `devin plugins install
  Icaro0310/devin-state#packages/janitor/adapters`. The manifest
  launches the server through `uvx --from 'devin-janitor[mcp]' devin-janitor-mcp`, which
  resolves once the next PyPI release ships — until then install from
  source (`pip install -e 'packages/janitor[mcp]'` from a checkout).

## Troubleshooting

- If a command is not found, reopen PowerShell and run `uv tool update-shell`.
