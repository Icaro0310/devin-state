# devin-janitor — Linux guide

This guide covers Linux setup only. See [README.md](README.md) for features, shared commands, limitations, and the safety model.

Linux uses the extended runtime: local execution plus optional Devin VM/QwenPaw delegation when this artifact supports it.

## Prerequisites

- `uv` and Python 3.10 or newer; `uv` can manage Python.

## Install

Install the isolated Python CLI:

```bash
uv tool install 'devin-janitor'
```

## Devin paths

Session data normally lives under `${XDG_DATA_HOME:-$HOME/.local/share}/devin/cli/`; UI state and ACP stores under `${XDG_CONFIG_HOME:-$HOME/.config}/Devin/User/`.
Use the tool's documented `--data-dir` or `--config-dir` flags for non-default locations.

## Environment notes

- Delegated runtime is optional; this guide installs local tooling only.
- Linux can use additional compute or Linux-compatible delegated tooling when available.
- macOS is planned but not claimed as tested.

## Linux specifics

- **Installer choice:** `uv tool install` is the recommended path (isolated environment, managed Python). `pipx install` works identically for PyPI packages; `pip install --user` is the last-resort fallback — no isolation, watch dependency conflicts.
- **PATH:** executables land in `~/.local/bin`. If a command is not found, add `export PATH="$HOME/.local/bin:$PATH"` to `~/.bashrc`/`~/.zshrc` and open a new shell.
- **Distros:** tested on Ubuntu; Debian, Fedora and Arch follow the same steps — only `uv`/Python acquisition differs (distro package or the uv installer script).
- **Headless and minimal environments:** no display is needed — every CLI is text-only. In containers or WSL, install `uv` and Git and follow the same steps; `XDG_*` paths resolve normally.
- **Permissions:** tools read Devin data under `$XDG_DATA_HOME/devin` and write only their own config/state — no root or sudo is required.
- **Scheduling:** optional recurring work belongs to `systemd --user` timers or cron; installation never creates jobs.

## Recurring runs (optional)

_Daily cleanup. `devin-janitor install` registers the built-in daily report job (cron / Task Scheduler / elapsed hook) — prefer it over hand-rolled entries._

```cron
30 4 * * * devin-janitor run --apply
```

Equivalent `systemd --user` timer works too; enable lingering if it must run without a login session.


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

- If a command is not found, ensure the `uv` tools directory is on `PATH` and run `uv tool update-shell`.
