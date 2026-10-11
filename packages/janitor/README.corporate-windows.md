# devin-janitor, Corporate Windows guide

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
Use `--data-dir`/`--config-dir` (plus `--sessions-db`/`--acp-dir`/`--locks-dir` for finer control) for non-default locations.

## Environment notes

- Keep execution local; do not configure VM, QwenPaw, external compute or workload delegation.
- Registry-declared external integrations remain optional and are not installed by this guide.
- macOS is planned but not claimed as tested.

## Corporate Windows specifics

- **No admin rights needed:** `uv` and every tool install under `%LOCALAPPDATA%`/`%APPDATA%`, nothing writes to `Program Files`, the registry, or requires elevation.
- **Proxy:** set `HTTPS_PROXY`/`HTTP_PROXY` before installing. Per session: `$env:HTTPS_PROXY="http://proxy:port"`; persistently: `setx HTTPS_PROXY "http://proxy:port"`. `uv`, `pip` and `npm` honor them.
- **TLS inspection:** if the corporate proxy intercepts TLS, point the tools at the company CA bundle: `$env:REQUESTS_CA_BUNDLE=` `"C:\path\corp-root.pem"` for pip/requests and `$env:SSL_CERT_FILE="C:\path\corp-root.pem"` for uv and urllib (see the Zscaler section for the full per-tool map). Certificate errors at install time mean the proxy, not the package.
- **Execution policy:** installed CLIs are real executables, `Set-ExecutionPolicy` only matters for `.ps1` scripts from a checkout; `-Scope CurrentUser RemoteSigned` suffices, no admin.
- **Blocked installers:** if winget/Store are disabled by policy, `uv` installs as a standalone binary, download the GitHub release zip, extract to `%LOCALAPPDATA%\bin`, add it to PATH.
- **Long paths:** keep checkout/install roots short (`C:\dev`), MAX_PATH (260 chars) can still bite inside virtualenvs; `LongPathsEnabled` needs admin, short roots do not.
- **EDR/antivirus:** if a scan kills the install, retry with an exclusion or ask IT to allowlist `%LOCALAPPDATA%\uv` and `%USERPROFILE%\.local\bin`. These tools never elevate or listen on the network by default.
- **Offline/air-gapped:** `pip download <package> -d wheels\` on a connected machine, copy the folder, then `pip install --no-index --find-links wheels\` on the target (pure-Python tools; native deps need a matching platform wheel). For `source_only` tools installed from a copied checkout, stage the build backend too (`pip download setuptools wheel`), then install with `pip install --no-index --find-links wheels\ --no-build-isolation .` inside the checkout.
- **Fully local runtime:** no network calls. The opt-in `--judge command:<cmd>` hook spawns a user-supplied command, absent under local-only.

## Zscaler

Zscaler é comum em ambientes corporativos e se comporta diferente de um proxy genérico. Dois produtos importam aqui: **Zscaler Internet Access (ZIA)**, proxy com inspeção de TLS, e **Zscaler Private Access (ZPA)**, túnel/VPN para aplicações internas.

- **Certificado raiz:** a inspeção de TLS da ZIA substitui o certificado dos sites pelo da Zscaler. Sem a raiz no bundle correto, `pip`/`uv`/`npm`/`git` falham com `SSL: CERTIFICATE_VERIFY_FAILED`. A raiz normalmente está em `C:\ProgramData\Zscaler\` (ou pode ser exportada pelo Zscaler Client Connector). Cada ferramenta lê a raiz de um lugar diferente:
  ```powershell
  $env:REQUESTS_CA_BUNDLE="C:\path\zscaler-root.pem"   # pip e ferramentas baseadas em requests
  $env:SSL_CERT_FILE="C:\path\zscaler-root.pem"        # uv, urllib do Python (inclui o check de manifest do DevKit)
  $env:NODE_EXTRA_CA_CERTS="C:\path\zscaler-root.pem"  # node/npm
  git config --global http.sslCAInfo "C:\path\zscaler-root.pem"
  ```
  Se a raiz da Zscaler já estiver no repositório de certificados do Windows (caso comum: instalada por política), `uv` também resolve com `uv --native-tls` ou `$env:UV_NATIVE_TLS="1"`, que lê o store do SO em vez do bundle embutido.
- **PAC file / auto-config:** se o proxy vem de um PAC em vez de variável fixa, `HTTPS_PROXY` manual pode não bastar. Descubra o proxy ativo antes de setar a variável: `netsh winhttp show proxy`, ou o painel do Zscaler Client Connector. Para downloads pontuais, copie o endereço que o PAC resolve para `HTTPS_PROXY`/`HTTP_PROXY`.
- **Portas e protocolos:** os MCP servers que este ecossistema instala usam transporte `stdio`, sem porta não-padrão, e ZPA não interfere. Exceções opt-in existem e estão no bullet "Fully local runtime" deste guia (ex.: o perfil corporate do devin-switch registra MCPs remotos HTTPS; o `--source mcp` do devin-qa-pack sai por HTTPS). Ferramentas remotas assim dependem de a ZPA/liberação alcançar o host delas.
- **"É a Zscaler ou outra coisa?":** `SSL: CERTIFICATE_VERIFY_FAILED` cujo emissor do certificado é `Zscaler` significa inspeção de TLS; resolva pela raiz acima. Timeout ou `connection refused` aponta mais para firewall/regra de rede, não TLS. Valide o proxy ativo e reporte ao TI com o host e a porta.


## Recurring runs (optional)

_Daily cleanup. `devin-janitor install` registers the built-in daily report job (cron / Task Scheduler / elapsed hook); prefer it over hand-rolled entries._

```powershell
schtasks /create /tn "devin-janitor" /tr "devin-janitor run --apply" /sc daily /st 04:30 /f
```

User-scope `schtasks` needs no admin. If Group Policy disables Task Scheduler (`0x80070005` "Access is denied"), run the command manually or use the tool's own `install` subcommand where available. Options needing elevation, "Run whether user is logged on or not", highest privileges, are usually policy-blocked; when they are, a user-scope logon trigger (`/sc onlogon`) is the realistic fallback.


## Adapters (MCP / Devin skill / plugin)

- MCP server: `pip install 'devin-janitor[mcp]'` then run `devin-janitor-mcp` (stdio).
  Read-only tools only.
- Devin plugin + skill: `devin plugins install
  Icaro0310/devin-state#packages/janitor/adapters`. The manifest
  launches the server through `uvx --from 'devin-janitor[mcp]' devin-janitor-mcp`, which
  resolves once the next PyPI release ships, until then install from
  source (`pip install -e 'packages/janitor[mcp]'` from a checkout).


## Troubleshooting

- If a command is not found, reopen PowerShell and run `uv tool update-shell`.
