# devin-state, Corporate Windows guide

This guide covers restricted Windows setup only. For unrestricted Windows, see [README.windows.md](README.windows.md); for features, shared commands, limitations, and the safety model, see [README.md](README.md).

Corporate Windows is a local-only environment: no Devin VM, QwenPaw, Slack dependency, external compute, workload delegation or required external integration.

## Prerequisites

- `uv` and Python 3.10 or newer; `uv` can manage Python.

## Install

Install the isolated Python CLI:

```powershell
uv tool install "devin-redact"
```

## Devin paths

Session data normally lives under `%APPDATA%\devin\cli\`; UI state and ACP stores under `%APPDATA%\Devin\User\`.
Use `session-end` takes `--sessions-db`/`--data-dir`/`--out`; `verify-publish` takes `--verdicts-dir` for non-default locations.

## Environment notes

- Keep execution local; do not configure VM, QwenPaw, external compute or workload delegation.
- Registry-declared external integrations remain optional and are not installed by this guide.
- macOS is planned but not claimed as tested.

## Corporate Windows specifics

- **No admin rights needed:** `uv` and every tool install under `%LOCALAPPDATA%`/`%APPDATA%`, nothing writes to `Program Files`, the registry, or requires elevation.
- **Proxy:** set `HTTPS_PROXY`/`HTTP_PROXY` before installing. Per session: `$env:HTTPS_PROXY="http://proxy:port"`; persistently: `setx HTTPS_PROXY "http://proxy:port"`. `uv`, `pip` and `npm` honor them.
- **TLS inspection:** if the corporate proxy intercepts TLS, point the tools at the company CA bundle: `$env:REQUESTS_CA_BUNDLE="C:\path\corp-root.pem"` for pip/requests and `$env:SSL_CERT_FILE="C:\path\corp-root.pem"` for uv and urllib (see the Zscaler section for the full per-tool map). Certificate errors at install time mean the proxy, not the package.
- **Execution policy:** installed CLIs are real executables, `Set-ExecutionPolicy` only matters for `.ps1` scripts from a checkout; `-Scope CurrentUser RemoteSigned` suffices, no admin.
- **Blocked installers:** if winget/Store are disabled by policy, `uv` installs as a standalone binary, download the GitHub release zip, extract to `%LOCALAPPDATA%\bin`, add it to PATH.
- **Long paths:** keep checkout/install roots short (`C:\dev`), MAX_PATH (260 chars) can still bite inside virtualenvs; `LongPathsEnabled` needs admin, short roots do not.
- **EDR/antivirus:** if a scan kills the install, retry with an exclusion or ask IT to allowlist `%LOCALAPPDATA%\uv` and `%USERPROFILE%\.local\bin`. These tools never elevate or listen on the network by default.
- **Offline/air-gapped:** `pip download <package> -d wheels\` on a connected machine, copy the folder, then `pip install --no-index --find-links wheels\` on the target (pure-Python tools; native deps need a matching platform wheel). For `source_only` tools installed from a copied checkout, stage the build backend too (`pip download setuptools wheel`), then install with `pip install --no-index --find-links wheels\ --no-build-isolation .` inside the checkout.
- **Fully local runtime:** installed tools make no required network calls, this tool has none; it reads `sessions.db` and local stores only.

## Zscaler

Zscaler é comum em ambientes corporativos e se comporta diferente de um proxy genérico. Dois produtos importam aqui: **Zscaler Internet Access (ZIA)**, proxy com inspeção de TLS, e **Zscaler Private Access (ZPA)**, túnel/VPN para aplicações internas.

- **Certificado raiz:** a inspeção de TLS da ZIA substitui o certificado dos sites pelo da Zscaler. Sem a raiz no bundle correto, `pip`/`uv`/`npm`/`git` falham com `SSL: CERTIFICATE_VERIFY_FAILED`. A raiz vive no repositório de certificados do Windows (instalada por política ou pelo Client Connector), e o bundle das variáveis abaixo precisa ser PEM (Base-64), não DER. Pelo GUI, exporte via Trusted Root Certification Authorities → Zscaler → Export escolhendo "Base-64 encoded X.509 (.CER)": `certmgr.msc` abre apenas o store do usuário atual; raízes instaladas por política na máquina aparecem no `certlm.msc`. Via PowerShell, `Get-ChildItem Cert:\LocalMachine\Root | ? Subject -like "*Zscaler*"` + `Export-Certificate` gera DER; converta para PEM com `certutil -encode zscaler-root.cer zscaler-root.pem`. Em alternativa peça o PEM ao TI. Cada ferramenta lê a raiz de um lugar diferente:
  ```powershell
  $env:REQUESTS_CA_BUNDLE="C:\path\zscaler-root.pem"   # pip e ferramentas baseadas em requests
  $env:SSL_CERT_FILE="C:\path\zscaler-root.pem"        # uv, urllib do Python (inclui o check de manifest do DevKit)
  $env:NODE_EXTRA_CA_CERTS="C:\path\zscaler-root.pem"  # node/npm
  git config --global http.sslCAInfo "C:\path\zscaler-root.pem"
  ```
  Se a raiz da Zscaler já estiver no repositório de certificados do Windows (caso comum: instalada por política), `uv` também resolve com `uv --native-tls` ou `$env:UV_NATIVE_TLS="1"`, que lê o store do SO em vez do bundle embutido.
- **PAC file / auto-config:** se o proxy vem de um PAC em vez de variável fixa, `HTTPS_PROXY` manual pode não bastar. Descubra o proxy ativo antes de setar a variável: `netsh winhttp show proxy`, ou o painel do Zscaler Client Connector. Para downloads pontuais, copie o endereço que o PAC resolve para `HTTPS_PROXY`/`HTTP_PROXY`.
- **Portas e protocolos:** os MCP servers que este ecossistema instala usam transporte `stdio`, sem porta não-padrão, e ZPA não interfere. Exceções opt-in existem em alguns pacotes e estão descritas no bullet "Fully local runtime" do guia corporate de cada um (ex.: o perfil corporate do devin-switch registra MCPs remotos HTTPS; o `--source mcp` do devin-qa-pack sai por HTTPS). Ferramentas remotas assim dependem de a ZPA/liberação alcançar o host delas.
- **"É a Zscaler ou outra coisa?":** `SSL: CERTIFICATE_VERIFY_FAILED` cujo emissor do certificado é `Zscaler` significa inspeção de TLS; resolva pela raiz acima. Timeout ou `connection refused` aponta mais para firewall/regra de rede, não TLS. Valide o proxy ativo e reporte ao TI com o host e a porta.


## Troubleshooting

- If a command is not found, reopen PowerShell and run `uv tool update-shell`.
