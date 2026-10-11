---
name: session-janitor
description: "(LEGADO/arquivado — superseded pela skill packaged `devin-janitor`) Documentação do pipeline histórico de limpeza diária de sessões-poluição do Devin Desktop. Para agentes: apenas scan/report dry-run; apply/vacuum corre só via Task Scheduler ou invocação humana explícita."
triggers:
  - model
---

# Session Janitor (LEGADO — arquivado)

> **Estado**: arquivado como proveniência. A superfície atual para agentes
> é a skill packaged `devin-janitor` (`packages/janitor/adapters/skills/`),
> que expõe apenas `devin-janitor scan`/`report` — dry-run, sem escrita.
> Este documento descreve o que a task agendada faz; **um agente nunca
> corre `--apply`, `--vacuum-only` ou qualquer comando destrutivo** —
> execução é exclusiva do Task Scheduler ou de invocação humana explícita.

`scripts/session-janitor.py` — corre diariamente via Task Scheduler
(`DevinSessionJanitor`, 04:30) e mantém o space/session list limpo.

## Pipeline

1. **Export primeiro** — corre `devin-history-export.py`; aborta se falhar.
   O transcript cru fica sempre em `ObsidianVault/Sessões/` antes de apagar.
2. **Classificação em tiers** (reusa `audit_sessions.py`):
   - KEEP — allowlist `.devin/janitor-keep.json`, títulos "não apagar"/SLACK-BRAIN,
     ou última atividade < 48h (`--grace-hours`)
   - AUTO-DELETE — vazias; ruído de automação/eval (DJAEVIN, classificações,
     probes, billing…); ciclos efémeros heartbeat/mailbox one-shot;
     duplicadas (mesmo título normalizado, fica a irmã com mais atividade)
   - JUDGE — sinais fracos/ambíguos → `djaevin-local` tool `judge` decide se há
     conhecimento durável. **Fail-open**: Djævin em baixo = conserva tudo.
3. **Apaga** rows em `sessions.db` + ficheiros `acp-messages/<id>.db*`.
   Ficheiros bloqueados (Devin aberto) ficam em `.devin/janitor-pending.json`
   e são re-tentados em cada corrida.
4. **VACUUM** só se Devin.exe estiver fechado; senão fica para
   `session-db-maintenance.py --vacuum-only`.

## Operação

Para um agente, a operação permitida é **somente dry-run** (a forma
packaged é `devin-janitor scan`/`report`; este script legado corre
sem flags para o mesmo efeito):

```bash
python scripts/session-janitor.py            # dry-run (plano)
python scripts/session-janitor.py --apply    # EXECUÇÃO — só humano/task agendada
```

`--apply` e `--vacuum-only` são operações destrutivas com confirmação
humana; nunca devem aparecer numa superfície AI-driven.

Flags: `--grace-hours N` · `--max-delete N` · `--no-djævin` · `--no-export`

- Log por corrida: `.devin/memory/janitor-log.jsonl` (apagadas + porquê)
- Proteger sessão: `.devin/janitor-keep.json` (`ids` / `title_patterns`)
- Lock task diária: `schtasks /query /tn DevinSessionJanitor`

## Lições

- (2026-09-29) Sessões DJAEVIN/eval ("billing", "Classify:", judge calls,
  payloads JSON) e ciclos heartbeat/mailbox são ~55% da poluição — relevantes
  no momento, inúteis depois. O conhecimento durável deles já vive nas
  sessões SLACK-BRAIN, em `heartbeat/state.json`, no vault e nas skills
  `learned-*` — apagar é seguro após export.
- (2026-09-29) O Djævin fala stdio via `poordjaevin serve`; para o janitor usa
  backend `nli` (local, não cria sessões Devin novas). O backend `acp` criaria
  uma sessão Devin por consulta — a própria poluição que se quer limpar.
  (O antigo backend Ollama foi removido do ecossistema.)
