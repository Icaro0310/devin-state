# SPEC 02 — `devin-redact` (Vaga 0)

## 1. Problema

Os transcripts de agentes acumulam segredos: `cat .env` no output de uma tool,
keys coladas no chat, tokens em mensagens de erro. Publicar ou partilhar sessões
vaza credenciais. **Evidência direta:** a auditoria de hoje encontrou um **código
de pareamento real do Devin CLI** dentro de um prompt do histórico.

Ferramentas existentes (geheim, agent-leaks, AgentLogs) fazem isto para Claude
Code/Codex — **nenhuma lê a `sessions.db`**.

## 2. Extra Devin (e os 3 testes)

**Extra:** entende **semântica de tool call** — sabe que `cat .env` foi executado
(le `tool_call_state.rawInput`) e redige o *output associado*; e redige
**in-place em SQLite**, não apenas texto.

- **Concorrente lado a lado:** geheim/agent-leaks operam em ficheiros JSONL;
  **não sabem ler nem escrever numa DB SQLite** nem distinguir o comando do seu output.
- **Sem Devin:** o extra (semântica de tool call + store relacional) desaparece.
- **Uma frase:** *"É o único que entende os comandos que correram e limpa a base de dados, não só o texto."*

## 3. Escopo

- `scan` (read-only), `redact` (dry-run por defeito), `verify` (bloqueia publicação),
  `diff` (relatório HTML autocontido antes/depois, mascarado).
- Alvos: `sessions.db`, `acp-messages/*.db`, `.devin/memory/memories.jsonl`,
  exports Markdown/CSV, `.env`/`mcp_config.json`.
- Deteção: padrões (chaves, tokens, cookies, credenciais), ficheiros sensíveis
  conhecidos, **e** semântica de tool (`rawInput` → redigir output de `cat`/`grep`
  sobre ficheiros sensíveis).
- **Ligado por defeito** no `devin-history` (o exportador passa a redigir sempre).
- Relatório que bloqueia: contagens por categoria e `PUBLICATION STATUS: BLOCKED`.

## 4. NÃO-escopo

- Não é preventivo (não impede o agente de ler segredos — isso é `devin-policy`).
- Não faz upload nem partilha.
- Não promete deteção de 100% (falsos negativos existem — declarado no README).
- Não substitui `gitleaks` no CI (complementa).

## 5. Interfaces

| Interface | Descrição |
|---|---|
| **Biblioteca** `devin_redact` | Motor de deteção + redação (reutilizável por outros repos) |
| **CLI** `devin-redact` | `scan` · `redact` · `verify` · `diff` · `--report` |
| **Hook** (opcional) | `SessionEnd` → scan automático do dia |
| **Skill** | `/redact` para uso dentro do Devin |
| **PyPI** | `pipx install devin-redact` |

## 6. Formato de saída / contrato de dados

```json
{"files_scanned": 247, "secrets": 12, "emails": 38,
 "absolute_paths": 91, "project_names": 7,
 "publication_status": "BLOCKED", "findings": [...]}
```
Flags irreversíveis em forma longa apenas (`--apply --i-know-this-is-irreversible`),
como faz o `geheim` — evita toques acidentais.

## 7. Fixtures e testes (TDD — fixtures primeiro)

1. Corpus de teste com **segredos plantados** (sintéticos) em: DB, JSONL, Markdown, `.env`.
2. Golden files: o output do `scan` é estável.
3. Testes: `redact` em **cópia** nunca corrompe a DB (abre depois com o parser) ·
   `verify` bloqueia · falsos positivos em texto benigno · Unicode/encoding ·
   paths Windows · idempotência (redigir duas vezes não estraga).
4. CI: Windows + Linux.

## 8. Riscos e mitigação

| Risco | Mitigação |
|---|---|
| Corromper a DB ao redigir | Backup obrigatório + transação SQLite + teste de abertura pós-redação |
| Falsos negativos | Declarar no README; integrar `trufflehog`/`gitleaks` como camada opcional |
| Irreversibilidade | Dry-run por defeito + flags longas + relatório antes de aplicar |
| Falsa sensação de segurança | Secção "Limitations" obrigatória + recomendação de pre-commit gitleaks |

## 9. Critério de "pronto"

- [ ] `scan` deteta o corpus de teste (recall declarado)
- [ ] `redact` em cópia deixa a DB abrir e parsear (teste dedicado)
- [ ] `verify` devolve BLOCKED com segredos presentes
- [ ] `devin-history` exporta com `--redact` por defeito
- [ ] Testes verdes Windows + Linux · README (EN) com Prior art e Limitations
- [ ] `pipx install devin-redact` funciona

## 10. Tarefas (ordem)

1. Corpus de fixtures com segredos plantados + golden files.
2. Motor de deteção (padrões + ficheiros sensíveis).
3. Camada semântica de tool call (`rawInput` → output).
4. Escrita in-place em SQLite (com backup + transação).
5. CLI `scan/redact/verify` + relatório.
6. Integrar no `devin-history-export.py` como default.
7. Publicar PyPI + repo + CI.
