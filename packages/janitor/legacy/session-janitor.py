#!/usr/bin/env python3
"""session-janitor.py — limpeza diária de sessões-poluição do Devin Desktop.

Pipeline (ordem de segurança):
  1. Exporta tudo para o arquivo de transcrições (history-export.py) —
     rede de segurança: transcript cru fica arquivado antes de apagar.
  2. Classifica cada sessão em tiers:
       KEEP        — marcada "não apagar", allowlist, ou dentro da janela de
                     graça (default 48h desde última atividade)
       AUTO-DELETE — vazias; ruído de automação/eval (classificações,
                     probes); ciclos efémeros heartbeat/mailbox; duplicadas
                     (fica a irmã com mais atividade)
       JUDGE       — sinais fracos mas ambíguas → pergunta a um juiz local
                     se vale a pena preservar
  3. Apaga candidatas: rows em sessions.db + ficheiros acp-messages/*.db.
     Ficheiros bloqueados (Devin aberto) ficam em `.devin/janitor-pending.json`
     e são re-tentados em cada corrida.
  4. VACUUM só se o Devin.exe estiver fechado.

O juiz é fail-open: se o backend estiver em baixo, sessões
ambíguas são CONSERVADAS — nunca apagadas sem veredito.

Uso:
    python session-janitor.py              # dry-run: mostra o plano
    python session-janitor.py --apply      # executa a limpeza
    python session-janitor.py --apply --no-judge --grace-hours 72

Agendamento diário (agendador do SO): ver a documentação arquivada nesta
pasta.
"""

import argparse
import glob
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from session_audit import gui_rows, session_rows

HOME = Path.home()
DB = HOME / "AppData/Roaming/devin/cli/sessions.db"
GUI_DIR = HOME / "AppData/Roaming/devin/User/acp-messages"
LOCKS_DIR = HOME / "AppData/Roaming/devin/cli/session_locks"
WS = Path(__file__).resolve().parent.parent
EXPORTER = Path(os.environ.get(
    "JANITOR_EXPORTER",
    str(WS / "scripts/devin-history-export.py")))
KEEP_FILE = WS / ".devin/janitor-keep.json"
PENDING_FILE = WS / ".devin/janitor-pending.json"
LOG_FILE = WS / ".devin/memory/janitor-log.jsonl"

MSG_TABLES = ["message_nodes", "tool_call_state", "rendered_commits",
              "subagent_heads", "prompt_history"]

# Sessões de automação sem qualquer valor retido (patterns sobre o título)
NOISE_RE = re.compile(
    r"judge tool|classif|support_triage|entailment|^\[\d+\]$|^\{\"items\"|"
    r"^billing$|^BLOCKED$|SESSION_OK|echo.*test|sentinel|safe test command|"
    r"heartbeat-probe|Lista.*(tools|ferramentas).*djaevin-local|tools MCP.*djaevin-local",
    re.IGNORECASE)

# Ciclos one-shot cujo conhecimento durável já vive noutro lado
# (sessões de ponte, estado local da automação, arquivo de notas, skills
# learned-*)
EPHEMERAL_RE = re.compile(
    r"inbox|slack-bridge|slack bridge|Tarefa Slack|Processamento|"
    r"Processar ficheiros|timeout ACP|heartbeat", re.IGNORECASE)

# Veredito do juiz sobre sessões ambíguas
JUDGE_STATEMENT = (
    "This session transcript contains durable, reusable knowledge — "
    "decisions, conventions, fixes or project context worth preserving "
    "for future work.")

JUDGE_PYTHON = Path(os.environ.get(
    "JANITOR_JUDGE_PYTHON",
    str(WS / "vendor/judge/.venv/Scripts/python.exe")))
# The private bridge module name was scrubbed for distribution — point
# JANITOR_JUDGE_MODULE at a real installation's module to re-enable.
JUDGE_MODULE = os.environ.get("JANITOR_JUDGE_MODULE", "judge_bridge.cli")
JUDGE_ENV = {
    **os.environ,
    # Legacy/archived: usa um backend NLI local (offline, sem serviço
    # externo).
    "JUDGE_BACKEND": os.environ.get("JANITOR_JUDGE_BACKEND", "nli"),
    "JUDGE_CALIBRATOR": str(WS / "results/judge-eval/calibrator.json"),
}


# ---------------------------------------------------------------- keep list

def load_keep() -> tuple[set, re.Pattern]:
    """`.devin/janitor-keep.json`: {"ids": [...], "title_patterns": [...]}"""
    ids, pats = set(), []
    if KEEP_FILE.exists():
        try:
            d = json.loads(KEEP_FILE.read_text(encoding="utf-8"))
            ids = set(d.get("ids", []))
            pats = d.get("title_patterns", [])
        except (json.JSONDecodeError, OSError):
            pass
    pats += [r"n[ãa]o apagar", r"SLACK-BRAIN"]
    return ids, re.compile("|".join(pats), re.IGNORECASE)


def load_pending() -> dict:
    if PENDING_FILE.exists():
        try:
            return json.loads(PENDING_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def norm_title(t: str) -> str:
    return re.sub(r"[^a-z0-9]", "", t.lower())[:60]


# ------------------------------------------------------------------ juiz

class LocalJudge:
    """Cliente stdio mínimo para o bridge `judge`. Fail-open."""

    def __init__(self):
        self.proc = None
        self._id = 0
        self.available = False
        try:
            self.proc = subprocess.Popen(
                [str(JUDGE_PYTHON), "-m", JUDGE_MODULE, "serve"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, env=JUDGE_ENV, cwd=str(WS))
            self._call("initialize", {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "session-janitor", "version": "1.0"}})
            self.proc.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            self.proc.stdin.flush()
            self.available = True
        except Exception:  # noqa: BLE001 - optional bridge, fail-soft
            self.available = False

    def _call(self, method, params):
        self._id += 1
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method,
             "params": params}) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("judge closed stdout")
            msg = json.loads(line)
            if msg.get("id") == self._id:
                if "error" in msg:
                    raise RuntimeError(str(msg["error"]))
                return msg["result"]

    def judge(self, text: str) -> dict | None:
        """Devolve verdict do juiz ou None se abstém/indisponível."""
        if not self.available:
            return None
        try:
            res = self._call("tools/call", {
                "name": "judge",
                "arguments": {"text": text[:4000],
                              "statement": JUDGE_STATEMENT}})
            txt = "".join(c.get("text", "") for c in res.get("content", []))
            return json.loads(txt)
        except Exception:  # noqa: BLE001 - optional bridge, fail-soft
            self.available = False
            return None

    def close(self):
        if self.proc:
            try:
                self.proc.terminate()
            except OSError:
                pass


# --------------------------------------------------------- classificação

def classify(rows, keep_ids, keep_re, grace_ts):
    """Devolve (auto_delete, judge_candidates, kept) com razões."""
    auto, judge, kept = [], [], {}

    # pré-passe: detetar duplicadas — mesmo título normalizado, fica a melhor
    by_title = {}
    for r in rows:
        by_title.setdefault((r["project"], norm_title(r["title"])), []).append(r)
    dup_losers = set()
    for sibs in by_title.values():
        if len(sibs) < 2 or not norm_title(sibs[0]["title"]):
            continue
        best = max(sibs, key=lambda x: x["user_msgs"] * 3 + x["tool_calls"])
        for s in sibs:
            if s["id"] != best["id"]:
                dup_losers.add(s["id"])

    for r in rows:
        sid, t = r["id"], r["title"]
        score = r["user_msgs"] * 3 + r["tool_calls"]

        if sid in keep_ids or keep_re.search(t):
            kept[sid] = "allowlist/marcada"
            continue
        if r["last_activity"] and r["last_activity"] > grace_ts:
            kept[sid] = "janela de graça"
            continue

        empty = (r["status"] == "vazia" or
                 (r["user_msgs"] == 0 and r["tool_calls"] == 0
                  and r["assistant_msgs"] == 0))
        if empty:
            auto.append((r, "vazia"))
        elif sid in dup_losers:
            auto.append((r, "duplicada"))
        elif NOISE_RE.search(t) and r["tool_calls"] <= 5:
            auto.append((r, "ruído de automação/eval"))
        elif EPHEMERAL_RE.search(t) and r["user_msgs"] <= 75 \
                and r["tool_calls"] <= 60:
            auto.append((r, "ciclo efémero heartbeat/mailbox"))
        elif r["user_msgs"] <= 6 and r["tool_calls"] <= 15 \
                and r["files_touched"] == 0 and score < 20:
            judge.append(r)
        else:
            kept[sid] = "trabalho substantivo"

    return auto, judge, kept


# -------------------------------------------------------------- deleção

def delete_cli(con, sid):
    for t in MSG_TABLES:
        try:
            con.execute(f"DELETE FROM {t} WHERE session_id=?", (sid,))
        except sqlite3.Error:
            pass
    con.execute("DELETE FROM sessions WHERE id=?", (sid,))


def delete_gui_files(sid, pending: dict) -> bool:
    """Remove acp-messages/<sid>.db* — devolve True se removeu tudo."""
    files = glob.glob(str(GUI_DIR / f"{sid}.db*")) + \
        glob.glob(str(GUI_DIR / f"{sid}.lock"))
    ok = True
    for p in files:
        try:
            os.remove(p)
        except OSError:
            ok = False
    if not ok:
        pending.setdefault(sid, int(time.time()))
    else:
        pending.pop(sid, None)
    return ok


def devin_running() -> bool:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Devin.exe", "/FO", "CSV"],
            capture_output=True, text=True, timeout=20, check=False).stdout
        return out.count("Devin.exe") > 1
    except Exception:  # noqa: BLE001 - assume running when probe fails
        return True


# ------------------------------------------------------------------ main

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="executa (sem isto é dry-run)")
    ap.add_argument("--grace-hours", type=float, default=48)
    ap.add_argument("--max-delete", type=int, default=100)
    ap.add_argument("--no-judge", action="store_true")
    ap.add_argument("--no-export", action="store_true")
    args = ap.parse_args()

    rows = session_rows() + gui_rows()
    keep_ids, keep_re = load_keep()
    grace_ts = time.time() - args.grace_hours * 3600
    pending = load_pending()

    auto, judge_cands, kept = classify(rows, keep_ids, keep_re, grace_ts)

    # ---- juiz decide as ambíguas
    judge = None
    judged_del, judged_keep, judge_down = [], [], 0
    if judge_cands and not args.no_judge:
        judge = LocalJudge()
        if not judge.available:
            print("Juiz indisponível — ambíguas conservadas (fail-open).")
            judge_down = len(judge_cands)
        else:
            for r in judge_cands:
                text = f"{r['title']}\n\n{r['prompt']}"
                v = judge.judge(text)
                if v is None or v.get("abstained"):
                    judged_keep.append(r)
                elif v.get("value") is False:
                    judged_del.append(
                        (r, (f"judge: sem conhecimento durável "
                             f"(p={v.get('prob_true')})")))
                else:
                    judged_keep.append(r)
            judge.close()
    else:
        judged_keep = judge_cands if args.no_judge else []

    targets = auto + judged_del
    targets = targets[: args.max_delete]

    # ---- relatório do plano
    print(f"{'DRY-RUN' if not args.apply else 'APPLY'} · {len(rows)} sessões · "
          f"graça {args.grace_hours:.0f}h")
    print(f"  manter: {len(kept) + len(judged_keep) + judge_down} "
          f"(allowlist/graça/substantivo + {len(judged_keep)} julgadas úteis)")
    print(f"  apagar: {len(targets)}")
    for r, why in targets:
        dt = datetime.fromtimestamp(r["created"], tz=timezone.utc).astimezone().strftime("%Y-%m-%d")
        print(f"    [{r['origin']}] {r['id'][:40]:40} {dt} {why:42} "
              f"{r['title'][:50]}")

    if not args.apply or not targets:
        if not args.apply:
            print("\n(dry-run — corre com --apply para executar)")
        return 0

    # ---- 1. export (rede de segurança)
    if not args.no_export:
        print("\n== export de transcrições ==")
        rc = subprocess.run([sys.executable, str(EXPORTER)],
                            timeout=900, check=False).returncode
        if rc != 0:
            print("export falhou — aborto antes de apagar.", file=sys.stderr)
            return 3

    # ---- 2. apagar
    print("== apagar ==")
    con = sqlite3.connect(str(DB), timeout=30)
    con.execute("PRAGMA busy_timeout=30000")
    n_cli = n_gui = 0
    for r, _why in targets:
        if con.execute("SELECT 1 FROM sessions WHERE id=?",
                       (r["id"],)).fetchone():
            delete_cli(con, r["id"])
            n_cli += 1
        if (r["origin"] == "gui" or glob.glob(str(GUI_DIR / f"{r['id']}.db*"))) \
                and delete_gui_files(r["id"], pending):
            n_gui += 1
    # re-tentar ficheiros pendentes de corridas anteriores
    for sid in list(pending):
        delete_gui_files(sid, pending)
    con.commit()
    con.close()

    # locks órfãos em session_locks/
    live = {r["id"] for r in session_rows()}
    orphan = [p for p in glob.glob(str(LOCKS_DIR / "*.lock"))
              if Path(p).stem not in live]
    for p in orphan:
        try:
            os.remove(p)
        except OSError:
            pass

    # ---- 3. vacuum só com Devin fechado
    if not devin_running():
        con = sqlite3.connect(str(DB))
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        con.execute("VACUUM")
        con.close()
        print("vacuum executado (Devin fechado)")
    else:
        print("Devin aberto — vacuum adiado "
              "(corre a manutenção --vacuum-only ao fechar)")

    # ---- 4. log + pending
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": int(time.time()),
            "deleted": [{"id": r["id"], "origin": r["origin"],
                         "title": r["title"], "why": w}
                        for r, w in targets],
            "judged_keep": [r["id"] for r in judged_keep],
            "judge_down": judge_down,
            "pending_locked": list(pending),
            "orphan_locks_removed": len(orphan),
        }, ensure_ascii=False) + "\n")
    if pending:
        PENDING_FILE.write_text(json.dumps(pending, indent=1), encoding="utf-8")
    elif PENDING_FILE.exists():
        PENDING_FILE.unlink()

    print(f"\napagadas: {n_cli} rows CLI + {n_gui} sessões GUI · "
          f"locks órfãos: {len(orphan)} · pendentes (bloqueadas): {len(pending)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
