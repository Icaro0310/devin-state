"""``devin-janitor`` CLI — thin wrapper; all logic lives in the library.

Subcommands:

- ``scan``    classification preview (``--json`` for machines)
- ``run``     the safety pipeline; dry-run unless ``--apply``
- ``pending`` inspect/retry the locked-files retry queue
- ``report``  recoverable-space report; advisory, always exits 0
- ``install`` schedule a daily ``report`` job (F6 pattern, opt-in)
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from devin_internals.schema import SchemaError

from devin_janitor.cleanup import (
    TIER1,
    TIER2,
    TIER3,
    CleanupRefused,
    apply_tier1,
    apply_tier3,
    parse_tiers,
    verify_snapshot,
)
from devin_janitor.config import JanitorConfig
from devin_janitor.execute import (
    apply_deletions,
    devin_running,
    load_pending,
    remove_orphan_locks,
    retry_pending,
    save_pending,
    vacuum_if_safe,
)
from devin_janitor.exporter import ExportError, run_export
from devin_janitor.inventory import (
    SessionRow,
    live_session_ids,
    load_inventory,
)
from devin_janitor.judge import Verdict, make_judge
from devin_janitor.notify import resolve_notify_cmd, send_notification
from devin_janitor.paths import resolve
from devin_janitor.reap import (
    DEFAULT_STATE_FILE,
    ProcFsTable,
    _redact,
    append_ledger,
    load_reap_state,
    reap,
    render,
    save_reap_state,
    scan,
)
from devin_janitor.report import (
    append_log,
    audit_entry,
    fmt_bytes,
    parse_horizon,
    plan_summary,
    render_space_report,
    run_summary,
    space_report,
)
from devin_janitor.tiers import (
    classify,
    devin_artifacts_payload,
    load_keep_file,
)

DEFAULT_KEEP_FILE = ".devin/janitor-keep.json"
DEFAULT_PENDING_FILE = ".devin/janitor-pending.json"
DEFAULT_LOG_FILE = ".devin/memory/janitor-log.jsonl"
DEFAULT_REAP_LEDGER = ".devin/memory/janitor-reap-ledger.jsonl"
DEFAULT_DEVIN_DIR = ".devin"


def _row_json(row: SessionRow, tier: str, reason: str) -> dict:
    d = asdict(row)
    d["tier"] = tier
    d["reason"] = reason
    return d


def _add_path_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--data-dir", help="Devin data root (overrides autodetect)")
    p.add_argument("--config-dir", help="Devin UI config root (overrides autodetect)")
    p.add_argument("--sessions-db", help="explicit path to sessions.db")
    p.add_argument("--acp-dir", help="explicit acp-messages directory")
    p.add_argument("--locks-dir", help="explicit session_locks directory")


def _add_devin_dir_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--devin-dir", default=DEFAULT_DEVIN_DIR,
                   help=".devin/ runtime-state dir to classify "
                        f"(default: {DEFAULT_DEVIN_DIR})")


def _resolve(args: argparse.Namespace):
    return resolve(
        data_dir=args.data_dir,
        config_dir=args.config_dir,
        sessions_db=args.sessions_db,
        acp_messages_dir=args.acp_dir,
        session_locks_dir=args.locks_dir,
    )


def _judge_sessions(
    spec: str, candidates: list[SessionRow], statement: str
) -> tuple[list[tuple[SessionRow, str]], list[SessionRow], int, str]:
    """Run the judge over JUDGE-tier rows.

    Returns ``(judged_delete, judged_keep, judge_down, judge_name)``.
    Fail-open: abstentions and unavailability keep sessions.
    """
    judge = make_judge(spec)
    name = judge.name
    if not candidates:
        judge.close()
        return [], [], 0, name
    if not judge.available():
        judge.close()
        return [], [], len(candidates), name
    judged_delete, judged_keep = [], []
    try:
        for row in candidates:
            verdict: Verdict = judge.judge(row, statement)
            if verdict.keep is False:
                judged_delete.append(
                    (row, f"judge: no durable knowledge ({verdict.reason})")
                )
            else:
                judged_keep.append(row)
    finally:
        judge.close()
    return judged_delete, judged_keep, 0, name


def _classification_payload(
    rows: list[SessionRow],
    classification,
    judged_keep: list[SessionRow],
    judged_delete: list[tuple[SessionRow, str]],
    judge_down_ids: set[str],
) -> dict:
    kept_ids = set(classification.kept)
    return {
        "total": len(rows),
        "tiers": {
            "keep": [
                _row_json(r, "keep", classification.kept[r.id])
                for r in rows
                if r.id in kept_ids
            ],
            "auto_delete": [
                _row_json(r, "auto_delete", why)
                for r, why in classification.auto_delete
            ],
            "judge": {
                "delete": [
                    _row_json(r, "judge", why) for r, why in judged_delete
                ],
                "keep": [_row_json(r, "keep", "judged useful")
                         for r in judged_keep],
                "unresolved": [
                    _row_json(r, "judge", "judge unavailable")
                    for r in classification.judge
                    if r.id in judge_down_ids
                ],
            },
        },
    }


# ------------------------------------------------------------------ scan --


def cmd_scan(args: argparse.Namespace) -> int:
    paths = _resolve(args)
    cfg = JanitorConfig.load(args.config)
    if args.grace_hours is not None:
        cfg.grace_hours = args.grace_hours
    keep_ids, keep_patterns = load_keep_file(args.keep_file)

    rows = load_inventory(paths)
    classification = classify(
        rows, cfg, keep_ids=keep_ids, keep_patterns=keep_patterns
    )
    # .devin/ artifacts: unreadable/malformed paths raise here — loud,
    # not silently skipped (absence is fine, yields an empty listing)
    artifacts = devin_artifacts_payload(args.devin_dir)

    if args.json:
        payload = _classification_payload(
            rows, classification, [], [],
            {r.id for r in classification.judge},
        )
        payload["devin_artifacts"] = artifacts
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print(f"{len(rows)} sessions · grace {cfg.grace_hours:.0f}h")
    for tier_name, items in (
        ("keep", [(r, classification.kept[r.id])
                  for r in rows if r.id in classification.kept]),
        ("auto_delete", classification.auto_delete),
        ("judge", [(r, "ambiguous — needs judge") for r in classification.judge]),
    ):
        print(f"  {tier_name}: {len(items)}")
        if args.verbose:
            for r, why in items:
                print(f"    {r.id[:40]:40} {why:42} {r.title[:50]}")
    if not artifacts["exists"]:
        print(f"  .devin: missing ({artifacts['dir']})")
    else:
        t = artifacts["by_tier"]
        print(
            f"  .devin: {artifacts['total']} artifacts · "
            f"keep {t['keep']} · auto_delete {t['auto_delete']} · "
            f"judge {t['judge']}"
        )
        if args.verbose:
            for a in artifacts["artifacts"]:
                print(
                    f"    {a['rel_path'][:48]:48} {a['tier']:11} "
                    f"{a['reason']:38} {fmt_bytes(a['bytes'])}"
                )
    return 0


# ------------------------------------------------------------------- run --


def cmd_run(args: argparse.Namespace) -> int:
    """Run the pipeline, then notify (``--notify-cmd``/env, fail-open).

    ``summary`` is populated by ``_run_pipeline`` as values become known
    and shipped to the notify command with the run's ``rc`` — so a failed
    run notifies too, with whatever was learned before the abort.
    """
    summary = {
        "apply": bool(args.apply),
        "total": 0,
        "planned": 0,
        "deleted": 0,
        "retained": 0,
        "pending": 0,
    }
    try:
        rc = _run_pipeline(args, summary)
    except (ValueError, RuntimeError, OSError,
            subprocess.CalledProcessError) as exc:
        # the same error conversion main() applies — done here so the
        # notification below still ships the real rc
        print(f"error: {exc}", file=sys.stderr)
        rc = 2
    send_notification(
        resolve_notify_cmd(args.notify_cmd), {**summary, "rc": rc}
    )
    return rc


def _run_pipeline(args: argparse.Namespace, summary: dict) -> int:
    paths = _resolve(args)
    cfg = JanitorConfig.load(args.config)
    if args.grace_hours is not None:
        cfg.grace_hours = args.grace_hours
    if args.max_delete is not None:
        cfg.max_delete = args.max_delete
    tiers = parse_tiers(args.tiers)  # ValueError → rc 2 via main()
    keep_ids, keep_patterns = load_keep_file(args.keep_file)
    pending = load_pending(args.pending_file)
    summary["pending"] = len(pending)

    if not paths.sessions_db.is_file() and tiers & {TIER1, TIER2}:
        print(f"error: no sessions.db at {paths.sessions_db}", file=sys.stderr)
        return 1

    rows = load_inventory(paths)
    summary["total"] = len(rows)
    classification = classify(
        rows, cfg, keep_ids=keep_ids, keep_patterns=keep_patterns
    )

    judged_delete, judged_keep, judge_down, judge_name = _judge_sessions(
        args.judge, classification.judge, cfg.judge_statement
    )
    if judge_down:
        print(
            f"judge unavailable — {judge_down} ambiguous session(s) kept "
            "(fail-open)."
        )

    targets = (
        (classification.auto_delete + judged_delete)[: cfg.max_delete]
        if TIER2 in tiers
        else []
    )
    summary["planned"] = len(targets)
    # sessions this run leaves alone: keepers plus deletes outside the
    # selected --tiers / --max-delete cap (they stay on disk either way)
    summary["retained"] = len(rows) - len(targets)
    n_auto = min(len(classification.auto_delete), len(targets))

    print(
        plan_summary(
            apply=args.apply,
            total=len(rows),
            grace_hours=cfg.grace_hours,
            classification=classification,
            judged_keep=judged_keep,
            judged_delete=judged_delete,
            judge_down=judge_down,
            targets=targets,
        )
    )
    if TIER3 in tiers:
        print(
            "  tier3 (gui state in state.vscdb): gated — needs "
            "--include-gui + a verified --snapshot manifest (<24h old)"
        )

    if not args.apply:
        return 0

    # 0. tier3 gate — every check runs before the first write
    if TIER3 in tiers:
        if not args.include_gui:
            print(
                "error: tier3 deletes GUI session state — pass "
                "--include-gui to confirm",
                file=sys.stderr,
            )
            return 2
        snap = verify_snapshot(args.snapshot)
        if not snap["ok"]:
            print(
                f"error: tier3 refused — {snap['reason']}",
                file=sys.stderr,
            )
            return 4
        if devin_running():
            print(
                "error: tier3 refused — Devin appears to be running; "
                "state.vscdb is only written when the GUI is closed",
                file=sys.stderr,
            )
            return 4

    # 1. export first — abort before deleting if the hook fails
    try:
        if args.export_cmd and targets:
            print("\n== export ==")
            run_export(args.export_cmd)
    except ExportError as exc:
        print(f"export failed — aborting: {exc}", file=sys.stderr)
        return 3

    # 2. tier2: session deletions (skipped when tier2 not selected)
    stats = {"cli_rows": 0, "gui_sessions": 0, "still_locked": len(pending)}
    if targets:
        print("== delete ==")
        stats = apply_deletions(paths, targets, pending)
        summary["deleted"] = stats["sessions"]
        summary["pending"] = len(pending)

    # 3. tier1: orphan rows + dead-session leftovers + orphan locks;
    #    vacuum reclaims the sidecars (only when Devin is closed)
    tier1_stats = None
    orphan = 0
    vacuumed = False
    if TIER1 in tiers:
        live = live_session_ids(paths)
        tier1_stats = apply_tier1(paths, live, skip=set(pending))
        orphan = remove_orphan_locks(paths, live)
        vacuumed = vacuum_if_safe(paths)

    # 4. tier3: stale GUI session-state keys (gates already verified)
    tier3_stats = None
    if TIER3 in tiers:
        try:
            tier3_stats = apply_tier3(
                paths,
                stale_before=time.time() - cfg.grace_hours * 3600,
                include_gui=True,
                snapshot=args.snapshot,
            )
        except CleanupRefused as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 4

    # 5. audit log + pending queue
    entry = audit_entry(
        deleted=targets[:n_auto],
        judged_keep=judged_keep,
        judged_delete=targets[n_auto:],
        judge_name=judge_name,
        judge_down=judge_down,
        pending_locked=list(pending),
        orphan_locks_removed=orphan,
        vacuumed=vacuumed,
    )
    entry["tiers"] = sorted(tiers)
    if tier1_stats:
        entry["tier1"] = tier1_stats
    if tier3_stats is not None:
        entry["tier3"] = tier3_stats
    append_log(args.log_file, entry)
    save_pending(args.pending_file, pending)

    print()
    print(
        run_summary(
            cli_rows=stats["cli_rows"],
            gui_sessions=stats["gui_sessions"],
            orphan_locks=orphan,
            pending=len(pending),
            vacuumed=vacuumed,
        )
    )
    if tier1_stats:
        print(
            f"tier1: {tier1_stats['orphan_rows']} orphan rows · "
            f"{tier1_stats['leftover_files']} leftover files"
        )
    if tier3_stats:
        print(
            f"tier3: {tier3_stats['keys']} gui state keys removed "
            f"(snapshot {tier3_stats['snapshot']})"
        )
    return 0


# --------------------------------------------------------------- pending --


def cmd_pending(args: argparse.Namespace) -> int:
    pending = load_pending(args.pending_file)
    if args.retry:
        paths = _resolve(args)
        retry_pending(paths.acp_messages_dir, pending)
        save_pending(args.pending_file, pending)
        print(f"retried; still pending: {len(pending)}")
        return 0
    if not pending:
        print("no pending deletions")
        return 0
    print(json.dumps(pending, indent=1))
    return 0


# --------------------------------------------------------------- reap ----


def _cap_log_size(path: str | Path, max_bytes: int = 256 * 1024) -> None:
    """Keep the reap audit log under ``max_bytes`` — the 3-min timer
    runs ~480 sweeps/day and a noisy detector would grow it forever.
    Rotation keeps the newest entries (the tail)."""
    p = Path(path)
    try:
        if p.stat().st_size <= max_bytes:
            return
        tail = p.read_bytes()[-max_bytes:]
        nl = tail.find(b"\n")
        p.write_bytes(tail[nl + 1:] if nl >= 0 else tail)
    except OSError:
        pass


def cmd_reap(args: argparse.Namespace) -> int:
    """Reap runaway orphan processes (Linux only; dry-run default).

    Destructive path is gated four ways: same-UID only (root refuses
    outright), attribution to a dead Devin session via procmap, grace
    tracked across runs, and a max_kill circuit breaker. A
    ``reap.disabled`` kill-switch file next to the state file makes
    every sweep a no-op before any /proc work.
    """
    if not sys.platform.startswith("linux"):
        print("error: 'reap' is Linux-only (reads /proc)", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("error: 'reap' refuses to run as root", file=sys.stderr)
        return 2
    disable_file = (
        Path(args.disable_file) if args.disable_file
        else Path(args.state_file).parent / "reap.disabled"
    )
    if disable_file.exists():
        print(f"reap disabled by {disable_file} — sweep skipped")
        return 0
    paths = _resolve(args)
    state = load_reap_state(args.state_file)
    table = ProcFsTable()
    res = scan(
        table,
        locks_dir=paths.session_locks_dir,
        sessions_db=paths.sessions_db,
        state=state,
        grace_min=args.grace_min,
        cpu_pct=args.cpu_pct,
        sample_sec=args.sample_sec,
        max_kill=args.max_kill,
    )
    if args.apply and res.candidates:
        killed = reap(table, res.candidates, term_wait=args.term_wait)
        res.killed, res.survivors = killed.killed, killed.survivors
    save_reap_state(args.state_file, state)
    # decisions go to the dedicated append-only ledger (≥30d retention)
    # — the calibration evalset must survive log rotation; the capped
    # shared log keeps only the sweep summary
    now = int(time.time())
    decisions = res.candidates if not args.apply else res.killed
    append_ledger(args.ledger_file, [
        {"ts": now, "decision": "would_kill" if not args.apply else "killed",
         "pid": c.proc.pid,
         "starttime": c.proc.starttime,
         "comm": c.proc.comm,
         "cmdline": _redact(c.proc.cmdline)[:200],
         "session": c.session_slug,
         "cpu_pct": round(c.cpu_pct, 1),
         "age_s": int(c.proc.age_s),
         "reason": c.reason}
        for c in decisions
    ] + [
        {"ts": now, "decision": "survivor", "pid": pid}
        for pid in res.survivors
    ] + (
        [{"ts": now, "decision": "circuit_tripped",
          "eligible": len(res.skipped)}] if res.circuit else []
    ))
    if res.candidates or res.killed or res.survivors or res.circuit:
        _cap_log_size(args.log_file)
        append_log(args.log_file, {
            "ts": now,
            "kind": "reap",
            "apply": bool(args.apply),
            "scanned": res.scanned,
            "orphans": res.orphans,
            "attributed": res.attributed,
            "eligible": len(res.candidates),
            "killed": len(res.killed),
            "survivors": len(res.survivors),
            "circuit": res.circuit,
        })
    if args.json:
        payload = {
            "apply": bool(args.apply),
            "scanned": res.scanned,
            "orphans": res.orphans,
            "attributed": res.attributed,
            "attribution_ok": res.attribution_ok,
            "circuit": res.circuit,
            "candidates": [
                {"pid": c.proc.pid, "comm": c.proc.comm,
                 "cmdline": _redact(c.proc.cmdline),
                 "session": c.session_slug,
                 "cpu_pct": c.cpu_pct, "age_s": c.proc.age_s,
                 "reason": c.reason}
                for c in res.candidates
            ],
            "skipped": [
                {"pid": p.pid, "comm": p.comm, "reason": why}
                for p, why in res.skipped
            ],
            "killed": [c.proc.pid for c in res.killed],
            "survivors": res.survivors,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render(res, apply=args.apply))
    return 0


# --------------------------------------------------------------- report --


def cmd_report(args: argparse.Namespace) -> int:
    paths = _resolve(args)
    # parse before anything else: an invalid horizon exits 2 instead of
    # printing a report built on a silently ignored projection request
    project_days = (
        parse_horizon(args.project) if args.project is not None else None
    )
    cfg = JanitorConfig.load(args.config)
    if args.grace_hours is not None:
        cfg.grace_hours = args.grace_hours
    keep_ids, keep_patterns = load_keep_file(args.keep_file)
    pending = load_pending(args.pending_file)

    extra_ids = set(pending)
    if args.judge != "none":
        try:
            rows = load_inventory(paths)
            cls = classify(
                rows, cfg, keep_ids=keep_ids, keep_patterns=keep_patterns
            )
            judged_delete, _, _, _ = _judge_sessions(
                args.judge, cls.judge, cfg.judge_statement
            )
            extra_ids.update(r.id for r, _ in judged_delete)
        except (SchemaError, sqlite3.Error, OSError):
            pass  # advisory — recoverable estimate just stays conservative

    try:
        rep = space_report(
            paths,
            cfg,
            keep_ids=keep_ids,
            keep_patterns=keep_patterns,
            extra_delete_ids=extra_ids,
            labels_path=args.labels_file,
            exclude_labeled=args.exclude_labeled,
            project_days=project_days,
            devin_dir=args.devin_dir,
        )
    except Exception as exc:  # noqa: BLE001 - advisory — must never fail the command
        rep = {
            "stores": [],
            "totals": {"bytes": 0, "recoverable_bytes": 0},
            "classification": None,
            "classification_error": str(exc),
        }
    if args.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
    else:
        print(render_space_report(rep))
    return 0


# --------------------------------------------------------------- install --


def cmd_install(args: argparse.Namespace) -> int:
    """JA-1 — register the daily ``report`` job (F6 scheduling pattern).

    ``--daily`` is mandatory and the only schedule offered: the job runs
    ``devin-janitor report`` (read-only). Deletion is never scheduled —
    ``--apply`` stays a manual, reviewed decision.
    """
    if not args.daily:
        print(
            "error: 'install' only schedules the daily report job — "
            "pass --daily (only 'report' is ever scheduled; --apply stays "
            "manual)",
            file=sys.stderr,
        )
        return 2
    from devin_janitor.install import install_daily
    result = install_daily(config_dir=args.config_dir,
                           backend=args.backend)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"installed '{result['job']}' [{result['backend']}]")
        print(f"  command: {result['command']}")
        print(f"  registry: {result['registry']}")
        if result["backend"] == "elapsed":
            print(
                "  elapsed backend: add 'python tools/schedule.py check "
                "--run' to a UserPromptSubmit hook (see devin-powerups "
                "README)"
            )
    return 0


# ------------------------------------------------------------------ main --


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devin-janitor",
        description=(
            "Session lifecycle janitor for Devin: export first, classify in "
            "tiers, delete only the safe tiers, retry locked files, vacuum "
            "only when Devin is closed."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="classification preview")
    _add_path_args(p)
    _add_devin_dir_arg(p)
    p.add_argument("--config", help="JSON config overriding tier rules")
    p.add_argument("--keep-file", default=DEFAULT_KEEP_FILE)
    p.add_argument("--grace-hours", type=float, default=None)
    p.add_argument("--json", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("run", help="the pipeline (dry-run without --apply)")
    _add_path_args(p)
    p.add_argument("--apply", action="store_true",
                   help="execute (default is dry-run)")
    p.add_argument("--tiers", default=None,
                   help="cleanup tiers to apply: '1,2' (default), "
                        "'1', '2', '3', 'all' — tier3 is always opt-in")
    p.add_argument("--include-gui", action="store_true",
                   help="allow tier3 to touch state.vscdb (requires "
                        "--snapshot too)")
    p.add_argument("--snapshot", default=None,
                   help="devin-backup snapshot dir/manifest <24h old — "
                        "required for tier3")
    p.add_argument("--config", help="JSON config overriding tier rules")
    p.add_argument("--grace-hours", type=float, default=None)
    p.add_argument("--max-delete", type=int, default=None)
    p.add_argument("--judge", default="none",
                   help="none|devin-judge[:<bin>]|command:<cmd>")
    p.add_argument("--export-cmd", default=None,
                   help="shell command run BEFORE any deletion; "
                        "non-zero exit aborts the run")
    p.add_argument("--notify-cmd", default=None,
                   help="shell command run AFTER the run, receiving the "
                        "run summary as JSON on stdin (env: "
                        "JANITOR_NOTIFY_CMD when the flag is absent); "
                        "fail-open — notify errors warn, never fail")
    p.add_argument("--keep-file", default=DEFAULT_KEEP_FILE)
    p.add_argument("--pending-file", default=DEFAULT_PENDING_FILE)
    p.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("pending", help="locked-files retry queue")
    _add_path_args(p)
    p.add_argument("--pending-file", default=DEFAULT_PENDING_FILE)
    p.add_argument("--list", action="store_true", help="list queue (default)")
    p.add_argument("--retry", action="store_true",
                   help="retry queued gui-file deletions")
    p.set_defaults(func=cmd_pending)

    p = sub.add_parser(
        "reap",
        help="reap runaway orphan processes (dry-run without --apply)",
    )
    _add_path_args(p)
    p.add_argument("--apply", action="store_true",
                   help="TERM then KILL eligible orphans (default: dry-run)")
    p.add_argument("--grace-min", type=float, default=10.0,
                   help="minutes a proc must stay orphaned before it's "
                        "eligible (default: 10)")
    p.add_argument("--cpu-pct", type=float, default=30.0,
                   help="minimum sampled CPU%% to count as runaway "
                        "(default: 30)")
    p.add_argument("--sample-sec", type=float, default=2.0,
                   help="CPU sampling window in seconds (default: 2)")
    p.add_argument("--term-wait", type=float, default=3.0,
                   help="seconds to wait after SIGTERM before SIGKILL "
                        "(default: 3)")
    p.add_argument("--max-kill", type=int, default=5,
                   help="circuit breaker: if eligible candidates exceed "
                        "this, kill NOTHING (default: 5)")
    p.add_argument("--state-file", default=DEFAULT_STATE_FILE,
                   help="orphan first-seen + attribution tracker "
                        f"(default: {DEFAULT_STATE_FILE})")
    p.add_argument("--ledger-file", default=DEFAULT_REAP_LEDGER,
                   help="append-only would_kill/killed decision ledger, "
                        f"30-day retention (default: {DEFAULT_REAP_LEDGER})")
    p.add_argument("--disable-file", default=None,
                   help="kill-switch path — presence skips every sweep "
                        "(default: reap.disabled next to --state-file)")
    p.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_reap)

    p = sub.add_parser(
        "report", help="recoverable-space report (advisory, read-only)"
    )
    _add_path_args(p)
    _add_devin_dir_arg(p)
    p.add_argument("--config", help="JSON config overriding tier rules")
    p.add_argument("--keep-file", default=DEFAULT_KEEP_FILE)
    p.add_argument("--pending-file", default=DEFAULT_PENDING_FILE)
    p.add_argument("--grace-hours", type=float, default=None)
    p.add_argument("--judge", default="none",
                   help="none|devin-judge[:<bin>]|command:<cmd>")
    p.add_argument("--labels-file", default=None,
                   help="bridge session-labels.json override "
                        "(default: bridge state dir)")
    p.add_argument("--exclude-labeled", action="store_true",
                   help="exclude bridge-labeled automatic sessions from "
                        "the classification")
    p.add_argument("--project", default=None, metavar="N[h|d|w]",
                   help="project each store's size N ahead (e.g. 90d, "
                        "12w, 720h) at the observed accumulation rate — "
                        "estimate only; stores without enough history "
                        "report 'insufficient data'")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser(
        "install", help="schedule a daily 'report' job "
        "(cron / Task Scheduler / elapsed hook — F6, opt-in)"
    )
    p.add_argument("--daily", action="store_true",
                   help="register the daily 'devin-janitor report' job "
                        "(required; only reporting is ever scheduled)")
    p.add_argument("--config-dir", help="Devin config dir override "
                   "(where .devin-ecosystem/scheduled.json lives)")
    p.add_argument("--backend", default="auto",
                   choices=["auto", "tasksch", "cron", "elapsed"])
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_install)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, RuntimeError, OSError,
            subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
