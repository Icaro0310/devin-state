"""Thin CLI wrapper — all logic lives in the library modules."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__, cflite, engine, paths, publish, session_end, staged
from .sarif import report_to_sarif


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devin-redact",
        description="Secret and PII redaction that understands Devin tool-call "
        "semantics (unofficial).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_target_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("paths", nargs="+", type=Path, help="files or directories to inspect")
        p.add_argument("--report", type=Path, default=None, help="also write the JSON report to this file")

    scan_p = sub.add_parser("scan", help="read-only scan, prints a JSON report")
    _add_target_args(scan_p)
    scan_p.add_argument(
        "--format",
        choices=("json", "sarif"),
        default="json",
        help="output format (sarif = SARIF 2.1.0 for CI/code-scanning ingestion)",
    )

    redact_p = sub.add_parser("redact", help="redact findings (dry-run by default)")
    _add_target_args(redact_p)
    redact_p.add_argument("--apply", action="store_true", help="actually write redactions")
    redact_p.add_argument(
        "--i-know-this-is-irreversible",
        action="store_true",
        help="required with --apply (long flag, on purpose)",
    )

    verify_p = sub.add_parser("verify", help="publication gate — non-zero exit unless CLEAN")
    verify_p.add_argument("paths", nargs="+", type=Path, help="files or directories to verify")
    verify_p.add_argument("--json", action="store_true", help="print the full JSON report")

    gate_p = sub.add_parser(
        "gate",
        help="machine gate — prints just CLEAN/REVIEW/BLOCKED; "
        "exits 0 for CLEAN/REVIEW, 1 for BLOCKED, 2 on error",
    )
    gate_p.add_argument("paths", nargs="+", type=Path, help="files or directories to gate")
    gate_p.add_argument(
        "--staged",
        action="store_true",
        help="scan each path's staged index blob (git :0:<path>) instead "
        "of the working-tree file — the pre-commit mode, so edits or "
        "deletions after `git add` cannot bypass the gate",
    )

    hook_p = sub.add_parser(
        "sessionend-scan",
        help="SessionEnd hook handler — read-only scan of the default "
        "sessions.db, prints one compact verdict line, exits 0 "
        "unless a hard error occurs",
    )
    hook_p.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=None,
        help="sessions.db to scan (default: auto-detect Devin's store)",
    )
    hook_p.add_argument(
        "--session-id",
        default=None,
        help="restrict the scan to this session's rows — the bounded "
        "mode for a SessionEnd handler that knows which session ended",
    )

    se_p = sub.add_parser(
        "session-end",
        help="SessionEnd hook — resolve the just-ended session, scan its "
        "messages and write a verdict side file (fail-soft, exits 0 "
        "even on SKIPPED/BLOCKED)",
    )
    se_p.add_argument(
        "--session-id",
        default=None,
        help="session to scan (default: {\"session_id\": …} on stdin, then "
        "DEVIN_SESSION_ID, then the most recently active session)",
    )
    se_p.add_argument(
        "--sessions-db",
        type=Path,
        default=None,
        help="sessions.db to read (default: auto-detect Devin's store)",
    )
    se_p.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Devin data root for side files (default: the resolved "
        "store's root or DEVIN_REDACT_DATA_DIR)",
    )
    se_p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="verdict side file (default: <data-dir>/redact/<session-id>.json)",
    )
    se_p.add_argument(
        "--json",
        action="store_true",
        help="also print the verdict JSON to stdout",
    )

    vp_p = sub.add_parser(
        "verify-publish",
        help="gate a devin-history export dir — non-zero exit unless "
        "every exported session scans CLEAN",
    )
    vp_p.add_argument("export_dir", type=Path, help="devin-history export directory")
    vp_p.add_argument(
        "--verdicts-dir",
        type=Path,
        default=None,
        help="dir of session-end verdict side files to cross-reference "
        "(default: <data-dir>/redact)",
    )
    vp_p.add_argument("--json", action="store_true", help="print the full JSON report")

    cf_p = sub.add_parser(
        "cflite-promote",
        help="promote ClusterFuzzLite minimized crashes into the fuzz "
        "regression corpus — dedups by sha256 and records provenance "
        "in the corpus manifest",
    )
    cf_src = cf_p.add_mutually_exclusive_group(required=True)
    cf_src.add_argument(
        "--crashes-dir",
        type=Path,
        default=None,
        help="directory of (already unpacked) crash artifacts — the "
        "offline path; files are discovered recursively",
    )
    cf_src.add_argument(
        "--run-id",
        default=None,
        help="GitHub Actions run id — crash artifacts are fetched with "
        "`gh run download` first",
    )
    cf_p.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="NAME",
        help="restrict a --run-id download to this artifact name; "
        "repeatable (requires --run-id)",
    )
    cf_p.add_argument(
        "--corpus-dir",
        type=Path,
        default=None,
        help="regression corpus dir (default: <package>/fuzz/corpus, or "
        "DEVIN_REDACT_CFLITE_CORPUS)",
    )
    cf_p.add_argument(
        "--max-bytes",
        type=int,
        default=cflite.MAX_CRASH_BYTES,
        help="size cap for a minimized reproducer (default: %(default)s)",
    )
    cf_p.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be promoted; write nothing",
    )
    cf_p.add_argument("--json", action="store_true", help="print the full JSON report")
    return parser


def _blocking_errors(report: dict) -> list[dict]:
    """Errors meaning a target could not be scanned at all.

    ``skipped: binary file`` entries are informational — the scan still
    covered everything else — so they never count as hard errors.
    """
    return [
        e
        for e in report.get("errors", [])
        if not str(e.get("error", "")).startswith("skipped:")
    ]


def _emit(report: dict, report_path: Path | None) -> None:
    blob = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True)
    print(blob)
    if report_path is not None:
        report_path.write_text(blob + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        report = engine.scan(args.paths)
        _emit(report_to_sarif(report) if args.format == "sarif" else report, args.report)
        return 0

    if args.command == "redact":
        if args.apply and not args.i_know_this_is_irreversible:
            print(
                "devin-redact: --apply requires --i-know-this-is-irreversible",
                file=sys.stderr,
            )
            return 3
        try:
            result = engine.redact(
                args.paths,
                apply=args.apply,
                confirm_irreversible=args.i_know_this_is_irreversible,
            )
        except RuntimeError as exc:
            print(f"devin-redact: {exc}", file=sys.stderr)
            return 3
        _emit(result, args.report)
        return 0 if result.get("applied_ok", True) else 1

    if args.command == "verify":
        report = engine.scan(args.paths)
        if args.json:
            _emit(report, None)
        else:
            print(f"PUBLICATION STATUS: {report['publication_status']}")
            print(
                f"{report['files_scanned']} file(s) scanned, "
                f"{report['findings_total']} finding(s) "
                f"({report['secrets']} secret-class)"
            )
            for cat, n in report["by_category"].items():
                print(f"  {cat}: {n}")
        return 0 if report["publication_status"] == "CLEAN" else 1

    if args.command == "gate":
        if args.staged:
            try:
                blobs, errs = staged.staged_blobs(args.paths)
            except staged.StagedScanError as exc:
                print(f"devin-redact: {exc}", file=sys.stderr)
                return 2
            report = engine.scan_blobs(blobs, errors=errs)
        else:
            report = engine.scan(args.paths)
        hard = _blocking_errors(report)
        if hard:
            for e in hard:
                print(f"devin-redact: {e['file']}: {e['error']}", file=sys.stderr)
            return 2
        status = str(report["publication_status"])
        print(status)
        return 1 if status == "BLOCKED" else 0

    if args.command == "sessionend-scan":
        target = args.path if args.path is not None else paths.default_sessions_db()
        if args.path is not None and not args.path.is_file():
            print(f"devin-redact: not a file: {args.path}", file=sys.stderr)
            return 2
        if target is None:
            # No sessions.db on this machine — nothing to scan; a hook
            # must not fail over that, so the verdict is CLEAN.
            print("devin-redact: findings=0 publication_status=CLEAN")
            return 0
        if args.session_id:
            report = engine.scan_session(target, args.session_id)
        else:
            report = engine.scan([target])
        hard = _blocking_errors(report)
        if hard:
            for e in hard:
                print(f"devin-redact: {e['file']}: {e['error']}", file=sys.stderr)
            return 2
        print(
            f"devin-redact: findings={report['findings_total']} "
            f"publication_status={report['publication_status']}"
        )
        return 0

    if args.command == "session-end":
        if args.sessions_db is not None and not args.sessions_db.is_file():
            print(
                f"devin-redact: not a file: {args.sessions_db}", file=sys.stderr
            )
            return 2
        stdin_text = None
        if args.session_id is None and not sys.stdin.isatty():
            try:
                stdin_text = sys.stdin.read(session_end._STDIN_CAP) or None
            except OSError:
                stdin_text = None
        verdict = session_end.run_hook(
            session_id=args.session_id,
            sessions_db=args.sessions_db,
            data_dir=args.data_dir,
            out=args.out,
            stdin_text=stdin_text,
        )
        if args.json:
            _emit(verdict, None)
        else:
            print(
                f"devin-redact: session={verdict['session_id'] or '?'} "
                f"publication_status={verdict['publication_status']} "
                f"verdict={verdict['verdict_file']}"
            )
            if verdict.get("reason"):
                print(f"devin-redact: {verdict['reason']}", file=sys.stderr)
        # Fail-soft: SKIPPED and even BLOCKED still exit 0 — a SessionEnd
        # hook must never block session teardown.
        return 0

    if args.command == "verify-publish":
        if not args.export_dir.is_dir():
            print(
                f"devin-redact: not a directory: {args.export_dir}",
                file=sys.stderr,
            )
            return 2
        report = publish.verify_publish(
            args.export_dir, verdicts_dir=args.verdicts_dir
        )
        if args.json:
            _emit(report, None)
        else:
            print(f"PUBLICATION STATUS: {report['publication_status']}")
            print(
                f"{report['sessions_total']} exported session(s): "
                f"{report['sessions_clean']} clean, "
                f"{report['sessions_review']} review, "
                f"{report['sessions_blocked']} blocked"
            )
            for s in report["sessions"]:
                if s["publication_status"] != "CLEAN":
                    print(
                        f"  {s['publication_status']}: {s['file']} "
                        f"(session {s['session_id'] or '?'}) — "
                        f"{s['findings_total']} finding(s)"
                    )
            for w in report["warnings"]:
                print(f"  warning: {w}")
        return 0 if report["publication_status"] == "CLEAN" else 1

    if args.command == "cflite-promote":
        if args.artifact and args.run_id is None:
            print(
                "devin-redact: --artifact requires --run-id",
                file=sys.stderr,
            )
            return 2
        if args.max_bytes < 1:
            print(
                "devin-redact: --max-bytes must be a positive integer",
                file=sys.stderr,
            )
            return 2
        corpus_dir = (
            args.corpus_dir
            if args.corpus_dir is not None
            else cflite.default_corpus_dir()
        )
        tmp = None
        crashes_dir = args.crashes_dir
        if args.run_id is not None:
            tmp = tempfile.TemporaryDirectory(prefix="devin-redact-cflite-")
            crashes_dir = Path(tmp.name)
            try:
                cflite.download_run_artifacts(
                    args.run_id, crashes_dir, names=args.artifact
                )
            except cflite.CfliteError as exc:
                print(f"devin-redact: {exc}", file=sys.stderr)
                tmp.cleanup()
                return 2
        try:
            if not crashes_dir.is_dir():
                print(
                    f"devin-redact: not a directory: {crashes_dir}",
                    file=sys.stderr,
                )
                return 2
            report = cflite.promote(
                crashes_dir,
                corpus_dir,
                run_id=args.run_id,
                max_bytes=args.max_bytes,
                dry_run=args.dry_run,
            )
        except OSError as exc:
            print(f"devin-redact: {exc}", file=sys.stderr)
            return 2
        finally:
            if tmp is not None:
                tmp.cleanup()
        if args.json:
            _emit(report, None)
        else:
            print(
                f"devin-redact: candidates={report['candidates']} "
                f"promoted={len(report['promoted'])} "
                f"duplicates={len(report['duplicates'])} "
                f"rejected={len(report['rejected'])} "
                f"corpus={report['corpus_dir']}"
                + (" (dry-run)" if report["dry_run"] else "")
            )
            for p in report["promoted"]:
                print(f"  promoted: {p['file']} <- {p['source']} ({p['size']} bytes)")
            for d in report["duplicates"]:
                print(f"  duplicate: {d['source']} ({d['detail']})")
            for r in report["rejected"]:
                print(f"  rejected: {r['source']} ({r['reason']})")
            for w in report["warnings"]:
                print(f"devin-redact: warning: {w}", file=sys.stderr)
        for e in report["errors"]:
            print(f"devin-redact: {e['file']}: {e['error']}", file=sys.stderr)
        return 1 if (report["rejected"] or report["errors"]) else 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
