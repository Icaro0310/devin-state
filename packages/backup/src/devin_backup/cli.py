"""Thin CLI wrapper — all logic lives in the library modules."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from devin_backup import (
    __version__,
    diff,
    restore,
    rotate,
    smoke,
    snapshot,
    verify,
)
from devin_backup.stores import (
    DataDirError,
    default_backups_dir,
    default_config_dir,
    default_data_dir,
)


def _resolve_dirs(args) -> tuple[Path, Path]:
    data_dir = (
        Path(args.data_dir).expanduser()
        if getattr(args, "data_dir", None)
        else default_data_dir()
    )
    out = (
        Path(args.out).expanduser()
        if getattr(args, "out", None)
        else default_backups_dir(data_dir)
    )
    return data_dir, out


def _cmd_create(args) -> int:
    if args.move and not args.remote:
        print("error: --move only makes sense with --remote",
              file=sys.stderr)
        return 2
    data_dir, out = _resolve_dirs(args)
    config_dir = args.config_dir
    if config_dir is None and args.data_dir is None:
        config_dir = default_config_dir()
    snap = snapshot.create_snapshot(
        data_dir, out, config_dir=config_dir,
        exclude=tuple(args.exclude or ()),
        exclude_secrets=args.exclude_secrets,
    )
    manifest = snapshot.load_manifest(snap)
    total = sum(f.get("size", 0) for f in manifest["files"])
    print(f"created snapshot: {snap}")
    print(f"  {len(manifest['files'])} file(s), {total} bytes")
    for entry in manifest.get("excluded", []):
        print(f"  excluded: {entry['path']}")
    for rel, version in manifest["schema_versions"].items():
        print(f"  {rel}: schema v{version}")
    for entry in manifest["files"]:
        if entry["copied_via"] != "sqlite-backup" and entry["kind"] == "sqlite":
            print(f"  note: {entry['path']} fell back to file-copy")
    if args.remote:
        from devin_backup import remote
        result = remote.offload_snapshot(
            snap, args.remote, move=args.move)
        print(f"offloaded → {result['dest']}  "
              f"({result['bytes']} bytes via {result['method']})")
        if result["moved"]:
            print("  local snapshot removed")
    return 0


def _cmd_verify(args) -> int:
    report = verify.verify_snapshot(args.snapshot_dir)
    for r in report["results"]:
        mark = "ok  " if r["ok"] else "FAIL"
        line = f"  {mark} {r['path']}"
        if not r["ok"]:
            line += f"  ({r['status']})"
        print(line)
    state = "ok" if report["ok"] else "FAILED"
    print(f"{state}: {report['checked']} checked, {report['failed']} failed")
    return 0 if report["ok"] else 1


def _cmd_list(args) -> int:
    _, out = _resolve_dirs(args)
    snaps = rotate.list_snapshots(out)
    if not snaps:
        print(f"no snapshots in {out}")
        return 0
    for s in snaps:
        schemas = ", ".join(
            f"{Path(k).name} v{v}" for k, v in s["schema_versions"].items()
        ) or "-"
        print(
            f"{s['name']:<24} {s['kind']:<12} {s['files']:>3} files  "
            f"{s['size']:>10} B  {schemas}"
        )
    return 0


def _smoke_detail(result: dict) -> str:
    if not result["ok"]:
        # surface the real cause ('store is missing', hash mismatch,
        # 'not a readable database') instead of the sqlite label
        return result["detail"] or result["integrity"]
    if not result["sqlite"]:
        return "not a sqlite store"
    schema = (
        f"schema v{result['schema_version']}"
        if result["schema_version"] is not None
        else "schema unknown"
    )
    digest = f" · hash {result['hash']}" if result.get("hash") else ""
    return f"integrity {result['integrity']}{digest} · {schema}"


def _print_smoke(report: dict, scope: str) -> None:
    print(f"smoke — {scope}:")
    for r in report["results"]:
        mark = "ok  " if r["ok"] else "FAIL"
        print(f"  {mark} {r['path']}  ({_smoke_detail(r)})")
    state = "ok" if report["ok"] else "FAILED"
    print(
        f"smoke {state}: {report['checked']} checked, "
        f"{report['failed']} failed"
    )


def _cmd_restore(args) -> int:
    plan = restore.restore_snapshot(
        args.snapshot_dir,
        args.to,
        config_dir=args.config_to or default_config_dir(),
        dry_run=args.dry_run,
        backup=not args.no_backup,
    )
    for w in plan["warnings"]:
        print(f"warning: {w}", file=sys.stderr)
    if plan["dry_run"]:
        print("dry-run - no files written (pass --apply to restore)")
        for rel in plan["would_write"]:
            print(f"  would write {rel}")
        for rel in plan["would_overwrite"]:
            print(f"  would overwrite {rel}")
        if plan["would_backup"]:
            print("  current files would first be saved to a pre-restore backup")
    else:
        if plan["pre_restore_backup"]:
            print(f"pre-restore backup: {plan['pre_restore_backup']}")
        print(f"restored {len(plan['written'])} file(s) to {plan['target']}")
    if not args.smoke:
        return 0
    if plan["dry_run"]:
        report = smoke.smoke_snapshot(args.snapshot_dir)
        scope = "snapshot sources (dry-run — nothing was written)"
    else:
        report = smoke.smoke_restored(
            args.snapshot_dir, plan["target"], plan["config_target"]
        )
        scope = "restored stores"
    _print_smoke(report, scope)
    return 0 if report["ok"] else 1


def _fmt_size(size) -> str:
    return "-" if size is None else f"{size} B"


def _cmd_diff(args) -> int:
    data_dir = (
        Path(args.data_dir).expanduser()
        if args.data_dir
        else default_data_dir()
    )
    config_dir = (
        Path(args.config_dir).expanduser() if args.config_dir else None
    )
    report = diff.diff_snapshot(
        args.snapshot_dir, data_dir, config_dir=config_dir
    )
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print(f"snapshot: {report['snapshot']}")
    print(f"live:     {report['data_dir']}")
    for w in report["warnings"]:
        print(f"warning: {w}", file=sys.stderr)
    rows = report["files"]
    for r in sorted(rows, key=lambda x: x["path"]):
        status = r["status"]
        if r["status"] == diff.SAME and r["bytes_equal"] is False:
            status = "same*"
        delta = r["size_delta"]
        delta_s = "-" if delta is None else f"{delta:+d} B"
        print(
            f"  {status:<14} {r['path']:<44} "
            f"{_fmt_size(r['snapshot_size']):>10} → "
            f"{_fmt_size(r['live_size']):>10}  {delta_s}"
        )
        if r["tables"]:
            changed = ", ".join(
                f"{t} {n0}→{n1}" for t, (n0, n1) in r["tables"].items()
            )
            print(f"    {'':<14} rows: {changed}")
    if any(r["status"] == diff.SAME and r["bytes_equal"] is False
           for r in rows):
        print("  * identical content; file bytes differ "
              "(sqlite-backup copies are not byte-identical)")
    s = report["summary"]
    print(
        f"{s.get(diff.SAME, 0)} same · {s.get(diff.DIFFERENT, 0)} different · "
        f"{s.get(diff.SNAPSHOT_ONLY, 0)} snapshot-only · "
        f"{s.get(diff.LIVE_ONLY, 0)} live-only · "
        f"{s.get(diff.SNAPSHOT_MISSING, 0)} missing from snapshot"
    )
    return 0


def _cmd_rotate(args) -> int:
    _, out = _resolve_dirs(args)
    if not args.yes:
        print(
            "error: rotate permanently deletes snapshots - re-run with --yes",
            file=sys.stderr,
        )
        return 2
    older_than = (
        rotate.parse_duration(args.older_than) if args.older_than else None
    )
    keep = args.keep
    if keep is None:
        env_keep = os.environ.get("DEVIN_BACKUP_KEEP")
        if older_than is None:
            # keep-mode default: env or 10
            keep = int(env_keep or "10")
        elif env_keep is not None:
            # a configured retention floor still protects --older-than runs
            keep = int(env_keep)
    deleted = rotate.rotate_snapshots(out, keep=keep, older_than=older_than)
    if not deleted:
        criteria = []
        if keep is not None:
            criteria.append(f"keep={keep}")
        if args.older_than:
            criteria.append(f"older-than={args.older_than}")
        print(f"nothing to delete ({', '.join(criteria)})")
    for d in deleted:
        print(f"deleted {d.name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devin-backup",
        description="Safe backup & restore for Devin Desktop stores.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_dirs(p, data_dir=True):
        if data_dir:
            p.add_argument(
                "--data-dir",
                help="Devin data dir (default: $DEVIN_DATA_DIR or platform default)",
            )
        p.add_argument(
            "--out",
            help="backups dir (default: $DEVIN_BACKUP_DIR or <data-dir>/backups)",
        )

    p_create = sub.add_parser("create", help="snapshot all Devin stores")
    add_dirs(p_create)
    p_create.add_argument(
        "--config-dir",
        help="separate Devin UI config root (Linux default is detected)",
    )
    p_create.add_argument(
        "--exclude", action="append", metavar="PATTERN",
        help="skip stores whose relative path matches PATTERN "
        "(substring or glob; repeatable)",
    )
    p_create.add_argument(
        "--exclude-secrets", action="store_true",
        help="skip stores known to carry credentials/PII "
        "(state.vscdb, credentials.toml, *.pem, *.key)",
    )
    p_create.add_argument(
        "--remote", metavar="DEST",
        help="after creating and re-verifying the snapshot, offload it to "
        "DEST — an rsync-style '[user@]host:path' ssh target (needs rsync "
        "on PATH; posix) or a mounted/local path (verified copy, no rsync "
        "needed). The local snapshot is kept unless --move is also given",
    )
    p_create.add_argument(
        "--move", action="store_true",
        help="with --remote: delete the local snapshot after a successful "
        "offload (default keeps the local copy)",
    )
    p_create.set_defaults(func=_cmd_create)

    p_verify = sub.add_parser("verify", help="check a snapshot's integrity")
    p_verify.add_argument("snapshot_dir")
    p_verify.set_defaults(func=_cmd_verify)

    p_list = sub.add_parser("list", help="list snapshots")
    add_dirs(p_list)
    p_list.set_defaults(func=_cmd_list)

    p_restore = sub.add_parser("restore", help="restore a snapshot")
    p_restore.add_argument("snapshot_dir")
    p_restore.add_argument("--to", required=True, help="target Devin data root")
    p_restore.add_argument(
        "--config-to",
        help="target Devin UI config root (default: platform location)",
    )
    group = p_restore.add_mutually_exclusive_group()
    group.add_argument(
        "--dry-run", dest="dry_run", action="store_true", default=True,
        help="(default) show what would happen, write nothing",
    )
    group.add_argument(
        "--apply", dest="dry_run", action="store_false",
        help="actually restore",
    )
    p_restore.add_argument(
        "--no-backup", action="store_true",
        help="skip the pre-restore backup (refuses to overwrite anything)",
    )
    p_restore.add_argument(
        "--smoke", action="store_true",
        help="integrity-check every store the restore touches and report "
        "its schema version — the restored files with --apply, the "
        "snapshot sources in dry-run (read-only either way); "
        "exit 1 if any store fails",
    )
    p_restore.set_defaults(func=_cmd_restore)

    p_diff = sub.add_parser(
        "diff",
        help="compare a snapshot against the live stores (read-only)",
    )
    p_diff.add_argument("snapshot_dir")
    p_diff.add_argument(
        "--data-dir",
        help="live Devin data dir (default: $DEVIN_DATA_DIR or platform default)",
    )
    p_diff.add_argument(
        "--config-dir",
        help="live Devin UI config root (default: platform location)",
    )
    p_diff.add_argument(
        "--json", action="store_true", help="machine-readable JSON output"
    )
    p_diff.set_defaults(func=_cmd_diff)

    p_rotate = sub.add_parser(
        "rotate",
        help="delete old snapshots — keep last N and/or older than a duration",
    )
    add_dirs(p_rotate)
    p_rotate.add_argument(
        "--keep", type=int, default=None,
        help="snapshots to keep (default: $DEVIN_BACKUP_KEEP or 10); "
        "with --older-than it acts as a floor — rotation never leaves "
        "fewer than this many",
    )
    p_rotate.add_argument(
        "--older-than", metavar="DUR",
        help="also rotate snapshots older than DUR — <N>h, <N>d or <N>w "
        "(e.g. 12h, 30d, 4w), by snapshot dir mtime",
    )
    p_rotate.add_argument(
        "--yes", action="store_true",
        help="confirm deletion (required — rotate is destructive)",
    )
    p_rotate.set_defaults(func=_cmd_rotate)

    p_copy = sub.add_parser(
        "copy-to", help="copy a snapshot to a secondary dir and "
        "re-verify hashes at the destination (BK-2)")
    p_copy.add_argument("snapshot_dir")
    p_copy.add_argument("dest", help="secondary destination parent dir "
                        "(mounted drive, NAS mount, synced folder)")
    p_copy.add_argument("--json", action="store_true")
    p_copy.set_defaults(func=_cmd_copy_to)

    p_inst = sub.add_parser(
        "install", help="schedule a daily 'create' job "
        "(cron / Task Scheduler / elapsed hook — F6, opt-in)")
    p_inst.add_argument("--out", help="snapshot output dir for the job")
    p_inst.add_argument("--config-dir", help="Devin config dir override "
                        "(where .devin-ecosystem/scheduled.json lives)")
    p_inst.add_argument("--backend", default="auto",
                        choices=["auto", "tasksch", "cron", "elapsed"])
    p_inst.add_argument("--json", action="store_true")
    p_inst.set_defaults(func=_cmd_install)

    return parser


def _cmd_copy_to(args) -> int:
    from devin_backup.secondary import copy_to
    result = copy_to(args.snapshot_dir, args.dest)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        v = result["verify"]
        print(f"copied → {result['dest']}")
        print(f"  re-verified: {v['checked']} file(s), "
              f"{v['failed']} failed")
    return 0


def _cmd_install(args) -> int:
    from devin_backup.install import install_daily
    result = install_daily(out_dir=args.out, config_dir=args.config_dir,
                           backend=args.backend)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"installed '{result['job']}' [{result['backend']}]")
        print(f"  command: {result['command']}")
        print(f"  registry: {result['registry']}")
        if result["backend"] == "elapsed":
            print("  elapsed backend: add "
                  "'python tools/schedule.py check --run' to a "
                  "UserPromptSubmit hook (see devin-powerups README)")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (
        snapshot.SnapshotError,
        restore.RestoreError,
        DataDirError,
        ValueError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
