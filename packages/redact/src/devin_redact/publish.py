"""Publication gate for ``devin-history`` export directories (RD-4).

``verify_publish()`` cross-references redaction findings with the export
state of a ``devin-history`` output directory: it enumerates the exported
sessions (``index.json`` / ``index.md`` when present, else the
``<YYYY-MM-DD>_<session-id>.{md,json}`` file layout), scans each exported
file read-only, and reports per-session verdicts so nothing is published
while secrets remain.

When a ``session-end`` verdict side file exists for an exported session
(``<verdicts-dir>/<session-id>.json``) it is cross-referenced too: a hook
verdict of ``BLOCKED`` next to a ``CLEAN`` export means the export was
redacted after the scan — or silently dropped the leaking content — and
is surfaced as a warning (which holds the overall verdict at ``REVIEW``).

Read-only: nothing under the export dir or the verdicts dir is modified.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import __version__, engine, paths

_SESSION_SUFFIXES = {".md", ".json"}
_INDEX_NAMES = {"index.md", "index.json"}
_MD_SESSION_ID = re.compile(r"(?m)^session_id:\s*(\S+)\s*$")
_MD_WIKILINK = re.compile(r"\[\[([^\]|]+?)(?:\|([^\]]*))?\]\]")
_MD_HEAD_BYTES = 4096
_DATE_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}_(.+)$")


def _session_id_from_filename(name: str) -> str | None:
    """``<YYYY-MM-DD>_<session-id>.<ext>`` → session id, or ``None``."""
    stem = Path(name).stem
    m = _DATE_PREFIX.match(stem)
    return m.group(1) if m else None


def _session_id_of(path: Path) -> str | None:
    """Best-effort session id for an exported file: embedded field or
    frontmatter first, the ``devin-history`` filename shape last."""
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            sid = data.get("session_id") if isinstance(data, dict) else None
            if isinstance(sid, str) and sid:
                return sid
        elif path.suffix.lower() == ".md":
            head = path.read_text(encoding="utf-8")[:_MD_HEAD_BYTES]
            m = _MD_SESSION_ID.search(head)
            if m:
                return m.group(1)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return _session_id_from_filename(path.name)


def _export_entries(export_dir: Path) -> tuple[list[dict], str | None]:
    """Enumerate exported session files.

    Returns ``(entries, index_name)`` where each entry is
    ``{"file": Path, "title": str | None}``. Prefers ``index.json`` (the
    ``devin-history`` machine index), then ``index.md`` wikilinks, then
    every session-shaped file in the directory.
    """
    index_json = export_dir / "index.json"
    if index_json.is_file():
        try:
            data = json.loads(index_json.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            data = None
        sessions = data.get("sessions") if isinstance(data, dict) else None
        if isinstance(sessions, list):
            entries = [
                {"file": export_dir / str(e["file"]), "title": e.get("title")}
                for e in sessions
                if isinstance(e, dict) and isinstance(e.get("file"), str)
            ]
            return entries, "index.json"

    index_md = export_dir / "index.md"
    if index_md.is_file():
        try:
            text = index_md.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            text = ""
        entries = []
        for name, title in _MD_WIKILINK.findall(text):
            # devin-history index links strip the ".md" suffix.
            if Path(name).suffix.lower() not in _SESSION_SUFFIXES:
                name += ".md"
            entries.append({"file": export_dir / name, "title": title or None})
        if entries:
            return entries, "index.md"

    entries = [
        {"file": p, "title": None}
        for p in sorted(export_dir.iterdir())
        if p.is_file()
        and p.suffix.lower() in _SESSION_SUFFIXES
        and p.name not in _INDEX_NAMES
    ]
    return entries, None


def _hook_verdict(verdicts_dir: Path, session_id: str | None) -> str | None:
    """``publication_status`` of the session-end side file, if present."""
    if not session_id:
        return None
    vfile = verdicts_dir / f"{session_id}.json"
    try:
        data = json.loads(vfile.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    status = data.get("publication_status") if isinstance(data, dict) else None
    return status if isinstance(status, str) else None


def _overall(sessions: list[dict], warnings: list[str]) -> str:
    statuses = {str(s["publication_status"]) for s in sessions}
    if "BLOCKED" in statuses:
        return "BLOCKED"
    if "REVIEW" in statuses or warnings:
        return "REVIEW"
    return "CLEAN"


def verify_publish(export_dir, *, verdicts_dir=None) -> dict:
    """Scan a ``devin-history`` export dir and report per-session verdicts."""
    export_dir = Path(export_dir)
    vdir = (
        Path(verdicts_dir)
        if verdicts_dir is not None
        else paths.default_redact_dir()
    )
    entries, index_name = _export_entries(export_dir)

    sessions: list[dict] = []
    warnings: list[str] = []
    errors: list[dict[str, str]] = []

    # The index enumerates; it must never *limit* coverage. An index that
    # omits a session-shaped file on disk — hand-edited, generated by an
    # older exporter, or hostile — would otherwise let a leaking session
    # sail through the gate unscanned. Every session-shaped file in the
    # directory is scanned whether or not the index mentions it.
    if index_name is not None:
        listed = {entry["file"].resolve() for entry in entries}
        for p in sorted(export_dir.iterdir()):
            if (
                p.is_file()
                and p.suffix.lower() in _SESSION_SUFFIXES
                and p.name not in _INDEX_NAMES
                and p.resolve() not in listed
            ):
                entries.append({"file": p, "title": None})

    export_root = export_dir.resolve()
    for entry in entries:
        f: Path = entry["file"]
        try:
            f.resolve().relative_to(export_root)
        except ValueError:
            warnings.append(
                f"{f.name}: index entry resolves outside the export dir — "
                "scanned anyway, but verify the index provenance"
            )
        if not f.is_file():
            sid = _session_id_from_filename(f.name)
            sessions.append(
                {
                    "session_id": sid,
                    "file": f.name,
                    "title": entry.get("title"),
                    "publication_status": "MISSING",
                    "findings_total": 0,
                    "secrets": 0,
                    "by_category": {},
                    "hook_status": _hook_verdict(vdir, sid),
                }
            )
            warnings.append(f"{f.name}: listed in the index but the file is missing")
            continue
        sid = _session_id_of(f)
        report = engine.scan([f])
        status = str(report["publication_status"])
        hook_status = _hook_verdict(vdir, sid)
        rec = {
            "session_id": sid,
            "file": f.name,
            "title": entry.get("title"),
            "publication_status": status,
            "findings_total": report["findings_total"],
            "secrets": report["secrets"],
            "by_category": report["by_category"],
            "hook_status": hook_status,
        }
        sessions.append(rec)
        for e in report["errors"]:
            errors.append({"file": str(f), "error": e["error"]})
        if hook_status == "BLOCKED" and status == "CLEAN":
            warnings.append(
                f"{f.name}: session-end verdict was BLOCKED but the export "
                f"scans CLEAN — the export may have been redacted since, "
                f"or it dropped the flagged content"
            )

    sessions.sort(key=lambda s: (str(s["session_id"]), str(s["file"])))
    blocked = sum(1 for s in sessions if s["publication_status"] == "BLOCKED")
    review = sum(1 for s in sessions if s["publication_status"] == "REVIEW")
    return {
        "tool": "devin-redact",
        "version": __version__,
        "export_dir": str(export_dir),
        "index": index_name,
        "verdicts_dir": str(vdir),
        "sessions_total": len(sessions),
        "sessions_clean": len(sessions) - blocked - review,
        "sessions_review": review,
        "sessions_blocked": blocked,
        "sessions": sessions,
        "warnings": warnings,
        "publication_status": _overall(sessions, warnings),
        "errors": errors,
    }
