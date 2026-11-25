"""Gate baseline — suppress findings a repo has already triaged.

Scanner false positives on legitimate code (an ``exclude_secrets``
parameter name, a ``PASS`` verdict constant, a ``globalStorage`` path
literal) used to leave every consumer of ``devin-redact gate`` with a
permanently red lane unrelated to the diff under review
(devin-state#108). A committed ``redact-baseline.json`` records the
findings already triaged; the gate then fails only on *new* findings —
anything whose key is not in the baseline is treated exactly as before.

Matching key: ``(file, category, pattern, kind, fingerprint)`` with
per-key occurrence counts. ``file`` is normalised to a posix path
relative to the baseline file's directory (absolute paths that escape
it stay absolute — deterministic per machine). ``location`` is
*deliberately* not part of the key: line numbers drift on every edit
and would resurrect suppressed findings, while ``fingerprint`` already
pins the sensitive value. Counts keep multiplicity honest — a second
occurrence of a baselined finding still counts as new.

The baseline is versioned (``"version": 1``), audited (it is a normal
committed file — its diff is the review trail) and surfaced: the gate
reports suppressed/stale counts on stderr while stdout stays the clean
single-word verdict contract.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import engine, staged

BASELINE_FILENAME = "redact-baseline.json"
BASELINE_VERSION = 1

# Key fields, in order — ``location`` and ``preview`` are audit
# metadata only, never part of the match.
_KEY_FIELDS = ("file", "category", "pattern", "kind", "fingerprint")


class BaselineError(RuntimeError):
    """The baseline file is missing, unreadable or malformed.

    The gate fails closed on this (exit 2): a baseline that cannot be
    parsed cannot vouch for which findings are pre-existing, and
    silently ignoring it would resurrect the false-positive lane the
    mechanism exists to remove.
    """


@dataclass(frozen=True)
class Baseline:
    """A loaded baseline: remaining match counts per finding key."""

    path: Path
    counts: Counter = field(compare=False)  # key tuple -> occurrences left
    entries: int = 0  # distinct keys recorded (for reporting)


def normalize_file(
    file_str: str, *, file_base: Path, base_dir: Path
) -> str:
    """Canonical posix key for a finding's display path.

    ``file_str`` is interpreted relative to ``file_base`` unless
    absolute — the cwd for worktree scans, the repo root for
    ``--staged`` (whose blob names are repo-relative). The result is
    the path relative to ``base_dir`` (the baseline file's directory);
    a path that escapes it falls back to its absolute posix form so
    out-of-tree scans still match deterministically.
    """
    p = Path(file_str)
    if not p.is_absolute():
        p = Path(file_base) / p
    try:
        rel = os.path.relpath(
            os.path.abspath(p), os.path.abspath(base_dir)
        )
    except (OSError, ValueError):
        # Windows: relpath across drives raises ValueError.
        rel = ""
    if rel and rel != os.pardir and not rel.startswith(os.pardir + os.sep):
        return Path(rel).as_posix()
    return Path(os.path.abspath(p)).as_posix()


def finding_key(
    finding: dict, *, file_base: Path, base_dir: Path
) -> tuple[str, str, str, str, str]:
    """The baseline match key for one report finding."""
    return (
        normalize_file(
            str(finding.get("file", "")), file_base=file_base, base_dir=base_dir
        ),
        str(finding.get("category", "")),
        str(finding.get("pattern", "")),
        str(finding.get("kind", "")),
        str(finding.get("fingerprint", "")),
    )


def _entry_key(entry: dict) -> tuple[str, str, str, str, str]:
    return tuple(str(entry.get(f, "")) for f in _KEY_FIELDS)


def load_baseline(path: Path) -> Baseline:
    """Parse and validate a baseline JSON file.

    Raises :class:`BaselineError` on any deviation — the gate treats a
    broken baseline as a hard error rather than guessing which findings
    were pre-triaged.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BaselineError(f"baseline {path}: top level must be an object")
    version = data.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"baseline {path}: unsupported version {version!r} "
            f"(expected {BASELINE_VERSION})"
        )
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise BaselineError(f"baseline {path}: 'findings' must be a list")
    counts: Counter = Counter()
    for i, entry in enumerate(findings):
        if not isinstance(entry, dict):
            raise BaselineError(f"baseline {path}: findings[{i}] not an object")
        for field_name in ("file", "category", "pattern", "fingerprint"):
            if not entry.get(field_name):
                raise BaselineError(
                    f"baseline {path}: findings[{i}] missing '{field_name}'"
                )
        try:
            count = int(entry.get("count", 1))
        except (TypeError, ValueError):
            raise BaselineError(
                f"baseline {path}: findings[{i}] 'count' not an integer"
            ) from None
        if count < 1:
            raise BaselineError(
                f"baseline {path}: findings[{i}] 'count' must be >= 1"
            )
        counts[_entry_key(entry)] += count
    return Baseline(path=path, counts=counts, entries=len(findings))


def discover_baseline(cwd: Path) -> Path | None:
    """Locate a ``redact-baseline.json`` for this run, or ``None``.

    The cwd wins (a subdirectory may carry a narrower baseline); then
    the enclosing git repository's root — the layout the pre-commit and
    CI consumers use, where the baseline sits next to the gated tree.
    A missing git binary or non-repo cwd simply yields ``None``: no
    baseline is a normal, un-suppressed gate.
    """
    cwd = Path(cwd)
    local = cwd / BASELINE_FILENAME
    if local.is_file():
        return local
    try:
        root = staged.repo_root(cwd)
    except staged.StagedScanError:
        return None
    remote = root / BASELINE_FILENAME
    if remote.is_file() and remote != local:
        return remote
    return None


def apply_baseline(
    report: dict, baseline: Baseline, *, file_base: Path
) -> tuple[dict, dict]:
    """Split ``report``'s findings into active vs baselined.

    Returns ``(filtered_report, stats)``: the report is rebuilt with
    only the active findings (same SPEC §6 contract via
    :func:`engine.rebuild_report`) plus a ``baseline`` block recording
    ``suppressed``/``stale``/``entries`` counts; ``stats`` mirrors it
    for the CLI's stderr note. Baseline entries never seen in this
    scan are ``stale`` — reported, not an error (a finding fixed since
    the baseline was written is the good outcome).
    """
    base_dir = baseline.path.parent
    remaining = Counter(baseline.counts)
    active: list[dict] = []
    suppressed_by_cat: Counter = Counter()
    suppressed = 0
    for finding in report.get("findings", []):
        key = finding_key(finding, file_base=file_base, base_dir=base_dir)
        if remaining.get(key, 0) > 0:
            remaining[key] -= 1
            suppressed += 1
            suppressed_by_cat[str(finding.get("category", ""))] += 1
        else:
            active.append(finding)
    stale = sum(remaining.values())
    filtered = engine.rebuild_report(report, active)
    stats = {
        "baseline": str(baseline.path),
        "entries": baseline.entries,
        "suppressed": suppressed,
        "stale": stale,
        "suppressed_by_category": dict(sorted(suppressed_by_cat.items())),
    }
    filtered["baseline"] = {
        "file": stats["baseline"],
        "entries": stats["entries"],
        "suppressed": suppressed,
        "stale": stale,
    }
    return filtered, stats


def write_baseline(
    path: Path,
    report: dict,
    *,
    file_base: Path,
    note: str | None = None,
) -> dict:
    """Write ``report``'s findings as a new baseline file.

    Findings are aggregated by match key with occurrence ``count``;
    ``location`` of the first occurrence is kept as an audit hint (it
    plays no part in matching). ``preview`` is deliberately *not*
    stored: even masked, secret-derived text can re-trigger the
    patterns — a baseline that flags itself would BLOCK the gate it is
    meant to unblock. Returns the written summary for the CLI's stderr
    note. The caller owns the audit step — the file is only safe once
    its diff has been reviewed and committed.
    """
    path = Path(path)
    base_dir = path.parent
    groups: dict[tuple[str, str, str, str, str], dict] = {}
    order: list[tuple[str, str, str, str, str]] = []
    for finding in report.get("findings", []):
        key = finding_key(finding, file_base=file_base, base_dir=base_dir)
        if key not in groups:
            groups[key] = {
                "file": key[0],
                "category": key[1],
                "pattern": key[2],
                "kind": key[3],
                "fingerprint": key[4],
                "count": 0,
                "location": str(finding.get("location", "")),
            }
            order.append(key)
        groups[key]["count"] += 1
    entries = [groups[k] for k in sorted(order)]
    doc = {
        "version": BASELINE_VERSION,
        "tool": "devin-redact",
        "generated_by": f"devin-redact {engine.__version__}",
        "note": note
        or "Findings triaged as accepted/false-positive — regenerate "
        "with `devin-redact gate --update-baseline` and review the diff.",
        "findings": entries,
    }
    blob = json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=True) + "\n"
    path.write_text(blob, encoding="utf-8")
    return {
        "baseline": str(path),
        "entries": len(entries),
        "findings": sum(e["count"] for e in entries),
    }
