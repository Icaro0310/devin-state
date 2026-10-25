"""Tiered session classification — the safety core of the janitor.

Every session lands in exactly one tier:

- ``KEEP``        — allowlisted (keep-file ids / title patterns, "não apagar",
                    SLACK-BRAIN), inside the grace window, or substantive work
- ``AUTO_DELETE`` — empty, automation/eval noise, ephemeral heartbeat/mailbox
                    cycles, or a duplicate loser
- ``JUDGE``       — weak but ambiguous signals; deferred to the pluggable
                    judge (default ``none`` keeps them all — fail-open)

Semantics are ported 1:1 from ``legacy/session-janitor.py``.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from devin_janitor.config import JanitorConfig
from devin_janitor.inventory import (
    DevinArtifact,
    SessionRow,
    load_devin_artifacts,
)


class Tier(Enum):
    KEEP = "keep"
    AUTO_DELETE = "auto_delete"
    JUDGE = "judge"


@dataclass
class Classification:
    """Result of one classification pass."""

    auto_delete: list[tuple[SessionRow, str]] = field(default_factory=list)
    judge: list[SessionRow] = field(default_factory=list)
    kept: dict[str, str] = field(default_factory=dict)  # id -> reason

    def tier_of(self, session_id: str) -> Tier:
        if session_id in self.kept:
            return Tier.KEEP
        if any(r.id == session_id for r, _ in self.auto_delete):
            return Tier.AUTO_DELETE
        return Tier.JUDGE

    def summary(self) -> dict[str, int]:
        return {
            "keep": len(self.kept),
            "auto_delete": len(self.auto_delete),
            "judge": len(self.judge),
        }


def norm_title(title: str) -> str:
    return re.sub(r"[^a-z0-9]", "", title.lower())[:60]


def load_keep_file(path: str | Path | None) -> tuple[set[str], list[str]]:
    """``{"ids": [...], "title_patterns": [...]}`` — both optional."""
    if path is None:
        return set(), []
    p = Path(path).expanduser()
    if not p.is_file():
        return set(), []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set(), []
    return set(data.get("ids", [])), list(data.get("title_patterns", []))


def classify(
    rows: list[SessionRow],
    config: JanitorConfig | None = None,
    *,
    keep_ids: set[str] | None = None,
    keep_patterns: list[str] | None = None,
    now: float | None = None,
) -> Classification:
    """Assign every row to a tier. ``now`` is epoch seconds (test hook)."""
    cfg = config or JanitorConfig()
    keep_ids = keep_ids or set()
    keep_re = cfg.keep_re(keep_patterns)
    grace_ts = (now if now is not None else time.time()) - cfg.grace_hours * 3600

    result = Classification()

    # Pre-pass: same normalized title within a project → keep the sibling
    # with the most activity, the rest are duplicates.
    by_title: dict[tuple[str, str], list[SessionRow]] = {}
    for r in rows:
        by_title.setdefault((r.project, norm_title(r.title)), []).append(r)
    dup_losers: set[str] = set()
    for sibs in by_title.values():
        if len(sibs) < 2 or not norm_title(sibs[0].title):
            continue
        best = max(sibs, key=lambda x: x.score)
        dup_losers.update(s.id for s in sibs if s.id != best.id)

    for r in rows:
        title = r.title

        if r.id in keep_ids or keep_re.search(title):
            result.kept[r.id] = "allowlist/marked"
            continue
        if r.last_activity and r.last_activity > grace_ts:
            result.kept[r.id] = "grace window"
            continue

        if r.is_empty:
            result.auto_delete.append((r, "empty"))
        elif r.id in dup_losers:
            result.auto_delete.append((r, "duplicate"))
        elif cfg.noise_re.search(title) and r.tool_calls <= cfg.noise_max_tool_calls:
            result.auto_delete.append((r, "automation/eval noise"))
        elif (
            cfg.ephemeral_re.search(title)
            and r.user_msgs <= cfg.ephemeral_max_user_msgs
            and r.tool_calls <= cfg.ephemeral_max_tool_calls
        ):
            result.auto_delete.append((r, "ephemeral heartbeat/mailbox cycle"))
        elif (
            r.user_msgs <= cfg.judge_max_user_msgs
            and r.tool_calls <= cfg.judge_max_tool_calls
            and r.files_touched == 0
            and r.score < cfg.judge_max_score
        ):
            result.judge.append(r)
        else:
            result.kept[r.id] = "substantive work"

    return result


# ---------------------------------------------------- .devin/ artifacts ----
#
# The PAS learning loop and the janitor itself accumulate runtime state in a
# project's .devin/ dir. Artifacts get the same three tiers as sessions,
# assigned by path (first match wins):
#
# - KEEP        — durable state a future session needs: *.json state files
#                 (learning-state.json, janitor-keep.json, the pending
#                 queue), docs, config, everything under rules/ and skills/
# - AUTO_DELETE — safe to reclaim: regenerable caches (search.db, graph.db),
#                 sqlite checkpoint sidecars, transient leftovers, and
#                 bounded append logs (*.jsonl — prune/rotate, e.g.
#                 memory/hook-fires.jsonl, memory/janitor-log.jsonl)
# - JUDGE       — unrecognized: unknown sqlite stores, possible live locks,
#                 anything else. Fail-open = kept; a human reviews.

REGENERABLE_CACHE_NAMES = frozenset({"search.db", "graph.db"})
TRANSIENT_SUFFIXES = (".tmp", ".bak", ".swp", ".pyc", ".pyo", "~")
TRANSIENT_NAMES = frozenset({".ds_store", "thumbs.db", "desktop.ini"})
ARTIFACT_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
LOG_SUFFIXES = (".jsonl", ".ndjson", ".log")
KEEP_DIRS = frozenset({"rules", "skills"})
DOC_SUFFIXES = (".md", ".txt", ".rst")
CONFIG_SUFFIXES = (".toml", ".yaml", ".yml", ".ini", ".cfg")
SQLITE_SUFFIXES = (".db", ".sqlite", ".sqlite3")


@dataclass
class ArtifactClassification:
    """Tier verdicts for ``.devin/`` artifacts — same enum as sessions."""

    verdicts: list[tuple[DevinArtifact, Tier, str]] = field(
        default_factory=list
    )

    def tier_of(self, rel_path: str) -> Tier | None:
        for a, tier, _ in self.verdicts:
            if a.rel_path == rel_path:
                return tier
        return None

    def in_tier(self, tier: Tier) -> list[tuple[DevinArtifact, str]]:
        return [(a, why) for a, t, why in self.verdicts if t is tier]

    def summary(self) -> dict[str, int]:
        return {
            "keep": len(self.in_tier(Tier.KEEP)),
            "auto_delete": len(self.in_tier(Tier.AUTO_DELETE)),
            "judge": len(self.in_tier(Tier.JUDGE)),
        }


def _artifact_rule(rel_path: str) -> tuple[Tier, str]:
    parts = rel_path.lower().split("/")
    base = parts[-1]
    top = parts[0] if len(parts) > 1 else ""
    if "__pycache__" in parts[:-1]:
        return Tier.AUTO_DELETE, "transient leftover"
    if base in TRANSIENT_NAMES or base.endswith(TRANSIENT_SUFFIXES):
        return Tier.AUTO_DELETE, "transient leftover"
    if base.endswith(ARTIFACT_SIDECAR_SUFFIXES):
        return Tier.AUTO_DELETE, "sqlite sidecar (checkpoint-reclaimed)"
    if base in REGENERABLE_CACHE_NAMES:
        return Tier.AUTO_DELETE, "regenerable cache"
    if base.endswith(LOG_SUFFIXES):
        return Tier.AUTO_DELETE, "bounded log — prune/rotate"
    if top in KEEP_DIRS:
        return Tier.KEEP, "rules/skills knowledge"
    if base.endswith(DOC_SUFFIXES):
        return Tier.KEEP, "documentation"
    if base.endswith(".json"):
        return Tier.KEEP, "durable state"
    if base.endswith(CONFIG_SUFFIXES):
        return Tier.KEEP, "configuration"
    if base.endswith(".lock"):
        return Tier.JUDGE, "possible live lock — do not touch"
    if base.endswith(SQLITE_SUFFIXES):
        return Tier.JUDGE, "unrecognized sqlite store — verify regenerable"
    return Tier.JUDGE, "unrecognized artifact — review manually"


def classify_devin_artifacts(
    artifacts: list[DevinArtifact],
) -> ArtifactClassification:
    """Tier every artifact in a ``.devin/`` inventory listing."""
    result = ArtifactClassification()
    for a in artifacts:
        tier, why = _artifact_rule(a.rel_path)
        result.verdicts.append((a, tier, why))
    return result


def devin_artifacts_payload(devin_dir: str | Path) -> dict:
    """JSON-friendly ``.devin/`` artifact report (shared by scan and MCP).

    Raises :class:`inventory.DevinArtifactError` on unreadable/malformed
    paths — the caller decides whether that is fatal (``scan``) or a
    per-store ``error`` entry (``report``).
    """
    d = Path(devin_dir).expanduser()
    artifacts = load_devin_artifacts(d)
    cls = classify_devin_artifacts(artifacts)
    return {
        "dir": str(d),
        "exists": d.is_dir(),
        "total": len(artifacts),
        "by_tier": cls.summary(),
        "artifacts": [
            {
                "rel_path": a.rel_path,
                "bytes": a.bytes,
                "mtime": a.mtime,
                "tier": tier.value,
                "reason": why,
            }
            for a, tier, why in cls.verdicts
        ],
    }
