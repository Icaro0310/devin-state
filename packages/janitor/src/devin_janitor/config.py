"""Config-driven tier rules.

The legacy script hardcoded its noise/ephemeral regexes and thresholds. Here
they live in :class:`JanitorConfig`, overridable via a JSON config file
(``--config``). Defaults reproduce the legacy semantics exactly.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Sessions whose titles match these are pure automation/eval noise.
DEFAULT_NOISE_PATTERNS = [
    (r"judge tool|classif|support_triage|entailment|^\[\d+\]$|^\{\"items\"|"
    r"^billing$|^BLOCKED$|SESSION_OK|echo.*test|sentinel|safe test command|"
    r"heartbeat-probe|Lista.*(tools|ferramentas).*djaevin-local|tools MCP.*djaevin-local|"
    # robot eval-scoring sessions (directive 2026-11-03): any variant of the
    # Score/Assess/Evaluate/Judge-* phrasing the eval loop generates — these
    # never carry durable knowledge and must not survive via the judge tier.
    r"^Score[ _]|^Assess[ _]|^Evaluate[ _]|^Judge[ _]|"
    r"^ping$|^pong$|^ok$|exact(ly)?[ _-]?ok|^functions\.|^\{\"scores|"
    # PT eval verbs + EN verify/validate/evaluating at title start: every
    # observed match is the ~38-msg/0-tool-call NLI gate template, never
    # user work. "[ _]" covers both space titles and namer's Title_Case.
    r"^Evaluating[ _]|^Avaliar[ _]|^Pontuar[ _]|^Julgar[ _]|"
    r"^Verify[ _]|^Validate[ _]|"
    # NLI-eval vocabulary anywhere in the title.
    r"premis|hypothes|hip[oó]tes|aleg[aã][cç][aã]o|veracidade|sustentad|"
    r"estimate from 0|claim evaluation|intent assessment|untrusted json|"
    # "reply exactly: ok/pong" model probes — exact/ok/pong co-occurring
    # with a reply-verb in either order (probes get renamed by
    # session-namer, so title shape is a permutation of these words).
    # (?<![a-z0-9])/(?![a-z0-9]) instead of \b: underscores are word chars,
    # so \b never fires inside Title_Case probe names.
    r"(?<![a-z0-9])(ok|pong|exact(ly)?)(?![a-z0-9]).*"
    r"(?<![a-z0-9])(reply|respond|response|request|acknowledge|confirm|"
    r"require|echo|only|one|generation|instruction|ok|pong)(?![a-z0-9])|"
    r"(?<![a-z0-9])(reply|respond|response|request|acknowledge|confirm|"
    r"require|echo|only|one|generation|instruction)(?![a-z0-9]).*"
    r"(?<![a-z0-9])(ok|pong|exact(ly)?)(?![a-z0-9])"),
]

# One-shot cycles whose durable knowledge lives elsewhere (slack-brain
# sessions, heartbeat state, the vault, learned-* skills).
DEFAULT_EPHEMERAL_PATTERNS = [
    (r"inbox|slack-bridge|slack bridge|Tarefa Slack|Processamento|"
    r"Processar ficheiros|timeout ACP|heartbeat"),
]

# Title patterns that always keep a session (merged with the keep-file's own
# ``title_patterns``).
DEFAULT_KEEP_TITLE_PATTERNS = [r"n[ãa]o apagar", r"SLACK-BRAIN"]

DEFAULT_JUDGE_STATEMENT = (
    "This session transcript contains durable, reusable knowledge — "
    "decisions, conventions, fixes or project context worth preserving "
    "for future work. Automation/eval-scoring sessions (claim scoring, "
    "entailment evals, heartbeat probes) are never durable knowledge — "
    "their outputs live in the eval system's own store, so answer delete."
)


@dataclass
class JanitorConfig:
    """Tunable classification rules + thresholds."""

    noise_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_NOISE_PATTERNS)
    )
    ephemeral_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_EPHEMERAL_PATTERNS)
    )
    keep_title_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_KEEP_TITLE_PATTERNS)
    )
    grace_hours: float = 48.0
    max_delete: int = 100
    noise_max_tool_calls: int = 5
    ephemeral_max_user_msgs: int = 75
    ephemeral_max_tool_calls: int = 60
    judge_max_user_msgs: int = 6
    judge_max_tool_calls: int = 15
    judge_max_score: int = 20
    judge_statement: str = DEFAULT_JUDGE_STATEMENT

    @staticmethod
    def _compile(patterns: list[str]) -> re.Pattern:
        # an empty pattern list must match NOTHING — "|".join([]) compiles
        # to "" which matches every string
        return re.compile("|".join(patterns) if patterns else r"$^", re.IGNORECASE)

    @property
    def noise_re(self) -> re.Pattern:
        return self._compile(self.noise_patterns)

    @property
    def ephemeral_re(self) -> re.Pattern:
        return self._compile(self.ephemeral_patterns)

    def keep_re(self, extra_patterns: list[str] | None = None) -> re.Pattern:
        pats = list(self.keep_title_patterns) + list(extra_patterns or [])
        return self._compile(pats)

    @classmethod
    def load(cls, path: str | Path | None) -> JanitorConfig:
        """Defaults merged with a JSON config file, if given.

        Unknown keys are ignored so a config written for a newer version
        still loads.
        """
        cfg = cls()
        if path is None:
            return cfg
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
        known = {f for f in cfg.__dataclass_fields__}
        for key, value in data.items():
            if key in known:
                setattr(cfg, key, value)
        return cfg

    def summary(self) -> dict[str, Any]:
        return {
            "grace_hours": self.grace_hours,
            "max_delete": self.max_delete,
            "noise_patterns": len(self.noise_patterns),
            "ephemeral_patterns": len(self.ephemeral_patterns),
        }
