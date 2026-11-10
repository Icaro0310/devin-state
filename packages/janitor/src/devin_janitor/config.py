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
# ``^[Rr]obot_`` is the universal prefix stamped on scoring-bridge sessions
# (the djaevin-acp bridge prefixes titles for POORDJAEVIN_ACP_MANAGED_TAG
# "djaevin-acp"); content is disposable, so they always auto-delete.
DEFAULT_NOISE_PATTERNS = [
    (r"^[Rr]obot_|judge tool|classif|support_triage|entailment|^\[\d+\]$|"
    r"^\{\"items\"|^billing$|^BLOCKED$|SESSION_OK|echo.*test|sentinel|"
    r"safe test command|heartbeat-probe|"
    r"Lista.*(tools|ferramentas).*djaevin-local|tools MCP.*djaevin-local"),
]

# Automation scoring calls (the poordjaevin ACP judge) carry a *descriptive*
# title taken from the premise being judged, so the title alone does not
# reveal them — e.g. "Isolate Janitor Few-Shot Pools" is really a scoring
# call. The giveaway is the first user message: it is a verbatim scoring
# template, never a real task. These phrases are near-literal fragments of
# that template, deliberately specific so a genuine user prompt won't match.
DEFAULT_JUDGE_PROMPT_PATTERNS = [
    r"strict entailment judge used as a scoring backend",
    r"For every \[premise, hypothesis\] pair in the JSON data below",
    r"estimate from 0 to 100 how strongly the premise entails the hypothesis",
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
    "for future work."
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
    judge_prompt_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_JUDGE_PROMPT_PATTERNS)
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

    @property
    def judge_prompt_re(self) -> re.Pattern:
        return self._compile(self.judge_prompt_patterns)

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
