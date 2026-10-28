"""Pathological-input time budgets — devin-state#96.

``env_assignment[19]`` (the MySQL-family flag carrier: a ``\\bmysql\\w*\\b``
anchor plus a lazy flag tail) used to hang for 20+ minutes on an unlucky
transcript — catastrophic backtracking while exploring decompositions for
a ``-p`` flag that never arrives. The tail was restructured greedily with
boundary classes; this file pins the worst observed cases to a per-input
budget so the next regex regression fails in milliseconds instead of
stalling a CI worker.

The global ``pytest.ini`` ``timeout = 120`` is only a backstop — it turns
a hang into a slow failure. The contract here is the measured budget:
every input below must scan in well under a second on a laptop-class CPU.
"""

import time

import pytest
from devin_redact.engine import redact_text

# Generous headroom over the slowest measured case (~115 ms on a 2022
# laptop) while still two orders of magnitude below the historical hang.
BUDGET_SECONDS = 0.75

PATHOLOGICAL_INPUTS = [
    # The exact reproducer from the issue: URI userinfo collides with the
    # mysql flag-carrier anchor and no -p flag ever follows.
    "conn mysql://root:toorpass@127.0.0.1/db end",
    # Carrier anchor followed by a long flag run that never yields -p.
    "mysql " + "a " * 400,
    "mysql --flag1 --flag2 --flag3 " * 30,
    "mysqldump -u root " + "-x " * 300,
    # Long userinfo stretch inside a URI (backtracking amplifier).
    "conn mysql://root:" + "x" * 2000 + "@h/d",
    # Line continuations keep the tail alive across rows.
    "mysql " + "\\\narg " * 200,
    # Near-miss anchors: look like the carrier but are not.
    "xmysql://u:p@h/d notmysql://u:p@h/d mysqladmin://u:p@h",
    "mariadb " + "-v " * 250,
    # Repeated carrier restarts on one line.
    " ".join(["mysql://u:p@h/d"] * 40),
    # vault write / nomad var put: the option tail (``[ \t]+-X(ARG)?``*)
    # overlaps the mandatory path ``\S+`` — CodeQL py/redos flags the
    # theoretical repartitioning. Path now requires ``(?!-)``; these
    # inputs pin the measured cost of the flagged arms.
    "vault write " + "-a " * 300 + "k=v",
    "vault write " + '-fmt=json ' * 100 + "secret/p " + "k=v " * 50,
    "nomad var put " + "-x " * 300 + "p k=v",
    "vault write " + "-x " * 200,
]


@pytest.mark.parametrize("payload", PATHOLOGICAL_INPUTS)
def test_scan_completes_within_budget(payload):
    start = time.monotonic()
    redact_text(payload)
    elapsed = time.monotonic() - start
    assert elapsed < BUDGET_SECONDS, (
        f"redact_text took {elapsed:.2f}s on {len(payload)}-byte input "
        f"(budget {BUDGET_SECONDS}s) — possible ReDoS regression"
    )


def test_uri_userinfo_still_redacted():
    """The budget fix must not drop the connection_uri coverage that
    motivated the carrier patterns in the first place."""
    text, hits = redact_text("conn mysql://root:toorpass@127.0.0.1/db end")
    assert "toorpass" not in text
    assert any(h["category"] == "connection_uri" for h in hits)


def test_mysql_p_flag_still_caught():
    """And the flag carrier the anchor exists for still fires."""
    text, _ = redact_text("mysqldump -u root -pSup3rSecret db > dump.sql")
    assert "Sup3rSecret" not in text
