"""Fixtures-first: a synthetic Devin data dir built on devin-internals-spec.

``devin_dir`` mirrors the real layout::

    <tmp>/devin/cli/sessions.db          (v17 DDL, rows added per-test)
    <tmp>/devin/User/acp-messages/*.db   (fabricated per-session stores)
    <tmp>/devin/cli/session_locks/*.lock
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

import pytest
from devin_internals.fixtures import (
    ACP_MESSAGES_DDL,
    create_sessions_db,
)
from devin_janitor.paths import DevinPaths

NOW_S = time.time()
OLD_S = NOW_S - 10 * 86400  # safely outside any grace window


def add_session(
    db_path: Path,
    sid: str,
    *,
    title: str = "",
    project: str = "/proj/a",
    user_msgs: int = 0,
    assistant_msgs: int = 0,
    tool_calls: int = 0,
    created: float = OLD_S,
    last_activity: float = OLD_S,
    prompt: str = "",
    files: list[str] | None = None,
    metadata: str | None = None,
) -> None:
    """Insert a session with controlled activity counters.

    ``metadata`` is the raw sessions.db metadata JSON blob (e.g.
    ``'{"janitor_managed":"djaevin-acp"}'``) used to stamp provenance.
    """
    con = sqlite3.connect(str(db_path))
    with con:
        con.execute(
            "INSERT INTO sessions(id, working_directory, backend_type, model,"
            " agent_mode, created_at, last_activity_at, title, main_chain_id,"
            " shell_last_seen_index, cogs_json, workspace_dirs, hidden,"
            " metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sid,
                project,
                "fixture",
                "fixture",
                "fixture",
                int(created * 1000),
                int(last_activity * 1000),
                title,
                1,
                0,
                None,
                json.dumps([project]),
                0,
                metadata,
            ),
        )
        node = 0
        for i in range(user_msgs):
            node += 1
            text = prompt if i == 0 else f"user message {i}"
            con.execute(
                "INSERT INTO message_nodes(session_id, node_id,"
                " parent_node_id, chat_message, created_at, metadata)"
                " VALUES (?,?,?,?,?,?)",
                (
                    sid,
                    node,
                    node - 1 or None,
                    json.dumps({"role": "user", "text": text}),
                    int(created * 1000) + node,
                    None,
                ),
            )
        for i in range(assistant_msgs):
            node += 1
            con.execute(
                "INSERT INTO message_nodes(session_id, node_id,"
                " parent_node_id, chat_message, created_at, metadata)"
                " VALUES (?,?,?,?,?,?)",
                (
                    sid,
                    node,
                    node - 1 or None,
                    json.dumps({"role": "agent", "text": f"answer {i}"}),
                    int(created * 1000) + node,
                    None,
                ),
            )
        for i in range(tool_calls):
            payload = {"synthetic": True, "n": i}
            if files and i < len(files):
                payload["file_path"] = files[i]
            con.execute(
                "INSERT INTO tool_call_state(session_id, tool_call_id,"
                " tool_call_json, tool_call_update_json) VALUES (?,?,?,?)",
                (sid, f"tc-{i}", json.dumps(payload), None),
            )
    con.close()


def add_gui_session(acp_dir: Path, sid: str, *, title: str = "",
                    n_messages: int = 4, old: bool = True,
                    janitor_managed: str | None = None,
                    user_prompt: str | None = None) -> Path:
    """Fabricate an ``acp-messages/<sid>.db`` with synthetic messages.

    ``old`` backdates the mtime (used as last_activity) outside the default
    grace window. ``janitor_managed`` stamps the GUI provenance tag in the
    meta table; ``user_prompt`` becomes the first user message's
    ``_meta["cognition.ai/message"]`` text (the scoring-template carrier).
    """
    db = acp_dir / f"{sid}.db"
    con = sqlite3.connect(str(db))
    with con:
        con.executescript(ACP_MESSAGES_DDL)
        meta_rows = [("fixture.session_id", sid), ("title", title)]
        if janitor_managed:
            meta_rows.append(("janitor_managed", janitor_managed))
        con.executemany(
            "INSERT INTO meta(key, value) VALUES (?, ?)", meta_rows)
        kinds = ["user.prompt", "agent.delta", "tool_call", "agent.delta"]
        for pos in range(n_messages):
            if pos == 0 and user_prompt is not None:
                payload = {"_meta": {"cognition.ai/message": user_prompt}}
            else:
                payload = {"synthetic": 1}
            con.execute(
                "INSERT INTO messages(position, kind, payload)"
                " VALUES (?,?,?)",
                (pos, kinds[pos % len(kinds)], json.dumps(payload)),
            )
    con.close()
    if old:
        os.utime(db, (OLD_S, OLD_S))
    return db


@pytest.fixture()
def devin_dir(tmp_path: Path) -> DevinPaths:
    """An empty-schema Devin data tree under tmp_path."""
    root = tmp_path / "devin"
    create_sessions_db(root / "cli" / "sessions.db", n_sessions=0)
    (root / "User" / "acp-messages").mkdir(parents=True, exist_ok=True)
    (root / "cli" / "session_locks").mkdir(parents=True, exist_ok=True)
    return DevinPaths.from_root(root)
