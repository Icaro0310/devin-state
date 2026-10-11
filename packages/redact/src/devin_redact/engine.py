"""Detection + redaction engine.

``scan()`` walks files and SQLite databases, applies the patterns from
:mod:`devin_redact.patterns` (and the tool-call semantics from
:mod:`devin_redact.semantic`), and returns the JSON report contract defined
in ``docs/SPEC.md`` §6. It is strictly read-only: it never opens a database
in write mode and never mutates a file.

``redact()`` performs the same walk but produces masked replacements
(``<REDACTED:sha256prefix>``). It defaults to dry-run; writing requires
``apply=True`` **and** ``confirm_irreversible=True``. SQLite writes are
protected by a mandatory ``.bak`` backup, a single transaction, and a
post-redact open test (rollback + restore on failure).
"""

from __future__ import annotations

import ast
import hashlib
import itertools
import json
import os
import re
import shutil
import sqlite3
import tempfile
from pathlib import Path, PurePosixPath

from . import __version__
from .patterns import PATTERNS, SECRET_CATEGORIES, pattern_name, sensitive_match
from .semantic import analyze_tool_call_json

_DB_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
_SQLITE_MAGIC = b"SQLite format 3\x00"
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
_BINARY_SNIFF_BYTES = 8192
_DB_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
_REDACTED_TAG = "<REDACTED:"
_SEMANTIC_CATEGORY = "sensitive_tool_output"
_BLOCKING_CATEGORIES = SECRET_CATEGORIES | {_SEMANTIC_CATEGORY}

Finding = dict[str, object]


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _tag(value: str) -> str:
    return f"<REDACTED:{_fingerprint(value)}>"


def _mask(value: str) -> str:
    """Lossy preview — never emits the full sensitive value."""
    if "\n" in value:
        value = value.splitlines()[0]
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


_CODE_VALUE_RE = re.compile(
    r"^\s*(?:[(\[{]|[A-Za-z_][\w.]*\s*\()"
)


def _literal_string_value(rhs: str) -> bool:
    """True when ``rhs`` still parses as a plain string/bytes literal —
    a hardcoded value, not a code expression.

    ``ast.literal_eval`` does the parsing, so every spelling of "one
    literal" flags: parentheses (``("x")`` — they group, they do not
    contain), nested parens, ``r``/``b``/``u`` prefixes, triple quotes,
    implicit concatenation (``("a" "b")``) and a trailing ``#``
    comment. Calls, f-strings, name references and real containers
    (``("a", "b")``, ``["k"]``, ``{"k": "v"}``) fail the eval and stay
    suppressed as code. A single-element tuple (``("x",)``) is the same
    hardcoded literal one comma away, so it flags too.
    """
    try:
        value = ast.literal_eval(rhs.strip())
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return False
    if isinstance(value, (str, bytes)):
        return True
    # A one-element tuple — ``("x",)`` — is the wrapped literal plus a
    # trailing comma: still a hardcoded value, not a container of code.
    return (
        isinstance(value, tuple)
        and len(value) == 1
        and isinstance(value[0], (str, bytes))
    )


def _looks_like_code_assignment(whole: str) -> bool:
    """False-positive guard for ``env_assignment`` matches.

    The pattern anchors on names containing KEY/SECRET/TOKEN/etc., which
    also matches code constants — ``_STRUCTURAL_KEYS = frozenset({...})``,
    ``TOKEN_RE = re.compile(...)``, ``SECRET_PATTERNS = [...]``. A repo
    holding scanner configs, env parsers or policy generators hits this
    on every gate run, including devin-redact's own source.

    Suppress when the right-hand side is a container literal
    (``(``, ``[``, ``{``) or a call (``name(``): real env values are
    bare or quoted tokens, never code expressions. An RHS that still
    parses to a plain string/bytes literal — the only shape that can
    hold a real hardcoded secret — is flagged even inside parentheses
    (``PASSWORD = ("hunter2")``): parens group but do not contain.
    """
    eq = whole.find("=")
    if eq == -1:
        return False
    rhs = whole[eq + 1 :]
    if not _CODE_VALUE_RE.match(rhs):
        return False
    return not _literal_string_value(rhs)


def _iter_matches(text: str):
    """Yield ``(category, pattern_name, match)`` for every pattern hit."""
    for category, regexes in PATTERNS.items():
        for index, rx in enumerate(regexes):
            for m in rx.finditer(text):
                if _REDACTED_TAG in m.group(0):
                    # Already redacted — don't double-report/re-redact.
                    continue
                if (
                    category == "env_assignment"
                    and _looks_like_code_assignment(m.group(0))
                ):
                    continue
                yield category, pattern_name(category, index), m


def scan_text(text: str, *, file: str, location: str) -> list[Finding]:
    """Apply every pattern to ``text`` and return findings (sorted, deduped)."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for category, name, m in _iter_matches(text):
        value = sensitive_match(m)
        key = (category, name, m.start(1) if m.lastindex else m.start())
        if key in seen:
            continue
        seen.add(key)
        line = _line_of(text, m.start())
        findings.append(
            {
                "file": file,
                "category": category,
                "pattern": name,
                "kind": "pattern",
                "location": f"{location}:line {line}",
                "fingerprint": _fingerprint(value),
                "preview": _mask(value),
            }
        )
    return findings


def redact_text(text: str) -> tuple[str, list[dict]]:
    """Replace every secret span in ``text`` with ``<REDACTED:fp>``.

    ``env_assignment`` matches keep their ``KEY=`` prefix so a redacted
    ``.env`` stays readable. Overlapping matches resolve greedily: the
    leftmost (then longest) span wins. Returns ``(new_text, edits)``.
    Idempotent — ``<REDACTED:…>`` tags are never re-redacted.
    """
    candidates: list[tuple[int, int, str, str, str]] = []
    for category, name, m in _iter_matches(text):
        value = sensitive_match(m)
        fp = _fingerprint(value)
        if category == "env_assignment":
            whole = m.group(0)
            eq = whole.index("=")
            start, end = m.span(0)
            replacement = f"{whole[: eq + 1]}{_tag(value)}"
        else:
            start, end = m.span(1) if m.lastindex else m.span(0)
            replacement = _tag(value)
        candidates.append((start, end, replacement, category, fp))

    candidates.sort(key=lambda c: (c[0], -(c[1] - c[0])))
    accepted: list[tuple[int, int, str, str, str]] = []
    last_end = -1
    for cand in candidates:
        if cand[0] >= last_end:
            accepted.append(cand)
            last_end = cand[1]

    new_text = text
    edits: list[dict] = []
    for start, end, replacement, category, fp in reversed(accepted):
        new_text = new_text[:start] + replacement + new_text[end:]
        edits.append(
            {
                "category": category,
                "line": _line_of(text, start),
                "fingerprint": fp,
            }
        )
    edits.reverse()
    return new_text, edits


def _iter_files(paths: list[Path]) -> list[Path]:
    files: set[Path] = set()
    for p in paths:
        if p.is_dir():
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
                for name in sorted(names):
                    files.add(Path(root) / name)
        elif p.is_file():
            files.add(p)
    return sorted(files, key=lambda f: str(f).lower())


def _looks_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def _target_type(path: Path) -> str:
    """Dispatch a scan/redact target: ``"sqlite"``, ``"text"`` or ``"binary"``.

    SQLite stores are detected by extension first (cheap) and then by the
    ``SQLite format 3`` magic header, so derived databases — ``graph.db``,
    ``search.db``, ``memory.db``, ``acp-messages/*.db`` — are scanned as
    databases even when they reach us under an unusual name or no
    extension at all. Anything else that is not binary (``.md`` notes,
    ``.json``/``.jsonl`` exports, ``.env``, plain text) is scanned as text.
    """
    if path.suffix.lower() in _DB_SUFFIXES:
        return "sqlite"
    try:
        with open(path, "rb") as fh:
            head = fh.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return "binary"
    if head.startswith(_SQLITE_MAGIC):
        return "sqlite"
    if b"\x00" in head:
        return "binary"
    return "text"


def _leaf_strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _leaf_strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _leaf_strings(v)]
    return []


def _redact_leaves(obj) -> tuple[object, list[dict]]:
    """Clone ``obj`` with every string leaf passed through redact_text."""
    edits: list[dict] = []
    if isinstance(obj, str):
        new, edits = redact_text(obj)
        return new, edits
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nv, e = _redact_leaves(v)
            out[k] = nv
            edits.extend(e)
        return out, edits
    if isinstance(obj, list):
        out = []
        for v in obj:
            nv, e = _redact_leaves(v)
            out.append(nv)
            edits.extend(e)
        return out, edits
    return obj, edits


# Keys inside `content` subtrees that carry structure, not payload — they
# are preserved so the redacted JSON keeps its acp shape.
_STRUCTURAL_KEYS = frozenset({"type", "mimeType", "toolCallId", "status", "kind"})


def _tag_all_leaves(obj) -> tuple[object, list[str]]:
    """Replace every payload string leaf with its redaction tag; returns
    ``(new_obj, fingerprints_of_replaced_leaves)``. Idempotent."""
    fps: list[str] = []
    if isinstance(obj, str):
        if _REDACTED_TAG in obj:
            return obj, fps
        return _tag(obj), [_fingerprint(obj)]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _STRUCTURAL_KEYS and isinstance(v, str):
                out[k] = v
                continue
            nv, f = _tag_all_leaves(v)
            out[k] = nv
            fps.extend(f)
        return out, fps
    if isinstance(obj, list):
        out = []
        for v in obj:
            nv, f = _tag_all_leaves(v)
            out.append(nv)
            fps.extend(f)
        return out, fps
    return obj, fps


def _redact_content_leaves(obj) -> tuple[object, list[dict]]:
    """Wholesale-redact every string leaf inside ``content`` subtrees — the
    semantic-context path for tool output of sensitive reads."""
    edits: list[dict] = []
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "content":
                nv, fps = _tag_all_leaves(v)
                edits.extend(
                    {"category": _SEMANTIC_CATEGORY, "fingerprint": fp} for fp in fps
                )
            else:
                nv, e = _redact_content_leaves(v)
                edits.extend(e)
            out[k] = nv
        return out, edits
    if isinstance(obj, list):
        out = []
        for v in obj:
            nv, e = _redact_content_leaves(v)
            out.append(nv)
            edits.extend(e)
        return out, edits
    return obj, edits


def _scan_cell(value: str, display: str, location: str) -> list[Finding]:
    """Scan one text cell. JSON cells are decoded so multi-line payload
    strings (e.g. tool-call output) get real newlines — otherwise
    line-anchored patterns like ``env_assignment`` would miss them."""
    stripped = value.lstrip()
    texts: list[str]
    if stripped.startswith(("{", "[")):
        try:
            texts = _leaf_strings(json.loads(value))
        except (json.JSONDecodeError, RecursionError):
            texts = [value]
    else:
        texts = [value]
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for text in texts:
        for f in scan_text(text, file=display, location=location):
            key = (str(f["category"]), str(f["fingerprint"]))
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)
    return findings


# --------------------------------------------------------------------------
# Cross-chunk pass (RD-2)
# --------------------------------------------------------------------------
#
# A secret streamed in pieces can land split across two adjacent payloads —
# half an AWS key at the end of one tool output, the rest at the start of
# the next. Each payload alone matches no pattern, so per-cell scanning
# misses it. The pass below re-scans *concatenations* of adjacent text
# payloads — `tool_call_json`+`tool_call_update_json` of the same
# `tool_call_state` row, adjacent `tool_call_state` rows of the same
# session, adjacent `message_nodes` rows of the same session, and leaves
# inside one payload (streaming parts) — keeping it strictly bounded:
# adjacent pairs only, same session only, and the full pattern suite only
# runs when a cheap boundary pre-filter says a split is plausible.

# How many leaves off a payload edge are considered "near the boundary".
_CHUNK_EDGE_LEAVES = 8
# Window (chars off the end of a payload) searched for context patterns.
_SPLIT_TAIL_WINDOW = 160
# A token-ish run spanning a payload boundary with at least this many
# combined chars is scanned unconditionally — every pattern-shaped secret
# is a long token, so this catches splits at *any* byte offset, including
# 1-char fragments that contain no marker at all.
_BOUNDARY_RUN_MIN = 12
# Token-ish run at a payload edge: a split secret continues as word chars.
_TOKEN_EDGE = re.compile(r"[A-Za-z0-9_+/.~=-]+")
_TOKEN_TAIL = re.compile(r"[A-Za-z0-9_+/.~=-]+$")
# Distinctive starts of the secret shapes in `patterns.py`. A payload whose
# trailing token contains one of these (or ends mid-marker) may hold the
# first half of a split secret.
_SPLIT_HEAD_MARKERS = (
    "AKIA",
    "ASIA",
    "sk-",
    "sk_live_",
    "rk_live_",
    "AIza",
    "xox",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "eyJ",
    "-----BEGIN",
)
# Context-dependent secret shapes: the keyword part sits in the earlier
# payload, the sensitive tail runs to (or past) the boundary.
_SPLIT_CONTEXT_RES = (
    re.compile(r"[Bb]earer(?:\s+[A-Za-z0-9._~+/=-]*)?$"),
    re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*"
        r"(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*"
        r"\s*=\s*\S*$"
    ),
    re.compile(r"(?i)(?:pairing|pair)[ -]?code\s*[:=]?\s*[A-Z0-9-]{0,}$"),
)


def _payload_parts(value) -> tuple[list[str], str]:
    """Flatten one cell to ``(leaf_strings, joined_text)``."""
    if not isinstance(value, str) or not value:
        return [], ""
    stripped = value.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            leaves = _leaf_strings(json.loads(value))
        except (json.JSONDecodeError, RecursionError):
            leaves = [value]
    else:
        leaves = [value]
    return leaves, "".join(leaves)


def _edge(text: str) -> tuple[int, int, bool]:
    """Boundary descriptor for one payload: ``(head_len, tail_len,
    suspicious_tail)``.

    ``head_len``/``tail_len`` are the token-ish runs at the start/end of
    ``text``; ``suspicious_tail`` is true when the trailing token contains
    a secret-shape marker (or a marker prefix) or the tail window ends
    inside a context pattern (`Bearer …`, `KEY=…`, `pairing code: …`)
    whose value reaches the boundary. Computed once per payload so pair
    checks are arithmetic, not regex calls.
    """
    head_match = _TOKEN_EDGE.match(text) if text else None
    tail_match = _TOKEN_TAIL.search(text) if text else None
    tail = tail_match.group(0) if tail_match else ""
    suspicious = False
    if tail:
        for marker in _SPLIT_HEAD_MARKERS:
            if marker in tail or marker.startswith(tail):
                suspicious = True
                break
    if not suspicious and text:
        window = text[-_SPLIT_TAIL_WINDOW:]
        suspicious = any(rx.search(window) for rx in _SPLIT_CONTEXT_RES)
    return (len(head_match.group(0)) if head_match else 0, len(tail), suspicious)


def _maybe_split(a: tuple[int, int, bool], b: tuple[int, int, bool]) -> bool:
    """Cheap pre-filter: could ``a`` end mid-secret that ``b`` continues?

    ``a``/``b`` are :func:`_edge` descriptors. Requires ``b`` to open with
    a token-ish run (the continuation), then either a token-run of secret
    length spanning the boundary (covers splits at any byte offset, even
    1-char fragments) or a suspicious tail on ``a``.
    """
    head_b = b[0]
    if not head_b:
        return False
    tail_len, suspicious = a[1], a[2]
    if tail_len and tail_len + head_b >= _BOUNDARY_RUN_MIN:
        return True
    return suspicious


def _chunk_finding(
    f: Finding, location: str, combined_with: str | None
) -> Finding:
    f["kind"] = "cross-chunk"
    f["location"] = location
    if combined_with:
        f["combined_with"] = combined_with
    return f


def _unit_chunk_findings(
    leaves: list[str],
    text: str,
    known: set[tuple[str, str]],
    display: str,
    location: str,
) -> list[Finding]:
    """Findings reassembled *inside* one payload — secrets split across
    streaming parts (adjacent leaves) of a single cell."""
    out: list[Finding] = []
    n = len(leaves)
    if n < 2:
        return out
    edges = [_edge(leaf) for leaf in leaves]
    seen = set(known)
    # The whole-joined scan catches secrets spanning several contiguous
    # leaves. It only runs when some adjacent leaf boundary looks like a
    # mid-secret split — a contiguous span always crosses one.
    if any(_maybe_split(edges[i], edges[i + 1]) for i in range(n - 1)):
        for f in scan_text(text, file=display, location=location):
            key = (str(f["category"]), str(f["fingerprint"]))
            if key in seen:
                continue
            seen.add(key)
            out.append(_chunk_finding(f, location, None))
    # Pairwise edge leaves catch non-contiguous splits — JSON structural
    # leaves (`"type"`, `"content"`) sit between the halves in the joined
    # text, so the whole-joined scan cannot see those.
    for i in range(n):
        la = leaves[i]
        for j in range(i + 1, min(i + _CHUNK_EDGE_LEAVES + 1, n)):
            if not _maybe_split(edges[i], edges[j]):
                continue
            for f in scan_text(la + leaves[j], file=display, location=location):
                key = (str(f["category"]), str(f["fingerprint"]))
                if key in seen:
                    continue
                seen.add(key)
                out.append(_chunk_finding(f, location, None))
    return out


def _pair_chunk_findings(
    unit_a: tuple[list[str], str],
    unit_b: tuple[list[str], str],
    known: set[tuple[str, str]],
    display: str,
    location: str,
    combined_with: str,
) -> list[Finding]:
    """Findings reassembled across the boundary of two adjacent payloads.

    Candidate concatenations: the whole joined texts, each side's text
    against the other side's boundary leaves, and pairwise edge leaves —
    JSON structural leaves (`"type"`, `"content"`, ids) otherwise sit
    between the halves and would keep them apart.
    """
    leaves_a, text_a = unit_a
    leaves_b, text_b = unit_b
    edge_a = leaves_a[-_CHUNK_EDGE_LEAVES:]
    edge_b = leaves_b[:_CHUNK_EDGE_LEAVES]
    edge_text_a = _edge(text_a)
    edge_text_b = _edge(text_b)
    edges_a = [_edge(la) for la in edge_a]
    edges_b = [_edge(lb) for lb in edge_b]
    candidates: list[tuple[tuple[int, int, bool], tuple[int, int, bool], str, str]] = [
        (edge_text_a, edge_text_b, text_a, text_b)
    ]
    candidates += [
        (edge_text_a, edges_b[k], text_a, lb) for k, lb in enumerate(edge_b)
    ]
    candidates += [
        (edges_a[k], edge_text_b, la, text_b) for k, la in enumerate(edge_a)
    ]
    candidates += [
        (ea, eb, la, lb) for ea, la in zip(edges_a, edge_a) for eb, lb in zip(edges_b, edge_b)
    ]
    out: list[Finding] = []
    seen = set(known)
    for ea, eb, a, b in candidates:
        if not _maybe_split(ea, eb):
            continue
        for f in scan_text(a + b, file=display, location=location):
            key = (str(f["category"]), str(f["fingerprint"]))
            if key in seen:
                continue
            seen.add(key)
            out.append(_chunk_finding(f, location, combined_with))
    return out


def _known_by_location(findings: list[Finding]) -> dict[str, set[tuple[str, str]]]:
    """Map each ``table.column#rowid=N`` locator to the ``(category,
    fingerprint)`` pairs the per-cell pass already found there — so the
    chunked pass dedupes without rescanning."""
    known: dict[str, set[tuple[str, str]]] = {}
    for f in findings:
        loc = str(f.get("location", ""))
        if "#rowid=" not in loc:
            continue
        known.setdefault(loc, set()).add(
            (str(f["category"]), str(f["fingerprint"]))
        )
    return known


def _scan_chunked(
    con: sqlite3.Connection,
    display: str,
    session_id: str | None = None,
    scanned: list[Finding] | None = None,
) -> list[Finding]:
    """Cross-chunk pass over the sessions.db-shaped tables.

    Bounded: only `tool_call_state` and `message_nodes`, only adjacent
    rows, only inside one `session_id` (which is also the scoping key
    when ``session_id`` is given), and the full pattern suite only runs
    where the boundary pre-filter says a split is plausible.
    """
    findings: list[Finding] = []
    tables = set(_db_tables(con))
    specs = (
        ("tool_call_state", ("tool_call_json", "tool_call_update_json")),
        ("message_nodes", ("chat_message",)),
    )
    known_by_loc = _known_by_location(scanned or [])
    for table, cols in specs:
        if table not in tables:
            continue
        existing = {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}
        if not set(cols) <= existing:
            continue
        has_session = "session_id" in existing
        try:
            rows = sorted(_db_rows(con, table, session_id), key=lambda r: r[0])
        except sqlite3.Error:
            continue
        label = "+".join(cols)
        units: list[tuple[int, object, list[str], str, set[tuple[str, str]]]] = []
        for rowid, cells in rows:
            leaves: list[str] = []
            parts: list[str] = []
            known: set[tuple[str, str]] = set()
            for col in cols:
                ls, t = _payload_parts(cells.get(col))
                leaves.extend(ls)
                parts.append(t)
                known |= known_by_loc.get(
                    f"{table}.{col}#rowid={rowid}", set()
                )
            text = "".join(parts)
            location = f"{table}.{label}#rowid={rowid}"
            new = _unit_chunk_findings(leaves, text, known, display, location)
            findings.extend(new)
            known |= {
                (str(f["category"]), str(f["fingerprint"])) for f in new
            }
            units.append((rowid, cells.get("session_id"), leaves, text, known))
        for a, b in itertools.pairwise(units):
            rid_a, sess_a, leaves_a, text_a, known_a = a
            rid_b, sess_b, leaves_b, text_b, known_b = b
            if has_session and session_id is None and (not sess_a or sess_a != sess_b):
                continue
            loc_a = f"{table}.{label}#rowid={rid_a}"
            loc_b = f"{table}.{label}#rowid={rid_b}"
            findings.extend(
                _pair_chunk_findings(
                    (leaves_a, text_a),
                    (leaves_b, text_b),
                    known_a | known_b,
                    display,
                    loc_a,
                    loc_b,
                )
            )
    return findings


def _open_ro(path: Path) -> sqlite3.Connection:
    uri = "file:" + str(path.resolve()).replace("\\", "/") + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _db_tables(con: sqlite3.Connection) -> list[str]:
    return [
        r[0]
        for r in con.execute(
            "select name from sqlite_master where type='table' "
            "and name not like 'sqlite_%' order by name"
        )
    ]


def _db_rows(con: sqlite3.Connection, table: str, session_id: str | None = None):
    """Yield ``(rowid, {col: value})`` for rows of ``table``.

    With ``session_id``, only rows attributed to that session are yielded:
    tables with a ``session_id`` column are filtered on it, ``sessions``
    is filtered on ``id``, and tables with neither contribute nothing
    (global stores like ``app_state`` are not session data).
    """
    safe = table.replace('"', '""')
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{safe}")')]
    where, args = "", ()
    if session_id is not None:
        if "session_id" in cols:
            where, args = " WHERE session_id = ?", (session_id,)
        elif table == "sessions" and "id" in cols:
            where, args = " WHERE id = ?", (session_id,)
        else:
            return
    for row in con.execute(f'SELECT rowid, * FROM "{safe}"{where}', args):
        yield row[0], dict(zip(cols, row[1:]))


def _semantic_finding(display: str, location: str, flag: dict, output: str) -> Finding:
    return {
        "file": display,
        "category": _SEMANTIC_CATEGORY,
        "pattern": "sensitive_read",
        "kind": "semantic-context",
        "location": location,
        "fingerprint": _fingerprint(output),
        "preview": _mask(output) if output else "(empty output)",
        "reason": flag["reason"],
        "target": flag["target"],
    }


def _scan_db(
    path: Path, display: str, session_id: str | None = None
) -> tuple[list[Finding], str | None]:
    """Scan every TEXT-looking cell of a SQLite DB, plus the tool-call
    semantic layer over ``tool_call_state``.

    With ``session_id``, only rows attributed to that session are scanned
    (see :func:`_db_rows`). The ``sessions`` table itself is skipped in
    that mode — its row is session metadata (working dir, title), not a
    message, and the ``project_name``/``absolute_path`` hygiene findings
    it yields would make every session verdict ``REVIEW``."""
    findings: list[Finding] = []
    try:
        con = _open_ro(path)
    except sqlite3.Error as exc:
        return findings, f"sqlite open failed: {exc}"
    try:
        for table in _db_tables(con):
            if session_id is not None and table == "sessions":
                continue
            try:
                rows = list(_db_rows(con, table, session_id))
            except sqlite3.Error:
                continue
            for rowid, cells in rows:
                for col_name, value in cells.items():
                    if not isinstance(value, str) or not value:
                        continue
                    location = f"{table}.{col_name}#rowid={rowid}"
                    findings.extend(_scan_cell(value, display, location))
                    if (
                        table == "sessions"
                        and col_name == "working_directory"
                        and session_id is None
                        and _REDACTED_TAG not in value
                    ):
                        base = PurePosixPath(value.replace("\\", "/")).name
                        if base:
                            findings.append(
                                {
                                    "file": display,
                                    "category": "project_name",
                                    "pattern": "working_directory",
                                    "kind": "metadata",
                                    "location": location,
                                    "fingerprint": _fingerprint(base),
                                    "preview": _mask(base),
                                }
                            )
                if table == "tool_call_state":
                    call_json = cells.get("tool_call_json")
                    update_json = cells.get("tool_call_update_json")
                    if not isinstance(call_json, str):
                        continue
                    flag = analyze_tool_call_json(call_json)
                    if flag and isinstance(update_json, str):
                        location = f"{table}.tool_call_update_json#rowid={rowid}"
                        if _REDACTED_TAG not in update_json:
                            findings.append(
                                _semantic_finding(display, location, flag, update_json)
                            )
        findings.extend(_scan_chunked(con, display, session_id, findings))
    except sqlite3.Error as exc:
        return findings, f"sqlite scan failed: {exc}"
    finally:
        con.close()
    return findings, None


def _scan_text_file(path: Path, display: str) -> tuple[list[Finding], str | None]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [], f"read failed: {exc}"
    text = raw.decode("utf-8", errors="replace")
    return scan_text(text, file=display, location="text"), None


def _summarize(findings: list[Finding]) -> tuple[dict[str, int], int, str]:
    by_category: dict[str, int] = {}
    for fd in findings:
        cat = str(fd["category"])
        by_category[cat] = by_category.get(cat, 0) + 1
    secrets = sum(by_category.get(c, 0) for c in _BLOCKING_CATEGORIES)
    if secrets:
        status = "BLOCKED"
    elif findings:
        status = "REVIEW"
    else:
        status = "CLEAN"
    return dict(sorted(by_category.items())), secrets, status


def _report(
    scanned: int, findings: list[Finding], errors: list[dict]
) -> dict:
    """Assemble the SPEC §6 report shared by ``scan``/``scan_blobs``."""
    findings.sort(
        key=lambda x: (str(x["file"]), str(x["location"]), str(x["category"]), str(x["fingerprint"]))
    )
    by_category, secrets, status = _summarize(findings)
    return {
        "tool": "devin-redact",
        "version": __version__,
        "files_scanned": scanned,
        "secrets": secrets,
        "emails": by_category.get("email", 0),
        "absolute_paths": by_category.get("absolute_path", 0),
        "project_names": by_category.get("project_name", 0),
        "findings_total": len(findings),
        "by_category": by_category,
        "publication_status": status,
        "findings": findings,
        "errors": errors,
    }


def scan(paths) -> dict:
    """Scan files/directories and return the report contract (SPEC §6).

    Deterministic: identical input yields identical output.
    """
    files = _iter_files([Path(p) for p in paths])
    all_findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    scanned = 0

    for f in files:
        display = str(f)
        kind = _target_type(f)
        if kind == "sqlite":
            findings, err = _scan_db(f, display)
        elif kind == "binary":
            errors.append({"file": display, "error": "skipped: binary file"})
            continue
        else:
            findings, err = _scan_text_file(f, display)
        scanned += 1
        all_findings.extend(findings)
        if err:
            errors.append({"file": display, "error": err})

    return _report(scanned, all_findings, errors)


def _blob_kind(name: str, blob: bytes) -> str:
    """Dispatch a ``(name, content)`` blob — the in-memory counterpart
    of :func:`_target_type`: sqlite by suffix first then magic header,
    binary by NUL byte, text otherwise."""
    if Path(name).suffix.lower() in _DB_SUFFIXES:
        return "sqlite"
    head = blob[:_BINARY_SNIFF_BYTES]
    if head.startswith(_SQLITE_MAGIC):
        return "sqlite"
    if b"\x00" in head:
        return "binary"
    return "text"


def _scan_blob_db(
    name: str, blob: bytes, sidecars: dict[str, bytes] | None = None
) -> tuple[list[Finding], str | None]:
    """Scan a SQLite blob via a temp file — ``sqlite3`` needs a real path.

    ``sidecars`` carries the staged ``-wal``/``-shm``/``-journal`` siblings
    of ``name`` as ``{suffix: content}``. A WAL-mode store staged between
    checkpoints keeps committed rows only in ``<db>-wal``, so that file is
    materialized next to the temp db and sqlite replays it on open — the
    same view a checkout of the commit produces. ``-shm`` is a transient
    index sqlite rebuilds and ``-journal`` only triggers the rollback a
    checkout would run anyway, so neither is materialized.
    """
    fd, tmp_name = tempfile.mkstemp(suffix=".db")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        wal = (sidecars or {}).get("-wal")
        if wal is not None:
            Path(tmp_name + "-wal").write_bytes(wal)
        return _scan_db(Path(tmp_name), name)
    finally:
        Path(tmp_name).unlink(missing_ok=True)
        Path(tmp_name + "-wal").unlink(missing_ok=True)
        Path(tmp_name + "-shm").unlink(missing_ok=True)


def scan_blobs(blobs, *, errors: list[dict] | None = None) -> dict:
    """Scan ``(display_name, content_bytes)`` pairs and return the same
    report contract as :func:`scan`.

    This is the staged-blob path of the pre-commit gate
    (``devin_redact.staged``): the working tree is not authoritative for
    what a commit records — content may be edited or deleted after
    ``git add`` — so the bytes come from the caller (the git index)
    rather than the filesystem. ``errors`` seeds the report's error
    list with resolution failures (e.g. paths with no staged blob).

    SQLite sidecar blobs (``<db>-wal``, ``-shm``, ``-journal``) are not
    scanned standalone: they group with their primary database so a
    staged WAL-mode store is scanned with its uncheckpointed commits
    replayed. Attached sidecars count toward ``files_scanned``; orphans
    (no staged primary) dispatch as ordinary blobs.
    """
    all_findings: list[Finding] = []
    errs: list[dict] = list(errors or [])
    scanned = 0

    sidecars: dict[str, dict[str, bytes]] = {}
    primaries: list[tuple[str, bytes]] = []
    for name, blob in blobs:
        suffix = next(
            (s for s in _DB_SIDECAR_SUFFIXES if name.endswith(s)), None
        )
        if suffix is None:
            primaries.append((name, blob))
        else:
            sidecars.setdefault(name[: -len(suffix)], {})[suffix] = blob

    def _scan_one(
        name: str, blob: bytes, sc: dict[str, bytes] | None = None
    ) -> None:
        nonlocal scanned
        kind = _blob_kind(name, blob)
        if kind == "sqlite":
            findings, err = _scan_blob_db(name, blob, sc)
        elif kind == "binary":
            errs.append({"file": name, "error": "skipped: binary file"})
            return
        else:
            findings = scan_text(
                blob.decode("utf-8", "replace"), file=name, location="text"
            )
            err = None
        scanned += 1
        all_findings.extend(findings)
        if err:
            errs.append({"file": name, "error": err})

    for name, blob in primaries:
        if name in sidecars and _blob_kind(name, blob) == "sqlite":
            sc = sidecars.pop(name)
            _scan_one(name, blob, sc)
            scanned += len(sc)
        else:
            _scan_one(name, blob)

    # Sidecars whose primary is absent or not a SQLite blob stand alone.
    for base, sc in sidecars.items():
        for suffix, blob in sc.items():
            _scan_one(base + suffix, blob)

    return _report(scanned, all_findings, errs)


def session_exists(db_path, session_id: str) -> bool | None:
    """Whether ``sessions`` contains ``session_id``.

    ``None`` when the question cannot be answered (unreadable DB, no
    ``sessions`` table) — callers treat that as "unknown", not absent.
    """
    try:
        con = _open_ro(Path(db_path))
    except sqlite3.Error:
        return None
    try:
        if "sessions" not in _db_tables(con):
            return None
        row = con.execute(
            "SELECT 1 FROM sessions WHERE id = ? LIMIT 1", (session_id,)
        ).fetchone()
        return row is not None
    except sqlite3.Error:
        return None
    finally:
        con.close()


def latest_session_id(db_path) -> str | None:
    """Most recently active session id in a ``sessions.db``, or ``None``
    when it cannot be determined (unreadable DB, no ``sessions`` table)."""
    try:
        con = _open_ro(Path(db_path))
    except sqlite3.Error:
        return None
    try:
        if "sessions" not in _db_tables(con):
            return None
        row = con.execute(
            "SELECT id FROM sessions ORDER BY last_activity_at DESC LIMIT 1"
        ).fetchone()
        return str(row[0]) if row else None
    except sqlite3.Error:
        return None
    finally:
        con.close()


def scan_session(db_path, session_id: str) -> dict:
    """Scan the rows of one session in a ``sessions.db``-shaped store.

    Same finding/report vocabulary as :func:`scan` but scoped by
    ``session_id`` (see :func:`_db_rows`); read-only. Used by the
    ``session-end`` hook so it audits the just-ended session instead of
    re-scanning the whole store. The ``project_name`` metadata finding is
    skipped in this mode — it comes from the session's own
    ``working_directory`` and would make every verdict REVIEW.
    """
    path = Path(db_path)
    display = str(path)
    findings, err = _scan_db(path, display, session_id=session_id)
    findings.sort(
        key=lambda x: (str(x["file"]), str(x["location"]), str(x["category"]), str(x["fingerprint"]))
    )
    by_category, secrets, status = _summarize(findings)
    return {
        "tool": "devin-redact",
        "version": __version__,
        "session_id": session_id,
        "files_scanned": 1,
        "secrets": secrets,
        "findings_total": len(findings),
        "by_category": by_category,
        "publication_status": status,
        "findings": findings,
        "errors": [{"file": display, "error": err}] if err else [],
    }


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------


def _plan_cell(value: str, semantic_output: bool) -> tuple[str | None, list[dict]]:
    """Return ``(new_value, edits)`` or ``(None, [])`` when unchanged."""
    stripped = value.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            obj = json.loads(value)
        except (json.JSONDecodeError, RecursionError):
            new, edits = redact_text(value)
            return (new, edits) if edits else (None, [])
        if semantic_output:
            new_obj, edits = _redact_content_leaves(obj)
        else:
            new_obj, edits = _redact_leaves(obj)
        if not edits:
            return None, []
        return json.dumps(new_obj, ensure_ascii=False), edits
    if semantic_output:
        if _REDACTED_TAG in value:
            return None, []
        return _tag(value), [{"category": _SEMANTIC_CATEGORY, "fingerprint": _fingerprint(value)}]
    new, edits = redact_text(value)
    return (new, edits) if edits else (None, [])


def _plan_db(path: Path, display: str) -> tuple[list[dict], str | None]:
    """Plan cell updates for a SQLite DB."""
    cell_edits: list[dict] = []
    try:
        con = _open_ro(path)
    except sqlite3.Error as exc:
        return cell_edits, f"sqlite open failed: {exc}"
    try:
        for table in _db_tables(con):
            try:
                rows = list(_db_rows(con, table))
            except sqlite3.Error:
                continue
            for rowid, cells in rows:
                semantic_cols: set[str] = set()
                if table == "tool_call_state":
                    flag = analyze_tool_call_json(str(cells.get("tool_call_json") or ""))
                    if flag:
                        semantic_cols.add("tool_call_update_json")
                for col_name, value in cells.items():
                    if not isinstance(value, str) or not value:
                        continue
                    new_value, edits = _plan_cell(value, col_name in semantic_cols)
                    if new_value is None:
                        continue
                    cell_edits.append(
                        {
                            "table": table,
                            "column": col_name,
                            "rowid": rowid,
                            "new_value": new_value,
                            "edits": edits,
                        }
                    )
    except sqlite3.Error as exc:
        return cell_edits, f"sqlite scan failed: {exc}"
    finally:
        con.close()
    return cell_edits, None


def _backup(path: Path) -> Path:
    bak = path.with_name(path.name + ".bak")
    shutil.copy2(path, bak)
    for side in (path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        if side.exists():
            shutil.copy2(side, side.with_name(side.name + ".bak"))
    return bak


def _update_cell(con: sqlite3.Connection, edit: dict) -> None:
    con.execute(
        f'UPDATE "{edit["table"].replace(chr(34), chr(34) * 2)}" '
        f'SET "{edit["column"].replace(chr(34), chr(34) * 2)}" = ? WHERE rowid = ?',
        (edit["new_value"], edit["rowid"]),
    )


def _apply_db(path: Path, cell_edits: list[dict]) -> None:
    """Apply cell updates in one transaction; rollback + restore on failure."""
    _backup(path)
    con = sqlite3.connect(path)
    try:
        con.execute("BEGIN")
        for edit in cell_edits:
            _update_cell(con, edit)
        con.commit()
    except Exception:
        con.rollback()
        con.close()
        raise
    con.close()
    # Post-redact open test: the DB must still parse.
    try:
        chk = _open_ro(path)
        (ok,) = chk.execute("PRAGMA integrity_check").fetchone()
        chk.execute("SELECT count(*) FROM sqlite_master").fetchone()
        chk.close()
        if ok != "ok":
            raise sqlite3.DatabaseError(f"integrity_check: {ok}")
    except sqlite3.Error:
        bak = path.with_name(path.name + ".bak")
        shutil.copy2(bak, path)
        raise


def _apply_text(path: Path, new_text: str) -> None:
    """Atomic text rewrite: .bak first, then tmp file + os.replace."""
    _backup(path)
    tmp = path.with_name(path.name + ".redact-tmp")
    try:
        tmp.write_text(new_text, encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def redact(paths, *, apply: bool = False, confirm_irreversible: bool = False) -> dict:
    """Redact findings. Dry-run by default.

    ``apply=True`` writes masked replacements in place and requires
    ``confirm_irreversible=True`` (the CLI's ``--apply
    --i-know-this-is-irreversible``). Every modified file gets a ``.bak``
    sibling backup; DB writes run in a single transaction with a
    post-redact open test.
    """
    if apply and not confirm_irreversible:
        raise RuntimeError(
            "in-place redaction requires confirm_irreversible=True "
            "(CLI: --apply --i-know-this-is-irreversible)"
        )

    files = _iter_files([Path(p) for p in paths])
    planned: list[dict] = []  # per-file plans
    edit_log: list[dict] = []
    errors: list[dict[str, str]] = []

    for f in files:
        display = str(f)
        kind = _target_type(f)
        if kind == "sqlite":
            cell_edits, err = _plan_db(f, display)
            if err:
                errors.append({"file": display, "error": err})
                continue
            if cell_edits:
                planned.append({"kind": "db", "path": f, "cells": cell_edits})
                for cell in cell_edits:
                    for e in cell["edits"]:
                        edit_log.append(
                            {
                                "file": display,
                                "location": f"{cell['table']}.{cell['column']}#rowid={cell['rowid']}",
                                **e,
                            }
                        )
        elif kind == "binary":
            errors.append({"file": display, "error": "skipped: binary file"})
            continue
        else:
            try:
                raw = f.read_bytes()
                text = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                errors.append({"file": display, "error": f"read failed: {exc}"})
                continue
            new_text, edits = redact_text(text)
            if edits:
                planned.append({"kind": "text", "path": f, "new_text": new_text})
                for e in edits:
                    edit_log.append({"file": display, "location": f"line {e['line']}", **{k: v for k, v in e.items() if k != "line"}})

    result = {
        "dry_run": not apply,
        "applied": apply,
        "files_scanned": len(files),
        "files_changed": len(planned),
        "replacements": len(edit_log),
        "edits": sorted(edit_log, key=lambda e: (str(e["file"]), str(e["location"]))),
        "errors": errors,
        "backups": [],
    }

    if not apply:
        result["note"] = "dry-run — no file or database was modified"
        return result

    for plan in planned:
        path: Path = plan["path"]
        try:
            if plan["kind"] == "db":
                _apply_db(path, plan["cells"])
            else:
                _apply_text(path, plan["new_text"])
            result["backups"].append(str(path.with_name(path.name + ".bak")))
        except Exception as exc:  # noqa: BLE001 - collect per-file errors, keep applying
            errors.append({"file": str(path), "error": f"apply failed: {exc}"})
            result["applied_ok"] = False
    result.setdefault("applied_ok", not errors)
    return result
