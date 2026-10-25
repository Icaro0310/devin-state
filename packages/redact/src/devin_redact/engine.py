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
from .patterns import (
    ENV_NAME_PATTERN,
    PATTERNS,
    SECRET_CATEGORIES,
    pattern_name,
    sensitive_match,
)
from .semantic import analyze_tool_call_json

_DB_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
_SQLITE_MAGIC = b"SQLite format 3\x00"
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}
_BINARY_SNIFF_BYTES = 8192
_DB_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
_REDACTED_TAG = "<REDACTED:"
_SEMANTIC_CATEGORY = "sensitive_tool_output"
_BLOCKING_CATEGORIES = SECRET_CATEGORIES | {_SEMANTIC_CATEGORY}

# Names that mark content as text even when no codec accepts it —
# a staged ``.env`` or ``config.yaml`` whose bytes fail every decode is
# scanned lossy (surrogateescape + printable projection), never skipped
# silently: the gate cannot vouch for bytes it did not read.
_TEXT_SUFFIXES = {
    ".env", ".txt", ".md", ".markdown", ".rst", ".log",
    ".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".config", ".properties", ".xml", ".csv", ".tsv",
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash",
    ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".rb", ".go", ".rs",
    ".java", ".kt", ".c", ".h", ".cpp", ".hpp", ".cs", ".php",
    ".pl", ".lua", ".sql", ".html", ".htm", ".css", ".tf",
    ".pem", ".key", ".crt", ".cer", ".pub", ".asc",
}
_TEXT_BASENAMES = {
    ".env", ".envrc", ".netrc", ".npmrc", ".pypirc", ".gitconfig",
    ".git-credentials", ".htpasswd", ".pgpass", "dockerfile",
    "makefile", "gnumakefile", "id_rsa", "id_dsa", "id_ecdsa",
    "id_ed25519", "credentials", "secrets",
}


def _text_marked(name: str) -> bool:
    """Does this path's *name* mark it as text — a file the gate must
    never skip silently? Suffix list plus well-known credential-ish
    basenames (``.env*`` included — dotfiles carry no suffix)."""
    base = PurePosixPath(str(name).replace("\\", "/")).name.lower()
    if base in _TEXT_BASENAMES or base.startswith(".env"):
        return True
    return Path(base).suffix.lower() in _TEXT_SUFFIXES

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
    r"^\s*(?:[(\[{]|[A-Za-z_][\w.]*\s*\(|lambda\b)"
)

# A bare type expression: dotted/subscripted atoms joined by ``|`` —
# ``str``, ``Optional[str]``, ``typing.List[int]``, ``list[str] | None``.
_TYPE_ATOM = (
    r"[A-Za-z_][\w.]*"
    r"(?:\[[^\[\]\n]*(?:\[[^\[\]\n]*\][^\[\]\n]*)*\])?"
)
_TYPE_EXPR_RE = re.compile(
    _TYPE_ATOM + r"(?:\s*\|\s*" + _TYPE_ATOM + r")*"
)
# Builtin + typing names a bare annotation can resolve to. Lowercase
# scalars that are not in this set (``hunter2``) stay flagged.
_TYPE_NAMES = frozenset(
    {
        "str", "int", "float", "bool", "bytes", "bytearray", "complex",
        "dict", "list", "set", "tuple", "frozenset", "type", "object",
        "memoryview", "range", "slice", "None", "True", "False",
        "Ellipsis", "NotImplemented", "Any", "Optional", "Union",
        "Literal", "Annotated", "Callable", "ClassVar", "Final",
        "Self", "Never", "NoReturn", "IO", "Text", "Pattern", "Match",
        "Sequence", "Mapping", "Iterable", "Iterator", "Awaitable",
        "Coroutine", "Generator", "ContextManager", "PathLike",
        "date", "datetime", "time", "timedelta", "Decimal", "UUID",
        "Path", "SecretStr",
    }
)


# A dotted path in annotation position — ``pathlib.Path``,
# ``datetime.datetime``, ``typing.Optional``. The terminal segment of a
# real annotation names a type: a builtin/typing name or, by
# convention, a CapWords class. A bare ``abc.def`` whose last segment is
# neither is credential-shaped (``api_key: abc.def``), not an
# annotation.
_DOTTED_PATH_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")


def _dotted_terminal_is_type(path: str) -> bool:
    """Is the last segment of a dotted path a plausible type name —
    builtin/typing (``datetime.datetime``) or CapWords class
    (``pathlib.Path``, ``models.User``)?"""
    last = path.rsplit(".", 1)[1]
    return last in _TYPE_NAMES or last[:1].isupper()


def _looks_like_type_annotation(rhs: str) -> bool:
    """True when ``rhs`` is a bare type expression, not a secret value.

    ``api_key: str`` and ``token: Optional[str]`` are source-language
    type annotations, but the colon pattern also fires on them —
    flagging (and worse, redacting) the type corrupts the code. Only
    shapes that can *only* name a type are suppressed: a subscripted
    generic, a ``|`` union, a dotted path whose terminal segment is a
    type name, a builtin/typing name, or an annotation with a
    ``= default`` tail. A bare lowercase scalar (``api_key: hunter2``),
    a lowercase dotted scalar (``api_key: abc.def`` — credential-shaped,
    not a type) or any quoted value still flags — a quoted ``"str"`` is
    a real string value in YAML/JSON, never an annotation.
    """
    v = rhs.strip()
    if not v:
        return False
    v = v.split(" #", 1)[0].rstrip()   # trailing comment
    v = v.split("=", 1)[0].rstrip()    # annotated default: ``x: T = ...``
    if not v or not _TYPE_EXPR_RE.fullmatch(v):
        return False
    if "[" in v or "|" in v:
        # generic / union — but a credential can hide inside a
        # subscript (``list[abc.def]``), so every dotted path in the
        # expression must still terminate in a type-like name.
        return all(
            _dotted_terminal_is_type(m.group(0))
            for m in _DOTTED_PATH_RE.finditer(v)
        )
    if "." in v:
        # ``mod.Type`` is an annotation; ``abc.def``/``v1.2`` is a
        # credential-shaped scalar. Require a well-formed dotted path
        # whose terminal segment reads like a type name.
        return (
            _DOTTED_PATH_RE.fullmatch(v) is not None
            and _dotted_terminal_is_type(v)
        )
    return v in _TYPE_NAMES


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

    The separator is the FIRST ``:``/``=`` in the match — variable
    names can contain neither, so it is always the real assignment
    point. Looking for ``=`` alone inspected text *inside* quoted
    values: ``"api_key": "hello=fetch()"`` saw the ``=`` mid-string and
    suppressed the pair as a call. Bare type expressions are suppressed
    too (``api_key: str`` is an annotation, not a value).
    """
    sep = re.search(r"[:=]", whole)
    if sep is None:
        return False
    rhs = whole[sep.end() :]
    if _looks_like_type_annotation(rhs):
        return True
    if not _CODE_VALUE_RE.match(rhs):
        return False
    return not _literal_string_value(rhs)


# A closed ``<REDACTED:…>`` tag — prior redaction output. Only this span
# is off-limits to re-processing; text around it is not.
_TAG_RUN = re.compile(r"<REDACTED:[^>\n]*>")

# env_assignment pattern 0 without the ``(?m)^`` anchor — used ONLY by the
# tag-gap fragment rescan. The anchored pattern misses a ``KEY=``/``KEY:``
# candidate that does not lead the fragment: after a closed tag, non-key
# text may come first ('API_KEY=<tag>suffix OTHER_TOKEN=raw' left the tail
# raw — the TS port caught this in devin-powerups#223). ``\s*`` plus a
# word-boundary lookbehind on the name reproduces the anchored match
# exactly at a key-led fragment start — leading whitespace stays inside
# the match — and still finds each assignment later in the fragment.
_ENV_FRAGMENT_RE = re.compile(
    r"[\s\ufeff]*(?<!\w)(?:export\s+)?[\"']?" + ENV_NAME_PATTERN +
    r"[\"']?\s*[:=]\s*(?:"
    r"(?:\"(?:\\.|[^\"\\\r\n])*?\""
    r"|'(?:\\.|[^'\\\r\n])*?'"
    r"|`(?:\\.|[^`\\\r\n])*?`)"
    r"(?=[ \t]*[,}\]]|[ \t]*$)"
    r"|\S[^\n]*"
    r")"
)

# Tag-gap rescan regex per env_assignment pattern index: the anchored
# pattern needs its de-anchored twin; already-unanchored patterns (the
# JSON/dict colon form) rescan with themselves.
_ENV_FRAGMENT_RES: dict[int, re.Pattern[str]] = {0: _ENV_FRAGMENT_RE}


class _ShiftedMatch:
    """``re.Match`` facade whose positions are shifted by ``delta`` into
    the parent text's coordinates.

    Used for matches found while re-scanning a tag-free *fragment* of a
    skipped match — the fragment match reports offsets relative to the
    fragment, but consumers need offsets in the original text. Only the
    ``re.Match`` members the engine uses are proxied (``group``,
    ``start``, ``end``, ``span``, ``lastindex``).
    """

    __slots__ = ("_delta", "_m")

    def __init__(self, m: re.Match[str], delta: int) -> None:
        self._m = m
        self._delta = delta

    @property
    def lastindex(self) -> int | None:
        return self._m.lastindex

    def group(self, index: int = 0) -> str:
        return self._m.group(index)

    def start(self, index: int = 0) -> int:
        return self._m.start(index) + self._delta

    def end(self, index: int = 0) -> int:
        return self._m.end(index) + self._delta

    def span(self, index: int = 0) -> tuple[int, int]:
        start, end = self._m.span(index)
        return start + self._delta, end + self._delta


def _comment_start(s: str) -> int:
    """Index of the first ``#`` outside quotes — where comment text
    begins — or ``len(s)`` when the line has no comment."""
    single = double = False
    i = 0
    while i < len(s):
        ch = s[i]
        if single:
            if ch == "\\":
                i += 1
            elif ch == "'":
                single = False
        elif double:
            if ch == "\\":
                i += 1
            elif ch == '"':
                double = False
        elif ch == "'":
            single = True
        elif ch == '"':
            double = True
        elif ch == "#":
            return i
        i += 1
    return len(s)


def _enclosures_closed(s: str) -> bool:
    """True when ``s`` leaves no open enclosure: brackets balanced, no
    dangling quote, no comment.

    Used to tell whether a fragment boundary sits *inside* a literal,
    container or comment — where a redaction replacement could eat the
    enclosure's delimiters and corrupt valid source. A tiny state
    machine, not a parser: quotes inside the other quote kind and
    backslash escapes are handled; a ``#`` outside quotes makes the rest
    of the line a comment, so the candidate is dropped (an over-cautious
    answer only keeps the old skip, which is safe).
    """
    depth = 0
    single = double = False
    i = 0
    while i < len(s):
        ch = s[i]
        if single:
            if ch == "\\":
                i += 1  # escaped char — can't close the quote
            elif ch == "'":
                single = False
        elif double:
            if ch == "\\":
                i += 1
            elif ch == '"':
                double = False
        elif ch == "'":
            single = True
        elif ch == '"':
            double = True
        elif ch == "#":
            return False
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        i += 1
    return depth == 0 and not single and not double


def _iter_fragment_matches(
    rx: re.Pattern[str],
    text: str,
    lo: int,
    hi: int,
    env: bool,
    value_start: int,
):
    """Yield ``rx`` matches inside ``text[lo:hi]`` shifted by ``lo``.

    ``env`` candidates get the code-assignment guard plus the enclosure
    check: the value text from ``value_start`` must reach each side of
    the candidate with every bracket closed and quote paired — a
    candidate inside ``'…'``, ``"…"`` or ``[…``/``(…``/``{…`` is dropped
    rather than let its replacement eat delimiters.
    """
    if env:
        # An unquoted ``#`` starts a comment: the tail is comment text,
        # not rescan candidates — but the secret *before* it must still
        # redact, so the fragment is trimmed there (plus the whitespace
        # between value and marker, which belongs to the comment).
        hi = lo + _comment_start(text[lo:hi])
        while hi > lo and text[hi - 1] in " \t":
            hi -= 1
    if lo >= hi:
        return
    for m in rx.finditer(text[lo:hi]):
        whole = m.group(0)
        if _REDACTED_TAG in whole:
            # A malformed (unclosed) tag inside the fragment — still
            # never re-processed, same as the whole-match rule.
            continue
        if env:
            if _looks_like_code_assignment(whole):
                continue
            start, end = lo + m.start(), lo + m.end()
            if not (
                _enclosures_closed(text[value_start:start])
                and _enclosures_closed(text[value_start:end])
            ):
                continue
        yield _ShiftedMatch(m, lo)


def _iter_tag_gap(
    rx: re.Pattern[str],
    text: str,
    m: re.Match[str],
    env: bool,
    index: int = 0,
):
    """Yield ``rx`` matches inside the tag-free fragments of ``m``.

    A match containing ``<REDACTED:…>`` is prior redaction output — but
    only the tag's own span is off-limits. Greedy patterns reach past
    the tag: ``env_assignment`` swallows the rest of the line, so a
    second secret inside the same match — the ``OTHER=`` in
    ``KEY=<REDACTED:x> OTHER=raw`` — would stay raw if the whole match
    were dropped, and it can never match separately (the pattern is
    ``^``-anchored). Each tag-free fragment is therefore re-scanned with
    the same pattern (issue #66). A ``<REDACTED:`` prefix with no
    closing ``>`` is malformed, not a real tag — the old whole-match
    skip still applies there.
    """
    tags = list(_TAG_RUN.finditer(text, m.start(), m.end()))
    if not tags:
        return
    # env fragments re-scan with the per-pattern de-anchored variant —
    # the anchored pattern would miss an assignment that does not lead
    # the fragment (devin-powerups#223 parity note).
    scan_rx = _ENV_FRAGMENT_RES.get(index, rx) if env else rx
    # For env_assignment the enclosure state is measured from the
    # value's first char — the position after the ``=``/``:`` separator
    # (variable names can contain neither).
    if env:
        sep = re.search(r"[:=]", m.group(0))
        value_start = m.start() + (sep.start() + 1 if sep else 0)
    else:
        value_start = m.start()
    pos = m.start()
    for tag in tags:
        yield from _iter_fragment_matches(scan_rx, text, pos, tag.start(), env, value_start)
        pos = tag.end()
    yield from _iter_fragment_matches(scan_rx, text, pos, m.end(), env, value_start)


def _iter_matches(text: str):
    """Yield ``(category, pattern_name, match)`` for every pattern hit."""
    for category, regexes in PATTERNS.items():
        env = category == "env_assignment"
        for index, rx in enumerate(regexes):
            for m in rx.finditer(text):
                if _REDACTED_TAG in m.group(0):
                    # Prior redaction output — re-scan only the tag-free
                    # fragments; the env code guard and the enclosure
                    # check apply per fragment there.
                    for fm in _iter_tag_gap(rx, text, m, env, index):
                        yield category, pattern_name(category, index), fm
                    continue
                if env and _looks_like_code_assignment(m.group(0)):
                    continue
                yield category, pattern_name(category, index), m


def scan_text(text: str, *, file: str, location: str) -> list[Finding]:
    """Apply every pattern to ``text`` and return findings (sorted, deduped)."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    spans: dict[str, list[tuple[int, int]]] = {}
    for category, name, m in _iter_matches(text):
        value = sensitive_match(m)
        key = (category, name, m.start(1) if m.lastindex else m.start())
        if key in seen:
            continue
        seen.add(key)
        # A match strictly inside an earlier same-category match is the
        # same secret in a shorter form: the unterminated-PEM pattern is
        # a strict prefix of a complete block, so a terminated key must
        # not count twice (the longer, complete match wins because it
        # iterates first).
        span = m.span(0)
        bucket = spans.setdefault(category, [])
        if any(
            s <= span[0] and span[1] <= e and (s, e) != span
            for s, e in bucket
        ):
            continue
        bucket.append(span)
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
            # ``=`` or ``:`` — variable names (quoted or bare) contain
            # neither, so the first separator char is the assignment.
            eq = re.search(r"[:=]", whole).start()
            start, end = m.span(0)
            # A quoted value keeps its enclosing quotes — an unquoted
            # tag in a string slot breaks JSON/Python structure
            # (`"api_key":<REDACTED>` is invalid; `"api_key":"<tag>"`
            # is not). ``qm`` captures the optional whitespace plus the
            # (possibly ``\``-escaped) opening quote so the replacement
            # re-emits the same quote token on both sides.
            qm = re.match(r"\s*(\\?[\"'`])", whole[eq + 1 :])
            if qm:
                replacement = (
                    whole[: eq + 1] + qm.group(0)
                    + _tag(value) + qm.group(1)
                )
            else:
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
    return _decode_file_bytes(chunk) is None


def _mostly_printable(text: str) -> bool:
    """Conservative text check: ≤5% non-printable, non-whitespace chars."""
    if not text:
        return False
    bad = sum(
        1 for c in text if not (c.isprintable() or c in "\n\r\t\f\v")
    )
    return bad / len(text) <= 0.05


def _decode_file_bytes(raw: bytes) -> tuple[str, str] | None:
    """``(text, encoding)`` when ``raw`` plausibly holds text, else None.

    UTF-8 first — valid UTF-8 with a stray NUL still counts (the
    non-printable projection pass rejoins secrets a control byte splits).
    Then UTF-16: a BOM (``\\xff\\xfe``/``\\xfe\\xff``), or the BOM-less
    tell-tale of NULs clustered on one byte parity — the shape of
    ``API_KEY=…`` written by Windows PowerShell redirection, which the
    old NUL-byte sniff classified as opaque binary and skipped entirely.
    Decoded UTF-16 must contain no NUL and be mostly printable, so real
    binaries still fail closed into ``skipped: binary file``.

    Two refinements keep the sniff honest:

    * BOM'd input decodes with the endian-specific codec and keeps the
      ``\\ufeff`` char, so re-encoding via ``_apply_text`` re-emits the
      original byte order — a ``FE FF`` big-endian export no longer
      round-trips as ``FF FE``. The leading mark is ignored for the
      NUL/printability gates and never lands in a fingerprint
      (``sensitive_match`` strips it).
    * A truncated final character (a sniff slice can cut a surrogate
      pair at ``_BINARY_SNIFF_BYTES``) is dropped before judging — only
      when the decode error reaches the very end of ``raw``. That
      tolerance exists so the bounded sniffs (``_looks_binary``,
      ``_target_type``, ``_blob_kind``) and the read-only scans still
      see the decodable head; it must never reach a rewrite.
      ``redact()`` therefore re-verifies a non-UTF-8 decode against the
      whole file and carries any undecodable tail through
      ``_apply_text`` as raw bytes — a rewrite can no longer silently
      truncate the file.

    Last resort: a lossy ``surrogateescape`` UTF-8 decode. Text with a
    few invalid bytes — a staged ``.env`` holding a credential plus one
    bad byte — still scans instead of skipping as opaque binary; dense
    non-printable content keeps failing the printability gate and stays
    binary.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None and _mostly_printable(text):
        return text, "utf-8"

    enc: str | None = None
    if raw[:2] == b"\xff\xfe":
        enc = "utf-16-le"
    elif raw[:2] == b"\xfe\xff":
        enc = "utf-16-be"
    elif b"\x00" in raw:
        head = raw[:_BINARY_SNIFF_BYTES]
        even_nuls = sum(
            1 for i in range(0, len(head), 2) if head[i] == 0
        )
        odd_nuls = sum(
            1 for i in range(1, len(head), 2) if head[i] == 0
        )
        if odd_nuls >= max(3, even_nuls * 3):
            enc = "utf-16-le"
        elif even_nuls >= max(3, odd_nuls * 3):
            enc = "utf-16-be"
    if enc is not None:
        try:
            cand = raw.decode(enc)
        except UnicodeDecodeError as exc:
            # Truncated tail only — an error reaching the end of ``raw``
            # means the last code point is incomplete (sniff boundary).
            cand = None
            if exc.end >= len(raw):
                try:
                    cand = raw[: exc.start].decode(enc)
                except (UnicodeDecodeError, ValueError):
                    cand = None
        except ValueError:
            cand = None
        if cand is not None:
            check = cand.removeprefix("\ufeff")
            if "\x00" not in check and _mostly_printable(check):
                return cand, enc

    text = raw.decode("utf-8", "surrogateescape")
    if _mostly_printable(text):
        return text, "utf-8"
    return None


# ANSI escape sequences are stripped as *units* before the per-char
# drop: ``ESC`` alone is non-printable and falls away anyway, but its
# printable tail (``[31m`` of a colour code) would survive and keep a
# split token apart. Order matters — CSI/OSC/charset first, then the
# generic two-byte form.
_ANSI_SEQ_RE = re.compile(
    r"\x1b\[[0-9:;<=>?]*[ -/]*[@-~]"  # CSI  ESC [ params … final
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC  ESC ] … BEL/ST
    r"|\x1b[()][0-9A-Za-z]"  # charset selects  ESC ( 0
    r"|\x1b[@-Z\\-~]"  # remaining two-byte escapes (incl. ST)
)


def _printable_projection(text: str) -> str:
    """Drop ANSI escapes and non-printable chars (and U+FFFD from lossy
    decodes) — the scan-side twin of
    :func:`devin_redact.cflite._debinarize`: a secret split by a control
    byte, colour code, or stray NUL rejoins into one contiguous token
    and matches. Newlines/tabs survive."""
    text = _ANSI_SEQ_RE.sub("", text)
    return "".join(
        c
        for c in text
        if (c.isprintable() or c in "\n\r\t") and c != "\ufffd"
    )


def _scan_text_with_projection(
    text: str, *, file: str, location: str
) -> list[Finding]:
    """scan_text over ``text`` plus, when it holds non-printable chars,
    over its printable projection — findings from the projected view are
    marked ``kind="binary-projection"`` (offsets/lines are approximate
    there, and the per-cell rewrite cannot map them: detection-only)."""
    findings = scan_text(text, file=file, location=location)
    projected = _printable_projection(text)
    if projected == text:
        return findings
    seen = {
        (str(f["category"]), str(f["fingerprint"])) for f in findings
    }
    for f in scan_text(projected, file=file, location=location):
        key = (str(f["category"]), str(f["fingerprint"]))
        if key in seen:
            continue
        seen.add(key)
        f["kind"] = "binary-projection"
        findings.append(f)
    return findings


def _scan_lossy(raw: bytes, display: str) -> list[Finding]:
    """Fail-closed scan for bytes no decoder accepts but whose name is
    text-marked: decode with ``surrogateescape`` (keeps every byte) and
    let the printable projection rejoin the ASCII regions — a
    credential sitting beside undecodable noise can no longer ride a
    ``skipped: binary`` verdict through the gate."""
    return _scan_text_with_projection(
        raw.decode("utf-8", "surrogateescape"),
        file=display,
        location="text",
    )


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
    # NUL-bearing content is binary only when nothing decodes it —
    # UTF-16 exports and UTF-8-with-stray-NUL text are still scannable.
    if b"\x00" in head and _decode_file_bytes(head) is None:
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


def _key_strings(obj) -> list[str]:
    """String dict *keys* of a JSON payload — a secret can sit in key
    position (``{"sk-…": "enabled"}``-style config maps). Keys are kept
    out of ``_leaf_strings`` because the chunked pass joins leaves back
    together; they are scanned separately in :func:`_scan_cell`, and
    ``_redact_leaves`` rewrites a flagged key to its tag so detection
    and redaction cover the same surface."""
    if isinstance(obj, dict):
        out: list[str] = []
        for k, v in obj.items():
            if isinstance(k, str):
                out.append(k)
            out.extend(_key_strings(v))
        return out
    if isinstance(obj, list):
        return [s for v in obj for s in _key_strings(v)]
    return []


def _redact_leaves(obj) -> tuple[object, list[dict]]:
    """Clone ``obj`` with every string leaf passed through redact_text.

    A secret-shaped dict *key* is rewritten to its tag too — scan
    reports it via ``_key_strings`` but the value-only rewrite used to
    leave it shipping. The pair survives under the masked key so the
    document's shape is preserved (``{"sk-…": "enabled"}`` →
    ``{"<REDACTED:…>": "enabled"}``).
    """
    edits: list[dict] = []
    if isinstance(obj, str):
        new, edits = redact_text(obj)
        return new, edits
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nv, e = _redact_leaves(v)
            edits.extend(e)
            if isinstance(k, str):
                nk, ke = redact_text(k)
                if ke:
                    k = nk
                    edits.extend(ke)
            out[k] = nv
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
            obj = json.loads(value)
        except (json.JSONDecodeError, RecursionError):
            texts = [value]
        else:
            texts = _leaf_strings(obj) + _key_strings(obj)
    else:
        texts = [value]
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for text in texts:
        for f in _scan_text_with_projection(
            text, file=display, location=location
        ):
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
    "xapp-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat",
    "gldt",
    "glrt",
    "glcbt",
    "glagent",
    "npm_",
    "pypi-",
    "dop_v1_",
    "SG.",
    "sq0",
    "shp",
    "ya29.",
    "hf_",
    "whsec_",
    "AGE-SECRET-KEY-",
    "hooks.slack",
    "discord",
    "webhook",
    "://",
    "eyJ",
    "-----BEGIN",
)
# Context-dependent secret shapes: the keyword part sits in the earlier
# payload, the sensitive tail runs to (or past) the boundary.
_SPLIT_CONTEXT_RES = (
    re.compile(r"(?i)bearer[\s:=]*[A-Za-z0-9._~+/=-]*$"),
    re.compile(
        r"(?i)[\"']?[A-Za-z_][A-Za-z0-9_]*"
        r"(?:key|secret|token|password|passwd|credential|auth)"
        r"[A-Za-z0-9_]*[\"']?\s*[:=]\s*\S*$"
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
        # Per-cell locations carry a trailing ``:line N`` — the chunked
        # pass looks findings up by ``table.column#rowid=N``.
        loc = loc.split(":line ")[0]
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
    decoded = _decode_file_bytes(raw)
    if decoded is not None:
        return _scan_text_with_projection(
            decoded[0], file=display, location="text"
        ), None
    if _text_marked(path.name):
        return _scan_lossy(raw, display), None
    return [], "skipped: binary file"


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
        elif kind == "binary" and not _text_marked(f.name):
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
    binary when nothing decodes it, text otherwise."""
    if Path(name).suffix.lower() in _DB_SUFFIXES:
        return "sqlite"
    head = blob[:_BINARY_SNIFF_BYTES]
    if head.startswith(_SQLITE_MAGIC):
        return "sqlite"
    if b"\x00" in head and _decode_file_bytes(head) is None:
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

    SQLite sidecar blobs (``<db>-wal``, ``-shm``, ``-journal``) group
    with their primary database so a staged WAL-mode store is scanned
    with its uncheckpointed commits replayed — but each sidecar's own
    bytes are then scanned too: a committed sidecar that contains
    plaintext secrets must not slip through attached-but-unscanned.
    Orphans (no staged primary) dispatch as ordinary blobs.
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
        else:
            decoded = _decode_file_bytes(blob)
            if decoded is not None:
                findings = _scan_text_with_projection(
                    decoded[0], file=name, location="text"
                )
                err = None
            elif _text_marked(name):
                # Text-named but undecodable: never silently CLEAN —
                # scan the lossy projection (fail closed).
                findings, err = _scan_lossy(blob, name), None
            else:
                errs.append({"file": name, "error": "skipped: binary file"})
                return
        scanned += 1
        all_findings.extend(findings)
        if err:
            errs.append({"file": name, "error": err})

    for name, blob in primaries:
        if name in sidecars and _blob_kind(name, blob) == "sqlite":
            sc = sidecars.pop(name)
            _scan_one(name, blob, sc)
            for suffix, sblob in sc.items():
                _scan_one(name + suffix, sblob)
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


def _apply_text(
    path: Path,
    new_text: str,
    encoding: str = "utf-8",
    tail: bytes = b"",
) -> None:
    """Atomic text rewrite: .bak first, then tmp file + os.replace.

    ``encoding`` preserves the input's coding — a UTF-16 file goes back
    as UTF-16 in its source byte order (BOM included when the input had
    one, because the decoded text keeps the ``\\ufeff`` mark). Bytes
    that arrived via ``surrogateescape`` — text-marked files with a few
    undecodable bytes — encode back byte-exactly. ``tail`` carries raw
    bytes that never entered the decoded text — the truncated final
    code point of a damaged UTF-16 file — and is re-appended verbatim
    so the rewrite cannot silently drop them."""
    _backup(path)
    tmp = path.with_name(path.name + ".redact-tmp")
    try:
        try:
            data = new_text.encode(encoding)
        except UnicodeEncodeError:
            data = new_text.encode(encoding, "surrogateescape")
        tmp.write_bytes(data + tail)
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
        elif kind == "binary" and not _text_marked(f.name):
            errors.append({"file": display, "error": "skipped: binary file"})
            continue
        else:
            try:
                raw = f.read_bytes()
            except OSError as exc:
                errors.append({"file": display, "error": f"read failed: {exc}"})
                continue
            decoded = _decode_file_bytes(raw)
            if decoded is None:
                if not _text_marked(f.name):
                    errors.append(
                        {"file": display, "error": "skipped: binary file"}
                    )
                    continue
                # Lossy but byte-exact: surrogateescape round-trips the
                # undecodable bytes through the rewrite untouched.
                decoded = (raw.decode("utf-8", "surrogateescape"), "utf-8")
            text, encoding = decoded
            tail = b""
            if encoding != "utf-8":
                # ``_decode_file_bytes`` tolerates a truncated final
                # code point for the bounded binary sniff and the
                # read-only scans — but rewriting only the decoded
                # prefix would silently delete the original tail bytes.
                # Re-decode the whole file: when the error sits at EOF
                # the raw tail travels beside the plan and is appended
                # verbatim by ``_apply_text``; a mid-content error
                # (unreachable — such files decode None above, but
                # belt-and-braces) skips loudly instead of truncating.
                try:
                    raw.decode(encoding)
                except UnicodeDecodeError as exc:
                    if exc.end >= len(raw):
                        tail = raw[exc.start :]
                    else:
                        errors.append(
                            {
                                "file": display,
                                "error": (
                                    f"skipped: undecodable {encoding}"
                                    " content — rewrite would corrupt"
                                ),
                            }
                        )
                        continue
                except ValueError as exc:
                    errors.append(
                        {"file": display, "error": f"skipped: {exc}"}
                    )
                    continue
            new_text, edits = redact_text(text)
            if edits:
                planned.append(
                    {
                        "kind": "text",
                        "path": f,
                        "new_text": new_text,
                        "encoding": encoding,
                        "tail": tail,
                    }
                )
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
                _apply_text(
                    path,
                    plan["new_text"],
                    plan.get("encoding", "utf-8"),
                    tail=plan.get("tail", b""),
                )
            result["backups"].append(str(path.with_name(path.name + ".bak")))
        except Exception as exc:  # noqa: BLE001 - collect per-file errors, keep applying
            errors.append({"file": str(path), "error": f"apply failed: {exc}"})
            result["applied_ok"] = False
    result.setdefault("applied_ok", not errors)
    return result
