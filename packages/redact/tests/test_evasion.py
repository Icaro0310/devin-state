"""Adversarial-parser regression tests — the audit corpus.

Every case here was a real leak before the coverage pass: standard token
formats with no pattern, structural evasions (casing, separators, JSON
shapes, encodings) that let pattern-shaped secrets slip through, and a
fail-open trust of ``index.json`` in ``verify-publish``. All values are
synthetic.
"""

import ast
import sqlite3
from pathlib import Path

import devin_redact
import pytest
from devin_redact import engine, publish
from devin_redact.engine import redact_text, scan_text
from test_chunked import FAKE_AWS_KEY, SCHEMA
from test_scan import _fp

AWS = FAKE_AWS_KEY
GHP = "ghp_" + "A" * 36


# ---------------------------------------------------------------------
# token formats — every one of these survived verbatim before the fix
# ---------------------------------------------------------------------

TOKEN_CASES = {
    "gitlab_pat": "glpat-" + "x" * 20,
    "gitlab_deploy": "gldt-" + "x" * 20,
    "gitlab_runner": "glrt-" + "x" * 20,
    "slack_app": "xapp-1-A0BCDEFGH-abcdefghijkl",
    "stripe_whsec": "whsec_" + "a" * 24,
    "google_oauth": "ya29.a0Af" + "b" * 60,
    "npm": "npm_" + "a" * 36,
    "pypi": "pypi-AgEIcHlwaS5vcmc" + "a" * 60,
    "digitalocean": "dop_v1_" + "a" * 64,
    "sendgrid": "SG." + "a" * 22 + "." + "b" * 43,
    "square_atp": "sq0atp-" + "a" * 22,
    "square_csp": "sq0csp-" + "a" * 43,
    "shopify_at": "shpat_" + "a" * 32,
    "shopify_ca": "shpca_" + "a" * 32,
    "huggingface": "hf_" + "a" * 34,
    "age_key": "AGE-SECRET-KEY-1" + "Q" * 58,
}


@pytest.mark.parametrize("token", TOKEN_CASES.values(), ids=TOKEN_CASES)
def test_new_token_formats_caught(token):
    findings = scan_text(f"leak {token} end", file="x", location="text")
    assert _fp(token) in {str(f["fingerprint"]) for f in findings}
    assert all(f["category"] != "email" for f in findings)


@pytest.mark.parametrize("token", TOKEN_CASES.values(), ids=TOKEN_CASES)
def test_new_token_formats_redact(token):
    new, edits = redact_text(f"leak {token} end")
    assert token not in new
    assert edits


def test_urlencoded_assignment_token_caught():
    """`api_key%3D<token>` — %-encoding glues the name to the token;
    distinctive machine prefixes match unanchored so the value still
    lands."""
    text = "next=api_key%3D" + GHP
    new, _ = redact_text(text)
    assert GHP not in new


# ---------------------------------------------------------------------
# JWT shapes — short payloads/signatures and alg:none used to slip
# ---------------------------------------------------------------------

def test_jwt_short_payload_and_signature():
    jwt = "eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl"
    findings = scan_text("t " + jwt, file="x", location="text")
    assert _fp(jwt) in {str(f["fingerprint"]) for f in findings}


def test_jwt_empty_signature_alg_none():
    jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
    findings = scan_text("t " + jwt, file="x", location="text")
    assert _fp(jwt) in {str(f["fingerprint"]) for f in findings}


# ---------------------------------------------------------------------
# PEM variants
# ---------------------------------------------------------------------

def test_pgp_private_key_block_caught():
    pem = (
        "-----BEGIN PGP PRIVATE KEY " + "BLOCK-----\n"
        "xg0BDGVzdA==\n"
        "-----END PGP PRIVATE KEY BLOCK-----"
    )
    findings = scan_text(pem, file="x", location="text")
    assert any(f["category"] == "private_key" for f in findings)


def test_unterminated_pem_body_caught():
    """A truncated/streamed PEM — header plus base64 body, no footer —
    is still key material."""
    text = (
        "-----BEGIN OPENSSH PRIVATE " + "KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n"
        "(paste cut off here)"
    )
    findings = scan_text(text, file="x", location="text")
    assert any(f["category"] == "private_key" for f in findings)
    new, _ = redact_text(text)
    assert "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=" not in new


def test_bare_pem_header_not_flagged():
    """A header mention with no body is documentation, not a key."""
    text = "it starts with -----BEGIN OPENSSH PRIVATE " + "KEY----- usually\n"
    findings = scan_text(text, file="x", location="text")
    assert not [f for f in findings if f["category"] == "private_key"]


# ---------------------------------------------------------------------
# Authorization headers
# ---------------------------------------------------------------------

def test_bearer_case_and_separator_variants():
    for header in ("Bearer", "BEARER", "bearer", "Bearer:", "bearer="):
        tok = "a" * 30
        findings = scan_text(
            f"Authorization: {header} {tok}", file="x", location="text"
        )
        assert _fp(tok) in {str(f["fingerprint"]) for f in findings}, header


def test_bearer_token_suffix_word_not_flagged():
    """'BearerToken' has no separator — it is a word, not a scheme."""
    findings = scan_text(
        "const BearerTokenName = somethingLongEnough16", file="x",
        location="text",
    )
    assert not [f for f in findings if f["category"] == "bearer_token"]


def test_basic_authorization_header_caught():
    cred = "dXNlcjpwYXNzd29yZA=="  # user:password, synthetic
    findings = scan_text(
        "Authorization: Basic " + cred, file="x", location="text"
    )
    assert _fp(cred) in {str(f["fingerprint"]) for f in findings}


def test_basic_prose_not_flagged():
    findings = scan_text(
        "Authorization: basic authentication is required here",
        file="x",
        location="text",
    )
    assert not findings


# ---------------------------------------------------------------------
# env_assignment shapes — separators, casings, JSON forms
# ---------------------------------------------------------------------

ENV_CASES = {
    "yaml_colon": "api_key: hunter2fake\n",
    "json_pair": '"api_key": "hunter2fake"\n',
    "dict_pair": "cfg = {'secret_key': 'hunter2fake'}\n",
    "escaped_json": '{\\"token\\": \\"hunter2fake\\"}\n',
    "camel_key": 'apiKey = "hunter2fake"\n',
    "camel_token": "authToken = hunter2fake\n",
    "lower_key": 'api_key = "hunter2fake"\n',
    "lower_password": "db_password = hunter2fake\n",
    "lower_apikey": "apikey = hunter2fake\n",
    "bare_key": 'key = "hunter2fake"\n',
    "inline_json": 'note {"token": "hunter2fake"} tail\n',
    "js_literal": "cfg = {apiKey: 'hunter2fake'}\n",
}


@pytest.mark.parametrize("text", ENV_CASES.values(), ids=ENV_CASES)
def test_env_assignment_evasion_shapes(text):
    findings = scan_text(text, file="x", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert env, text
    new, edits = redact_text(text)
    assert "hunter2fake" not in new
    assert edits


def test_env_colon_redact_keeps_name_prefix():
    new, _ = redact_text('"api_key": "hunter2fake"\n')
    # The value was quoted, so the tag stays quoted — the redacted pair
    # is still valid JSON/YAML (`"api_key": "<REDACTED:…>"`).
    assert new.startswith('"api_key": "<REDACTED:')
    assert new.rstrip().endswith('>"')


def test_env_code_names_stay_unflagged():
    """Words that merely end in a keyword were already the trade-off:
    ``monkey``/``hotkey`` flag (accepted over-redaction collateral), but
    ``tokenize``/``keystore``/``keyboard``/``keyword`` must not."""
    for name in ("tokenize", "keystore", "keyboard", "keyword", "author",
                 "authority", "monkeypatch"):
        findings = scan_text(f'{name} = "x"\n', file="x.py", location="text")
        assert not findings, name


def test_env_name_ending_keyword_accepted_collateral():
    """Fail-closed: ``monkey``/``hotkey`` end in ``key`` and flag. Cheap
    collateral — a real ``apikey=`` would have leaked otherwise."""
    findings = scan_text('hotkey = "ctrl-x"\n', file="x", location="text")
    assert any(f["category"] == "env_assignment" for f in findings)


def test_high_entropy_unlabeled_blobs_not_flagged():
    """Documented scope: no entropy heuristic — commit SHAs and bare
    base64 blobs stay untouched (pattern-based by design)."""
    text = "commit " + "a" * 40 + "\nsha256 " + "b" * 64 + "\n"
    findings = scan_text(text, file="x", location="text")
    assert findings == []


# ---------------------------------------------------------------------
# connection URIs and webhook URLs
# ---------------------------------------------------------------------

URI_CASES = {
    "postgres": ("postgres://appuser:s3cr3tpw@db.internal:5432/app", "appuser:s3cr3tpw"),
    "mongodb_srv": ("mongodb+srv://appuser:s3cr3tpw@c0.x.mongodb.net/app", "appuser:s3cr3tpw"),
    "amqp": ("amqp://rabbit:hun73r@mq.local/vh", "rabbit:hun73r"),
    "redis": ("redis://default:sup3r@redis-1.io:12000", "default:sup3r"),
    "mysql": ("mysql://root:toorpass@127.0.0.1/db", "root:toorpass"),
    "generic": ("customapp://svc:s3cr3t@host.example/path", "svc:s3cr3t"),
}


@pytest.mark.parametrize("uri_and_secret", URI_CASES.values(), ids=URI_CASES)
def test_connection_uri_userinfo_caught(uri_and_secret):
    uri, secret = uri_and_secret
    findings = scan_text(f"conn {uri} end", file="x", location="text")
    uri_hits = [f for f in findings if f["category"] == "connection_uri"]
    assert uri_hits, uri
    assert _fp(secret) in {str(f["fingerprint"]) for f in uri_hits}
    new, _ = redact_text(f"conn {uri} end")
    assert secret not in new


def test_connection_uri_inside_env_value():
    """DATABASE_URL has no keyword in its name — the value shape is the
    only signal that matters."""
    text = "DATABASE_URL=postgres://appuser:s3cr3tpw@db:5432/app\n"
    new, _ = redact_text(text)
    assert "appuser:s3cr3tpw" not in new


def test_uri_without_password_not_flagged():
    """scheme://user@host carries no password — userinfo needs ':'."""
    findings = scan_text(
        "ssh://deploy@host.example/repo", file="x", location="text"
    )
    assert not [
        f for f in findings if f["category"] == "connection_uri"
    ]


WEBHOOK_CASES = {
    "slack": "https://hooks.slack.com/services/T00000000/B00000000/XXXXX",
    "discord": "https://discord.com/api/webhooks/1234567890/abcDEF_-0123",
    "discordapp": "https://canary.discordapp.com/api/webhooks/123/abcDEF_-0123",
    "office365": "https://outlook.office.com/webhookb2/aaaa-bbbb@cccc/dddd",
}


@pytest.mark.parametrize("url", WEBHOOK_CASES.values(), ids=WEBHOOK_CASES)
def test_webhook_urls_caught(url):
    findings = scan_text(f"post to {url}", file="x", location="text")
    assert any(f["category"] == "webhook_url" for f in findings)
    new, _ = redact_text(f"post to {url}")
    assert url not in new


def test_new_categories_block_publication(tmp_path):
    """webhook_url and connection_uri are secret-class: they must hold
    publication_status at BLOCKED."""
    p = tmp_path / "leak.txt"
    p.write_text("hook " + WEBHOOK_CASES["slack"] + "\n")
    report = devin_redact.scan([p])
    assert report["publication_status"] == "BLOCKED"
    assert report["secrets"] >= 1


# ---------------------------------------------------------------------
# encodings and binary-adjacent content
# ---------------------------------------------------------------------

def test_utf16_bom_file_scanned(tmp_path):
    p = tmp_path / "env16.env"
    p.write_bytes(("API_KEY=" + AWS + "\n").encode("utf-16"))
    report = devin_redact.scan([p])
    assert report["publication_status"] == "BLOCKED"
    assert _fp("API_KEY=" + AWS) in {
        str(f["fingerprint"]) for f in report["findings"]
    }


def test_utf16_no_bom_file_scanned(tmp_path):
    """PowerShell-style UTF-16LE without a BOM — NULs on one byte
    parity — used to read as opaque binary."""
    p = tmp_path / "env16.env"
    p.write_bytes(("API_KEY=" + AWS + "\n").encode("utf-16-le"))
    report = devin_redact.scan([p])
    assert report["publication_status"] == "BLOCKED"


def test_utf8_with_stray_nul_scanned(tmp_path):
    p = tmp_path / "withnul.txt"
    p.write_bytes(b"note\x00pad\nAPI_KEY=" + AWS.encode() + b"\n")
    report = devin_redact.scan([p])
    assert report["publication_status"] == "BLOCKED"


def test_staged_blob_utf16_scanned():
    """The pre-commit path: a UTF-16 .env staged blob must not slip
    through scan_blobs as 'skipped: binary'."""
    blob = ("API_KEY=" + AWS + "\n").encode("utf-16-le")
    report = engine.scan_blobs([("s.env", blob)])
    assert report["publication_status"] == "BLOCKED"


def test_control_byte_split_secret_detected(tmp_path):
    """A token split by a control byte/ANSI escape rejoins under the
    printable projection — detection-only (the rewrite cannot map the
    offsets back, same caveat as cross-chunk)."""
    p = tmp_path / "ctrl.txt"
    p.write_bytes(b"key: AKIAIOSFODN\x07N7EXAMPLE\n")
    report = devin_redact.scan([p])
    assert report["publication_status"] == "BLOCKED"
    kinds = {f["kind"] for f in report["findings"]}
    assert "binary-projection" in kinds


def test_ansi_escape_split_secret_detected(tmp_path):
    p = tmp_path / "ansi.txt"
    p.write_bytes(b"key: ghp_" + b"\x1b[31m" + b"A" * 36 + b"\n")
    report = devin_redact.scan([p])
    assert report["publication_status"] == "BLOCKED"


def test_real_binary_still_skipped(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x89PNG\x00\x01binary" + bytes(range(256)))
    report = devin_redact.scan([p])
    assert report["findings_total"] == 0
    assert any("binary" in e["error"] for e in report["errors"])


def test_redact_apply_utf16_round_trip(tmp_path):
    """--apply on a UTF-16 file rewrites in the same encoding."""
    p = tmp_path / "env16.env"
    p.write_bytes(("API_KEY=" + AWS + "\n").encode("utf-16"))
    result = devin_redact.redact([p], apply=True, confirm_irreversible=True)
    assert result["applied_ok"] is True
    text = p.read_bytes().decode("utf-16")
    assert AWS not in text
    assert "<REDACTED:" in text


def test_json_key_secret_detected(tmp_path):
    """A secret-shaped JSON *key* is a detection-only finding."""
    p = tmp_path / "keys.json"
    p.write_text(
        __import__("json").dumps({GHP: "enabled"}) + "\n"
    )
    report = devin_redact.scan([p])
    assert report["publication_status"] == "BLOCKED"
    assert _fp(GHP) in {str(f["fingerprint"]) for f in report["findings"]}


# ---------------------------------------------------------------------
# cross-chunk dedupe — whole secrets must not double-report
# ---------------------------------------------------------------------

def test_whole_secret_in_multileaf_payload_not_duplicated(tmp_path):
    """A >1-leaf payload whose boundary pre-filter trips must not emit
    the already-found whole secret again as a cross-chunk finding."""
    db = tmp_path / "sessions.db"
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)
    update = __import__("json").dumps(
        {
            "toolCallId": "tc-1",
            "status": "completed",
            "content": [
                {"type": "content", "content": {"type": "text",
                 "text": "edge boundary " + AWS}},
                {"type": "content", "content": {"type": "text",
                 "text": "secondleafvalue"}},
            ],
        }
    )
    con.execute(
        "INSERT INTO tool_call_state VALUES (?,?,?,?)",
        ("s1", "tc-1", None, update),
    )
    con.commit()
    con.close()
    report = devin_redact.scan([db])
    aws = [
        f for f in report["findings"]
        if f["fingerprint"] == _fp(AWS) and f["category"] == "api_key"
    ]
    assert len(aws) == 1
    assert aws[0]["kind"] == "pattern"


# ---------------------------------------------------------------------
# verify-publish — the index enumerates, it never limits
# ---------------------------------------------------------------------

def _export_dir(tmp_path: Path) -> Path:
    out = tmp_path / "export"
    out.mkdir()
    (out / "2026-05-28_sess-dirty.md").write_text(
        "---\nsession_id: sess-dirty\n---\nleak " + GHP + "\n"
    )
    (out / "2026-05-29_sess-clean.md").write_text(
        "---\nsession_id: sess-clean\n---\nfine\n"
    )
    return out


def test_index_omitting_dirty_session_still_blocks(tmp_path):
    """A crafted/stale index.json that omits a leaking session must not
    shrink coverage — on-disk session files are scanned regardless."""
    out = _export_dir(tmp_path)
    __import__("json")
    import json

    (out / "index.json").write_text(
        json.dumps(
            {
                "sessions": [
                    {"date": "2026-05-29",
                     "file": "2026-05-29_sess-clean.md", "title": "ok"}
                ]
            }
        )
    )
    report = publish.verify_publish(out, verdicts_dir=tmp_path / "none")
    assert report["publication_status"] == "BLOCKED"
    files = {s["file"] for s in report["sessions"]}
    assert "2026-05-28_sess-dirty.md" in files


def test_index_entry_outside_export_dir_warns(tmp_path):
    out = _export_dir(tmp_path)
    import json

    (out / "index.json").write_text(
        json.dumps(
            {"sessions": [{"date": "x", "file": "../escape.md",
                           "title": "esc"}]}
        )
    )
    report = publish.verify_publish(out, verdicts_dir=tmp_path / "none")
    assert any("outside the export dir" in w for w in report["warnings"])


# ---------------------------------------------------------------------
# Devin Review round 2/3 — redaction fidelity + fail-closed gaps
# ---------------------------------------------------------------------

def test_redacted_json_pair_stays_valid_json():
    """``{"api_key":"hunter2","enabled":true}`` used to redact to an
    *unquoted* ``<REDACTED:…>`` — unparseable JSON. A quoted value keeps
    its enclosing quotes now."""
    import json

    new, _ = redact_text('{"api_key":"hunter2","enabled":true}')
    obj = json.loads(new)
    assert str(obj["api_key"]).startswith("<REDACTED:")
    assert obj["enabled"] is True


def test_line_start_json_pair_does_not_eat_later_properties():
    """At line start the anchored pattern swallowed the rest of the
    line — `,"enabled":true` was deleted wholesale. A quoted value is
    bounded at its closing quote at JSON continuations."""
    new, _ = redact_text('"api_key":"hunter2","enabled":true\n')
    assert '"enabled":true' in new
    assert '"api_key":"<REDACTED:' in new
    assert "hunter2" not in new


def test_single_quoted_dict_pair_keeps_quotes():
    new, _ = redact_text("cfg = {'secret_key': 'hunter2fake'}\n")
    assert "hunter2fake" not in new
    assert "'secret_key': '<REDACTED:" in new


def test_escaped_quote_inside_value_fully_redacted():
    """``"token": "abc\\"def"`` — the value matcher stopped at the
    escaped quote and left the suffix raw. ``\\`` escapes now count as
    value chars, so the whole value is masked and the doc stays JSON."""
    import json

    new, _ = redact_text('{"token": "abc\\"defsecret"}')
    assert "defsecret" not in new
    assert str(json.loads(new)["token"]).startswith("<REDACTED:")


def test_quote_inside_other_quote_value_fully_redacted():
    """A ``'`` inside a ``"``-quoted value (legal JSON) must not close
    the match early — ``"it's …"`` is one string, not ``'`` ending it."""
    new, _ = redact_text('{"token": "it\'s a secret"}')
    assert "a secret" not in new


def test_equals_inside_quoted_value_still_detected():
    """``"api_key": "hello=fetch()"`` — the code-assignment guard found
    the ``=`` *inside* the quoted value and suppressed the finding as a
    call expression. The separator is the first ``:``/``=`` — quoted
    value text is never separator context."""
    findings = scan_text(
        '"api_key": "hello=fetch()"\n', file="x", location="text"
    )
    assert any(f["category"] == "env_assignment" for f in findings)
    new, _ = redact_text('"api_key": "hello=fetch()"\n')
    assert "hello=fetch()" not in new


def test_type_annotations_not_flagged_or_redacted():
    """``api_key: str`` / ``token: Optional[str]`` are Python type
    annotations, not secret assignments — flagging them corrupts source
    on redact. Bare type expressions stay unflagged; real scalars flag."""
    src = (
        "class Settings:\n"
        "    api_key: str\n"
        "    token: Optional[str]\n"
        "    secret: list[str]\n"
    )
    findings = scan_text(src, file="settings.py", location="text")
    assert not [
        f for f in findings if f["category"] == "env_assignment"
    ], findings
    new, _ = redact_text(src)
    assert "api_key: str" in new
    assert "Optional[str]" in new
    assert "<REDACTED:" not in new


def test_yaml_scalar_and_quoted_type_names_still_flagged():
    """The annotation guard must not open a hole: a bare scalar value
    (``hunter2``) and a *quoted* type name (``"str"`` is a real string
    value in YAML/JSON) still flag."""
    for text in ("api_key: hunter2fake\n", 'api_key: "str"\n'):
        findings = scan_text(text, file="x", location="text")
        assert any(
            f["category"] == "env_assignment" for f in findings
        ), text


def test_dotted_credential_value_flagged():
    """``api_key: abc.def`` used to scan CLEAN — the ``.`` in the bare
    value tripped the *dotted type* escape hatch and suppressed the
    finding. A dotted path only counts as an annotation when its
    terminal segment is a builtin/typing name or a CapWords class —
    ``abc.def`` and version-shaped ``v1.2`` are credential-shaped."""
    for text in ("api_key: abc.def\n", "api_key: v1.2\n"):
        findings = scan_text(text, file="x", location="text")
        assert any(
            f["category"] == "env_assignment" for f in findings
        ), text
        new, edits = redact_text(text)
        assert "<REDACTED:" in new and edits
    # the staged-file gate sees it too — no more silent CLEAN
    report = engine.scan_blobs([("s.env", b"api_key: abc.def\n")])
    assert report["publication_status"] == "BLOCKED"


def test_dotted_credential_inside_generic_flagged():
    """A credential cannot hide inside a subscript either —
    ``api_key: list[abc.def]`` carries no real type parameter."""
    findings = scan_text(
        "api_key: list[abc.def]\n", file="x", location="text"
    )
    assert any(f["category"] == "env_assignment" for f in findings)


def test_dotted_type_annotations_still_suppressed():
    """Real dotted annotations keep working: the terminal segment is a
    builtin/typing name (``datetime.datetime``, ``typing.Any``) or a
    CapWords class (``pathlib.Path``, ``models.User``)."""
    src = (
        "class Settings:\n"
        "    api_key: pathlib.Path\n"
        "    token: datetime.datetime\n"
        "    secret: Mapping[str, typing.Any]\n"
        "    auth: models.User | None\n"
    )
    findings = scan_text(src, file="settings.py", location="text")
    assert not [
        f for f in findings if f["category"] == "env_assignment"
    ], findings
    new, _ = redact_text(src)
    assert "<REDACTED:" not in new


def test_lowercase_dotted_type_annotations_suppressed():
    """``numpy.ndarray``, ``collections.deque``, ``socket.socket`` —
    real type names whose terminal segment is lowercase by convention,
    suppressed only under the module namespace that owns them.
    Flagging (and worse, redacting) them corrupts valid Python source."""
    src = (
        "weights: numpy.ndarray\n"
        "pending: collections.deque\n"
        "conn: socket.socket\n"
        "delta: datetime.timedelta\n"
        "proxy: weakref.proxy\n"
        "grid: list[numpy.ndarray]\n"
    )
    findings = scan_text(src, file="model.py", location="text")
    assert not [
        f for f in findings if f["category"] == "env_assignment"
    ], findings
    new, _ = redact_text(src)
    assert "<REDACTED:" not in new


def test_lowercase_type_terminal_needs_owning_namespace():
    """``proxy``/``ref``/``socket``/``array`` are type terminals only in
    their owning module — ``weakref.proxy`` is an annotation but
    ``customer.proxy`` is a credential-shaped scalar and must not pass
    the publication gate."""
    for text in (
        "password: customer.proxy\n",
        "api_key: auth.ref\n",
        "secret: my.socket\n",
        "token: conf.array\n",
    ):
        findings = scan_text(text, file="x", location="text")
        assert any(
            f["category"] == "env_assignment" for f in findings
        ), text
        new, edits = redact_text(text)
        assert "<REDACTED:" in new and edits, text
    report = engine.scan_blobs([("s.env", b"password: customer.proxy\n")])
    assert report["publication_status"] == "BLOCKED"


def test_import_aliased_type_annotations_suppressed():
    """``import numpy as n`` binds ``n`` in this file — ``n.ndarray``
    is the same annotation as ``numpy.ndarray``. Aliases are resolved
    from the text itself, not a static list, and ``from X import Y``
    binds bare names the same way."""
    src = (
        "import numpy as n\n"
        "from collections import deque\n"
        "from weakref import proxy\n"
        "weights: n.ndarray\n"
        "pending: deque\n"
        "handle: proxy\n"
    )
    findings = scan_text(src, file="model.py", location="text")
    assert not [
        f for f in findings if f["category"] == "env_assignment"
    ], findings
    new, _ = redact_text(src)
    assert "<REDACTED:" not in new
    # relative and star imports bind the same way
    src = (
        "from .collections import deque\n"
        "from weakref import *\n"
        "api_key: deque\n"
        "handle: ref\n"
    )
    findings = scan_text(src, file="m.py", location="text")
    assert not [
        f for f in findings if f["category"] == "env_assignment"
    ], findings
    # but a starred non-type module cannot excuse a credential value
    assert any(
        f["category"] == "env_assignment"
        for f in scan_text(
            "from os import *\napi_key: environ\n",
            file="m.py",
            location="text",
        )
    )


def test_annotated_string_default_still_flags():
    """``api_key: str = "hunter2"`` is an annotation *and* a hardcoded
    secret — the ``= default`` tail may only be stripped when the
    default is not a literal value. Redaction scopes to the literal
    and keeps the line parseable (``name: T = "<tag>"``). The
    trailing comment is dropped: it can carry secrets the single
    consumed finding hides from later scans."""
    src = 'api_key: str = "hunter2"  # keep me\nweights: n.ndarray = None\n'
    src = "import numpy as n\n" + src
    findings = scan_text(src, file="m.py", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert len(env) == 1, findings
    new, _ = redact_text(src, file="m.py")
    assert "hunter2" not in new
    assert 'api_key: str = "<REDACTED:' in new
    ast.parse(new)


def test_annotated_default_comment_never_survives():
    """``api_key: str = "x"  # password=y`` — the trailing comment
    can itself hold a credential; preserving it ships the secret
    even though the finding consumed the whole line."""
    src = 'api_key: str = "hunter2"  # password=secret123\n'
    findings = scan_text(src, file="m.py", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert len(env) == 1, findings
    new, _ = redact_text(src, file="m.py")
    assert "secret123" not in new and "hunter2" not in new
    ast.parse(new)


def test_annotated_default_keeps_literal_shape():
    """``b"…"`` stays bytes and ``("…",)`` stays a one-tuple — the
    tag becomes the payload, not a plain string."""
    for src, want in (
        ('api_key: bytes = b"hunter2"\n', 'b"<REDACTED:'),
        ('api_key: bytes = rb"hunter2"\n', 'rb"<REDACTED:'),
        ('api_key: tuple = ("hunter2",)\n', '("<REDACTED:'),
    ):
        new, _ = redact_text(src, file="m.py")
        assert want in new, (src, new)
        assert "hunter2" not in new
        ast.parse(new)


def test_prefixed_literal_assignment_keeps_prefix():
    """``api_key = b"hunter2"`` lands on the bare arm (the quote is
    not at value start), so the rewrite must still re-emit the
    literal prefix — a bare ``<tag>`` would not parse and a plain
    quoted tag would silently change bytes to str."""
    for prefix in ("b", "rb", "f", "u"):
        src = f'api_key = {prefix}"hunter2"\n'
        new, _ = redact_text(src, file="m.py")
        assert f'{prefix}"<REDACTED:' in new, (src, new)
        assert "hunter2" not in new
        ast.parse(new)
        # Untyped text gets the same quoting care — a pasted snippet
        # has no filename but the output should still parse.
        new2, _ = redact_text(src)
        assert f'{prefix}"<REDACTED:' in new2
        ast.parse(new2)


def test_yaml_block_scalar_value_masked():
    """``api_key: |`` / ``key: >`` put the secret on the following
    indented lines — masking only the indicator ships the value."""
    src = "api_key: |\n  hunter2secret\n  moresecret\nnext: v\n"
    findings = scan_text(src, file="c.yaml", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert len(env) == 1, findings
    new, _ = redact_text(src, file="c.yaml")
    assert "hunter2secret" not in new and "moresecret" not in new
    assert "next: v" in new
    # A ``|`` with no indented body falls back to the bare arm —
    # the next mapping key must survive untouched.
    src2 = "api_key: |\nother: v\n"
    new2, _ = redact_text(src2, file="c.yaml")
    assert "other: v" in new2


def test_dockerfile_env_arg_forms():
    """``ENV KEY=v``, ``ARG KEY=v`` and the legacy whitespace
    separator ``ENV KEY v`` are Dockerfile secret binds — the
    prefix was case-sensitive lowercase only."""
    for src, want in (
        ("ENV API_KEY=hunter2", "ENV API_KEY=<REDACTED:"),
        ("ARG TOKEN=hunter2", "ARG TOKEN=<REDACTED:"),
        ("ENV API_KEY hunter2", "ENV API_KEY <REDACTED:"),
        ("ARG TOKEN hunter2", "ARG TOKEN <REDACTED:"),
        ("SET API_KEY=hunter2", "SET API_KEY=<REDACTED:"),
        ("EXPORT API_KEY=hunter2", "EXPORT API_KEY=<REDACTED:"),
    ):
        findings = scan_text(src, file="Dockerfile", location="text")
        env = [f for f in findings if f["category"] == "env_assignment"]
        assert len(env) == 1, (src, findings)
        new, _ = redact_text(src, file="Dockerfile")
        assert want in new, (src, new)
        assert "hunter2" not in new


def test_url_query_secret_masked():
    """``?api_key=v`` lives mid-line in logged URLs — the value
    stops at the next param, fragment or whitespace."""
    cases = (
        ("https://x/cb?api_key=hunter2&state=1", "&state=1"),
        ("GET /a?token=hunter2 HTTP/1.1", "HTTP/1.1"),
        ("u?x=1&amp;api_key=hunter2", "&amp;"),
        ("#api_key=hunter2", "#api_key=<REDACTED:"),
    )
    for src, keep in cases:
        findings = scan_text(src, file="log.txt", location="text")
        env = [f for f in findings if f["category"] == "env_assignment"]
        assert len(env) == 1, (src, findings)
        new, _ = redact_text(src, file="log.txt")
        assert "hunter2" not in new
        assert keep in new, (src, new)


def test_list_bullet_env_entries():
    """``- API_KEY=x`` in docker-compose ``environment:`` lists —
    the bullet broke the line anchor and shipped the value."""
    src = "environment:\n  - API_KEY=hunter2\n  - DEBUG=1\n"
    findings = scan_text(src, file="dc.yml", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert len(env) == 1, findings
    new, _ = redact_text(src, file="dc.yml")
    assert "hunter2" not in new and "DEBUG=1" in new


def test_commented_out_secrets_still_flag():
    """``# API_KEY=x`` / ``// api_key=x`` / ``<!-- token=x -->``
    park the credential in a comment — it still ships."""
    for src in (
        "# API_KEY=hunter2",
        "// api_key=hunter2",
        "<!-- password=hunter2 -->",
        "; secret=hunter2",
    ):
        findings = scan_text(src, file="x.cfg", location="text")
        env = [f for f in findings if f["category"] == "env_assignment"]
        assert len(env) == 1, (src, findings)
        new, _ = redact_text(src, file="x.cfg")
        assert "hunter2" not in new


def test_trailing_comment_secret_is_own_finding():
    """``f(api_key="x") # password=y`` — the kwarg match must not
    let the comment's second credential slip through: the scan
    reports both and the redaction masks both."""
    src = 'f(api_key="x") # password=hunter2\n'
    findings = scan_text(src, file="x.py", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert len(env) == 2, findings
    new, _ = redact_text(src, file="x.py")
    assert "hunter2" not in new
    ast.parse(new)


def test_bindings_do_not_apply_inside_strings():
    """A ``name: value`` inside a triple-quoted string is string
    content, not annotation position — import bindings cannot excuse
    it (devin-state#92 review)."""
    src = (
        "from weakref import *\n"
        "from .collections import deque\n"
        'NOTES = """\n'
        "api_key: ref\n"
        "api_key: deque\n"
        '"""\n'
        "pending: deque\n"
        "handle: ref\n"
    )
    findings = scan_text(src, file="m.py", location="text")
    env = [
        f for f in findings if f["category"] == "env_assignment"
    ]
    assert len(env) == 2, findings
    # both flagged lines are the ones inside the string; the real
    # annotations after it still suppress
    new, _ = redact_text(src, file="m.py")
    assert "pending: deque" in new and "handle: ref" in new


def test_import_inside_docstring_binds_nothing():
    """An ``import`` line inside a triple-quoted string is string
    content — it cannot create the alias that would excuse a later
    ``api_key: n.ndarray``."""
    src = (
        'DOC = """\n'
        "import numpy as n\n"
        '"""\n'
        "api_key: n.ndarray\n"
    )
    findings = scan_text(src, file="m.py", location="text")
    assert any(f["category"] == "env_assignment" for f in findings)


def test_alias_rebound_by_assignment_binds_nothing():
    """``import numpy as n`` followed by ``n = "x"`` rebinds the name —
    the later ``api_key: n.ndarray`` is a plain attribute read under a
    credential keyword and must flag."""
    src = (
        "import numpy as n\n"
        'n = "not numpy anymore"\n'
        "api_key: n.ndarray\n"
    )
    findings = scan_text(src, file="m.py", location="text")
    assert any(f["category"] == "env_assignment" for f in findings)


def test_alias_rebound_by_for_def_del_binds_nothing():
    """``for n in``, ``def n``, ``class n`` and ``del n`` all rebind
    the name — a credential under the alias still flags."""
    for rebind in ("for n in xs:\n    pass", "def n():\n    pass",
                   "class n:\n    pass", "del n", "n: int = 5",
                   "n := 5", "match x:\n    case n:",
                   "with open(f) as n:\n    pass",
                   "except ValueError as n:\n    pass"):
        src = f"import numpy as n\n{rebind}\napi_key: n.ndarray\n"
        findings = scan_text(src, file="m.py", location="text")
        assert any(
            f["category"] == "env_assignment" for f in findings
        ), rebind


def test_unclosed_parenthesized_import_still_scans():
    """An unclosed ``from x import (`` binds nothing and must not stall
    or blind the scan — the secret after it still flags."""
    src = "from x import (\n    deque,\npassword: hunter2secret\n"
    findings = scan_text(src, file="m.py", location="text")
    assert any(f["category"] == "env_assignment" for f in findings)


def test_concatenated_and_continued_literals_flag():
    """Implicit string concatenation — ``"a" <backslash><newline>"b"``
    and ``("a" "b")`` — is one literal value; the whole of it must
    flag and the rewrite must stay parseable."""
    for src in (
        'api_key = "hun" \\\n "ter2"\n',
        'api_key = ("hun"\n "ter2")\n',
        'api_key = ("hun" \\\n "ter2")\n',
        'api_key = \\\n "hunter2"\n',
    ):
        findings = scan_text(src, file="m.py", location="text")
        env = [f for f in findings if f["category"] == "env_assignment"]
        assert len(env) == 1, (src, findings)
        new, _ = redact_text(src, file="m.py")
        assert "ter2" not in new and "hunter2" not in new, (src, new)
        ast.parse(new)


def test_shell_builtin_declarations_flag():
    """``declare -x``/``readonly``/``local``/``typeset``/``env``
    prefix assignments bind the same secret ``export`` did."""
    for src in (
        'declare -x API_KEY=hunter2secret\n',
        'declare -r -x API_KEY="hunter2"\n',
        'readonly API_KEY=hunter2secret\n',
        'local api_key=hunter2secret\n',
        'typeset API_KEY=hunter2secret\n',
        'env API_KEY=hunter2secret\n',
    ):
        findings = scan_text(src, file="x.sh", location="text")
        env = [f for f in findings if f["category"] == "env_assignment"]
        assert len(env) == 1, (src, findings)
        new, _ = redact_text(src, file="x.sh")
        assert "hunter2" not in new, (src, new)


def test_call_bound_secrets_flag():
    """``f(api_key="x")`` / ``cfg.setdefault("api_key", "x")``:
    a credential name bound to a literal inside a call is the
    same hardcoded secret without the line anchor."""
    flagged = (
        'f(api_key="hunter2")\n',
        'cfg.update(api_key="hunter2")\n',
        'boto3.client("s3", aws_secret_access_key="hunter2")\n',
        'os.environ.setdefault("API_KEY", "hunter2")\n',
        'd.get("api_key", "hunter2")\n',
    )
    for src in flagged:
        findings = scan_text(src, file="m.py", location="text")
        env = [f for f in findings if f["category"] == "env_assignment"]
        assert len(env) == 1, (src, findings)
        new, _ = redact_text(src, file="m.py")
        assert "hunter2" not in new, (src, new)
        ast.parse(new)
    # ``name == "x"`` is a comparison, not a binding — the
    # ``(?!=)`` guard keeps it out of env_assignment.
    findings = scan_text(
        'check(api_key=="hunter2")\n', file="m.py", location="text"
    )
    assert not [
        f for f in findings if f["category"] == "env_assignment"
    ]


def test_receiver_prefixed_assignments_flag():
    """``cfg.api_key = "x"`` / ``config["api_key"] = "x"``: a
    credential name hidden behind a receiver still binds a
    hardcoded secret, and the rewrite keeps the file parseable."""
    for src in (
        'config["api_key"] = "hunter2"\n',
        "config['token'] = 'hunter2'\n",
        'cfg.api_key = "hunter2"\n',
        'self.api_key = "hunter2"\n',
        'a.b.api_key = "hunter2"\n',
    ):
        findings = scan_text(src, file="m.py", location="text")
        env = [f for f in findings if f["category"] == "env_assignment"]
        assert len(env) == 1, (src, findings)
        new, _ = redact_text(src, file="m.py")
        assert "hunter2" not in new, (src, new)
        ast.parse(new)


def test_parenthesized_literal_across_lines_flags():
    """``key = (\\n "x"\\n)`` wraps a hardcoded secret — the value
    must flag and the rewrite must stay parseable, with or without
    an annotation head."""
    for src in (
        'api_key = (\n    "hunter2"\n)\n',
        'api_key: str = (\n    "hunter2"\n)\n',
    ):
        findings = scan_text(src, file="m.py", location="text")
        assert any(
            f["category"] == "env_assignment" for f in findings
        ), src
        new, _ = redact_text(src, file="m.py")
        assert "hunter2" not in new
        ast.parse(new)


def test_triple_quoted_value_masks_body_not_empty_opener():
    """``key = \"\"\"\\nx\\n\"\"\"`` must mask the whole literal — a
    single-quote arm matching the empty ``""`` prefix used to leave
    the body behind."""
    for src in (
        'api_key = """\nhunter2\n"""\n',
        "api_key = '''\nhunter2\n'''\n",
        'api_key = """hunter2"""\n',
    ):
        new, _ = redact_text(src, file="x.env")
        assert "hunter2" not in new, (src, new)


def test_env_redaction_preserves_separator_whitespace():
    """``key: v`` must stay a mapping — dropping the space turns the
    line into a YAML scalar. ``KEY=v`` has no space to keep."""
    new, _ = redact_text("api_key: n.ndarray\n", file="config.yaml")
    assert new.startswith("api_key: <REDACTED:"), new
    new, _ = redact_text("KEY=hunter2val\n", file=".env")
    assert new.startswith("KEY=<REDACTED:"), new


def test_conventional_alias_needs_the_import():
    """``np.ndarray`` is only a type when ``import numpy as np`` is
    in the text — without it the dotted name is credential-shaped.
    ``np`` must not be hardcoded as a numpy owner."""
    findings = scan_text("api_key: np.ndarray\n", file="m.py",
                         location="text")
    assert any(f["category"] == "env_assignment" for f in findings)
    findings = scan_text(
        "import numpy as np\napi_key: np.ndarray\n", file="m.py",
        location="text")
    assert not any(f["category"] == "env_assignment" for f in findings)


def test_unbound_alias_still_flags():
    """Without the import line there is no binding — ``n.ndarray`` is
    just a dotted scalar under a credential keyword and must flag."""
    findings = scan_text("api_key: n.ndarray\n", file="x", location="text")
    assert any(f["category"] == "env_assignment" for f in findings)
    findings = scan_text(
        "password: n.proxy\n", file="creds.env", location="text"
    )
    assert any(f["category"] == "env_assignment" for f in findings)


def test_parenthesized_import_binds_names():
    """``from collections import (deque, defaultdict)`` — including the
    multi-line form — binds the names like the plain form."""
    src = (
        "from collections import (\n"
        "    deque,\n"
        "    defaultdict,\n"
        ")\n"
        "pending: deque\n"
        "lookup: defaultdict\n"
    )
    findings = scan_text(src, file="m.py", location="text")
    assert not [
        f for f in findings if f["category"] == "env_assignment"
    ], findings
    new, _ = redact_text(src)
    assert "<REDACTED:" not in new
    # an inline comment inside the parens cannot hide the binding —
    # even one containing ``)``
    src = (
        "from collections import (\n"
        "    # primary container)\n"
        "    deque,\n"
        ")\n"
        "pending: deque\n"
    )
    assert not [
        f
        for f in scan_text(src, file="m.py", location="text")
        if f["category"] == "env_assignment"
    ]
    new, _ = redact_text(src)
    assert "<REDACTED:" not in new


def test_import_like_text_in_env_file_does_not_bind():
    """A ``.env``/``.yaml`` blob holding ``import numpy as n`` carries
    text, not a Python binding — ``api_key: n.ndarray`` there is a
    credential-shaped scalar and must still block the gate."""
    for fname in ("creds.env", "config.yaml", "notes.txt"):
        blob = "import numpy as n\napi_key: n.ndarray\n"
        findings = scan_text(blob, file=fname, location="text")
        assert any(
            f["category"] == "env_assignment" for f in findings
        ), fname
    report = engine.scan_blobs(
        [("creds.env", b"import numpy as n\napi_key: n.ndarray\n")]
    )
    assert report["publication_status"] == "BLOCKED"
    # while the same text in a .py file is a real annotation
    assert not [
        f
        for f in scan_text(
            "import numpy as n\napi_key: n.ndarray\n",
            file="m.py",
            location="text",
        )
        if f["category"] == "env_assignment"
    ]


def test_complete_pem_reported_once_not_twice():
    """A complete PEM block matched both ``pem_private_key`` and
    ``pem_private_key_unterminated`` (a strict prefix) — one key, two
    findings. Span-overlap dedupe keeps the complete match only."""
    pem = (
        "-----BEGIN RSA PRIVATE " + "KEY-----\n"
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUFBws=\n"
        "-----END RSA PRIVATE " + "KEY-----"
    )
    hits = [
        f
        for f in scan_text(pem, file="x", location="text")
        if f["category"] == "private_key"
    ]
    assert len(hits) == 1
    assert hits[0]["pattern"] == "pem_private_key"


def test_malformed_staged_text_scanned_not_skipped():
    """A staged ``.env`` blob holding a credential + one invalid UTF-8
    byte decoded to ``None`` → ``skipped: binary`` → gate CLEAN. The
    surrogateescape fallback decodes the good bytes so the printable
    projection still scans them."""
    blob = b"API_KEY=" + AWS.encode() + b"\nnote\xffhere\n"
    report = engine.scan_blobs([("s.env", blob)])
    assert report["publication_status"] == "BLOCKED"


def test_undecodable_text_named_blob_still_scanned():
    """Bytes no decoder accepts (dense non-printables) but a
    text-marked name (``.env``): the gate cannot vouch for them —
    surrogateescape + projection scans the ASCII region anyway."""
    blob = (
        b"\x00\x01\x02\x03API_KEY=" + AWS.encode()
        + bytes(range(200, 256)) * 30
    )
    report = engine.scan_blobs([("s.env", blob)])
    assert report["publication_status"] == "BLOCKED"
    # and a clean but undecodable text-marked blob is scanned, not
    # silently skipped
    clean = engine.scan_blobs(
        [("s.env", b"\x00\x01\x02" + bytes(range(200, 256)) * 30)]
    )
    assert clean["publication_status"] == "CLEAN"


def test_utf16_sniff_boundary_surrogate_pair_scanned():
    """A BOM-less UTF-16 file whose surrogate pair crosses byte 8192
    made the head sniff undecodable → ``_blob_kind`` said binary → a
    later ``API_KEY=`` reached the gate as CLEAN. A truncated trailing
    code point is tolerated for the sniff."""
    text = "x" * 4095 + "\U0001F600" + " tail API_KEY=" + AWS + "\n"
    blob = text.encode("utf-16-le")
    assert engine._blob_kind("f.txt", blob) == "text"
    report = engine.scan_blobs([("f.txt", blob)])
    assert report["publication_status"] == "BLOCKED"


def test_utf16be_apply_preserves_byte_order(tmp_path):
    """A ``FE FF`` BOM used to decode as generic ``utf-16`` and rewrite
    in native (little-endian) order. The endian-specific codec keeps
    both the BOM and the source byte order."""
    p = tmp_path / "env16.env"
    p.write_bytes(
        b"\xfe\xff" + ("API_KEY=" + AWS + "\n").encode("utf-16-be")
    )
    result = devin_redact.redact(
        [p], apply=True, confirm_irreversible=True
    )
    assert result["applied_ok"] is True
    data = p.read_bytes()
    assert data[:2] == b"\xfe\xff"
    text = data.decode("utf-16-be")
    assert AWS not in text
    assert "<REDACTED:" in text


def test_utf16le_apply_still_preserves_byte_order(tmp_path):
    p = tmp_path / "env16.env"
    p.write_bytes(("API_KEY=" + AWS + "\n").encode("utf-16"))
    result = devin_redact.redact(
        [p], apply=True, confirm_irreversible=True
    )
    assert result["applied_ok"] is True
    data = p.read_bytes()
    assert data[:2] == b"\xff\xfe"
    text = data.decode("utf-16")
    assert AWS not in text


def test_utf16_truncated_tail_preserved_on_apply(tmp_path):
    """A UTF-16 file ending mid-code-point used to rewrite *without*
    its tail bytes — ``_decode_file_bytes`` returned the decodable
    prefix and ``--apply`` wrote it back, silently truncating the file
    behind an applied_ok report. The undecodable tail now travels
    beside the plan and is re-appended verbatim."""
    raw = ("API_KEY=" + AWS + "\n").encode("utf-16") + b"\x61"
    p = tmp_path / "truncated.env"
    p.write_bytes(raw)
    result = devin_redact.redact(
        [p], apply=True, confirm_irreversible=True
    )
    assert result["applied_ok"] is True
    assert result["replacements"] == 1
    data = p.read_bytes()
    assert data.endswith(b"\x61")
    body = data[:-1].decode("utf-16")
    assert AWS not in body
    assert "<REDACTED:" in body


def test_utf16_truncated_tail_no_secret_untouched(tmp_path):
    """A secret-free truncated UTF-16 file is never rewritten — the
    tail-preservation path only runs when an edit is planned."""
    raw = "note=fine".encode("utf-16") + b"\x62"
    p = tmp_path / "clean.env"
    p.write_bytes(raw)
    result = devin_redact.redact(
        [p], apply=True, confirm_irreversible=True
    )
    assert result["applied_ok"] is True
    assert p.read_bytes() == raw


def test_utf16_truncated_tail_blob_still_scanned():
    """The tail-drop tolerance stays for *detection*: a BOM-less
    UTF-16 staged blob with a clipped final char still scans the
    decodable body instead of failing closed to binary."""
    blob = ("API_KEY=" + AWS + "\n").encode("utf-16-le") + b"\x42"
    report = engine.scan_blobs([("s.env", blob)])
    assert report["publication_status"] == "BLOCKED"


def test_json_key_secret_redacted_on_apply(tmp_path):
    """A credential used as a JSON *key* inside a DB cell is detected
    by ``_key_strings`` — but ``_redact_leaves`` used to rewrite only
    values, so the key shipped anyway. Flagged keys are rewritten to
    their tag now."""
    import json

    db = tmp_path / "sessions.db"
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)
    payload = json.dumps({GHP: "enabled"})
    con.execute(
        "INSERT INTO tool_call_state VALUES (?,?,?,?)",
        ("s1", "tc-1", None, payload),
    )
    con.commit()
    con.close()

    report = devin_redact.scan([db])
    assert report["publication_status"] == "BLOCKED"

    result = devin_redact.redact(
        [db], apply=True, confirm_irreversible=True
    )
    assert result["applied_ok"] is True
    con = sqlite3.connect(db)
    (val,) = con.execute(
        "SELECT tool_call_update_json FROM tool_call_state"
    ).fetchone()
    con.close()
    assert GHP not in val
    keys = list(json.loads(val))
    assert any(k.startswith("<REDACTED:") for k in keys)


def test_delimiter_text_inside_literal_does_not_open_span():
    """A ``'''``/``\"\"\"`` inside an ordinary string or a comment is
    text, not a delimiter — the span detector must not open a phantom
    docstring over later real annotations (devin-state#92 review)."""
    for decoy in (
        'EXAMPLE = "\'\'\'"',
        'EXAMPLE = \'"""\'',
        "# the docstring opener is ''', not here",
    ):
        src = decoy + "\napi_key: str\nhandle: int\n"
        findings = scan_text(src, file="m.py", location="text")
        assert not [
            f for f in findings if f["category"] == "env_assignment"
        ], (decoy, findings)
        new, _ = redact_text(src, file="m.py")
        assert new == src
        ast.parse(new)


def test_escaped_quote_does_not_close_docstring_span():
    """``\\"`` inside a docstring is an escape, not a closer — a
    credential on the lines after it is still string content and must
    flag even when bindings would excuse it in code position."""
    src = (
        "from weakref import *\n"
        'NOTES = """header \\""" still inside\n'
        "api_key: ref\n"
        '"""\n'
    )
    findings = scan_text(src, file="m.py", location="text")
    assert any(
        f["category"] == "env_assignment" for f in findings
    ), findings
    new, _ = redact_text(src, file="m.py")
    assert "api_key: ref" not in new and "<REDACTED:" in new


def test_annotated_default_redaction_preserves_syntax():
    """``api_key: str = "hunter2"`` masks only the literal — the
    annotation and ``=`` survive so the rewritten file still parses
    (devin-state#92 review)."""
    src = 'api_key: str = "hunter2"\nweights: list[float]\n'
    new, _ = redact_text(src, file="m.py")
    assert "hunter2" not in new
    assert 'api_key: str = "<REDACTED:' in new
    ast.parse(new)


def test_unquoted_scalar_slots_stay_parseable_in_python():
    """An unquoted tag is not a valid Python expression — in a ``.py``
    blob it is emitted quoted (and in untyped text for the ``:``
    annotation/dict slot), while ``.env`` output keeps the plain
    ``KEY=<tag>`` convention."""
    for src in (
        "api_key: hunter2\n",
        "api_key = hunter2\n",
        'api_key: str = ("hunter2")\n',
    ):
        new, _ = redact_text(src, file="m.py")
        assert "hunter2" not in new
        ast.parse(new), src
    new, _ = redact_text("api_key: hunter2\n")  # bare ``:`` slot
    assert "hunter2" not in new and '"<REDACTED:' in new
    new, _ = redact_text("API_KEY=hunter2\n", file="creds.env")
    assert "API_KEY=<REDACTED:" in new


def test_npmrc_authtoken_keeps_option_name():
    """``.npmrc`` lines are ``//host/:_authToken=v`` — the match opens
    with ``:`` so the option name must survive the replacement."""
    src = "//registry.npmjs.org/:_authToken=hunter2\n"
    new, findings = redact_text(src, file=".npmrc")
    assert "hunter2" not in new
    assert ":_authToken=<REDACTED:" in new
    assert len(findings) == 1


def test_netrc_positional_forms():
    """``.netrc``/``.authinfo`` credentials are positional
    (``machine h login u password p``), usually wrapped across lines;
    a ``default`` entry has no host. Only the password is masked —
    the surrounding context survives."""
    for src in (
        "machine github.com login ikaros password hunter2\n",
        "machine github.com\n  login ikaros\n  password hunter2\n",
        "default login u password hunter2\n",
        "machine a.com login u account hunter2\n",
    ):
        new, findings = redact_text(src, file="creds.netrc")
        assert "hunter2" not in new, src
        assert len(findings) == 1, (src, findings)
        assert "login" in new and "password" in new or "account" in new
    # an entry missing its password is not consumed into the next one
    src = "machine a.com login u\nmachine b.com login u2 password hunter2\n"
    new, findings = redact_text(src, file="creds.netrc")
    assert "machine a.com login u" in new and "hunter2" not in new
    assert len(findings) == 1
    # entries are line-anchored — prose spelling the keywords stays out
    for prose in (
        "the default login uses password authentication\n",
        "note: machine a.com login u password hunter2 inline\n",
    ):
        new, findings = redact_text(prose, file="doc.md")
        assert findings == [] and new == prose, (prose, findings)


def test_terraform_variable_default():
    """``variable "api_key" { default = "hunter2" }`` masks the
    quoted default and keeps the block structure."""
    src = 'variable "api_key" {\n  default = "hunter2"\n}\n'
    new, findings = redact_text(src, file="main.tf")
    assert "hunter2" not in new
    assert 'default = "<REDACTED:' in new
    assert len(findings) == 1


def test_ansible_vault_block_scalar():
    """An ``!vault |`` block scalar carries the ciphertext on the
    indented lines — all of it is masked and the next key survives."""
    src = (
        "api_key: !vault |\n"
        "  $ANSIBLE_VAULT;1.1;AES256\n"
        "  6162636465\n"
        "next: v\n"
    )
    new, findings = redact_text(src, file="secrets.yml")
    assert "ANSIBLE_VAULT" not in new and "6162636465" not in new
    assert "next: v" in new
    assert len(findings) == 1


def test_java_properties_separators():
    """Java ``.properties`` accepts ``=``, ``:``, whitespace and the
    escaped forms ``\\=``/``\\u003d`` — plus space separators, which
    only fire under a properties extension (prose elsewhere)."""
    for src, fn in (
        ("api_key=hunter2", "config.properties"),
        ("api_key:hunter2", "config.properties"),
        ("api_key hunter2", "config.properties"),
        ("api_key\\=hunter2", "config.properties"),
        ("api_key\\u003dhunter2", "config.properties"),
    ):
        new, findings = redact_text(src, file=fn)
        assert "hunter2" not in new, (src, fn)
        assert findings, (src, fn)
    # the space-separator arm is file-gated: identical text in a
    # plain-text file is prose, not a properties assignment
    new, findings = redact_text("api_key hunter2", file="notes.txt")
    assert findings == [] and new == "api_key hunter2"
    new, findings = redact_text(
        "PASSWORD must be rotated quarterly", file="notes.md"
    )
    assert findings == []


def test_xml_attribute_pair_and_setting():
    """XML config carries credentials as attribute pairs
    (``key="api_key" value="hunter2"``) or a direct secret-named
    attribute — the value is masked inside its quotes."""
    for src in (
        '<add key="api_key" value="hunter2" />',
        '<setting api_key="hunter2"/>',
    ):
        new, findings = redact_text(src, file="app.config")
        assert "hunter2" not in new, src
        assert findings


def test_cli_flag_credentials():
    """Command-line secret flags — each masks only the secret token
    and keeps the command line runnable."""
    for src in (
        "kubectl create secret generic s --from-literal=api_key=hunter2",
        "docker run -e API_KEY=hunter2 img",
        "docker run --env API_KEY=hunter2 img",
        "curl -u admin:hunter2 https://x",
        "curl --user admin:hunter2 https://x",
        "sshpass -p 'hunter2' ssh host",
        "redis-cli -a hunter2 ping",
        "mysql -u root -phunter2 db",
        "mysql -u root -P3306 -phunter2",
        "htpasswd -b .htpasswd admin hunter2",
    ):
        new, findings = redact_text(src, file="runbook.txt")
        assert "hunter2" not in new, src
        assert findings, src
    # mysql's uppercase -P is a port, not a password flag
    new, findings = redact_text("mysql -u root -P3306 db", file="x.txt")
    assert findings == [] and "P3306" in new
    # bare -p with no attached value prompts interactively — no secret
    new, findings = redact_text("mysql -u root -p db", file="x.txt")
    assert "hunter2" not in new


def test_sql_and_redis_config_secrets():
    """SQL ``IDENTIFIED ... BY`` and redis ``requirepass``/``masterauth``
    mask the credential and keep the surrounding statement."""
    for src in (
        "CREATE USER u IDENTIFIED BY 'hunter2';",
        "CREATE USER u IDENTIFIED WITH mysql_native_password BY 'hunter2';",
    ):
        new, findings = redact_text(src, file="mig.sql")
        assert "hunter2" not in new
        assert "IDENTIFIED" in new and "BY" in new
    for src in ("requirepass hunter2", "masterauth hunter2"):
        new, findings = redact_text(src, file="redis.conf")
        assert "hunter2" not in new
        assert findings


def test_midline_assignment_and_comparison_boundary():
    """A bare ``NAME=value`` mid-line flags (CLI args, cookies); a
    comparison (``==``, ``>=``) is not an assignment and stays out."""
    new, findings = redact_text(
        "Cookie: api_key=hunter2; other=1", file="hdrs.txt"
    )
    assert "hunter2" not in new and "other=1" in new
    new, findings = redact_text(
        'if api_key=="x" or token>=5: pass', file="a.py"
    )
    assert findings == []


def test_env_match_inside_tagged_string_is_decoy():
    """``["<REDACTED:x> API_KEY=innocent"]`` — a string already carrying
    a redaction tag is prior output; re-matching the decoy inside it
    must leave the line untouched."""
    src = 'TOKEN_KEY = ["<REDACTED:abc> API_KEY=innocent"]\n'
    new, findings = redact_text(src)
    assert new == src
    assert findings == []


def test_long_option_secret_arguments():
    """``--password pw``, ``--api-key k`` and friends mask the next
    argument; flags ending in ``-file``/``-type`` carry names, not
    secrets, and stay out."""
    for src in (
        "wget --http-password hunter2 https://x",
        "svn --password hunter2 co repo",
        "rclone config --password hunter2",
        "tool --api-key hunter2 run",
        "tool --client-secret hunter2",
        "tool --auth-token hunter2",
    ):
        new, findings = redact_text(src, file="cmd.txt")
        assert "hunter2" not in new, src
        assert findings, src
    for src in (
        "--password-file creds.txt",
        "--token-type bearer",
        "--key-store /path/ks",
    ):
        new, findings = redact_text(src, file="cmd.txt")
        assert findings == [] and new == src, src


def test_tool_specific_short_flags():
    """``docker login -p``, ``zip -P``, ``7z -p`` and
    ``aws configure set <name> <value>`` mask only the secret."""
    for src in (
        "docker login -u u -p hunter2",
        "podman login -p hunter2",
        "zip -P hunter2 a.zip f",
        "unzip -P hunter2 a.zip",
        "7z a -p'hunter2' a.7z",
        "aws configure set aws_secret_access_key hunter2",
        "aws configure set aws_access_key_id hunter2",
    ):
        new, findings = redact_text(src, file="cmd.txt")
        assert "hunter2" not in new, src
        assert findings, src
    for src in ("ssh -p 2222 host", "docker build -t img .", "unzip f.zip"):
        new, findings = redact_text(src, file="cmd.txt")
        assert findings == [] and new == src, src


def test_quoted_header_and_openssl_pass_scheme():
    """``-H "X-Api-Key: v"`` masks the header value inside its quotes;
    non-credential headers stay out. openssl ``-pass pass:v`` masks
    after the ``pass:`` scheme."""
    for src in (
        'curl -H "X-Api-Key: hunter2" https://x',
        'curl -H "Authorization: Bearer hunter2" https://x',
        "openssl enc -pass pass:hunter2",
        "openssl pkcs12 -passin pass:hunter2",
    ):
        new, findings = redact_text(src, file="cmd.txt")
        assert "hunter2" not in new, src
        assert findings, src
    for src in (
        '-H "Content-Type: application/json"',
        '-H "Access-Control-Allow-Credentials: true"',
    ):
        new, findings = redact_text(src, file="cmd.txt")
        assert findings == [] and new == src, src


def test_powershell_securestring_literal():
    """``ConvertTo-SecureString "pw"`` takes plaintext — mask it."""
    src = 'ConvertTo-SecureString "hunter2" -AsPlainText -Force'
    new, findings = redact_text(src, file="s.ps1")
    assert "hunter2" not in new and "-AsPlainText" in new
    assert findings


def test_cmdkey_slashflag_and_credential_pairs():
    """cmdkey ``/pass:v``, smbclient ``-U user%pass``, lftp
    ``-u user,pass`` and Oracle ``user/pass[@db]`` each mask only
    the password half of the pair."""
    for src in (
        "cmdkey /add:host /user:u /pass:hunter2",
        "smbclient //srv/share -U admin%hunter2",
        "lftp -u admin,hunter2 ftp.x",
        "sqlplus scott/hunter2@db",
        "sqlplus scott/hunter2",
        "exp scott/hunter2@orcl",
    ):
        new, findings = redact_text(src, file="cmd.txt")
        assert "hunter2" not in new, src
        assert findings, src
    # the user half survives — only the password is masked
    new, _ = redact_text("smbclient //s -U admin%hunter2", file="c.txt")
    assert "admin%<REDACTED:" in new


def test_tool_positional_and_miscl_flags():
    """``openssl passwd -6 pw``, ``plink -pw``, ``sqlcmd -P``,
    ``keytool -storepass``, ``twine -p``, ``poetry config`` and
    ``--passphrase``/``--oauth2-bearer`` mask the credential."""
    for src in (
        "openssl passwd -6 hunter2",
        "openssl passwd hunter2",
        "plink -pw hunter2 u@h",
        "pscp -pw hunter2 f u@h:",
        "sqlcmd -U sa -P hunter2",
        "keytool -list -storepass hunter2 -keystore k.jks",
        "twine upload -p hunter2 dist/*",
        "poetry config pypi-token.pypi hunter2",
        "gpg --passphrase hunter2 -c f",
        "curl --oauth2-bearer hunter2 https://x",
    ):
        new, findings = redact_text(src, file="cmd.txt")
        assert "hunter2" not in new, src
        assert findings, src
    # ``openssl passwd -stdin`` reads interactively — no literal arg
    new, findings = redact_text("openssl passwd -stdin", file="c.txt")
    assert findings == [] and "-stdin" in new


def test_call_name_arg_and_setters():
    """Credential names passed as call arguments — ``config.set``,
    ``putenv``/``getenv``/``define`` — and fluent setters such as
    ``e.set_key("v")`` mask only the value argument."""
    for src in (
        'config.set("sec", "api_key", "hunter2")',
        'cfg.update({"api_key": "hunter2"})',
        'os.putenv("API_KEY", "hunter2")',
        'os.getenv("API_KEY", "hunter2")',
        'define("DB_PASS", "hunter2");',
        'e.set_key("hunter2")',
        'client.withToken("hunter2")',
    ):
        new, findings = redact_text(src, file="a.py")
        assert "hunter2" not in new, src
        assert findings, src
    # name and call shape survive
    new, _ = redact_text(
        'config.set("sec", "api_key", "hunter2")', file="a.py"
    )
    assert '"api_key"' in new and "config.set" in new
    import ast

    ast.parse(new)
    # ordinary calls without credential context stay untouched
    new, findings = redact_text(
        'x.get("key", default_val)\nprint("hello")', file="a.py"
    )
    assert findings == [] and "default_val" in new


def test_shell_env_command_forms():
    """fish ``set -x``, csh ``setenv`` and macOS ``launchctl setenv``
    keep the command and name, masking only the value."""
    for src in (
        "set -x API_KEY hunter2",
        "set -gx API_KEY hunter2",
        "setenv API_KEY hunter2",
        "launchctl setenv API_KEY hunter2",
    ):
        new, findings = redact_text(src, file="rc.txt")
        assert "hunter2" not in new, src
        assert findings, src
        assert "API_KEY" in new, src
    # shell options without a credential name stay untouched
    new, findings = redact_text("set -e -u -o pipefail", file="rc.txt")
    assert findings == [] and new == "set -e -u -o pipefail"


def test_define_elisp_and_plist_forms():
    """``#define API_KEY "v"``, elisp ``setq``/``defvar`` and plist
    ``<key>/<string>`` pairs mask the literal."""
    for src in (
        '#define API_KEY "hunter2"',
        '(setq api-key "hunter2")',
        '(defvar api-key "hunter2")',
        '(defvar *api-key* "hunter2")',
        '(defcustom smtp-password "hunter2" "doc")',
        '<key>api_key</key><string>hunter2</string>',
    ):
        new, findings = redact_text(src, file="c.txt")
        assert "hunter2" not in new, src
        assert findings, src
    # plist ``<data>`` carries base64, not the literal — assert the
    # element text itself was masked
    new, findings = redact_text(
        "<key>api_secret</key><data>aHVudGVyMg==</data>", file="p.plist"
    )
    assert findings and "aHVudGVyMg" not in new
    assert "<data><REDACTED:" in new
    # structural and non-secret forms stay untouched
    for src in (
        "#define AUTH_TIMEOUT 30",
        "#define MAX_RETRIES 5",
        "(setq tab-width 4)",
        "<key>width</key><integer>42</integer>",
    ):
        new, findings = redact_text(src, file="c.txt")
        assert findings == [], src
        assert src in new, src


def test_pass_pwd_name_vocabulary():
    """``PASS``/``PWD``/``PASSPHRASE`` bind as credential names at the
    whole name or after an underscore; ``compass``/``bypass``/
    ``passport`` stay out."""
    for src in (
        "DB_PASS=hunter2",
        "FTP_PWD=hunter2",
        "app_passphrase=hunter2",
        "MY_PASSCODE=hunter2",
    ):
        new, findings = redact_text(src, file="e.env")
        assert "hunter2" not in new, src
        assert findings, src
    for src in (
        "BYPASS=1",
        "compass=x",
        "passport=x",
        "surpass=hunter2",
        "x_passport=hunter2",
    ):
        _, findings = redact_text(src, file="e.env")
        assert findings == [], src


def test_declaration_modifiers_and_make_ops():
    """Typed-language declarations (``const``/``private static
    final``/``val``), Rust reference annotations (``&str``,
    ``&'a mut str``) and make-style operators (``:=``/``?=``/
    ``+=``/``::=``) flag; the operator survives the mask."""
    for src, f in (
        ('private static final String API_KEY = "hunter2";', "a.java"),
        ('val apiKey = "hunter2"', "a.kt"),
        ('const API_KEY: &str = "hunter2"', "a.rs"),
        ("const API_KEY: &'static str = \"hunter2\"", "a.rs"),
        ('apiKey := "hunter2"', "a.go"),
        ("KEY := hunter2", "Makefile"),
        ("API_KEY ?= hunter2", "Makefile"),
        ("TOKEN ::= hunter2", "Makefile"),
        ("SECRET += hunter2", "Makefile"),
    ):
        new, findings = redact_text(src, file=f)
        assert "hunter2" not in new, src
        assert findings, src
    # the make operator is preserved, not eaten
    for op in (":=", "?=", "::=", "+="):
        new, _ = redact_text(f"API_KEY {op} hunter2", file="Makefile")
        assert op in new, (op, new)


def test_windows_and_misc_config_credentials():
    """``setx``, ``net user`` positional, ``git config`` and Erlang
    config tuples mask the credential value."""
    for src in (
        "setx API_KEY hunter2",
        "setx /M API_KEY hunter2",
        "net user admin hunter2 /add",
        "git config --global user.password hunter2",
        '{password, "hunter2"}.',
        '{api_key, "hunter2"}.',
        '{secret, "hunter2"}.',
        '[Environment]::SetEnvironmentVariable("API_KEY","hunter2")',
        'f("API_KEY","hunter2")',
    ):
        new, findings = redact_text(src, file="c.txt")
        assert "hunter2" not in new, src
        assert findings, src
    # negatives — no credential context
    for src in (
        "net user admin /add",
        '{key, "hunter2"}.',
        'x == hunter2',
        'name != "hunter2"',
    ):
        _, findings = redact_text(src, file="c.txt")
        assert findings == [], src


def test_env_subscripts_and_dotted_call_names():
    """Sigil/brace env subscripts and dotted property-path names in
    call args flag and keep syntax intact."""
    for src, f in (
        ('$ENV{API_KEY} = "hunter2";', "a.pl"),
        ("$_ENV['API_KEY'] = 'hunter2';", "a.php"),
        ('System.setProperty("db.password", "hunter2")', "j.java"),
        ('ini_set("session.secret", "hunter2")', "a.php"),
    ):
        new, findings = redact_text(src, file=f)
        assert "hunter2" not in new, src
        assert findings, src


def test_sql_with_password_and_basic_header():
    """Postgres ``WITH PASSWORD`` and a bare ``Authorization: Basic``
    header flag; a lowercase prose word after ``basic`` stays out."""
    for src in (
        "CREATE USER u WITH PASSWORD 'hunter2'",
        "ALTER ROLE u WITH PASSWORD 'hunter2'",
        "Authorization: Basic aHVudGVyMg==",
    ):
        new, findings = redact_text(src, file="c.txt")
        assert "hunter2" not in new and "aHVudGVyMg" not in new, src
        assert findings, src
    # one plain lowercase word is prose, not a credential blob
    new, findings = redact_text(
        "authorization: basic hunter2", file="c.txt"
    )
    assert "hunter2" in new
    assert findings == []


def test_auth_tuple_and_inline_map():
    """``auth=("u","p")``-style credential tuples mask only the
    password element, and bare inline-map values ``{KEY: v}`` flag;
    generic tuples under cred names stay code."""
    for src in (
        'session.auth = ("admin", "hunter2")',
        'auth=("admin","hunter2")',
        'credentials = ("u", "hunter2")',
        'HTTPBasicAuth("u", "hunter2")',
    ):
        new, findings = redact_text(src, file="a.py")
        assert "hunter2" not in new, src
        assert '"admin"' in new or "'admin'" in new or '"u"' in new, new
        assert findings, src
        import ast

        ast.parse(new)
    new, findings = redact_text("env: {API_KEY: hunter2}", file="d.yml")
    assert "hunter2" not in new
    assert "}" in new
    # tuple-of-literals under a generic cred name is still code
    for src in ("C_API_KEY = ('a', 'b')", "token = (\"a\", \"hunter2\")"):
        _, findings = redact_text(src, file="a.py")
        assert findings == [], src


def test_nginx_header_directive():
    """``proxy_set_header``/``add_header`` mask the quoted value."""
    for src in (
        'proxy_set_header Authorization "Bearer hunter2";',
        'add_header X-Api-Key "hunter2";',
    ):
        new, findings = redact_text(src, file="n.conf")
        assert "hunter2" not in new, src
        assert findings, src


def test_tool_scoped_secret_flags():
    """Tool-specific short flags and password-subcommand positionals
    mask only the credential token."""
    for src in (
        "doctl auth init -t hunter2",
        "xfreerdp /u:admin /p:hunter2 /v:host",
        "x11vnc -passwd hunter2",
        "mysqladmin -u root password hunter2",
        "rabbitmqctl change_password guest hunter2",
        "ipmitool -I lanplus -H host -U root -P hunter2 sol",
        "useradd -m -p hunter2 deploy",
        "usermod -p hunter2 deploy",
        "snmpget -v3 -u admin -A hunter2 host",
        "snmpset -v3 -u admin -X hunter2 host",
        r"net use z: \\srv\share hunter2 /user:admin",
        r"net use \\srv\ipc$ /user:admin hunter2",
    ):
        new, findings = redact_text(src, file="c.txt")
        assert "hunter2" not in new, src
        assert findings, src
    for src in (
        r"net use z: \\srv\share",
        "secure: true",
        "useradd -m deploy",
        "ipmitool -I lanplus -H host -U root sol",
    ):
        _, findings = redact_text(src, file="c.txt")
        assert findings == [], src


def test_travis_secure_blob():
    """``secure: <blob>`` is an encrypted Travis var — the length
    floor keeps ``secure: true`` out."""
    new, findings = redact_text(
        "secure: A7V1k2x9zQbN4rT8yU3iO6pL0sD5fG7hJ2kM", file="d.yml"
    )
    assert "A7V1k2" not in new
    assert findings
    _, findings = redact_text("secure: true", file="d.yml")
    assert findings == []


def test_xml_element_text_and_ldap_rootpw():
    """XML element text under a cred-named tag masks (``<key>`` name
    elements stay out so plist pairs survive), and LDAP
    ``rootpw``/``olcRootPW`` flag."""
    for src in (
        "<password>hunter2</password>",
        "<db.password>hunter2</db.password>",
        "<api_key>hunter2</api_key>",
    ):
        new, findings = redact_text(src, file="c.xml")
        assert "hunter2" not in new, src
        assert findings, src
    for src in (
        "<key>api_key</key>",
        "<name>hunter2</name>",
        "<password></password>",
    ):
        _, findings = redact_text(src, file="c.xml")
        assert findings == [], src
    for src in (
        "olcRootPW: hunter2",
        "olcRootPW={SSHA}aHVudGVyMg==",
        "rootpw hunter2",
        "db_pw=hunter2",
    ):
        new, findings = redact_text(src, file="s.conf")
        assert "hunter2" not in new and "aHVudGVy" not in new, src
        assert findings, src


def test_crypt_hashes_and_authpair_carriers():
    """Crypt-scheme password hashes (``$apr1$``, ``$6$``, ``$2y$``,
    ``{SHA}``/``{SSHA}``) flag wherever they appear — in
    ``.htpasswd`` lines, traefik ``users`` lists, or bare."""
    for src in (
        'app:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8vw/',
        'app:{SHA}fEqNCco3Yq9h5ZUglq3ABZxXVEM=',
        'root:$6$saltsalt$abcdef1234567890abcdef1234567890ab',
        'users = ["admin:$apr1$abc$def"]',
        'user:{SSHA}aGVsbG93b3JsZA==',
    ):
        _, findings = redact_text(src, file="x.htpasswd")
        assert findings, src


def test_password_file_tools_and_config_writers():
    """``htpasswd``/``mosquitto_passwd`` batch mode, CMS config
    writers and KV stores flag the positional secret."""
    for src in (
        'htpasswd -b f.txt admin hunter2',
        'htpasswd -cb f.txt admin hunter2',
        'htpasswd -nb admin hunter2',
        'mosquitto_passwd -b f.txt admin hunter2',
        'wp config set DB_PASSWORD hunter2',
        'wp option update admin_password hunter2',
        'consul kv put config/db_password hunter2',
        'vault kv put secret/db password=hunter2',
        'stats auth admin:hunter2',
    ):
        new, findings = redact_text(src, file="s.sh")
        assert findings, src
        assert "hunter2" not in new, src
    for src in (
        'htpasswd -n admin',
        'wp config set table_prefix wp_',
        'etcdctl put foo 1',
        'stats admin if TRUE',
    ):
        _, findings = redact_text(src, file="s.sh")
        assert findings == [], src


def test_sshpass_env_and_smtp_auth_plain():
    """``SSHPASS=x`` (no underscore between SSH and PASS) and
    SMTP/IMAP ``AUTH PLAIN`` blobs flag."""
    new, findings = redact_text(
        "SSHPASS=hunter2 sshpass -e ssh h", file="s.sh")
    assert findings and "hunter2" not in new
    for src in (
        "AUTH PLAIN AHVzZXIAaHVudGVyMg==",
        "a1 AUTHENTICATE PLAIN AHVzZXIAaHVudGVyMg==",
    ):
        new, findings = redact_text(src, file="s.log")
        assert findings, src
        assert "AHVz" not in new, src


def test_pgpass_and_secret_store_clis():
    """``.pgpass`` five-field rows flag under the filename gate;
    secret-store CLIs mask the ``--value``/``--secret-string``
    argument."""
    for src in (
        'localhost:5432:db:admin:hunter2',
        '*:*:db:admin:hunter2',
    ):
        new, findings = redact_text(src, file=".pgpass")
        assert findings and "hunter2" not in new, src
        _, findings = redact_text(src, file="x.txt")
        assert findings == [], src
    _, findings = redact_text("a:b:c:d:e", file=".pgpass")
    assert findings  # five colon fields in .pgpass is a row
    for src in (
        'az keyvault secret set --vault-name v --name n --value hunter2',
        'aws ssm put-parameter --name n --value hunter2 --type SecureString',
        'aws secretsmanager create-secret --name n --secret-string hunter2',
        'composer config http-basic.repo admin hunter2',
        'java -jar jenkins-cli.jar -auth admin:hunter2 build j',
        'doppler secrets set API_KEY hunter2',
        'cargo login hunter2abcd',
        'nuget setApiKey hunter2-abcd',
    ):
        new, findings = redact_text(src, file="s.sh")
        assert findings, src
        assert "hunter2" not in new, src


def test_ansible_vault_blob_masks_body():
    """The ``$ANSIBLE_VAULT`` marker and its hex ciphertext body
    mask as one span."""
    src = (
        "$ANSIBLE_VAULT;1.1;AES256\n"
        "6338646538306164\n6634626433316139\nnext: plain"
    )
    new, findings = redact_text(src, file="x.yml")
    assert findings
    assert "6338646538306164" not in new
    assert "ANSIBLE_VAULT" not in new
    assert "next: plain" in new


def test_admin_and_bruteforce_tool_flags():
    """Remote-exec/brute-force tools whose password rides a
    tool-scoped flag flag and mask; the list-file/port variants
    stay out."""
    for src in (
        'hydra -l admin -p hunter2 ssh://h',
        'crackmapexec smb h -u admin -p hunter2',
        'evil-winrm -i h -u admin -p hunter2',
        'psexec \\\\h -u admin -p hunter2 cmd',
        'gh secret set API_KEY --body "hunter2"',
        'gh variable set DEPLOY_TOKEN --body hunter2',
        'security add-generic-password -a u -s svc -w hunter2',
        'eyaml encrypt -s hunter2',
        'schtasks /create /tn t /ru admin /rp hunter2 /tr x',
        'rclone config create r s3 secret_access_key hunter2',
        'ncrack -p 22 --user u --pass hunter2 h',
    ):
        new, findings = redact_text(src, file="s.sh")
        assert findings, src
        assert "hunter2" not in new, src
    for src in (
        'hydra -l admin -P list.txt ssh://h',
        'gh variable set NAME --body x',
        'rclone config create r s3 provider AWS',
        'psexec \\\\h -u admin cmd',
    ):
        _, findings = redact_text(src, file="s.sh")
        assert findings == [], src


def test_review_round_setx_pgpass_quoted_vault():
    """Review fixes: ``setx`` keeps its command/name, ``.pgpass``
    escaped colons stay inside fields, quoted CLI credentials with
    spaces mask whole, and a blank line inside a vault blob does
    not unmask the tail."""
    new, _ = redact_text("setx API_KEY hunter2", file="s.bat")
    assert new.startswith("setx API_KEY ") and "hunter2" not in new
    new, _ = redact_text("setx /M API_KEY hunter2", file="s.bat")
    assert new.startswith("setx /M API_KEY ") and "hunter2" not in new
    for src in (
        "localhost:54\\:32:db:admin:hunter2",
        "lo\\:cal:5432:db:admin:hunter\\:2",
    ):
        new, findings = redact_text(src, file=".pgpass")
        assert findings and "hunter2" not in new and "hunter\\:2" not in new
    for src in (
        'composer config http-basic.repo admin "hun ter2"',
        'cargo login "hun ter2"',
        'doppler secrets set API_KEY "hun ter2"',
        'java -jar jenkins-cli.jar -auth "admin:hun ter2" build j',
    ):
        new, findings = redact_text(src, file="s.sh")
        assert findings, src
        assert "hun ter2" not in new and "ter2" not in new, src
    src = "$ANSIBLE_VAULT;1.1;AES256\n633864\n\n6634ff\nnext: plain"
    new, findings = redact_text(src, file="x.yml")
    assert findings and "6634ff" not in new and "next: plain" in new
