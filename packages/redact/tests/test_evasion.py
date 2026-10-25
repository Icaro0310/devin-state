"""Adversarial-parser regression tests — the audit corpus.

Every case here was a real leak before the coverage pass: standard token
formats with no pattern, structural evasions (casing, separators, JSON
shapes, encodings) that let pattern-shaped secrets slip through, and a
fail-open trust of ``index.json`` in ``verify-publish``. All values are
synthetic.
"""

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
    assert new.startswith('"api_key":<REDACTED:')


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
