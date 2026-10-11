"""M1 tests: recall on the planted corpus, benign input, idempotency."""

import hashlib
import json
import sqlite3
from pathlib import Path

import devin_redact
import pytest
from devin_redact import cli
from devin_redact.engine import scan_text

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = [
    FIXTURES / "sessions.db",
    FIXTURES / "memories.jsonl",
    FIXTURES / "export.md",
    FIXTURES / ".env",
]
BENIGN = FIXTURES / "benign.txt"

FAKE_JWT = (
    "eyJhbGciOiJGQUtFIiwidHlwIjoiRkFLRSJ9"
    ".ZmFrZS5wYXlsb2FkLmZha2U.c2lnbmF0dXJlLWZha2Utc2ln"
)
FAKE_API_KEY = "sk-" + "FAKE0000000000000000000000000000abcd"
FAKE_LIVE_API_KEY = "sk_live_" + "FAKE0000000000000000"
FAKE_GITHUB_TOKEN = "ghp_" + "FAKE00000000000000000000"
FAKE_GITHUB_OAUTH_TOKEN = "gho_" + "FAKE00000000000000000000"
FAKE_TEXT_API_KEY = "sk-" + "FAKE" + ("a" * 28)
FAKE_PEM = (
    "-----BEGIN PRIVATE " + "KEY-----\n"
    "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    "-----END PRIVATE " + "KEY-----"
)

# Every planted value, keyed by the category expected to catch it. The value
# must equal the exact matched substring so its sha256 fingerprint appears
# in the report.
PLANTED = {
    "api_key": [
        FAKE_API_KEY,
        FAKE_LIVE_API_KEY,
    ],
    "github_token": [
        FAKE_GITHUB_TOKEN,
        FAKE_GITHUB_OAUTH_TOKEN,
    ],
    "bearer_token": [FAKE_JWT],
    "private_key": [FAKE_PEM],
    "env_assignment": [
        "OPENAI_API" + "_KEY=" + FAKE_API_KEY,
        "DB_PASSWORD" + "=" + "hunter" + "2fake",
        "GITHUB_TOKEN" + "=" + FAKE_GITHUB_TOKEN,
        "AWS_SECRET_ACCESS_KEY" + "=" + ("FAKE" * 10),
        "STRIPE_SECRET_KEY" + "=" + FAKE_LIVE_API_KEY,
    ],
    "devin_pairing_code": ["FAKE-1234-ABCD"],
    "email": ["fake.user@example.com", "ci-bot@example.invalid"],
    "absolute_path": [
        r"C:\Users\fakeuser\secrets\prod.env",
        r"C:\Users\fakeuser\projects\demo-shop",
        "/home/fakeuser/devin-demo",
        "/Users/fakeuser/Dev/project",
    ],
}


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def test_scan_finds_all_planted_secrets():
    report = devin_redact.scan(CORPUS)
    fps_by_category: dict[str, set[str]] = {}
    for f in report["findings"]:
        fps_by_category.setdefault(str(f["category"]), set()).add(str(f["fingerprint"]))
    for category, values in PLANTED.items():
        for value in values:
            assert _fp(value) in fps_by_category.get(category, set()), (
                f"missing {category}: {value!r}"
            )


def test_report_contract_and_blocked():
    report = devin_redact.scan(CORPUS)
    for key in (
        "files_scanned",
        "secrets",
        "emails",
        "absolute_paths",
        "project_names",
        "publication_status",
        "findings",
        "by_category",
        "errors",
    ):
        assert key in report
    assert report["files_scanned"] == len(CORPUS)
    assert report["publication_status"] == "BLOCKED"
    assert report["secrets"] > 0
    assert report["errors"] == []


def test_findings_cover_db_and_text_files():
    report = devin_redact.scan(CORPUS)
    files = {str(f["file"]) for f in report["findings"]}
    for path in CORPUS:
        assert str(path) in files, f"no findings in {path}"
    db_locations = [
        str(f["location"]) for f in report["findings"] if "sessions.db" in str(f["file"])
    ]
    assert any("tool_call_state.tool_call_update_json" in loc for loc in db_locations)
    assert any("prompt_history.content" in loc for loc in db_locations)


def test_project_names_extracted():
    report = devin_redact.scan(CORPUS)
    names = {f["fingerprint"] for f in report["findings"] if f["category"] == "project_name"}
    assert _fp("demo-shop") in names


def test_benign_text_zero_findings():
    report = devin_redact.scan([BENIGN])
    assert report["findings_total"] == 0
    assert report["publication_status"] == "CLEAN"
    assert report["findings"] == []


def test_scan_is_idempotent_and_read_only():
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in CORPUS + [BENIGN]}
    first = devin_redact.scan(CORPUS)
    second = devin_redact.scan(CORPUS)
    assert first == second
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in CORPUS + [BENIGN]}
    assert before == after


def test_fixture_db_still_opens_after_scan():
    devin_redact.scan(CORPUS)
    con = sqlite3.connect(f"file:{FIXTURES / 'sessions.db'}?mode=ro", uri=True)
    (n,) = con.execute("select count(*) from tool_call_state").fetchone()
    con.close()
    assert n == 3


def test_redact_dry_run_only(tmp_path):
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in CORPUS}
    result = devin_redact.redact(CORPUS)
    assert result["dry_run"] is True
    assert result["applied"] is False
    assert result["replacements"] > 0
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in CORPUS}
    assert before == after
    with pytest.raises(RuntimeError):
        devin_redact.redact(CORPUS, apply=True)


def test_cli_scan_emits_json(capsys):
    code = cli.main(["scan", str(FIXTURES / ".env")])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["publication_status"] == "BLOCKED"


def test_cli_redact_apply_refused(capsys):
    assert cli.main(["redact", str(FIXTURES / ".env"), "--apply"]) == 3


def test_scan_text_unit():
    findings = scan_text("key: " + FAKE_TEXT_API_KEY, file="x", location="text")
    assert findings and findings[0]["category"] == "api_key"
    assert findings[0]["preview"].startswith("sk-F")
    assert "..." in findings[0]["preview"]


def test_env_assignment_suppresses_code_constants():
    """Scanner-config / parser source must not self-flag: names carrying
    KEY/SECRET/TOKEN bound to code expressions are constants, not env
    secrets. This is what lets a repo containing the scanner itself
    (or any regex/policy generator) pass the gate."""
    code = (
        "_STRUCTURAL_KEYS = frozenset({'type', 'kind'})\n"
        "_TRUE_TOKENS = ('keep', 'true')\n"
        "_PATH_KEY_RE = re.compile(r'path|file')\n"
        "SECRET_PATTERNS = [r'AKIA[0-9A-Z]{16}']\n"
        "CREDENTIAL_MAP = {'user': 'pass'}\n"
        "build_key = lambda: None\n"  # lowercase name: no KEY/SECRET/TOKEN
    )
    findings = scan_text(code, file="x.py", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert env == [], env


def test_env_assignment_still_flags_real_values():
    """The suppression only covers code expressions — bare and quoted
    secret values must still flag."""
    code = (
        "MY_API_KEY = 'abc123secretvalue'\n"
        "API_TOKEN=plaintext_token_123\n"
        "export DB_PASSWORD = hunter2!\n"
        "_PRIVATE_KEY = 'still-a-hardcoded-secret'\n"
    )
    findings = scan_text(code, file=".env", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert len(env) == 4


def test_env_assignment_flags_parenthesized_string_literal():
    """Regression: ``KEY = ("secret")`` is a string literal, not a code
    expression — parens group, they do not contain. Previously the
    code-assignment guard suppressed it and the gate went CLEAN."""
    findings = scan_text(
        'DB_PASSWORD = ("hunter' + '2fake")\n',
        file=".env",
        location="text",
    )
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert len(env) == 1


def test_env_assignment_still_suppresses_paren_code():
    """Parenthesized *expressions* (tuples, calls) remain suppressed —
    only a lone string literal inside parens flags."""
    code = (
        "API_TOKENS = ('keep', 'true')\n"
        "DB_PASSWORD = (get_secret())\n"
    )
    findings = scan_text(code, file="x.py", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert env == [], env


def test_env_assignment_paren_literal_variants_flag():
    """Every spelling of "one string literal" is the same hardcoded
    value — nested parens, prefixes, triple quotes, implicit
    concatenation, a trailing ``#`` comment, even a one-element tuple
    (``("x",)`` — the wrapped literal one comma away)."""
    code = (
        'A_API_KEY = ("v1fake")  # rotate soon\n'
        "B_API_KEY = ('v2' 'fake')\n"
        'C_API_KEY = ("v3fake",)\n'
        'D_API_KEY = (("v4fake"))\n'
        "E_API_KEY = ('''v5fake''')\n"
        'F_API_KEY = (b"v6fake")\n'
        'G_API_KEY = (rb"v7fake")\n'
    )
    findings = scan_text(code, file="x.py", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert len(env) == 7, env


def test_env_assignment_paren_expression_variants_suppressed():
    """Dynamic expressions stay suppressed — calls, f-strings,
    generator/comprehension expressions, conditionals and real
    containers are code, not literals."""
    code = (
        'A_API_KEY = (f"{get_key()}")\n'
        "B_API_KEY = (get_key())\n"
        "C_API_KEY = ('a', 'b')\n"
        "D_API_KEY = (x for x in y)\n"
        'E_API_KEY = ("x") if cond else other\n'
        "F_API_KEY = ['only-one']\n"
        "G_API_KEY = {'k': 'v'}\n"
    )
    findings = scan_text(code, file="x.py", location="text")
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert env == [], env
