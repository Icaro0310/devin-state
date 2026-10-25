"""Tests for ``devin-redact diff`` — the self-contained HTML before/after
report (``devin_redact.diffhtml``).

All secrets in fixtures are synthetic placeholders. The core guarantee
under test is the secrecy contract: the rendered report contains masked
previews and ``<REDACTED:fp>`` tags, never the raw matched values.
"""

import hashlib
import re
from pathlib import Path

from devin_redact import cli, diffhtml, engine
from devin_redact.diffhtml import render_html

FIXTURES = Path(__file__).parent / "fixtures"

FAKE_GITHUB_TOKEN = "ghp_" + "FAKE00000000000000000000"
FAKE_API_KEY = "sk-" + "FAKE" + ("a" * 28)
FAKE_ENV_VALUE = "hunter" + "2fake" + "TOKENtail9"


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_diff_writes_self_contained_html(tmp_path):
    src = _write(
        tmp_path,
        "leak.txt",
        f"token: {FAKE_GITHUB_TOKEN}\n"
        f"OPENAI_API_KEY={FAKE_API_KEY}\n"
        f"contact fake.user@example.com\n",
    )
    out = tmp_path / "report.html"
    assert cli.main(["diff", str(src), "-o", str(out)]) == 0
    doc = out.read_text(encoding="utf-8")

    # Self-contained: doctype, inline CSS, utf-8 meta, no external assets.
    assert doc.startswith("<!doctype html>")
    assert '<meta charset="utf-8">' in doc
    assert "<style>" in doc and "</html>" in doc
    assert "http://" not in doc and "https://" not in doc

    # Masked before/after: the tag with the sha256 fingerprint appears,
    # the raw secrets never do.
    assert "&lt;REDACTED:" in doc
    assert _fp(FAKE_GITHUB_TOKEN) in doc
    for secret in (FAKE_GITHUB_TOKEN, FAKE_API_KEY, FAKE_ENV_VALUE):
        assert secret not in doc


def test_diff_stdout_when_no_out(tmp_path, capsys):
    src = _write(tmp_path, "leak.txt", f"tok {FAKE_GITHUB_TOKEN}\n")
    assert cli.main(["diff", str(src)]) == 0
    doc = capsys.readouterr().out
    assert doc.startswith("<!doctype html>")
    assert "&lt;REDACTED:" in doc
    assert FAKE_GITHUB_TOKEN not in doc


def test_diff_summary_counts(tmp_path):
    src = _write(
        tmp_path,
        "leak.txt",
        f"{FAKE_GITHUB_TOKEN}\nme@example.invalid\n",
    )
    out = tmp_path / "r.html"
    assert cli.main(["diff", str(src), "-o", str(out)]) == 0
    doc = out.read_text(encoding="utf-8")
    # 1 github_token + 1 email finding.
    assert '<span class="num">2</span>' in doc
    assert 'class="badge blocked"' in doc
    assert "github_token" in doc and "email" in doc


def test_diff_structure_golden(tmp_path):
    """Structural snapshot: table headers and section order are stable —
    asserted as invariants, not full-file equality."""
    src = _write(tmp_path, "leak.txt", f"KEY={FAKE_API_KEY}\n")
    out = tmp_path / "r.html"
    assert cli.main(["diff", str(src), "-o", str(out)]) == 0
    doc = out.read_text(encoding="utf-8")
    headers = re.findall(r"<th\b[^>]*>(.*?)</th>", doc)
    assert headers == [
        "#",
        "File",
        "Location",
        "Category",
        "Before (masked)",
        "After",
        "Fingerprint",
        "Plan",
    ]
    for marker in (
        "devin-redact diff",
        "files scanned",
        "findings",
        "By category",
        "Findings",
        "env_assignment",
    ):
        assert marker in doc
    # env assignments keep their KEY= prefix — the footer documents it.
    assert "KEY=" in doc


def test_diff_escapes_html_entities():
    """Every rendered field is escaped — a finding carrying HTML markup
    must arrive as entities, never live markup."""
    report = {
        "version": "0.0.0",
        "files_scanned": 1,
        "findings_total": 1,
        "secrets": 1,
        "emails": 0,
        "absolute_paths": 0,
        "project_names": 0,
        "publication_status": "BLOCKED",
        "by_category": {"api_key": 1},
        "findings": [
            {
                "file": "<script>alert(1)</script>.db",
                "location": "text:line 1",
                "category": "api_key",
                "pattern": "openai_key",
                "kind": "pattern",
                "fingerprint": "deadbeefcafe",
                "preview": '<img src=x onerror="alert(2)">',
            }
        ],
        "errors": [{"file": "x", "error": "<b>read failed</b>"}],
    }
    doc = render_html(report, targets=["<script>in</script>"])
    assert "<script>" not in doc
    assert "<img" not in doc
    assert "&lt;script&gt;" in doc
    assert "&lt;img" in doc
    assert "&lt;b&gt;" in doc


def test_diff_escapes_preview_metachars_via_cli(tmp_path):
    """End-to-end escaping: an env value ending in ``<`` survives masking
    in the last four chars and must be escaped in the HTML."""
    src = _write(tmp_path, "leak.env", "MY_TOKEN=fakevalue<\n")
    out = tmp_path / "r.html"
    assert cli.main(["diff", str(src), "-o", str(out)]) == 0
    doc = out.read_text(encoding="utf-8")
    # Masked preview keeps the trailing "<" — it must arrive escaped.
    assert "MY_T...lue&lt;" in doc


def test_diff_marks_detection_only_for_cross_chunk():
    """Cross-chunk findings (secrets split across payload boundaries) are
    not covered by the per-cell rewrite — the report must say so."""
    report = engine.scan([FIXTURES])
    doc = render_html(
        report, planned=diffhtml.planned_locations(engine.redact([FIXTURES]))
    )
    assert "detection-only" in doc


def test_diff_empty_input_still_reports(tmp_path):
    src = _write(tmp_path, "clean.txt", "nothing sensitive here\n")
    out = tmp_path / "r.html"
    assert cli.main(["diff", str(src), "-o", str(out)]) == 0
    doc = out.read_text(encoding="utf-8")
    assert "No findings" in doc
    assert 'class="badge clean"' in doc


def test_diff_missing_input_fails_loud(tmp_path, capsys):
    missing = tmp_path / "nope.txt"
    assert cli.main(["diff", str(missing)]) == 2
    err = capsys.readouterr().err
    assert "not a file or directory" in err
    assert str(missing) in err


def test_diff_unreadable_input_fails_loud(tmp_path, capsys):
    """A SQLite-looking file that cannot be scanned is a hard error —
    the report is not written and the exit is non-zero."""
    bad = _write(tmp_path, "bad.db", "not really sqlite at all\n")
    # bad.db has the .db suffix so it dispatches as sqlite, but it is not
    # a real database — sqlite open fails.
    out = tmp_path / "r.html"
    code = cli.main(["diff", str(bad), "-o", str(out)])
    assert code == 2
    assert not out.exists()
    assert capsys.readouterr().err


def test_diff_utf8_output(tmp_path):
    """Non-ASCII in the file name and inside a masked preview must survive
    the write — the report is always utf-8, on every platform."""
    src = _write(
        tmp_path,
        "café.txt",
        "T_KEY=fakeé\n",
    )
    out = tmp_path / "résumé.html"
    assert cli.main(["diff", str(src), "-o", str(out)]) == 0
    doc = out.read_bytes().decode("utf-8")
    assert "café.txt" in doc
    assert "keé" in doc  # masked preview tail of `T_KEY=fakeé`


def test_diff_fixture_db_renders(tmp_path):
    """End-to-end on the committed corpus: every finding row renders,
    masked, with a Plan badge."""
    out = tmp_path / "r.html"
    assert cli.main(["diff", str(FIXTURES), "-o", str(out)]) == 0
    doc = out.read_text(encoding="utf-8")
    assert "sensitive_tool_output" in doc
    assert "project_name" in doc
    assert "detection-only" in doc  # cross-chunk findings in fixtures
    assert "planned" in doc
