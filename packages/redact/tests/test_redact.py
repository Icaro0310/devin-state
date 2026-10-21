"""M2 tests: real redact(), semantic layer, verify gate."""

import hashlib
import shutil
import sqlite3
from pathlib import Path

import devin_redact
import pytest
from devin_redact import cli, engine
from devin_redact.engine import redact_text, scan_text
from devin_redact.semantic import analyze_tool_call_json
from test_scan import (
    CORPUS,
    FAKE_API_KEY,
    FAKE_GITHUB_TOKEN,
    FAKE_JWT,
    FAKE_TEXT_API_KEY,
    PLANTED,
    _fp,
)

FIXTURES = Path(__file__).parent / "fixtures"
DB = FIXTURES / "sessions.db"


def _copy_corpus(tmp_path: Path) -> list[Path]:
    dst = tmp_path / "corpus"
    dst.mkdir()
    out = []
    for src in CORPUS:
        target = dst / src.name
        shutil.copy2(src, target)
        out.append(target)
    return out


def _all_fps(report: dict) -> set[str]:
    return {str(f["fingerprint"]) for f in report["findings"]}


def test_semantic_layer_flags_sensitive_reads():
    report = devin_redact.scan([DB])
    sem = [f for f in report["findings"] if f.get("kind") == "semantic-context"]
    # Both `cat .env` tool calls (rowid 1 and 2) are flagged; the benign
    # `ls -la` call (rowid 3) is not.
    assert {str(f["location"]) for f in sem} == {
        "tool_call_state.tool_call_update_json#rowid=1",
        "tool_call_state.tool_call_update_json#rowid=2",
    }
    assert all(f["category"] == "sensitive_tool_output" for f in sem)
    # tc-fixture-0002's output matches no pattern — its flag is purely
    # semantic. tc-fixture-0001's output also has pattern findings.
    assert report["publication_status"] == "BLOCKED"


def test_semantic_layer_ignores_benign_command():
    flag = analyze_tool_call_json(
        '{"kind":"execute","rawInput":{"command":"ls -la"},"title":"ls"}'
    )
    assert flag is None
    flag = analyze_tool_call_json(
        '{"kind":"execute","rawInput":{"command":"cat README.md"}}'
    )
    assert flag is None
    flag = analyze_tool_call_json(
        '{"kind":"execute","rawInput":{"command":"type C:\\\\x\\\\credentials.toml"}}'
    )
    assert flag and flag["reason"]


def test_redact_text_masks_and_keeps_key():
    assignment = "OPENAI_API" + "_KEY=" + FAKE_TEXT_API_KEY
    new, edits = redact_text(assignment + "\nDEBUG=1\n")
    assert new.startswith("OPENAI_API_KEY=<REDACTED:")
    assert "sk-FAKE" not in new
    assert "DEBUG=1" in new
    assert any(e["category"] == "env_assignment" for e in edits)


def test_redact_text_parenthesized_assignment():
    new, edits = redact_text('DB_PASSWORD = ("hunter' + '2fake")\n')
    assert "hunter" + "2fake" not in new
    assert new.startswith("DB_PASSWORD =<REDACTED:")
    assert any(e["category"] == "env_assignment" for e in edits)


def test_redact_text_idempotent():
    once, _ = redact_text("token " + FAKE_GITHUB_TOKEN + " end")
    twice, edits2 = redact_text(once)
    assert once == twice
    assert edits2 == []


def test_redact_text_tag_tail_assignment_redacts():
    """Issue #66: a match containing ``<REDACTED:…>`` was skipped
    wholesale, and ``env_assignment`` swallows the rest of the line — so
    a second ``KEY=`` inside the skipped match stayed raw (and, being
    mid-line, could never match on its own). Only the tag's own span is
    prior output; the tail assignment must still redact."""
    new, edits = redact_text("API_KEY=<REDACTED:abc123> OTHER" + "_TOKEN=rawsecret99")
    assert "<REDACTED:abc123>" in new  # prior tag is never re-processed
    assert "rawsecret99" not in new
    assert "OTHER_TOKEN=<REDACTED:" in new
    assert any(e["category"] == "env_assignment" for e in edits)


def test_redact_text_nested_tags_inside_match_tail_redacts():
    """Nested already-redacted assignments inside one greedy match:
    every nested tag survives byte-identically while the still-raw
    tail assignment redacts."""
    src = (
        "OUTER" + "_KEY=<REDACTED:x1> INNER" + "_KEY=<REDACTED:y2> DEEP" + "_SECRET=z9"
    )
    new, edits = redact_text(src)
    assert "<REDACTED:x1>" in new and "<REDACTED:y2>" in new
    assert "z9" not in new
    assert new.count("<REDACTED:") == 3
    assert len(edits) == 1


def test_redact_text_mid_value_tag_redacts_both_flanks():
    """A tag embedded mid-value must not shield the raw secrets on
    either side: both flanking assignments redact and the tag survives
    byte-identically (Devin Review on #66)."""
    src = "FIRST" + "_KEY=firstval1<REDACTED:mid99> SECOND" + "_KEY=secondval2"
    new, _edits = redact_text(src)
    assert "<REDACTED:mid99>" in new
    assert "firstval1" not in new
    assert "secondval2" not in new
    assert new.count("<REDACTED:") == 3


def test_redact_text_code_value_tail_after_tag_redacts():
    """A code-shaped head (suppressed by the code guard) must not hide
    a raw assignment after the tag: the ``frozenset`` call stays, the
    tail redacts."""
    src = "FIRST" + "_KEY = frozenset({'x'}) <REDACTED:t0> REAL" + "_TOKEN=tv9x"
    new, _edits = redact_text(src)
    assert "frozenset({'x'})" in new
    assert "<REDACTED:t0>" in new
    assert "tv9x" not in new
    assert "REAL_TOKEN=<REDACTED:" in new


def test_redact_text_tag_between_assignments_redacts_each_tail():
    """Multiple tags on one line: every still-raw assignment between or
    after them redacts, tags are left alone, output stays idempotent."""
    src = "A_KEY=<REDACTED:one> B_KEY=<REDACTED:two> C" + "_TOKEN=tailsecret9"
    new, _ = redact_text(src)
    assert "tailsecret9" not in new
    assert "<REDACTED:one>" in new and "<REDACTED:two>" in new
    assert new.count("<REDACTED:") == 3
    again, edits2 = redact_text(new)
    assert again == new and edits2 == []


def test_redact_text_plain_assignment_still_redacts():
    """Regression: a plain secret with no tag nearby is unaffected."""
    new, edits = redact_text("MY_SECRET" + "=plainvalue123\n")
    assert "plainvalue123" not in new
    assert new.startswith("MY_SECRET=<REDACTED:")
    assert any(e["category"] == "env_assignment" for e in edits)


def test_redact_text_standalone_tag_not_reprocessed():
    """A lone ``<REDACTED:…>`` tag is prior output: no re-redact, no
    corruption, no edits."""
    src = "already done: <REDACTED:0123456789abcdef> ok"
    new, edits = redact_text(src)
    assert new == src
    assert edits == []


def test_redact_text_tag_inside_container_literal_not_corrupted():
    """A tag sitting inside a container/call literal is *inside* code —
    re-matching its tail as a fresh assignment would eat the closing
    delimiters and corrupt valid source. The whole match stays skipped
    (Devin Review on #66)."""
    src = 'TOKEN_KEY = ["<REDACTED:abc> API_KEY=innocent"]\n'
    new, edits = redact_text(src)
    assert new == src
    assert edits == []
    import ast

    ast.parse(new)  # still valid Python


def test_redact_text_tag_embedded_in_quoted_value_not_corrupted():
    """A tag mid-value inside a quoted string is likewise enclosure
    context — the fragment rescan only runs when the first tag leads
    the value."""
    src = "MY_API_KEY = 'abc<REDACTED:x9>def'\n"
    new, edits = redact_text(src)
    assert new == src
    assert edits == []
    import ast

    ast.parse(new)


def test_redact_text_escaped_quote_tag_not_corrupted():
    """A backslash-escaped quote does not close the string: the tag sits
    inside a still-open literal and the whole match stays skipped
    (Devin Review round 3 on #66)."""
    src = 'TOKEN_KEY = "abc\\"<REDACTED:x1>tail"\n'
    new, edits = redact_text(src)
    assert new == src
    assert edits == []
    import ast

    ast.parse(new)


def test_redact_text_tag_in_comment_not_exposed():
    """A tag inside a trailing ``#`` comment is comment content: eating
    the ``#`` would expose it as live code, so the match stays
    skipped."""
    src = 'TOKEN_KEY = ("abc") # <REDACTED:x1>\n'
    new, edits = redact_text(src)
    assert new == src
    assert edits == []
    import ast

    ast.parse(new)


def test_redact_text_code_rhs_after_tag_stays_suppressed():
    """The code-assignment guard applies to fragment tails too: a
    container RHS after a tag is config, not a secret."""
    src = "FIRST" + "_KEY=<REDACTED:a> SECOND" + "_SECRET = frozenset({'x'})\n"
    new, edits = redact_text(src)
    assert new == src
    assert edits == []


def test_scan_text_tag_tail_assignment_reported():
    """scan side of #66: the tail secret is a finding, not just an edit."""
    findings = scan_text(
        "API_KEY=<REDACTED:abc123> OTHER" + "_TOKEN=rawsecret99",
        file="x",
        location="text",
    )
    env = [f for f in findings if f["category"] == "env_assignment"]
    assert len(env) == 1
    assert env[0]["fingerprint"] == _fp(" OTHER_TOKEN=rawsecret99")


def test_redact_on_copy(tmp_path):
    corpus = _copy_corpus(tmp_path)
    result = devin_redact.redact(corpus, apply=True, confirm_irreversible=True)
    assert result["applied"] is True
    assert result["applied_ok"] is True
    assert result["files_changed"] == len(corpus)

    dirty_report = devin_redact.scan(CORPUS)
    clean_report = devin_redact.scan(corpus)

    # Every planted secret fingerprint is gone from the redacted copy.
    planted_fps = {_fp(v) for values in PLANTED.values() for v in values}
    planted_fps.add(_fp(FAKE_JWT))
    leaked = planted_fps & _all_fps(clean_report)
    assert not leaked, f"still present after redact: {leaked}"
    assert clean_report["publication_status"] == "CLEAN"

    # The report preserves fingerprints of what was redacted.
    edit_fps = {e["fingerprint"] for e in result["edits"]}
    assert _fp(FAKE_API_KEY) in edit_fps
    assert dirty_report["secrets"] > 0

    # .bak backups exist next to every modified file.
    for p in corpus:
        assert p.with_name(p.name + ".bak").exists()


def test_redacted_db_still_opens_and_semantic_output_gone(tmp_path):
    corpus = _copy_corpus(tmp_path)
    db = corpus[0]
    devin_redact.redact([db], apply=True, confirm_irreversible=True)
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    blob = con.execute(
        "select tool_call_update_json from tool_call_state where tool_call_id='tc-fixture-0002'"
    ).fetchone()[0]
    con.close()
    assert "<REDACTED:" in blob
    assert "feature_flag" not in blob


def test_transaction_rollback_on_failure(tmp_path, monkeypatch):
    corpus = _copy_corpus(tmp_path)
    db = corpus[0]
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    def boom(con, edit):
        raise sqlite3.OperationalError("induced failure")

    monkeypatch.setattr(engine, "_update_cell", boom)
    result = devin_redact.redact([db], apply=True, confirm_irreversible=True)
    assert result["applied_ok"] is False

    # The DB is untouched and the backup exists.
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert db.with_name("sessions.db.bak").exists()
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.execute("select count(*) from tool_call_state").fetchone()
    con.close()


def test_redact_twice_is_idempotent(tmp_path):
    corpus = _copy_corpus(tmp_path)
    first = devin_redact.redact(corpus, apply=True, confirm_irreversible=True)
    second = devin_redact.redact(corpus, apply=True, confirm_irreversible=True)
    assert first["replacements"] > 0
    assert second["replacements"] == 0
    assert second["files_changed"] == 0


def test_apply_requires_confirmation(tmp_path):
    corpus = _copy_corpus(tmp_path)
    before = hashlib.sha256(corpus[3].read_bytes()).hexdigest()
    with pytest.raises(RuntimeError):
        devin_redact.redact(corpus, apply=True)
    assert hashlib.sha256(corpus[3].read_bytes()).hexdigest() == before


def test_verify_exit_codes(tmp_path):
    assert cli.main(["verify", str(DB)]) == 1
    corpus = _copy_corpus(tmp_path)
    devin_redact.redact(corpus, apply=True, confirm_irreversible=True)
    assert cli.main(["verify"] + [str(p) for p in corpus]) == 0
    assert cli.main(["verify", str(FIXTURES / "benign.txt")]) == 0


def test_verify_json_output(capsys):
    assert cli.main(["verify", "--json", str(DB)]) == 1
    report = __import__("json").loads(capsys.readouterr().out)
    assert report["publication_status"] == "BLOCKED"
