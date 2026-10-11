"""M2 tests: real redact(), semantic layer, verify gate."""

import hashlib
import shutil
import sqlite3
from pathlib import Path

import devin_redact
import pytest
from devin_redact import cli, engine
from devin_redact.engine import redact_text
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
