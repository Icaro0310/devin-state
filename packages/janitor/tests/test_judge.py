import sys
import textwrap

import pytest

from devin_janitor.inventory import SessionRow
from devin_janitor.judge import (
    CommandJudge,
    NoneJudge,
    PoordjaevinJudge,
    _parse_verdict_text,
    _split_binary,
    make_judge,
)


def row() -> SessionRow:
    return SessionRow(
        id="s", origin="cli", title="t", project="/p",
        created=0.0, last_activity=0.0, prompt="hello",
    )


def test_none_judge_abstains():
    j = make_judge("none")
    assert isinstance(j, NoneJudge)
    v = j.judge(row(), "statement")
    assert v.keep is None  # abstain → caller keeps the session


def test_make_judge_specs():
    assert make_judge(None).name == "none"
    assert make_judge("command:echo keep").name == "command"
    for alias in ("devin-judge", "poordjaevin", "judge"):
        j = make_judge(alias)
        assert isinstance(j, PoordjaevinJudge)
        assert j.name == "devin-judge"
    assert isinstance(make_judge("devin-judge:/x/bin"), PoordjaevinJudge)
    with pytest.raises(ValueError):
        make_judge("bogus")
    with pytest.raises(ValueError):
        make_judge("ollama")  # removed backend fails closed


def test_command_judge_parses_verdict(tmp_path):
    script = tmp_path / "judge.py"
    script.write_text(
        textwrap.dedent(
            """
            import sys, json
            payload = json.loads(sys.stdin.read())
            print(json.dumps({"keep": False, "why": "noise"}))
            """
        ),
        encoding="utf-8",
    )
    j = CommandJudge(f'"{sys.executable}" "{script}"')
    v = j.judge(row(), "statement")
    assert v.keep is False  # explicit delete verdict


def test_command_judge_fail_open_on_nonzero_exit():
    j = CommandJudge(f'"{sys.executable}" -c "import sys; sys.exit(1)"')
    v = j.judge(row(), "statement")
    assert v.keep is None  # fail-open


def test_command_judge_fail_open_on_bad_command():
    j = CommandJudge("definitely-not-a-real-binary-xyz123")
    v = j.judge(row(), "statement")
    assert v.keep is None


def test_parse_verdict_text():
    assert _parse_verdict_text('{"keep": false}') is False
    assert _parse_verdict_text('{"value": true}') is True
    assert _parse_verdict_text('{"abstained": true}') is None
    assert _parse_verdict_text("DELETE") is False
    assert _parse_verdict_text("keep") is True
    assert _parse_verdict_text("hmm not sure") is None


# ------------------------------------------------------------ devin-judge --


def _fake_poordjaevin(tmp_path, body: str) -> str:
    """An executable-looking binary spec: ``python fake.py``."""
    script = tmp_path / "poordjaevin-fake.py"
    script.write_text(textwrap.dedent(body), encoding="utf-8")
    return f'"{sys.executable}" "{script}"'


def test_poordjaevin_judge_delete_verdict(tmp_path):
    binary = _fake_poordjaevin(
        tmp_path,
        '''
        import json
        print(json.dumps({"keep": {"value": "delete",
                                   "confidence": 0.91}}))
        ''',
    )
    j = PoordjaevinJudge(binary=binary)
    assert j.available()
    v = j.judge(row(), "statement")
    assert v.keep is False  # explicit delete verdict
    assert "0.91" in v.reason


def test_poordjaevin_judge_keep_verdict(tmp_path):
    binary = _fake_poordjaevin(
        tmp_path,
        '''
        import json
        print(json.dumps({"keep": {"value": "keep",
                                   "confidence": 0.8}}))
        ''',
    )
    v = PoordjaevinJudge(binary=binary).judge(row(), "statement")
    assert v.keep is True


def test_poordjaevin_judge_fail_open(tmp_path):
    """Abstained/null/broken/no-binary answers all keep the session."""
    for body in (
        'import json; print(json.dumps({"keep": {"value": None}}))',
        'import json; print(json.dumps({"keep": {"value": "meh"}}))',
        'print("not json")',
        'import sys; sys.exit(1)',
    ):
        binary = _fake_poordjaevin(tmp_path, body)
        v = PoordjaevinJudge(binary=binary).judge(row(), "statement")
        assert v.keep is None, body

    missing = PoordjaevinJudge(binary="definitely-not-real-xyz123")
    assert not missing.available()
    # judged anyway (defence in depth): still abstains
    assert missing.judge(row(), "statement").keep is None


def test_poordjaevin_judge_low_confidence_delete_keeps(tmp_path):
    """Rule 1: a `delete` answer below the confidence floor must not
    delete — fail-open means abstain, not delete."""
    for conf in ("0.4", "null", "true", '"high"'):
        binary = _fake_poordjaevin(
            tmp_path,
            f'''
            print('{{"keep": {{"value": "delete", "confidence": {conf}}}}}')
            ''',
        )
        v = PoordjaevinJudge(binary=binary).judge(row(), "statement")
        assert v.keep is None, conf
        assert "confidence" in v.reason


def test_poordjaevin_judge_abstained_delete_keeps(tmp_path):
    binary = _fake_poordjaevin(
        tmp_path,
        '''
        import json
        print(json.dumps({"keep": {"value": "delete",
                                   "confidence": 0.99,
                                   "abstained": True}}))
        ''',
    )
    v = PoordjaevinJudge(binary=binary).judge(row(), "statement")
    assert v.keep is None


def test_poordjaevin_judge_malformed_shapes_keep(tmp_path):
    """Valid JSON with the wrong shape must abstain, not abort the run."""
    for body in (
        'import json; print(json.dumps([]))',
        'import json; print(json.dumps({"keep": "delete"}))',
        'import json; print(json.dumps({"keep": null}))',
        'import json; print(json.dumps("delete"))',
        'import json; print(json.dumps({"other": {"value": "delete"}}))',
    ):
        binary = _fake_poordjaevin(tmp_path, body)
        v = PoordjaevinJudge(binary=binary).judge(row(), "statement")
        assert v.keep is None, body


def test_split_binary_windows_path():
    """Windows argv convention: backslashes survive and quotes toggle
    grouping anywhere in a token (CommandLineToArgvW semantics)."""
    parts = _split_binary("C:\\Tools\\poordjaevin.exe", posix=False)
    assert parts == ["C:\\Tools\\poordjaevin.exe"]
    quoted = _split_binary('"C:\\Tools\\poordjaevin.exe" -v', posix=False)
    assert quoted == ["C:\\Tools\\poordjaevin.exe", "-v"]
    mid = _split_binary(
        'tool.exe --config="C:\\My Data\\cfg.json"', posix=False
    )
    assert mid == ["tool.exe", "--config=C:\\My Data\\cfg.json"]
    bare = _split_binary("tool -v --flag", posix=False)
    assert bare == ["tool", "-v", "--flag"]


def test_poordjaevin_judge_passes_state_and_questions(tmp_path):
    """The ask call receives the session summary as --state-file and a
    keep/delete choice question — verify what poordjaevin saw."""
    binary = _fake_poordjaevin(
        tmp_path,
        '''
        import argparse, json
        p = argparse.ArgumentParser()
        p.add_argument("cmd")
        p.add_argument("--state-file")
        p.add_argument("--questions")
        a = p.parse_args()
        state = open(a.state_file).read()
        q = json.load(open(a.questions))
        assert a.cmd == "ask"
        assert "hello" in state and "statement" in state
        assert q["keep"]["type"] == "choice"
        assert q["keep"]["options"] == ["keep", "delete"]
        print(json.dumps({"keep": {"value": "keep",
                                   "confidence": 1.0}}))
        ''',
    )
    v = PoordjaevinJudge(binary=binary).judge(row(), "statement")
    assert v.keep is True
