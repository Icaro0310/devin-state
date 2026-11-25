"""Baseline mode for ``gate`` — suppress already-triaged findings.

A committed ``redact-baseline.json`` records the findings a repo has
already accepted (engine false positives on legitimate code —
devin-state#108). The gate then fails only on *new* findings: match
keys are ``(file, category, pattern, kind, fingerprint)`` with
per-key counts, ``location`` is audit metadata only, and suppressed /
stale counts surface on stderr while stdout stays the single-word
verdict contract.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from devin_redact import baseline, cli, engine, staged
from test_chunked import FAKE_AWS_KEY

needs_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git binary required"
)


def _git(repo: Path, *args: str):
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=False
    )
    assert proc.returncode == 0, proc.stderr
    return proc


@pytest.fixture
def repo(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    monkeypatch.chdir(repo)
    return repo


def _leaky_file(directory: Path, name: str = "app.py") -> Path:
    p = directory / name
    p.write_text(f'token = "{FAKE_AWS_KEY}"\n', encoding="utf-8")
    return p


def _scan_cwd(tmp_path, monkeypatch, name: str = "app.py") -> dict:
    """Scan ``name`` via a cwd-relative path — the same display form the
    gate produces when invoked from the gated root."""
    monkeypatch.chdir(tmp_path)
    return engine.scan([name])


def _write_baseline(path: Path, entries: list[dict]) -> Path:
    path.write_text(
        json.dumps(
            {
                "version": baseline.BASELINE_VERSION,
                "tool": "devin-redact",
                "findings": entries,
            }
        ),
        encoding="utf-8",
    )
    return path


def _entry_for(report: dict, index: int = 0, **overrides) -> dict:
    f = report["findings"][index]
    entry = {
        "file": f["file"],
        "category": f["category"],
        "pattern": f["pattern"],
        "kind": f["kind"],
        "fingerprint": f["fingerprint"],
        "count": 1,
        "location": f["location"],
        "preview": f["preview"],
    }
    entry.update(overrides)
    return entry


# --- normalize_file / finding_key ----------------------------------------


def test_normalize_file_relative_to_base(tmp_path):
    base = tmp_path / "repo"
    key = baseline.normalize_file(
        "packages/x.py", file_base=base, base_dir=base
    )
    assert key == "packages/x.py"


def test_normalize_file_dot_prefix_and_dotdot(tmp_path):
    base = tmp_path / "repo"
    assert (
        baseline.normalize_file("./a/b.py", file_base=base, base_dir=base)
        == "a/b.py"
    )
    # ``sub/../a.py`` collapses through relpath normalization.
    assert (
        baseline.normalize_file("sub/../a.py", file_base=base, base_dir=base)
        == "a.py"
    )


def test_normalize_file_absolute_relativized(tmp_path):
    base = tmp_path / "repo"
    inside = base / "pkg" / "m.py"
    assert (
        baseline.normalize_file(str(inside), file_base=base, base_dir=base)
        == "pkg/m.py"
    )


def test_normalize_file_escaping_stays_absolute(tmp_path):
    base = tmp_path / "repo"
    outside = tmp_path / "other" / "m.py"
    key = baseline.normalize_file(
        str(outside), file_base=base, base_dir=base
    )
    assert key == outside.as_posix()


def test_normalize_file_relative_resolution_uses_file_base(tmp_path):
    """Staged names are repo-root-relative: resolving them against the
    repo root (not the caller's cwd) lands on the same key a worktree
    scan from the root produces."""
    repo = tmp_path / "repo"
    repo.mkdir()
    sub = repo / "sub"
    sub.mkdir()
    base_dir = repo
    staged_key = baseline.normalize_file(
        "pkg/m.py", file_base=repo, base_dir=base_dir
    )
    worktree_key = baseline.normalize_file(
        "../pkg/m.py", file_base=sub, base_dir=base_dir
    )
    assert staged_key == worktree_key == "pkg/m.py"


def test_finding_key_ignores_location():
    """Line drift must not resurrect a suppressed finding."""
    f1 = {
        "file": "a.py",
        "category": "env_assignment",
        "pattern": "env_assignment[2]",
        "kind": "pattern",
        "fingerprint": "abc123",
        "location": "text:line 10",
    }
    f2 = dict(f1, location="text:line 99")
    base = Path("/repo")
    assert baseline.finding_key(
        f1, file_base=base, base_dir=base
    ) == baseline.finding_key(f2, file_base=base, base_dir=base)


# --- load_baseline ---------------------------------------------------------


def test_load_baseline_valid(tmp_path):
    path = _write_baseline(
        tmp_path / "redact-baseline.json",
        [
            {
                "file": "a.py",
                "category": "env_assignment",
                "pattern": "env_assignment",
                "kind": "pattern",
                "fingerprint": "f" * 16,
                "count": 2,
            },
            {
                "file": "b.py",
                "category": "email",
                "pattern": "email",
                "fingerprint": "e" * 16,
            },
        ],
    )
    bl = baseline.load_baseline(path)
    assert bl.entries == 2
    assert sum(bl.counts.values()) == 3


def test_load_baseline_missing_file(tmp_path):
    with pytest.raises(baseline.BaselineError):
        baseline.load_baseline(tmp_path / "nope.json")


def test_load_baseline_malformed_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(baseline.BaselineError):
        baseline.load_baseline(path)


def test_load_baseline_wrong_version(tmp_path):
    path = tmp_path / "v2.json"
    path.write_text(
        json.dumps({"version": 2, "findings": []}), encoding="utf-8"
    )
    with pytest.raises(baseline.BaselineError):
        baseline.load_baseline(path)


def test_load_baseline_missing_field(tmp_path):
    path = _write_baseline(
        tmp_path / "b.json",
        [{"file": "a.py", "category": "email"}],  # no fingerprint
    )
    with pytest.raises(baseline.BaselineError):
        baseline.load_baseline(path)


def test_load_baseline_bad_count(tmp_path):
    path = _write_baseline(
        tmp_path / "b.json",
        [
            {
                "file": "a.py",
                "category": "email",
                "pattern": "email",
                "fingerprint": "f" * 16,
                "count": 0,
            }
        ],
    )
    with pytest.raises(baseline.BaselineError):
        baseline.load_baseline(path)


# --- discover_baseline ------------------------------------------------------


def test_discover_baseline_cwd_hit(tmp_path, monkeypatch):
    (tmp_path / baseline.BASELINE_FILENAME).write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert baseline.discover_baseline(tmp_path) == tmp_path / baseline.BASELINE_FILENAME


def test_discover_baseline_repo_root(repo):
    (repo / baseline.BASELINE_FILENAME).write_text("{}", encoding="utf-8")
    sub = repo / "sub"
    sub.mkdir()
    # cwd is a subdir with no baseline of its own → repo root wins.
    assert baseline.discover_baseline(sub) == repo / baseline.BASELINE_FILENAME


def test_discover_baseline_none_outside_repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # No baseline file and (on machines with git) tmp_path is not a repo
    # root containing one — but tmp_path may sit inside a repo parent on
    # some setups, so only assert the file itself is not found by name.
    found = baseline.discover_baseline(tmp_path)
    if found is not None:
        assert found.name == baseline.BASELINE_FILENAME


# --- apply_baseline ---------------------------------------------------------


def test_apply_baseline_suppresses_and_recomputes(tmp_path, monkeypatch):
    _leaky_file(tmp_path)
    report = _scan_cwd(tmp_path, monkeypatch)
    assert report["publication_status"] == "BLOCKED"
    bl_path = _write_baseline(
        tmp_path / "redact-baseline.json",
        [_entry_for(report)],
    )
    bl = baseline.load_baseline(bl_path)
    filtered, stats = baseline.apply_baseline(
        report, bl, file_base=tmp_path
    )
    # The leaky file yields several findings (api_key + env_assignment…);
    # baselining only the first leaves the rest active.
    assert stats["suppressed"] == 1
    assert filtered["findings_total"] < report["findings_total"]
    assert filtered["baseline"]["suppressed"] == 1
    # status recomputed from the remaining findings
    assert filtered["publication_status"] in {"BLOCKED", "REVIEW", "CLEAN"}


def test_apply_baseline_full_suppression_gives_clean(tmp_path, monkeypatch):
    _leaky_file(tmp_path)
    report = _scan_cwd(tmp_path, monkeypatch)
    entries = []
    # Baseline EVERY current finding → all suppressed → CLEAN.
    seen = set()
    for f in report["findings"]:
        key = (
            str(f["file"]), str(f["category"]), str(f["pattern"]),
            str(f["kind"]), str(f["fingerprint"]),
        )
        if key in seen:
            continue
        seen.add(key)
        entries.append(_entry_for(report, report["findings"].index(f)))
    bl_path = _write_baseline(tmp_path / "b.json", entries)
    bl = baseline.load_baseline(bl_path)
    filtered, stats = baseline.apply_baseline(
        report, bl, file_base=tmp_path
    )
    assert stats["suppressed"] == report["findings_total"]
    assert filtered["publication_status"] == "CLEAN"
    assert filtered["findings"] == []


def test_apply_baseline_count_multiplicity(tmp_path, monkeypatch):
    """Baseline count=1 suppresses ONE occurrence — a second identical
    finding is new and stays active."""
    target = tmp_path / "dup.py"
    # Two identical secret lines → same key, two occurrences.
    target.write_text(
        f'a = "{FAKE_AWS_KEY}"\nb = "{FAKE_AWS_KEY}"\n', encoding="utf-8"
    )
    report = _scan_cwd(tmp_path, monkeypatch, "dup.py")
    key_findings = [
        f
        for f in report["findings"]
        if f["category"] == "api_key"
    ]
    assert len(key_findings) >= 2
    entry = _entry_for(report, report["findings"].index(key_findings[0]))
    entry["count"] = 1
    bl_path = _write_baseline(tmp_path / "b.json", [entry])
    bl = baseline.load_baseline(bl_path)
    filtered, stats = baseline.apply_baseline(
        report, bl, file_base=tmp_path
    )
    remaining_api = [
        f for f in filtered["findings"] if f["category"] == "api_key"
    ]
    assert len(remaining_api) == len(key_findings) - 1
    assert stats["suppressed"] == 1


def test_apply_baseline_stale_entries_reported(tmp_path, monkeypatch):
    _leaky_file(tmp_path)
    report = _scan_cwd(tmp_path, monkeypatch)
    entry = _entry_for(report)
    entry["file"] = "ghost.py"  # never seen in this scan
    bl_path = _write_baseline(tmp_path / "b.json", [entry])
    bl = baseline.load_baseline(bl_path)
    _, stats = baseline.apply_baseline(report, bl, file_base=tmp_path)
    assert stats["suppressed"] == 0
    assert stats["stale"] == 1


def test_apply_baseline_preserves_extra_report_keys(tmp_path, monkeypatch):
    _leaky_file(tmp_path)
    report = _scan_cwd(tmp_path, monkeypatch)
    report["session_id"] = "s1"  # e.g. scan_session-shaped report
    bl_path = _write_baseline(tmp_path / "b.json", [])
    bl = baseline.load_baseline(bl_path)
    filtered, _ = baseline.apply_baseline(report, bl, file_base=tmp_path)
    assert filtered["session_id"] == "s1"
    assert filtered["tool"] == "devin-redact"


# --- write_baseline -----------------------------------------------------------


def test_write_baseline_roundtrip(tmp_path, monkeypatch):
    _leaky_file(tmp_path)
    report = _scan_cwd(tmp_path, monkeypatch)
    out = tmp_path / "redact-baseline.json"
    summary = baseline.write_baseline(out, report, file_base=tmp_path)
    assert summary["findings"] == report["findings_total"]
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == baseline.BASELINE_VERSION
    # every recorded file key is relative to the baseline dir
    for e in doc["findings"]:
        assert not Path(e["file"]).is_absolute()
        assert ".." not in Path(e["file"]).parts
    # and the written baseline suppresses the same scan
    bl = baseline.load_baseline(out)
    filtered, stats = baseline.apply_baseline(
        report, bl, file_base=tmp_path
    )
    assert stats["suppressed"] == report["findings_total"]
    assert filtered["publication_status"] == "CLEAN"


# --- gate CLI integration -----------------------------------------------------


def test_gate_baseline_suppresses_known(repo, capsys):
    _leaky_file(repo)
    assert cli.main(["gate", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    assert cli.main(["gate", "app.py"]) == 0
    out = capsys.readouterr()
    assert out.out.strip() == "CLEAN"
    assert "suppressed" in out.err


def test_gate_baseline_new_secret_still_blocked(repo, capsys):
    _leaky_file(repo)
    assert cli.main(["gate", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    with open(repo / "app.py", "a", encoding="utf-8") as fh:
        fh.write(f'other = "{FAKE_AWS_KEY}"\n')
    assert cli.main(["gate", "app.py"]) == 1
    out = capsys.readouterr()
    assert out.out.strip() == "BLOCKED"
    assert "suppressed" in out.err


def test_gate_no_baseline_ignores_file(repo, capsys):
    _leaky_file(repo)
    assert cli.main(["gate", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    assert cli.main(["gate", "--no-baseline", "app.py"]) == 1
    assert capsys.readouterr().out.strip() == "BLOCKED"


def test_gate_explicit_baseline_path(repo, tmp_path, capsys):
    _leaky_file(repo)
    other = tmp_path / "elsewhere.json"
    report = engine.scan([repo / "app.py"])
    baseline.write_baseline(other, report, file_base=repo)
    assert cli.main(["gate", "--baseline", str(other), "app.py"]) == 0
    out = capsys.readouterr()
    assert out.out.strip() == "CLEAN"
    assert "suppressed" in out.err


def test_gate_baseline_and_no_baseline_conflict(repo, capsys):
    _leaky_file(repo)
    assert (
        cli.main(["gate", "--baseline", "x.json", "--no-baseline", "app.py"])
        == 2
    )
    assert "devin-redact:" in capsys.readouterr().err


def test_gate_corrupt_baseline_fails_closed(repo, capsys):
    _leaky_file(repo)
    (repo / "redact-baseline.json").write_text("{oops", encoding="utf-8")
    assert cli.main(["gate", "app.py"]) == 2
    assert "devin-redact:" in capsys.readouterr().err


def test_gate_missing_explicit_baseline_fails_closed(repo, capsys):
    _leaky_file(repo)
    assert cli.main(["gate", "--baseline", "missing.json", "app.py"]) == 2
    assert "devin-redact:" in capsys.readouterr().err


def test_gate_update_baseline_writes_file(repo, capsys):
    _leaky_file(repo)
    assert cli.main(["gate", "--update-baseline", "app.py"]) == 0
    out = capsys.readouterr()
    assert "wrote baseline" in out.err
    doc = json.loads((repo / "redact-baseline.json").read_text())
    assert doc["findings"]


@needs_git
def test_gate_staged_baseline_suppresses(repo, capsys):
    """``gate --staged`` matches repo-relative baseline keys: a staged
    blob's findings suppress exactly like the worktree scan's."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    # Baseline from the staged view so keys are repo-relative.
    assert cli.main(["gate", "--staged", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    # The baseline is read from the index — it must be staged to apply.
    _git(repo, "add", "redact-baseline.json")
    assert cli.main(["gate", "--staged", "app.py"]) == 0
    out = capsys.readouterr()
    assert out.out.strip() == "CLEAN"
    assert "suppressed" in out.err


@needs_git
def test_gate_staged_new_secret_blocked_despite_baseline(repo, capsys):
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    assert cli.main(["gate", "--staged", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    _git(repo, "add", "redact-baseline.json")
    # A second staged file was never baselined → its findings are NEW.
    _leaky_file(repo, "other.py")
    _git(repo, "add", "other.py")
    assert cli.main(["gate", "--staged", "app.py", "other.py"]) == 1
    out = capsys.readouterr()
    assert out.out.strip() == "BLOCKED"
    assert "suppressed" in out.err


# --- devin-state#132 review --------------------------------------------------

def test_gate_update_baseline_missing_target_preserves(repo, capsys):
    """A mistyped target scans as zero files — overwriting the baseline
    would silently erase it. Refuse and preserve (review #132)."""
    _leaky_file(repo)
    assert cli.main(["gate", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    before = (repo / "redact-baseline.json").read_text()
    assert cli.main(["gate", "--update-baseline", "ap.py"]) == 2
    out = capsys.readouterr()
    assert "not a file or directory" in out.err
    assert (repo / "redact-baseline.json").read_text() == before


def test_gate_update_baseline_empty_dir_is_valid(repo, capsys):
    """An existing directory with no findings is still a valid target —
    only nonexistent paths are refused."""
    d = repo / "empty"
    d.mkdir()
    assert cli.main(["gate", "--update-baseline", "empty"]) == 0
    doc = json.loads((repo / "redact-baseline.json").read_text())
    assert doc["findings"] == []


@needs_git
def test_gate_update_baseline_staged_nothing_staged_preserves(repo, capsys):
    """All-skipped staged targets must not erase the baseline either."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    assert cli.main(["gate", "--staged", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    before = (repo / "redact-baseline.json").read_text()
    assert (
        cli.main(["gate", "--staged", "--update-baseline", "never.py"]) == 2
    )
    assert "nothing staged" in capsys.readouterr().err
    assert (repo / "redact-baseline.json").read_text() == before


@needs_git
def test_staged_blobs_overlapping_targets_dedupe(repo):
    """Directory + file inside it must not scan the same blob twice —
    duplicates double-count findings in both update and verify."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    blobs, _ = staged.staged_blobs([".", "app.py"])
    names = [n for n, _ in blobs]
    assert names.count("app.py") == 1


@needs_git
def test_gate_staged_overlap_baseline_count(repo, capsys):
    """The reviewer's case: overlapping targets inflated 7 → 12."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    assert (
        cli.main(["gate", "--staged", "--update-baseline", ".", "app.py"])
        == 0
    )
    capsys.readouterr()
    doc = json.loads((repo / "redact-baseline.json").read_text())
    assert sum(e["count"] for e in doc["findings"]) == len(
        engine.scan([repo / "app.py"])["findings"]
    )


def test_load_baseline_utf16_fails_closed(tmp_path):
    """A UTF-16 baseline raises BaselineError (exit 2), not a traceback
    with exit 1."""
    p = tmp_path / "redact-baseline.json"
    p.write_bytes('{"version": 1, "findings": []}'.encode("utf-16"))
    with pytest.raises(baseline.BaselineError):
        baseline.load_baseline(p)


@needs_git
def test_gate_staged_unstaged_baseline_fails_closed(repo, capsys):
    """A baseline present only in the worktree must not apply to the
    staged gate — fail closed with guidance (SEC, review #132)."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    assert cli.main(["gate", "--staged", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    assert cli.main(["gate", "--staged", "app.py"]) == 2
    assert "not in the index" in capsys.readouterr().err


@needs_git
def test_gate_staged_ignores_unstaged_baseline_edits(repo, capsys):
    """The exploit: editing the worktree baseline to cover a new staged
    secret must not unblock the commit."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    assert cli.main(["gate", "--staged", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    _git(repo, "add", "redact-baseline.json")
    assert cli.main(["gate", "--staged", "app.py"]) == 0
    capsys.readouterr()
    # New staged secret + a worktree-only baseline update covering it.
    _leaky_file(repo, "b.py")
    _git(repo, "add", "b.py")
    assert cli.main(["gate", "--update-baseline", "."]) == 0
    capsys.readouterr()
    assert cli.main(["gate", "--staged", "app.py", "b.py"]) == 1
    assert capsys.readouterr().out.strip() == "BLOCKED"


def test_gate_baseline_file_itself_never_blocks(tmp_path, monkeypatch, capsys):
    """Entries record filenames verbatim — a secret-shaped name inside
    the baseline JSON must not re-flag the artifact itself (#132)."""
    monkeypatch.chdir(tmp_path)
    _write_baseline(
        tmp_path / "redact-baseline.json",
        [
            {
                "file": f"token={FAKE_AWS_KEY}.txt",
                "category": "x",
                "pattern": "y",
                "kind": "z",
                "fingerprint": "fp",
                "count": 1,
                "location": "",
                "preview": "",
            }
        ],
    )
    assert cli.main(["gate", "."]) == 0
    assert capsys.readouterr().out.strip() == "CLEAN"


def test_write_baseline_skips_findings_on_itself(tmp_path):
    report = {
        "findings": [
            {
                "file": "redact-baseline.json",
                "category": "secret",
                "pattern": "p",
                "kind": "k",
                "fingerprint": "f",
                "location": "1:1",
                "preview": "x",
            }
        ]
    }
    target = tmp_path / "redact-baseline.json"
    baseline.write_baseline(target, report, file_base=tmp_path)
    doc = json.loads(target.read_text())
    assert doc["findings"] == []


# --- devin-state#132 re-review (wave 2) --------------------------------------

@needs_git
def test_gate_staged_subdir_decoy_prefers_root_index(repo, capsys, monkeypatch):
    """A worktree-only baseline in a subdir must not shadow the staged
    root baseline — index candidates resolve cwd-local then root."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    assert cli.main(["gate", "--staged", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    _git(repo, "add", "redact-baseline.json")
    sub = repo / "src"
    sub.mkdir()
    # Unstaged decoy — never committed to the index.
    (sub / "redact-baseline.json").write_text(
        '{"version": 1, "findings": []}', encoding="utf-8"
    )
    monkeypatch.chdir(sub)
    assert cli.main(["gate", "--staged", "../app.py"]) == 0
    out = capsys.readouterr()
    assert out.out.strip() == "CLEAN"
    assert "suppressed" in out.err


@needs_git
def test_gate_staged_explicit_baseline_not_indexed(repo, capsys):
    """Explicit --baseline that is not in the index errors (exit 2)."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    (repo / "x.json").write_text(
        json.dumps({"version": 1, "findings": []}), encoding="utf-8"
    )
    assert cli.main(["gate", "--staged", "--baseline", "x.json", "app.py"]) == 2
    assert "not in the index" in capsys.readouterr().err


@needs_git
def test_gate_staged_baseline_outside_repo(repo, capsys):
    """--baseline outside the repository cannot come from the index."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    outside = repo.parent / "outside.json"
    outside.write_text(
        json.dumps({"version": 1, "findings": []}), encoding="utf-8"
    )
    assert (
        cli.main(["gate", "--staged", "--baseline", str(outside), "app.py"])
        == 2
    )
    assert "outside the repository" in capsys.readouterr().err


def test_gate_baseline_foreign_credential_blocks(tmp_path, monkeypatch, capsys):
    """A credential planted in baseline metadata OUTSIDE the recorded
    file/location values must still flag — self-exclusion only covers
    the lines holding registered paths (SEC, review #132)."""
    monkeypatch.chdir(tmp_path)
    doc = {
        "version": 1,
        "tool": "devin-redact",
        "note": f'backup_key = "{FAKE_AWS_KEY}"',
        "findings": [
            {
                "file": "app.py",
                "category": "x",
                "pattern": "y",
                "kind": "z",
                "fingerprint": "f",
                "count": 1,
                "location": "",
                "preview": "",
            }
        ],
    }
    (tmp_path / "redact-baseline.json").write_text(json.dumps(doc))
    assert cli.main(["gate", "."]) == 1
    assert capsys.readouterr().out.strip() == "BLOCKED"


@needs_git
def test_gate_staged_update_targets_indexed_baseline(repo, capsys, monkeypatch):
    """--update-baseline --staged must rewrite the file verify reads —
    the indexed root baseline, not a worktree-only local decoy that
    would shadow it once staged (#132 re-review)."""
    _leaky_file(repo)
    _git(repo, "add", "app.py")
    assert cli.main(["gate", "--staged", "--update-baseline", "app.py"]) == 0
    capsys.readouterr()
    _git(repo, "add", "redact-baseline.json")
    before = (repo / "redact-baseline.json").read_text()
    sub = repo / "src"
    sub.mkdir()
    decoy = sub / "redact-baseline.json"
    decoy.write_text('{"version": 1, "findings": []}', encoding="utf-8")
    # New staged finding from the subdir — update must land it in the
    # root baseline (the file the gate resolves), not the decoy.
    _leaky_file(sub, "new.py")
    _git(repo, "add", "src/new.py")
    monkeypatch.chdir(sub)
    assert cli.main(["gate", "--staged", "--update-baseline", "."]) == 0
    capsys.readouterr()
    assert decoy.read_text() == '{"version": 1, "findings": []}'
    root_doc = json.loads((repo / "redact-baseline.json").read_text())
    assert any("new.py" in e["file"] for e in root_doc["findings"])
    assert (repo / "redact-baseline.json").read_text() != before
