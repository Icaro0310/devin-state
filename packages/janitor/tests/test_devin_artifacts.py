"""Tiered classification of ``.devin/`` runtime artifacts.

The PAS learning loop accumulates runtime state under a project's
``.devin/`` dir (``hook-fires.jsonl``, ``search.db``, ``graph.db``,
``learning-state.json`` and friends). The janitor tiers them with the
same KEEP / AUTO_DELETE / JUDGE enum as sessions — every fixture here
is synthetic and lives under ``tmp_path``; a real ``~/.devin`` is never
touched.
"""

import json
from pathlib import Path

import pytest
from devin_janitor.cli import main
from devin_janitor.inventory import (
    DevinArtifactError,
    load_devin_artifacts,
)
from devin_janitor.report import render_space_report, space_report
from devin_janitor.tiers import (
    Tier,
    classify_devin_artifacts,
    devin_artifacts_payload,
)


@pytest.fixture()
def dotdevin(tmp_path):
    d = tmp_path / ".devin"
    d.mkdir()
    return d


def _write(dotdevin: Path, rel: str, content: str = "x") -> Path:
    p = dotdevin / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _populate(dotdevin: Path) -> None:
    """A realistic .devin/ tree covering every rule branch."""
    _write(dotdevin, "memory/hook-fires.jsonl", '{"hook": 1}\n')
    _write(dotdevin, "memory/janitor-log.jsonl", '{"ts": 1}\n')
    _write(dotdevin, "search.db", "sqlite-ish")
    _write(dotdevin, "graph.db", "sqlite-ish")
    _write(dotdevin, "search.db-wal", "wal")
    _write(dotdevin, "learning-state.json", '{"version": 1}')
    _write(dotdevin, "janitor-keep.json", '{"ids": []}')
    _write(dotdevin, "janitor-pending.json", "{}")
    _write(dotdevin, "rules/style.md", "# rules")
    _write(dotdevin, "skills/learned-x/SKILL.md", "doc")
    _write(dotdevin, "skills/learned-x/helper.py", "print(1)")
    _write(dotdevin, "settings.toml", "[a]")
    _write(dotdevin, "mystery.db", "sqlite?")
    _write(dotdevin, "blob.bin", "bin")
    _write(dotdevin, "scratch.tmp", "t")
    _write(dotdevin, "notes/live.lock", "pid")


def _tier_map(dotdevin: Path):
    cls = classify_devin_artifacts(load_devin_artifacts(dotdevin))
    return {a.rel_path: (tier, why) for a, tier, why in cls.verdicts}


# --------------------------------------------------------------- loader --


def test_missing_devin_dir_returns_empty(tmp_path):
    assert load_devin_artifacts(tmp_path / ".devin") == []


def test_devin_path_not_a_dir_is_loud(tmp_path):
    (tmp_path / ".devin").write_text("a file, not a dir", encoding="utf-8")
    with pytest.raises(DevinArtifactError, match="not a directory"):
        load_devin_artifacts(tmp_path / ".devin")


def test_malformed_json_state_is_loud(dotdevin):
    _write(dotdevin, "learning-state.json", "{not json")
    with pytest.raises(DevinArtifactError, match="malformed"):
        load_devin_artifacts(dotdevin)


def test_unstatable_artifact_is_loud(dotdevin, monkeypatch):
    f = _write(dotdevin, "memory/hook-fires.jsonl", "{}\n")
    real_stat = Path.stat

    def boom(self, *a, **k):
        if self == f:
            raise PermissionError("denied")
        return real_stat(self, *a, **k)

    monkeypatch.setattr(Path, "stat", boom)
    with pytest.raises(DevinArtifactError, match="unreadable"):
        load_devin_artifacts(dotdevin)


def test_loader_skips_directories_and_reports_files(dotdevin):
    _populate(dotdevin)
    arts = load_devin_artifacts(dotdevin)
    rels = {a.rel_path for a in arts}
    assert "memory/hook-fires.jsonl" in rels
    assert "skills/learned-x/helper.py" in rels
    assert all(a.bytes > 0 and a.mtime > 0 for a in arts)
    # posix separators even on Windows
    assert all("\\" not in a.rel_path for a in arts)


# ------------------------------------------------------------ classifer --


def test_tier_assignments_per_artifact(dotdevin):
    _populate(dotdevin)
    tiers = _tier_map(dotdevin)
    expected = {
        # bounded append logs — safe to prune/rotate
        "memory/hook-fires.jsonl": (Tier.AUTO_DELETE, "bounded log"),
        "memory/janitor-log.jsonl": (Tier.AUTO_DELETE, "bounded log"),
        # regenerable caches + checkpoint sidecars
        "search.db": (Tier.AUTO_DELETE, "regenerable cache"),
        "graph.db": (Tier.AUTO_DELETE, "regenerable cache"),
        "search.db-wal": (Tier.AUTO_DELETE, "sidecar"),
        "scratch.tmp": (Tier.AUTO_DELETE, "transient"),
        # durable state / knowledge
        "learning-state.json": (Tier.KEEP, "durable state"),
        "janitor-keep.json": (Tier.KEEP, "durable state"),
        "janitor-pending.json": (Tier.KEEP, "durable state"),
        "rules/style.md": (Tier.KEEP, "rules/skills"),
        "skills/learned-x/SKILL.md": (Tier.KEEP, "rules/skills"),
        "skills/learned-x/helper.py": (Tier.KEEP, "rules/skills"),
        "settings.toml": (Tier.KEEP, "configuration"),
        # unrecognized — fail-open JUDGE
        "mystery.db": (Tier.JUDGE, "sqlite"),
        "blob.bin": (Tier.JUDGE, "unrecognized"),
        "notes/live.lock": (Tier.JUDGE, "live lock"),
    }
    assert set(tiers) == set(expected)
    for rel, (tier, why_hint) in expected.items():
        got_tier, got_why = tiers[rel]
        assert got_tier is tier, rel
        assert why_hint in got_why, rel


def test_classification_summary_counts(dotdevin):
    _populate(dotdevin)
    cls = classify_devin_artifacts(load_devin_artifacts(dotdevin))
    assert cls.summary() == {"keep": 7, "auto_delete": 6, "judge": 3}
    assert cls.tier_of("learning-state.json") is Tier.KEEP
    assert cls.tier_of("search.db") is Tier.AUTO_DELETE
    assert cls.tier_of("mystery.db") is Tier.JUDGE
    assert cls.tier_of("absent") is None


def test_payload_shape(dotdevin):
    _write(dotdevin, "learning-state.json", '{"v": 1}')
    payload = devin_artifacts_payload(dotdevin)
    assert payload["exists"] and payload["total"] == 1
    assert payload["by_tier"]["keep"] == 1
    a = payload["artifacts"][0]
    assert a["rel_path"] == "learning-state.json"
    assert a["tier"] == "keep" and a["reason"] == "durable state"


# ------------------------------------------------------------------ scan --


def test_scan_json_includes_devin_artifacts(devin_dir, dotdevin, tmp_path,
                                            capsys):
    _populate(dotdevin)
    rc = main([
        "scan", "--data-dir", str(devin_dir.root),
        "--devin-dir", str(dotdevin),
        "--keep-file", str(tmp_path / "k.json"),
        "--json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    arts = payload["devin_artifacts"]
    assert arts["exists"] and arts["total"] == 16
    assert arts["by_tier"] == {"keep": 7, "auto_delete": 6, "judge": 3}
    by_rel = {a["rel_path"]: a for a in arts["artifacts"]}
    assert by_rel["learning-state.json"]["tier"] == "keep"
    assert by_rel["memory/hook-fires.jsonl"]["tier"] == "auto_delete"
    assert by_rel["mystery.db"]["tier"] == "judge"


def test_scan_text_and_verbose_list_devin(devin_dir, dotdevin, tmp_path,
                                          capsys):
    _populate(dotdevin)
    rc = main([
        "scan", "--data-dir", str(devin_dir.root),
        "--devin-dir", str(dotdevin),
        "--keep-file", str(tmp_path / "k.json"),
        "-v",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert ".devin:" in out
    assert "hook-fires.jsonl" in out
    assert "bounded log" in out


def test_scan_missing_devin_dir_is_fine(devin_dir, tmp_path, capsys):
    rc = main([
        "scan", "--data-dir", str(devin_dir.root),
        "--devin-dir", str(tmp_path / "nope"),
        "--keep-file", str(tmp_path / "k.json"),
    ])
    assert rc == 0
    assert ".devin: missing" in capsys.readouterr().out


def test_scan_malformed_devin_state_fails_loud(devin_dir, dotdevin,
                                               tmp_path, capsys):
    _write(dotdevin, "learning-state.json", "{broken")
    rc = main([
        "scan", "--data-dir", str(devin_dir.root),
        "--devin-dir", str(dotdevin),
        "--keep-file", str(tmp_path / "k.json"),
    ])
    assert rc == 2
    assert "malformed" in capsys.readouterr().err


# ---------------------------------------------------------------- report --


def _by_name(rep):
    return {s["name"]: s for s in rep["stores"]}


def test_space_report_includes_devin_store(devin_dir, dotdevin):
    _populate(dotdevin)
    rep = space_report(devin_dir, devin_dir=dotdevin)
    store = _by_name(rep)[".devin"]
    assert store["exists"] and store["artifacts"] == 16
    assert store["by_tier"] == {"keep": 7, "auto_delete": 6, "judge": 3}
    auto_bytes = sum(
        a["bytes"] for a in store["detail"] if a["tier"] == "auto_delete"
    )
    assert store["recoverable_bytes"] == auto_bytes
    assert store["bytes"] > store["recoverable_bytes"]
    assert all(
        {"rel_path", "bytes", "mtime", "tier", "reason"} <= set(a)
        for a in store["detail"]
    )


def test_space_report_missing_devin_dir(devin_dir, tmp_path):
    rep = space_report(devin_dir, devin_dir=tmp_path / "nope")
    store = _by_name(rep)[".devin"]
    assert not store["exists"] and store["recoverable_bytes"] == 0


def test_space_report_malformed_devin_is_advisory(devin_dir, dotdevin):
    _write(dotdevin, "learning-state.json", "{broken")
    rep = space_report(devin_dir, devin_dir=dotdevin)
    store = _by_name(rep)[".devin"]
    assert store["error"] and "malformed" in store["error"]
    assert store["recoverable_bytes"] == 0


def test_render_lists_devin_artifacts_with_tiers(devin_dir, dotdevin):
    _populate(dotdevin)
    out = render_space_report(space_report(devin_dir, devin_dir=dotdevin))
    assert ".devin" in out
    assert "hook-fires.jsonl" in out
    assert "auto_delete" in out and "bounded log" in out


def test_report_cli_json_devin_store(devin_dir, dotdevin, tmp_path, capsys):
    _populate(dotdevin)
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--devin-dir", str(dotdevin),
        "--pending-file", str(tmp_path / "p.json"),
        "--json",
    ])
    assert rc == 0
    store = _by_name(json.loads(capsys.readouterr().out))[".devin"]
    assert store["exists"] and store["artifacts"] == 16
    assert store["recoverable_bytes"] > 0


def test_report_cli_malformed_devin_still_exits_0(devin_dir, dotdevin,
                                                tmp_path, capsys):
    """report is advisory: a corrupt .devin state file surfaces as the
    store's error row, never as a failed command."""
    _write(dotdevin, "learning-state.json", "{broken")
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--devin-dir", str(dotdevin),
        "--pending-file", str(tmp_path / "p.json"),
    ])
    assert rc == 0
    assert "error" in capsys.readouterr().out


def test_report_never_writes_to_devin_dir(devin_dir, dotdevin, tmp_path):
    _populate(dotdevin)
    before = {
        str(p.relative_to(dotdevin)): p.read_bytes()
        for p in sorted(dotdevin.rglob("*"))
        if p.is_file()
    }
    rc = main([
        "report", "--data-dir", str(devin_dir.root),
        "--devin-dir", str(dotdevin),
        "--pending-file", str(tmp_path / "p.json"),
    ])
    assert rc == 0
    after = {
        str(p.relative_to(dotdevin)): p.read_bytes()
        for p in sorted(dotdevin.rglob("*"))
        if p.is_file()
    }
    assert before == after


def test_mcp_classify_includes_devin_artifacts(devin_dir, dotdevin,
                                               tmp_path):
    from devin_janitor.mcp_server import do_classify

    _populate(dotdevin)
    out = do_classify(
        data_dir=str(devin_dir.root),
        keep_file=str(tmp_path / "k.json"),
        devin_dir=str(dotdevin),
    )
    assert out["devin_artifacts"]["total"] == 16
    assert out["devin_artifacts"]["by_tier"]["auto_delete"] == 6


def test_mcp_dry_run_includes_devin_store(devin_dir, dotdevin, tmp_path):
    from devin_janitor.mcp_server import do_dry_run

    _populate(dotdevin)
    out = do_dry_run(
        data_dir=str(devin_dir.root),
        pending_file=str(tmp_path / "p.json"),
        devin_dir=str(dotdevin),
    )
    assert _by_name(out)[".devin"]["exists"]
