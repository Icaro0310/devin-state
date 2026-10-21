"""``devin-redact cflite-promote`` — ClusterFuzzLite crashes → corpus.

Synthetic crash fixtures in tmp dirs cover the promotion contract: new
crashes land in the corpus as ``crash-<sha256>`` plus a manifest entry,
byte-identical artifacts dedup (across runs and within one batch),
out-of-bounds artifacts are rejected loudly, and the corpus dir is
created on demand.
"""

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from devin_redact import cflite, cli

# Arbitrary binary-safe bytes — what a libFuzzer-class testcase looks like.
CRASH_A = b"\x00\x01fuzz-input-A" * 8
CRASH_B = b"PK\x03\x04minimized-B" * 4
CRASH_C = b"\xfefuzzer\x00input\xffC"


def _crashes(tmp_path: Path, files: dict[str, bytes]) -> Path:
    d = tmp_path / "crashes"
    d.mkdir()
    for name, data in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return d


def _corpus(tmp_path: Path) -> Path:
    return tmp_path / "pack" / "corpus"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_promote_new_crash_into_corpus(tmp_path):
    crashes = _crashes(tmp_path, {"crash-deadbeef": CRASH_A})
    corpus = _corpus(tmp_path)
    report = cflite.promote(crashes, corpus)
    assert report["candidates"] == 1
    assert report["rejected"] == [] and report["errors"] == []
    assert len(report["promoted"]) == 1

    entry = corpus / f"crash-{_sha(CRASH_A)}"
    assert entry.read_bytes() == CRASH_A
    manifest = json.loads((corpus / "manifest.json").read_text())
    meta = manifest["entries"][entry.name]
    assert meta["sha256"] == _sha(CRASH_A)
    assert meta["size"] == len(CRASH_A)
    assert meta["source"] == "crash-deadbeef"


def test_promote_creates_missing_corpus_dir(tmp_path):
    crashes = _crashes(tmp_path, {"c1": CRASH_A})
    corpus = _corpus(tmp_path)
    assert not corpus.exists()
    cflite.promote(crashes, corpus)
    assert corpus.is_dir()


def test_dedup_second_run_skips(tmp_path):
    crashes = _crashes(tmp_path, {"crash-1": CRASH_A})
    corpus = _corpus(tmp_path)
    first = cflite.promote(crashes, corpus)
    assert len(first["promoted"]) == 1

    second = cflite.promote(crashes, corpus)
    assert second["promoted"] == []
    assert len(second["duplicates"]) == 1
    assert second["duplicates"][0]["detail"] == "already in corpus"
    assert len(list(corpus.iterdir())) == 2  # one entry + manifest.json


def test_dedup_within_batch(tmp_path):
    crashes = _crashes(tmp_path, {"a/crash-x": CRASH_A, "b/crash-y": CRASH_A})
    corpus = _corpus(tmp_path)
    report = cflite.promote(crashes, corpus)
    assert len(report["promoted"]) == 1
    assert len(report["duplicates"]) == 1
    assert report["duplicates"][0]["detail"].startswith("duplicate of another")


def test_dedup_against_manifestless_corpus_file(tmp_path):
    """An entry already on disk dedups by content even when no manifest
    records it (hand-seeded corpus, or a manifest lost in a merge)."""
    crashes = _crashes(tmp_path, {"crash-1": CRASH_A})
    corpus = _corpus(tmp_path)
    corpus.mkdir(parents=True)
    (corpus / f"crash-{_sha(CRASH_A)}").write_bytes(CRASH_A)

    report = cflite.promote(crashes, corpus)
    assert report["promoted"] == []
    assert report["duplicates"][0]["file"] == f"crash-{_sha(CRASH_A)}"


def test_reject_empty_artifact(tmp_path):
    crashes = _crashes(tmp_path, {"good": CRASH_B, "crash-empty": b""})
    corpus = _corpus(tmp_path)
    report = cflite.promote(crashes, corpus)
    assert len(report["rejected"]) == 1
    assert "empty" in report["rejected"][0]["reason"]
    # The valid crash still promotes — rejection is per-file, not per-run.
    assert len(report["promoted"]) == 1
    assert not (corpus / ("crash-" + _sha(b""))).exists()


def test_reject_oversized_artifact(tmp_path):
    crashes = _crashes(tmp_path, {"crash-huge": b"A" * 65})
    corpus = _corpus(tmp_path)
    report = cflite.promote(crashes, corpus, max_bytes=64)
    assert report["rejected"][0]["reason"].endswith("64-byte cap")
    assert report["promoted"] == []
    # A rejected artifact leaves no trace in the corpus.
    assert not corpus.exists() or list(corpus.iterdir()) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="posix fifo needed")
def test_reject_non_regular_file(tmp_path):
    crashes = _crashes(tmp_path, {"real": CRASH_C})
    fifo = crashes / "crash-fifo"
    os.mkfifo(fifo)
    assert not stat.S_ISREG(fifo.stat().st_mode)
    report = cflite.promote(crashes, _corpus(tmp_path))
    reasons = [r["reason"] for r in report["rejected"]]
    assert "not a regular file" in reasons


def test_dry_run_writes_nothing(tmp_path):
    crashes = _crashes(tmp_path, {"c1": CRASH_A, "c2": CRASH_B})
    corpus = _corpus(tmp_path)
    report = cflite.promote(crashes, corpus, dry_run=True)
    assert report["dry_run"] is True
    assert len(report["promoted"]) == 2
    assert report["manifest"] is None
    assert not corpus.exists()


def test_recursive_artifact_layout(tmp_path):
    """`gh run download` unpacks each artifact into its own subdir —
    candidates are discovered recursively."""
    crashes = _crashes(
        tmp_path,
        {"crashes-artifact/crash-1": CRASH_A, "other/crash-2": CRASH_B},
    )
    report = cflite.promote(crashes, _corpus(tmp_path))
    assert report["candidates"] == 2
    assert len(report["promoted"]) == 2


def test_corrupt_manifest_fails_loud_and_is_not_clobbered(tmp_path):
    crashes = _crashes(tmp_path, {"c1": CRASH_A})
    corpus = _corpus(tmp_path)
    corpus.mkdir(parents=True)
    bad = corpus / "manifest.json"
    bad.write_text("{ not json")
    report = cflite.promote(crashes, corpus)
    assert report["errors"], report
    assert "manifest.json" in report["errors"][0]["file"]
    assert report["manifest"] is None
    assert bad.read_text() == "{ not json"
    # The crash itself still promotes — provenance stays fixable.
    assert (corpus / f"crash-{_sha(CRASH_A)}").is_file()


def test_no_candidates_warns_but_succeeds(tmp_path):
    crashes = _crashes(tmp_path, {})
    report = cflite.promote(crashes, _corpus(tmp_path))
    assert report["candidates"] == 0
    assert report["warnings"], report


# --- CLI surface ------------------------------------------------------


def test_cli_promote_exit_zero_and_summary(tmp_path, capsys):
    crashes = _crashes(tmp_path, {"crash-1": CRASH_A})
    corpus = _corpus(tmp_path)
    code = cli.main(
        [
            "cflite-promote",
            "--crashes-dir",
            str(crashes),
            "--corpus-dir",
            str(corpus),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "promoted=1" in out


def test_cli_promote_json_report(tmp_path, capsys):
    crashes = _crashes(tmp_path, {"crash-1": CRASH_B})
    code = cli.main(
        [
            "cflite-promote",
            "--crashes-dir",
            str(crashes),
            "--corpus-dir",
            str(_corpus(tmp_path)),
            "--json",
        ]
    )
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == "devin-redact"
    assert len(report["promoted"]) == 1


def test_cli_rejected_artifacts_exit_one(tmp_path, capsys):
    crashes = _crashes(tmp_path, {"empty": b""})
    code = cli.main(
        [
            "cflite-promote",
            "--crashes-dir",
            str(crashes),
            "--corpus-dir",
            str(_corpus(tmp_path)),
        ]
    )
    assert code == 1
    assert "rejected=1" in capsys.readouterr().out


def test_cli_missing_crashes_dir_exit_two(tmp_path, capsys):
    code = cli.main(
        [
            "cflite-promote",
            "--crashes-dir",
            str(tmp_path / "nope"),
            "--corpus-dir",
            str(_corpus(tmp_path)),
        ]
    )
    assert code == 2
    assert "not a directory" in capsys.readouterr().err


def test_cli_artifact_flag_requires_run_id(tmp_path, capsys):
    crashes = _crashes(tmp_path, {"c1": CRASH_A})
    code = cli.main(
        [
            "cflite-promote",
            "--crashes-dir",
            str(crashes),
            "--artifact",
            "crashes",
        ]
    )
    assert code == 2
    assert "--artifact requires --run-id" in capsys.readouterr().err


def test_cli_run_id_downloads_then_promotes(tmp_path, monkeypatch, capsys):
    """--run-id goes through `gh run download` into a scratch dir; a
    fake gh plants an artifact-shaped subdir to prove the plumbing."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)

        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        dest = Path(cmd[cmd.index("--dir") + 1])
        (dest / "crashes").mkdir(parents=True)
        (dest / "crashes" / "crash-1").write_bytes(CRASH_C)
        return Proc()

    monkeypatch.setattr(cflite.subprocess, "run", fake_run)
    corpus = _corpus(tmp_path)
    code = cli.main(
        [
            "cflite-promote",
            "--run-id",
            "123456",
            "--corpus-dir",
            str(corpus),
        ]
    )
    assert code == 0, capsys.readouterr()
    assert calls and calls[0][:3] == ["gh", "run", "download"]
    assert "123456" in calls[0]
    assert (corpus / f"crash-{_sha(CRASH_C)}").is_file()
    manifest = json.loads((corpus / "manifest.json").read_text())
    assert manifest["entries"][f"crash-{_sha(CRASH_C)}"]["run_id"] == "123456"


def test_cli_run_id_gh_failure_exit_two(tmp_path, monkeypatch, capsys):
    def fake_run(cmd, **kwargs):
        class Proc:
            returncode = 1
            stdout = ""
            stderr = "no artifacts found"

        return Proc()

    monkeypatch.setattr(cflite.subprocess, "run", fake_run)
    code = cli.main(["cflite-promote", "--run-id", "999"])
    assert code == 2
    assert "gh run download 999 failed" in capsys.readouterr().err


def test_cli_dry_run(tmp_path, capsys):
    crashes = _crashes(tmp_path, {"c1": CRASH_A})
    corpus = _corpus(tmp_path)
    code = cli.main(
        [
            "cflite-promote",
            "--crashes-dir",
            str(crashes),
            "--corpus-dir",
            str(corpus),
            "--dry-run",
        ]
    )
    assert code == 0
    assert "(dry-run)" in capsys.readouterr().out
    assert not corpus.exists()


def test_corpus_env_override(tmp_path, monkeypatch):
    crashes = _crashes(tmp_path, {"c1": CRASH_A})
    corpus = _corpus(tmp_path)
    monkeypatch.setenv(cflite.CORPUS_ENV, str(corpus))
    report = cflite.promote(crashes)
    assert report["corpus_dir"] == str(corpus)
    assert (corpus / f"crash-{_sha(CRASH_A)}").is_file()


def test_unindexed_crash_reconciled_into_manifest(tmp_path):
    """A crash-<sha> file on disk without a manifest entry must not dedup
    silently — promote reconciles it into the manifest so corpus
    integrity holds (finding: unindexed existing crashes)."""
    corpus = _corpus(tmp_path)
    corpus.mkdir(parents=True)
    stray = corpus / f"crash-{_sha(CRASH_A)}"
    stray.write_bytes(CRASH_A)  # on disk, never indexed
    crashes = _crashes(tmp_path, {"crash-b": CRASH_B})
    report = cflite.promote(crashes, corpus)
    manifest = json.loads((corpus / "manifest.json").read_text())
    assert set(manifest["entries"]) == {stray.name, f"crash-{_sha(CRASH_B)}"}
    assert manifest["entries"][stray.name]["source"].startswith("pre-existing")
    assert report["duplicates"] == []  # crash-A was never a candidate here

    # Re-promoting the same bytes now reports a real duplicate.
    (tmp_path / "second").mkdir()
    crashes_a = _crashes(tmp_path / "second", {"sub/crash-a": CRASH_A})
    report3 = cflite.promote(crashes_a, corpus)
    assert report3["promoted"] == []
    assert any(d["file"] == stray.name for d in report3["duplicates"])


def test_incomplete_manifest_reconciled(tmp_path):
    """A manifest that exists but predates a hand-added crash entry is
    backfilled too — reconciliation is keyed on manifest['entries'],
    not on the manifest file being absent."""
    corpus = _corpus(tmp_path)
    corpus.mkdir(parents=True)
    stray = corpus / f"crash-{_sha(CRASH_A)}"
    stray.write_bytes(CRASH_A)  # on disk after the manifest was written
    (corpus / "manifest.json").write_text(
        json.dumps(
            {
                "tool": "devin-redact",
                "version": "0.0.0",
                "schema": 1,
                "entries": {},
            }
        )
    )
    report = cflite.promote(_crashes(tmp_path, {}), corpus)
    manifest = json.loads((corpus / "manifest.json").read_text())
    assert set(manifest["entries"]) == {stray.name}
    assert manifest["entries"][stray.name]["sha256"] == _sha(CRASH_A)
    assert report["manifest"] is not None


def test_seed_file_does_not_swallow_crash(tmp_path):
    """A non-crash file in the corpus sharing a crash's bytes must not
    satisfy dedup — only crash-<sha256> entries count (finding: seed
    files silently swallow crashes)."""
    corpus = _corpus(tmp_path)
    corpus.mkdir(parents=True)
    (corpus / "seed.txt").write_bytes(CRASH_A)  # same bytes, not an entry
    crashes = _crashes(tmp_path, {"crash-1": CRASH_A})
    report = cflite.promote(crashes, corpus)
    assert report["duplicates"] == []
    assert (corpus / f"crash-{_sha(CRASH_A)}").is_file()


def test_misnamed_crash_file_fails_loud(tmp_path):
    """A crash-* file whose name doesn't match its contents is corrupt —
    error, not a dedup hit."""
    corpus = _corpus(tmp_path)
    corpus.mkdir(parents=True)
    (corpus / f"crash-{'0' * 64}").write_bytes(CRASH_A)  # wrong name
    crashes = _crashes(tmp_path, {"c": CRASH_B})
    report = cflite.promote(crashes, corpus)
    assert any("corrupt" in e["error"] for e in report["errors"])


def test_source_records_artifact_relative_path(tmp_path):
    """For `gh run download` layouts the manifest's source carries the
    artifact dir name, not a dead temp path (finding: provenance)."""
    crashes = _crashes(
        tmp_path, {"fuzz-crashes-linux/crash-123": CRASH_A}
    )
    corpus = _corpus(tmp_path)
    cflite.promote(crashes, corpus)
    manifest = json.loads((corpus / "manifest.json").read_text())
    meta = manifest["entries"][f"crash-{_sha(CRASH_A)}"]
    assert meta["source"] == "fuzz-crashes-linux/crash-123"
    assert "source_path" not in meta


def test_sensitive_crash_rejected_by_default(tmp_path):
    """A crash carrying credential-shaped content is rejected unless the
    operator passes --allow-sensitive (finding: secrets into corpus)."""
    secret_crash = b'aws_key = "AKIA' + b'I' * 16 + b'"\n' + CRASH_A
    crashes = _crashes(tmp_path, {"crash-s": secret_crash})
    corpus = _corpus(tmp_path)
    report = cflite.promote(crashes, corpus)
    assert report["promoted"] == []
    assert any("sensitive" in r["reason"] for r in report["rejected"])
    assert not (corpus / f"crash-{_sha(secret_crash)}").exists()

    report2 = cflite.promote(crashes, corpus, allow_sensitive=True)
    assert len(report2["promoted"]) == 1


def test_cli_rejects_max_bytes_above_corpus_bound(tmp_path, capsys):
    """--max-bytes above MAX_CRASH_BYTES would create a corpus the
    regression test rejects — the CLI refuses (finding: override)."""
    crashes = _crashes(tmp_path, {"c": CRASH_A})
    corpus = _corpus(tmp_path)
    rc = cli.main(
        [
            "cflite-promote",
            "--crashes-dir",
            str(crashes),
            "--corpus-dir",
            str(corpus),
            "--max-bytes",
            str(cflite.MAX_CRASH_BYTES + 1),
        ]
    )
    assert rc == 2
    assert "corpus bound" in capsys.readouterr().err
