"""Fuzz regression pack: ``fuzz/corpus/`` is the promoted-crash corpus.

``devin-redact cflite-promote`` lands minimized ClusterFuzzLite crashes
here as ``crash-<sha256>`` files indexed by ``manifest.json``. The pack
must hold together — every entry on disk hashed into the manifest, all
within the reproducer bounds — and every entry must replay cleanly
through the exact atheris consumption the fuzz target performs (a crash
that still crashes fails loudly, which is the point of the pack).
"""

import hashlib
import json
from pathlib import Path

import pytest
from devin_redact import cflite

CORPUS_DIR = Path(__file__).resolve().parents[1] / "fuzz" / "corpus"
MANIFEST = CORPUS_DIR / cflite.MANIFEST_NAME


def _entries() -> list[Path]:
    """Crash entries on disk — files named ``crash-<sha256>``."""
    if not CORPUS_DIR.is_dir():
        return []
    return sorted(
        p
        for p in CORPUS_DIR.iterdir()
        if p.is_file()
        and p.name.startswith(cflite.ENTRY_PREFIX)
        and p.name != cflite.MANIFEST_NAME
    )


def test_corpus_pack_integrity():
    entries = _entries()
    if MANIFEST.is_file():
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        listed = set(manifest.get("entries", {}))
        assert listed == {p.name for p in entries}, (
            "manifest/disk drift — promote crashes via "
            "`devin-redact cflite-promote`, not by hand"
        )
        for name, meta in manifest["entries"].items():
            blob = (CORPUS_DIR / name).read_bytes()
            assert hashlib.sha256(blob).hexdigest() == meta["sha256"]
            assert len(blob) == meta["size"]
    for p in entries:
        size = p.stat().st_size
        assert 0 < size <= cflite.MAX_CRASH_BYTES, p


def test_corpus_entries_replay_without_crashing():
    """Replay each promoted crash through ``TestOneInput``'s consumption
    (kept in sync with ``fuzz/fuzz_redact.py``): the same provider calls,
    the same engine asserts. Needs atheris — present in the CFL image,
    optional locally."""
    entries = _entries()
    if not entries:
        pytest.skip("no promoted crashes in fuzz/corpus yet")
    atheris = pytest.importorskip("atheris")
    from devin_redact import engine

    for p in entries:
        fdp = atheris.FuzzedDataProvider(p.read_bytes())
        text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 4096))
        redacted, replacements = engine.redact_text(text)
        assert isinstance(redacted, str)
        assert isinstance(replacements, list)
        engine.scan_text(text, file=p.name, location="fuzz-corpus")
