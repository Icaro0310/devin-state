"""ClusterFuzzLite crash promotion — minimized crashes → regression corpus.

The ``fuzz`` workflow (``.github/workflows/cflite.yml``) runs the atheris
target (``fuzz/fuzz_redact.py``) in ``code-change`` mode: when a run finds
a crash, ClusterFuzzLite minimizes it and uploads the testcase as a
workflow-run artifact. ``promote()`` copies those artifacts into the
checked-in regression corpus (``fuzz/corpus/``) so every crash becomes a
permanent replay input for ``tests/test_fuzz_corpus.py``.

Corpus contract:

- one file per crash, named ``crash-<sha256-of-contents>`` — the name is
  the dedup key, so byte-identical artifacts collapse automatically;
- ``manifest.json`` records provenance (source artifact name, workflow
  run id, byte size, promotion timestamp);
- entries are binary-safe fuzzer inputs, so validation is bounds-only:
  a real reproducer is a regular file, non-empty, and within
  ``MAX_CRASH_BYTES`` — anything failing the bounds is *rejected* and
  reported in the ``rejected`` list, never silently skipped;
- before promotion, every candidate is scanned with the package's own
  ``engine.scan_text``: a crash carrying credential-shaped content is
  *rejected* by default (the corpus is committed to the repo) unless
  ``allow_sensitive=True`` makes the risk explicit;
- other files already in the corpus dir (notes, a future seed corpus)
  are left untouched and never treated as crash entries — only files
  named ``crash-<sha256>`` whose contents verify count for dedup.

Artifact acquisition is deliberately two-path: ``--crashes-dir`` reads an
already-unpacked dir (the offline/testable path), while ``--run-id``
fetches a run's artifacts through ``gh run download`` — each artifact
lands in its own subdirectory, so candidate discovery is recursive.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, engine

#: Environment override for the corpus location; ``--corpus-dir`` wins.
CORPUS_ENV = "DEVIN_REDACT_CFLITE_CORPUS"
#: Provenance index living inside the corpus dir.
MANIFEST_NAME = "manifest.json"
#: Every promoted crash is stored as ``crash-<sha256>``.
ENTRY_PREFIX = "crash-"
#: Upper bound for a minimized reproducer. The harness caps its unicode
#: consumption at 4096 chars + provider overhead; 1 MiB is generous —
#: anything bigger is a mis-exported artifact, not a minimized crash.
MAX_CRASH_BYTES = 1 << 20
_GH = "gh"


class CfliteError(RuntimeError):
    """Hard failure locating or downloading crash artifacts."""


def _package_root() -> Path | None:
    """The repo checkout of ``packages/redact``, when running from one."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "fuzz" / "fuzz_redact.py").is_file():
            return parent
    return None


def default_corpus_dir(environ: dict[str, str] | None = None) -> Path:
    """``<package>/fuzz/corpus`` — the checked-in regression pack.

    ``DEVIN_REDACT_CFLITE_CORPUS`` wins; outside a source checkout (wheel
    install) the fallback is ``./fuzz/corpus`` under the cwd.
    """
    env = os.environ if environ is None else environ
    override = env.get(CORPUS_ENV)
    if override:
        return Path(override)
    root = _package_root()
    return (root if root is not None else Path.cwd()) / "fuzz" / "corpus"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry_name(sha: str) -> str:
    return f"{ENTRY_PREFIX}{sha}"


def _iter_candidates(crashes_dir: Path) -> list[Path]:
    """Every non-directory path under ``crashes_dir``, recursively, in
    deterministic order. Non-regular files stay in the list — they are
    rejected by ``_validate`` rather than silently skipped."""
    return sorted(p for p in crashes_dir.rglob("*") if not p.is_dir())


def _validate(path: Path, max_bytes: int) -> str | None:
    """Rejection reason, or ``None`` when the file passes the bounds."""
    try:
        st = path.stat()
    except OSError as exc:
        return f"unreadable: {exc}"
    if not path.is_file():
        return "not a regular file"
    if st.st_size == 0:
        return "empty file — not a reproducer"
    if st.st_size > max_bytes:
        return f"{st.st_size} bytes exceeds the {max_bytes}-byte cap"
    return None


_ENTRY_RE = re.compile(rf"^{ENTRY_PREFIX}[0-9a-f]{{64}}$")


def _debinarize(text: str) -> str:
    """Drop every non-printable char — rejoins ASCII fragments that binary
    bytes split apart, so a credential interrupted by junk still matches
    contiguous patterns. Newlines/tabs survive for line-oriented rules."""
    return "".join(c for c in text if c.isprintable() or c in "\n\r\t")


def _corpus_hashes(corpus_dir: Path, errors: list[dict]) -> dict[str, str]:
    """sha256 → filename for every *validated crash entry* on disk.

    Only ``crash-<sha256>`` files whose name matches their contents
    count — a stray seed/note file with identical bytes must not
    satisfy dedup, or the crash never lands as a replayable entry.
    A misnamed ``crash-*`` file is corrupt and fails loud.
    """
    hashes: dict[str, str] = {}
    if not corpus_dir.is_dir():
        return hashes
    for p in sorted(corpus_dir.iterdir()):
        if not _ENTRY_RE.match(p.name):
            # a ``crash-`` name is the corpus contract — anything else
            # starting with the prefix is a malformed entry the
            # integrity test would reject, not a stray file to ignore
            if p.name.startswith(ENTRY_PREFIX):
                errors.append(
                    {
                        "file": str(p),
                        "error": "malformed crash entry name — "
                        f"expected {ENTRY_PREFIX}<sha256>",
                    }
                )
            continue
        if not p.is_file():
            errors.append(
                {
                    "file": str(p),
                    "error": "crash entry is not a regular file",
                }
            )
            continue
        # the same bounds as promoted candidates — an oversized or
        # empty entry is corrupt, whatever its name-hash agreement
        reason = _validate(p, MAX_CRASH_BYTES)
        if reason:
            errors.append(
                {"file": str(p), "error": f"corrupt entry: {reason}"}
            )
            continue
        try:
            sha = _sha256(p.read_bytes())
        except OSError as exc:
            errors.append({"file": str(p), "error": f"unreadable: {exc}"})
            continue
        if p.name != _entry_name(sha):
            errors.append(
                {
                    "file": str(p),
                    "error": "name does not match contents — corrupt entry",
                }
            )
            continue
        hashes.setdefault(sha, p.name)
    return hashes


def _load_manifest(corpus_dir: Path) -> tuple[dict, str | None]:
    """``(manifest, error)`` — a corrupt manifest fails loud and is never
    clobbered: ``promote`` reports the error and leaves the file alone."""
    mpath = corpus_dir / MANIFEST_NAME
    if not mpath.is_file():
        return (
            {
                "tool": "devin-redact",
                "version": __version__,
                "schema": 1,
                "entries": {},
            },
            None,
        )
    try:
        data = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {}, f"unreadable {MANIFEST_NAME}: {exc}"
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        return {}, f"malformed {MANIFEST_NAME}: missing 'entries' object"
    return data, None


def download_run_artifacts(
    run_id: str | int, dest_dir: Path, names: tuple[str, ...] | list[str] = ()
) -> None:
    """Fetch a workflow run's artifacts into ``dest_dir`` via ``gh``.

    ``gh run download`` unpacks each artifact into ``dest/<name>/`` (or
    directly into ``dest/`` when ``--name`` selects a single one) —
    ``promote`` discovers candidates recursively, so either layout works.
    """
    cmd = [_GH, "run", "download", str(run_id), "--dir", str(dest_dir)]
    for name in names:
        cmd += ["--name", name]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise CfliteError(
            "gh CLI not found — install it or pass --crashes-dir"
        ) from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise CfliteError(
            f"gh run download {run_id} failed (exit {proc.returncode}): {detail}"
        )


def promote(
    crashes_dir,
    corpus_dir=None,
    *,
    run_id: str | int | None = None,
    max_bytes: int = MAX_CRASH_BYTES,
    dry_run: bool = False,
    allow_sensitive: bool = False,
) -> dict:
    """Copy validated crash inputs into the corpus, deduped by sha256.

    Returns the JSON report. ``rejected`` and ``errors`` are the
    fail-loud channels — the CLI maps either being non-empty to a
    non-zero exit. ``dry_run`` computes the full report but writes
    nothing (no corpus files, no manifest).
    """
    crashes_dir = Path(crashes_dir)
    corpus_dir = Path(corpus_dir) if corpus_dir is not None else default_corpus_dir()
    errors: list[dict] = []
    rejected: list[dict] = []
    duplicates: list[dict] = []
    promoted: list[dict] = []

    manifest, manifest_error = _load_manifest(corpus_dir)
    if manifest_error:
        errors.append(
            {"file": str(corpus_dir / MANIFEST_NAME), "error": manifest_error}
        )

    known = _corpus_hashes(corpus_dir, errors)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Reconcile on-disk entries missing from the manifest — otherwise a
    # manifestless crash dedups silently and later manifests index only
    # newer entries, breaking corpus integrity checks.
    manifest_dirty = False
    if not manifest_error:
        for sha, fname in sorted(known.items()):
            if fname not in manifest["entries"]:
                size = (corpus_dir / fname).stat().st_size
                manifest["entries"][fname] = {
                    "sha256": sha,
                    "size": size,
                    "source": "pre-existing (unindexed)",
                    "run_id": None,
                    "promoted_at": now,
                }
                manifest_dirty = True

    batch: set[str] = set()
    manifest_path = (corpus_dir / MANIFEST_NAME).resolve()
    candidates = _iter_candidates(crashes_dir)

    writes: list[tuple[Path, bytes]] = []
    for path in candidates:
        if path.resolve() == manifest_path:
            continue  # never ingest our own manifest
        try:
            source = path.relative_to(crashes_dir).as_posix()
        except ValueError:
            source = str(path)
        reason = _validate(path, max_bytes)
        if reason:
            rejected.append({"source": source, "reason": reason})
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            errors.append({"file": source, "error": f"unreadable: {exc}"})
            continue
        if not allow_sensitive:
            text = data.decode("utf-8", errors="surrogateescape")
            views = [text]
            # surrogateescape keeps every byte, so ASCII runs survive —
            # but a credential *split* by binary bytes stays broken in
            # that view. The debinarized projection rejoins the
            # fragments, which is the gap Devin flagged.
            deb = _debinarize(text)
            if deb != text:
                views.append(deb)
            findings = [
                f
                for view in views
                for f in engine.scan_text(
                    view, file=source, location="cflite-promote"
                )
            ]
            # anything the scanner recognises blocks by default. The
            # corpus is byte-exact *and* commit-bound, so PII can't be
            # published as-is and can't be redacted either — rewriting a
            # span would change the reproducer's bytes, expand it past
            # the corpus bound, and binary-split spans can't be mapped
            # back to the original offsets anyway. The operator's
            # explicit opt-in for synthetic fuzz is --allow-sensitive.
            if findings:
                cats = sorted({str(f["category"]) for f in findings})
                rejected.append(
                    {
                        "source": source,
                        "reason": (
                            f"sensitive content ({', '.join(cats)}) — "
                            "re-run with --allow-sensitive to commit anyway"
                        ),
                    }
                )
                continue
        sha = _sha256(data)
        name = _entry_name(sha)
        if sha in known:
            duplicates.append(
                {
                    "source": source,
                    "sha256": sha,
                    "file": known[sha],
                    "detail": "already in corpus",
                }
            )
            continue
        if sha in batch:
            duplicates.append(
                {
                    "source": source,
                    "sha256": sha,
                    "file": name,
                    "detail": "duplicate of another candidate in this batch",
                }
            )
            continue
        batch.add(sha)
        promoted.append(
            {
                "file": name,
                "source": source,
                "size": len(data),
                "sha256": sha,
                "run_id": str(run_id) if run_id is not None else None,
            }
        )
        if not manifest_error:
            manifest["entries"][name] = {
                "sha256": sha,
                "size": len(data),
                "source": source,
                "run_id": str(run_id) if run_id is not None else None,
                "promoted_at": now,
            }
        writes.append((corpus_dir / name, data))

    manifest_written: str | None = None
    if not dry_run and (promoted or manifest_dirty):
        corpus_dir.mkdir(parents=True, exist_ok=True)
        for dest, data in writes:
            dest.write_bytes(data)
        if not manifest_error:
            mpath = corpus_dir / MANIFEST_NAME
            mpath.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            manifest_written = str(mpath)

    return {
        "tool": "devin-redact",
        "version": __version__,
        "crashes_dir": str(crashes_dir),
        "corpus_dir": str(corpus_dir),
        "run_id": str(run_id) if run_id is not None else None,
        "dry_run": dry_run,
        "max_bytes": max_bytes,
        "candidates": len(candidates),
        "promoted": promoted,
        "duplicates": duplicates,
        "rejected": rejected,
        "errors": errors,
        "manifest": manifest_written,
        "warnings": (
            [] if candidates else [f"no crash inputs found under {crashes_dir}"]
        ),
    }
