"""Staged-blob reads for the pre-commit gate (``gate --staged``).

The hook receives staged *filenames* from pre-commit, but the
working-tree copy is not what the commit records: a secret ``git
add``ed and then edited out of — or deleted from — the working tree
still ships in the commit, while a scan of the file on disk sees the
clean version. ``staged_blobs`` reads each path's index blob
(``git cat-file blob :0:<path>``) so the gate verdict always reflects
the staged content.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

Blob = tuple[str, bytes]


class StagedScanError(RuntimeError):
    """The index itself is unreadable — no git binary, not a repository.

    The gate must fail closed on this (exit 2): a hook that cannot see
    the staged content cannot vouch for the commit.
    """


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", "-C", str(cwd), *args],
            capture_output=True,
            check=False,
        )
    except OSError as exc:  # git missing or not executable
        raise StagedScanError(f"git invocation failed: {exc}") from exc


def _repo_root(cwd: Path) -> Path:
    proc = _git(["rev-parse", "--show-toplevel"], cwd)
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise StagedScanError(
            f"not a git repository ({detail or 'rev-parse failed'})"
        )
    return Path(proc.stdout.decode("utf-8", "replace").strip())


def staged_blobs(paths, cwd=None) -> tuple[list[Blob], list[dict]]:
    """Read each path's staged blob (``:0:<path>``) from the index.

    Returns ``(blobs, errors)``: blobs are ``(repo-relative name,
    content)`` pairs for :func:`devin_redact.engine.scan_blobs`, and
    errors use the report's ``{"file", "error"}`` shape.

    A path with no index entry — staged for deletion, or never ``git
    add``ed — yields a non-blocking ``skipped:`` entry: nothing staged
    means the commit records nothing for it. A path the index *does*
    hold but whose blob cannot be read (unmerged conflict stages,
    gitlinks) is a blocking error — the gate fails closed.
    """
    cwd = Path(cwd) if cwd is not None else Path.cwd()
    root = _repo_root(cwd)
    blobs: list[Blob] = []
    errors: list[dict] = []
    for p in paths:
        raw = str(p)
        abs_p = raw if os.path.isabs(raw) else os.path.join(cwd, raw)
        rel = os.path.relpath(os.path.normpath(abs_p), root)
        if rel == ".." or rel.startswith(f"..{os.sep}"):
            errors.append({"file": raw, "error": "outside the repository"})
            continue
        name = Path(rel).as_posix()
        proc = _git(["cat-file", "blob", f":0:{name}"], root)
        if proc.returncode == 0:
            blobs.append((name, proc.stdout))
            continue
        check = _git(["ls-files", "--error-unmatch", "--", name], root)
        if check.returncode == 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            errors.append(
                {"file": name, "error": f"staged blob unreadable: {detail}"}
            )
        else:
            errors.append({"file": name, "error": "skipped: no staged blob"})
    return blobs, errors
