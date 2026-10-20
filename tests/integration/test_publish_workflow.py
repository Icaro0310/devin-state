"""Static pins for .github/workflows/pypi-publish.yml.

Tag publishes consume the verified wheel from the `dist` artifact.
`actions/checkout` cleans the workspace, so it must run *before* the
artifact download or the publish loses dist/ entirely (regression
that failed backup-v0.1.1 / janitor-v0.1.1 / redact-v0.2.3 on
2026-10-20). These checks pin the ordering and the presence of the
wheel-content gate without requiring PyYAML.
"""

from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "pypi-publish.yml"
)


def _steps() -> list[str]:
    """Return the publish job's step headers, in file order."""
    text = WORKFLOW.read_text(encoding="utf-8")
    publish = text.split("  publish:", 1)[1]
    headers = [
        line.strip()
        for line in publish.splitlines()
        if line.startswith("      - ")
    ]
    assert headers, "publish job exposes no steps — workflow shape changed?"
    return headers


def test_checkout_precedes_dist_download():
    headers = _steps()
    checkout = next(i for i, h in enumerate(headers) if "uses: actions/checkout" in h)
    download = next(
        i for i, h in enumerate(headers) if "Download verified dist artifact" in h
    )
    assert checkout < download, (
        "checkout must run before the artifact download — it cleans the "
        "workspace and wipes dist/ when it runs after"
    )


def test_wheel_content_gate_runs_after_dist_is_present():
    headers = _steps()
    download = next(
        i for i, h in enumerate(headers) if "Download verified dist artifact" in h
    )
    build = next(i for i, h in enumerate(headers) if "Build sdist and wheel" in h)
    gate = next(
        i
        for i, h in enumerate(headers)
        if "Verify wheel covers declared scripts and extras" in h
    )
    upload = next(i for i, h in enumerate(headers) if "Upload to PyPI" in h)
    assert download < gate and build < gate, (
        "the wheel-content check must run only once dist/ exists"
    )
    assert gate < upload, "the wheel-content check must gate the upload"


def test_wheel_gate_asserts_scripts_and_extras():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "entry_points.txt" in text
    assert "Provides-Extra" in text
    assert "project.scripts" in text or '"scripts"' in text
    assert "optional-dependencies" in text


# -- dynamic coverage: run the gate's own python block on fixture wheels --

import re
import subprocess
import sys
import textwrap
import zipfile



def _gate_script() -> str:
    """Extract the 'Verify wheel covers declared scripts and extras'
    run-block so the test executes the workflow's own code, not a copy."""
    text = WORKFLOW.read_text(encoding="utf-8")
    step = re.search(
        r"Verify wheel covers declared scripts and extras\n"
        r"\s*run: \|\n((?:\s{10,}.*\n)+)",
        text,
    )
    assert step, "gate step shape changed — re-anchor the extractor"
    body = step.group(1)
    heredoc = re.search(r"python - <<'PY'\n((?:.*\n)*?)\s*PY", body)
    assert heredoc, "gate python heredoc not found"
    return textwrap.dedent(heredoc.group(1))


def _wheel(path: Path, distinfo: str, *, entry_points: str | None,
           extras: list[str]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path / "pkg-0.1.0-py3-none-any.whl", "w") as z:
        if entry_points is not None:
            z.writestr(f"{distinfo}/entry_points.txt", entry_points)
        md = "Metadata-Version: 2.1\nName: pkg\nVersion: 0.1.0\n"
        md += "".join(f"Provides-Extra: {e}\n" for e in extras)
        z.writestr(f"{distinfo}/METADATA", md)


def _pyproject(path: Path, *, scripts: dict | None,
               extras: dict | None) -> Path:
    pkg = path / "pkg"
    pkg.mkdir()
    lines = ["[project]", 'name = "pkg"', 'version = "0.1.0"']
    if scripts:
        lines.append("[project.scripts]")
        lines += [f'{k} = "{v}"' for k, v in scripts.items()]
    if extras:
        lines.append("[project.optional-dependencies]")
        lines += [f'{k} = []' for k in extras]
    (pkg / "pyproject.toml").write_text("\n".join(lines), encoding="utf-8")
    return pkg


def _run_gate(tmp_path: Path, script: str) -> subprocess.CompletedProcess:
    dist = tmp_path / "dist"
    dist.mkdir(exist_ok=True)
    pkg_dir = _pyproject(
        tmp_path, scripts=_SCRIPTS, extras=_EXTRAS)
    # The workflow interpolates needs.resolve.outputs.dir — the fixture
    # substitutes the fabricated package dir directly.
    rendered = script.replace(
        "${{ needs.resolve.outputs.dir }}", pkg_dir.as_posix())
    return subprocess.run(
        [sys.executable, "-c", rendered],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )


_SCRIPTS = {"devin-pkg": "pkg.cli:main", "devin-pkg-mcp": "pkg.mcp:main"}
_EXTRAS = {"mcp": []}
_EP = "[console_scripts]\ndevin-pkg = pkg.cli:main\ndevin-pkg-mcp = pkg.mcp:main\n"


def test_gate_passes_on_complete_wheel(tmp_path):
    script = _gate_script()
    dist = tmp_path / "dist"
    _wheel(dist, "pkg-0.1.0.dist-info", entry_points=_EP, extras=["mcp"])
    res = _run_gate(tmp_path, script)
    assert res.returncode == 0, res.stderr
    assert "verified" in res.stdout


def test_gate_tolerates_wheel_without_entry_points(tmp_path):
    """A wheel with no entry_points.txt must FAIL by naming the missing
    scripts — not crash on next(). (Scriptless wheels pass; see the
    scheduler-shape test below.)"""
    script = _gate_script()
    dist = tmp_path / "dist"
    _wheel(dist, "pkg-0.1.0.dist-info", entry_points=None, extras=["mcp"])
    res = _run_gate(tmp_path, script)
    assert res.returncode == 1
    assert "StopIteration" not in res.stderr
    assert "devin-pkg" in res.stderr or "devin-pkg" in res.stdout


def test_gate_fails_when_declared_scripts_missing(tmp_path):
    script = _gate_script()
    dist = tmp_path / "dist"
    _wheel(dist, "pkg-0.1.0.dist-info",
           entry_points="[console_scripts]\ndevin-pkg = pkg.cli:main\n",
           extras=["mcp"])
    res = _run_gate(tmp_path, script)
    assert res.returncode == 1
    assert "devin-pkg-mcp" in res.stderr or "devin-pkg-mcp" in res.stdout


def test_gate_passes_for_scriptless_package(tmp_path):
    """The scheduler shape: no scripts declared, no entry_points.txt —
    gate passes rather than crashing."""
    script = _gate_script()
    dist = tmp_path / "dist"
    _wheel(dist, "pkg-0.1.0.dist-info", entry_points=None, extras=[])
    pkg_dir = _pyproject(tmp_path, scripts=None, extras=None)
    rendered = script.replace(
        "${{ needs.resolve.outputs.dir }}", pkg_dir.as_posix())
    res = subprocess.run(
        [sys.executable, "-c", rendered],
        capture_output=True, text=True, cwd=tmp_path, check=False,
    )
    assert res.returncode == 0, res.stderr
