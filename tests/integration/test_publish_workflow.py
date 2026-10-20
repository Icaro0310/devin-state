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
