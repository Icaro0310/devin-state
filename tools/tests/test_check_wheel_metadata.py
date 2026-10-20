"""Gate coverage: wheels with and without declared scripts/extras."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_wheel_metadata import check_wheel


def _pkg(tmp_path: Path, *, scripts: bool = True, extras: bool = True) -> Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    scripts_block = (
        '[project.scripts]\ndemo-tool = "demo:main"\n' if scripts else ""
    )
    extras_block = (
        '[project.optional-dependencies]\nmcp = ["mcp>=1"]\n'
        if extras else ""
    )
    (pkg / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\n'
        f"{scripts_block}{extras_block}",
        encoding="utf-8",
    )
    return pkg


def _wheel(dist: Path, *, entry_points: bool = True,
           extras: tuple[str, ...] = ("mcp",),
           scripts: tuple[str, ...] = ("demo-tool",)) -> Path:
    dist.mkdir(parents=True, exist_ok=True)
    wheel = dist / "demo-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as z:
        if entry_points:
            lines = "".join(f"{s} = demo:main\n" for s in scripts)
            z.writestr(
                "demo-0.1.0.dist-info/entry_points.txt",
                f"[console_scripts]\n{lines}",
            )
        provides = "".join(f"Provides-Extra: {x}\n" for x in extras)
        z.writestr("demo-0.1.0.dist-info/METADATA", provides)
    return wheel


def test_complete_wheel_passes(tmp_path):
    dist = tmp_path / "dist"
    _wheel(dist)
    assert check_wheel(dist, _pkg(tmp_path)) == []


def test_missing_declared_script_fails(tmp_path):
    dist = tmp_path / "dist"
    _wheel(dist, scripts=())  # entry_points.txt present but empty list
    failures = check_wheel(dist, _pkg(tmp_path))
    assert any("demo-tool" in f for f in failures)


def test_no_scripts_no_entry_points_passes(tmp_path):
    """install-scheduler shape: no [project.scripts] declared, wheel
    legitimately ships no entry_points.txt — must not raise."""
    dist = tmp_path / "dist"
    _wheel(dist, entry_points=False)
    assert check_wheel(dist, _pkg(tmp_path, scripts=False)) == []


def test_declared_scripts_without_entry_points_fails(tmp_path):
    dist = tmp_path / "dist"
    _wheel(dist, entry_points=False)
    failures = check_wheel(dist, _pkg(tmp_path))
    assert any("entry_points.txt" in f for f in failures)


def test_missing_extra_fails(tmp_path):
    dist = tmp_path / "dist"
    _wheel(dist, extras=())
    failures = check_wheel(dist, _pkg(tmp_path))
    assert any("Provides-Extra" in f for f in failures)


def test_wheel_count_enforced(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    failures = check_wheel(dist, _pkg(tmp_path))
    assert any("exactly one wheel" in f for f in failures)
