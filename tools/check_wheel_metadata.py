"""Assert the built wheel carries every declared script and extra.

A version-matching wheel can still miss declared entry points or
extras (the -mcp gap the 0.1.1 release class fixes). This gate runs in
the publish job after the exact dist/ that passed verify is restored —
or after the install-scheduler leg builds its own — and refuses the
upload when the artifact disagrees with pyproject.toml.

Wheels with no [project.scripts] legitimately ship no
entry_points.txt (install-scheduler): the check then verifies extras
only. Run: python tools/check_wheel_metadata.py --dir <pkg> --dist dist/
"""

from __future__ import annotations

import argparse
import sys
import tomllib
import zipfile
from pathlib import Path


def check_wheel(dist: Path, package_dir: Path) -> list[str]:
    """Return the list of failures; empty means the wheel covers
    everything pyproject.toml declares."""
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        return [f"expected exactly one wheel in {dist}, got {wheels}"]
    meta = tomllib.loads(
        (package_dir / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    scripts = meta.get("scripts") or {}
    extras = meta.get("optional-dependencies") or {}

    failures: list[str] = []
    with zipfile.ZipFile(wheels[0]) as z:
        names = z.namelist()
        if scripts:
            entry = next(
                (n for n in names if n.endswith("entry_points.txt")), None
            )
            if entry is None:
                failures.append(
                    f"{wheels[0]} has no entry_points.txt but declares "
                    f"scripts {sorted(scripts)}"
                )
            else:
                ep = z.read(entry).decode()
                failures.extend(
                    f"{wheels[0]} missing script {name!r}"
                    for name in scripts
                    if f"{name} =" not in ep
                )
        if extras:
            metadata = next(
                (n for n in names if n.endswith("METADATA")), None
            )
            if metadata is None:
                failures.append(f"{wheels[0]} has no METADATA")
            else:
                md = z.read(metadata).decode()
                failures.extend(
                    f"{wheels[0]} missing Provides-Extra: {extra}"
                    for extra in extras
                    if f"Provides-Extra: {extra}" not in md
                )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, type=Path,
                        help="package directory holding pyproject.toml")
    parser.add_argument("--dist", required=True, type=Path,
                        help="directory containing the built wheel")
    args = parser.parse_args(argv)

    failures = check_wheel(args.dist, args.dir)
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print(f"wheel in {args.dist} covers declared scripts and extras")
    return 0


if __name__ == "__main__":
    sys.exit(main())
