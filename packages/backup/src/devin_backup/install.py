"""BK-1: install a scheduled ``devin-backup create`` job.

Backends and registry format come from ``devin_install_scheduler`` (the
shared F6 scheduling foundation — cron, Task Scheduler, or the elapsed
config-registry fallback ticked by powerups' ``UserPromptSubmit`` hook).

Backups write files but never touch Devin's stores destructively, so the
job does NOT require Devin closed — it only needs Devin's stores readable
(sqlite backup API tolerates a live store).

The scheduled command is ``python -m devin_backup.cli create --out DIR``
using the current interpreter, so it works from a venv install.
"""

from __future__ import annotations

import sys

from devin_install_scheduler import install_daily as _install_daily

JOB_NAME = "devin-backup-daily"


def _create_command(out_dir: str | None, compress: bool = False) -> str:
    cmd = f'"{sys.executable}" -m devin_backup.cli create'
    if out_dir:
        cmd += f' --out "{out_dir}"'
    if compress:
        cmd += " --compress"
    return cmd


def install_daily(out_dir: str | None = None,
                  config_dir: str | None = None,
                  backend: str = "auto",
                  compress: bool = False) -> dict:
    """Register the daily backup job; returns what was done."""
    return _install_daily(JOB_NAME, _create_command(out_dir, compress),
                          config_dir=config_dir, backend=backend)
