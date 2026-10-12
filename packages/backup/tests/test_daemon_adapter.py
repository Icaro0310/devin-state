"""Structural checks for adapters/daemon — the daily-snapshot scheduler.

Config artifacts, not code: assert the contract the schedulers depend on
(right ExecStart, daily-with-catch-up, resolved-exe placeholder, install
ordering, registry cleanup on remove, consistent task name).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

DAEMON = Path(__file__).resolve().parents[1] / "adapters" / "daemon"
NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def _read(name: str) -> str:
    return (DAEMON / name).read_text(encoding="utf-8")


class TestSystemdUnits:
    def test_service_runs_real_cli(self):
        svc = _read("devin-backup-daily.service")
        assert "Type=oneshot" in svc
        assert "ExecStart=/usr/bin/env devin-backup create" in svc
        # writes confined to the backups dirs under ProtectSystem=strict
        assert "ReadWritePaths=" in svc and "backups" in svc

    def test_timer_daily_with_catchup(self):
        timer = _read("devin-backup-daily.timer")
        assert "OnCalendar=" in timer
        assert "Persistent=true" in timer  # suspend-safe
        assert "WantedBy=timers.target" in timer


class TestTaskXml:
    def _root(self):
        return ET.parse(DAEMON / "devin-backup-daily.task.xml").getroot()

    def test_suspend_safe_triggers(self):
        root = self._root()
        triggers = root.find(f"{NS}Triggers")
        kinds = {t.tag.replace(NS, "") for t in triggers}
        assert {"LogonTrigger", "CalendarTrigger"} <= kinds
        # missed daily slot catches up at next wake
        assert root.find(f"{NS}Settings/{NS}StartWhenAvailable").text == "true"

    def test_action_uses_resolved_exe_placeholder(self):
        # Task Scheduler's PATH lacks %USERPROFILE%\.local\bin — the
        # action must be patched to the absolute CLI path at install.
        args = self._root().find(f"{NS}Actions/{NS}Exec/{NS}Arguments").text
        assert "__BACKUP_EXE__" in args
        assert " create" in args


class TestInstallRemoveScripts:
    def test_task_name_consistent(self):
        xml = _read("devin-backup-daily.task.xml")
        assert "<URI>\\devin-backup-daily</URI>" in xml
        for script in ("install-task.ps1", "remove-task.ps1"):
            assert "TaskName = 'devin-backup-daily'" in _read(script)

    def test_install_ordering(self):
        # canonical installer first (registry entry), then the XML import
        # overwrites the daily-only task with proper triggers.
        src = _read("install-task.ps1")
        assert src.index("devin-backup install --backend tasksch") < src.index(
            "Register-ScheduledTask")
        assert "__BACKUP_EXE__" in src
        # paths with '&' etc. must be XML-escaped before substitution
        assert "SecurityElement" in src or "Escape" in src

    def test_remove_cleans_registry_record(self):
        src = _read("remove-task.ps1")
        assert "Unregister-ScheduledTask" in src
        assert "scheduled.json" in src
        assert "PSObject.Properties.Remove" in src
