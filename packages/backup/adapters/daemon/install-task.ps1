#Requires -Version 5.1
<#
.SYNOPSIS
  Register the devin-backup-daily scheduled task (user scope, no admin).

.DESCRIPTION
  Two-step registration when `devin-backup` is on PATH:

    1. `devin-backup install --backend tasksch` — the canonical
       installer, which writes the .devin-ecosystem/scheduled.json
       registry entry (and registers a daily-only task).
    2. Import devin-backup-daily.task.xml with -Force — same job name,
       so it OVERWRITES the daily-only task with this adapter's triggers
       (logon + daily, StartWhenAvailable) and an action pointing at the
       resolved absolute CLI path.

  If the CLI is not installed, only step 2 runs (no registry entry) and
  the action falls back to the documented default install location,
  %USERPROFILE%\.local\bin\devin-backup.exe — edit the XML first if your
  install lives elsewhere.

  Why not just the canonical installer? Its tasksch backend registers
  `/sc DAILY` with no logon trigger and no missed-run setting — a laptop
  asleep at the daily slot would skip its backup silently. Why not just
  the CLI name? Task Scheduler's environment lacks %USERPROFILE%\.local\
  bin, where `uv tool install` puts the shim — a bare name is not found
  at run time, so the action uses the resolved absolute path.

  User-scope tasks need no elevation. If you get access denied
  (0x80070005), your account or policy blocks Task Scheduler — see
  README.corporate-windows.md.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install-task.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TaskName = 'devin-backup-daily'
)

$ErrorActionPreference = 'Stop'

$xmlPath = Join-Path $PSScriptRoot 'devin-backup-daily.task.xml'
if (-not (Test-Path $xmlPath)) {
    throw "task XML not found next to this script: $xmlPath"
}

# Resolve the executable the action will call: the CLI on PATH if
# present, else the documented `uv tool install` default.
$cli = Get-Command devin-backup -ErrorAction SilentlyContinue
$exePath = if ($cli) { $cli.Source } else {
    Join-Path $env:USERPROFILE '.local\bin\devin-backup.exe'
}

if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
    if ($cli) {
        # Step 1 — canonical installer: writes the .devin-ecosystem
        # registry entry (its own daily task gets overwritten below).
        & devin-backup install --backend tasksch
        if ($LASTEXITCODE -ne 0) {
            throw ("'devin-backup install --backend tasksch' failed " +
                "($LASTEXITCODE). On 0x80070005 see README.corporate-windows.md.")
        }
        Write-Host "Registry entry written by the canonical installer."
    }
    else {
        Write-Warning ("'devin-backup' is not on PATH — skipping the " +
            "canonical installer (no .devin-ecosystem registry entry) " +
            "and using the default exe path: $exePath")
    }

    # Step 2 — XML import: correct triggers + resolved absolute exe path.
    # Escape the path first: a profile/install dir containing '&', '<' or
    # '>' would produce malformed XML that registration rejects.
    try {
        $escapedExe = [System.Security.SecurityElement]::Escape($exePath)
        $xml = (Get-Content -Raw -Path $xmlPath).Replace('__BACKUP_EXE__', $escapedExe)
        Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force | Out-Null
    }
    catch {
        if ($_.Exception.HResult -eq -2147024891) {  # 0x80070005 E_ACCESSDENIED
            Write-Error ("Access denied registering '$TaskName'. " +
                "User-scope tasks normally need no admin — a policy is " +
                "blocking Task Scheduler. See README.corporate-windows.md.")
        }
        throw
    }
    Write-Host "Registered scheduled task '$TaskName' (user scope; logon + daily, StartWhenAvailable)."
    Write-Host "Smoke check: Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
}
