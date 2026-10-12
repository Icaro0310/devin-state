#Requires -Version 5.1
<#
.SYNOPSIS
  Register the devin-backup-daily scheduled task (user scope, no admin).

.DESCRIPTION
  Prefers the canonical installer: if `devin-backup` is on PATH this runs
  `devin-backup install --backend tasksch`, which registers the same
  "devin-backup-daily" job AND writes the .devin-ecosystem/scheduled.json
  registry entry. If the CLI is not installed, it falls back to importing
  devin-backup-daily.task.xml directly — same command, same schedule
  (logon + daily, StartWhenAvailable), minus the registry entry.

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

if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
    if (Get-Command devin-backup -ErrorAction SilentlyContinue) {
        # Canonical path: shared install-scheduler writes the registry entry.
        & devin-backup install --backend tasksch
        if ($LASTEXITCODE -ne 0) {
            throw "'devin-backup install --backend tasksch' failed ($LASTEXITCODE). " +
                "On 0x80070005 see README.corporate-windows.md."
        }
        Write-Host "Installed '$TaskName' via the canonical devin-backup installer."
    }
    else {
        Write-Warning "'devin-backup' is not on PATH — importing the task XML " +
            "directly (no .devin-ecosystem registry entry)."
        try {
            $xml = Get-Content -Raw -Path $xmlPath
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
        Write-Host "Registered scheduled task '$TaskName' (user scope)."
    }
    Write-Host "Smoke check: Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
}
