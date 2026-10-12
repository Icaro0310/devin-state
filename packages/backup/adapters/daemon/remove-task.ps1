#Requires -Version 5.1
<#
.SYNOPSIS
  Remove the devin-backup-daily scheduled task (user scope, no admin).

.DESCRIPTION
  Unregisters the Task Scheduler entry, whether it was created by
  `devin-backup install`, this script's XML import, or a manual schtasks
  call — then removes the job's record from
  .devin-ecosystem/scheduled.json if the canonical installer wrote one.
  Existing snapshots are left in place.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\remove-task.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TaskName = 'devin-backup-daily'
)

$ErrorActionPreference = 'Stop'

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    Write-Host "Scheduled task '$TaskName' is not registered — nothing to unregister."
}
elseif ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    catch {
        if ($_.Exception.HResult -eq -2147024891) {  # 0x80070005 E_ACCESSDENIED
            Write-Error ("Access denied removing '$TaskName'. " +
                "See README.corporate-windows.md.")
        }
        throw
    }
    Write-Host "Removed scheduled task '$TaskName'."
}

# Registry cleanup: <config-dir>\.devin-ecosystem\scheduled.json, where
# config-dir resolves like the installer — $env:DEVIN_CONFIG_DIR, else
# %APPDATA%\Devin (Windows default).
$configDir = if ($env:DEVIN_CONFIG_DIR) { $env:DEVIN_CONFIG_DIR } else {
    Join-Path $env:APPDATA 'Devin'
}
$regPath = Join-Path $configDir '.devin-ecosystem\scheduled.json'
if (Test-Path $regPath) {
    try {
        $reg = Get-Content -Raw -Path $regPath | ConvertFrom-Json
        if ($reg.jobs -and $reg.jobs.PSObject.Properties.Name -contains $TaskName) {
            if ($PSCmdlet.ShouldProcess($TaskName, 'Remove scheduled.json job record')) {
                $reg.jobs.PSObject.Properties.Remove($TaskName)
                $reg | ConvertTo-Json -Depth 10 | Set-Content -Path $regPath -Encoding UTF8
                Write-Host "Removed '$TaskName' record from $regPath"
            }
        }
    }
    catch {
        Write-Warning ("Task removed, but cleaning $regPath failed: " +
            "$($_.Exception.Message) — delete the job record by hand.")
    }
}
Write-Host "Existing snapshots are left in place."
