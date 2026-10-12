#Requires -Version 5.1
<#
.SYNOPSIS
  Remove the devin-backup-daily scheduled task (user scope, no admin).

.DESCRIPTION
  Unregisters the Task Scheduler entry, whether it was created by
  `devin-backup install`, this script's XML import, or a manual schtasks
  call. Existing snapshots and the .devin-ecosystem/scheduled.json record
  (if any) are left in place — delete the job record by hand if you want
  the registry clean too.

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
    Write-Host "Scheduled task '$TaskName' is not registered — nothing to do."
    return
}

if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
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
    Write-Host "Removed scheduled task '$TaskName'. Existing snapshots are left in place."
}
