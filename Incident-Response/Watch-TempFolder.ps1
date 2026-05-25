<#
.SYNOPSIS
    Real-time monitor for file activity in the Windows %TEMP% directory.

.DESCRIPTION
    Uses .NET FileSystemWatcher to detect file creation, deletion,
    modification, and rename events in the user's %TEMP% folder.
    Flags files with Hidden or System attributes immediately on detection,
    which is a common indicator of malware staging activity.

    All events are logged to a timestamped file and mirrored to the console.
    Run indefinitely until stopped with Ctrl+C, which cleanly unregisters
    all event listeners.

.PARAMETER WatchPath
    Directory to monitor. Defaults to the current user's %TEMP% folder.

.PARAMETER LogPath
    Directory to write the log file. Defaults to the Desktop.

.PARAMETER IncludeSubdirectories
    Switch. Extends monitoring to all subdirectories under WatchPath.

.EXAMPLE
    .\Watch-TempFolder.ps1
    Monitors %TEMP% with default settings.

.EXAMPLE
    .\Watch-TempFolder.ps1 -WatchPath "C:\Windows\Temp" -IncludeSubdirectories
    Monitors the system TEMP directory including all subdirectories.

.NOTES
    Author:   Dax Lewis
    Requires: PowerShell 5.1+
    Note:     Run as Administrator to detect system-level file activity
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$WatchPath = "$env:USERPROFILE\AppData\Local\Temp",

    [Parameter()]
    [string]$LogPath = [Environment]::GetFolderPath('Desktop'),

    [Parameter()]
    [switch]$IncludeSubdirectories
)

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile   = Join-Path $LogPath "Temp_Monitor_${Timestamp}.txt"

if (-not (Test-Path $WatchPath)) {
    Write-Error "Watch path does not exist: $WatchPath"
    exit 1
}

$Watcher = New-Object System.IO.FileSystemWatcher
$Watcher.Path                  = $WatchPath
$Watcher.IncludeSubdirectories = $IncludeSubdirectories.IsPresent
$Watcher.EnableRaisingEvents   = $true

Write-Host "--- TEMP FOLDER MONITOR ACTIVE ---" -ForegroundColor Cyan
Write-Host "Watching : $WatchPath" -ForegroundColor Gray
Write-Host "Log File : $LogFile" -ForegroundColor Gray
Write-Host "Press Ctrl+C to stop.`n"

"--- TEMP FOLDER MONITOR $(Get-Date) ---`nWatching: $WatchPath`n" |
    Out-File $LogFile -Encoding UTF8

$Action = {
    $FullPath   = $Event.SourceEventArgs.FullPath
    $ChangeType = $Event.SourceEventArgs.ChangeType
    $Time       = (Get-Date).ToString("HH:mm:ss.fff")

    $Message = "[$Time] $ChangeType : $FullPath"
    Write-Host $Message -ForegroundColor Yellow
    $Message | Out-File $using:LogFile -Append -Encoding UTF8

    if ($ChangeType -in 'Created','Changed') {
        try {
            $Item = Get-Item $FullPath -Force -ErrorAction Stop
            if ($Item.Attributes -match 'Hidden|System') {
                $Alert = "     [!] ALERT: HIDDEN/SYSTEM ATTRIBUTE DETECTED -- $FullPath"
                Write-Host $Alert -ForegroundColor Red
                $Alert | Out-File $using:LogFile -Append -Encoding UTF8
            }
        }
        catch { }
    }
}

$EventNames = @('Created','Deleted','Changed','Renamed')
foreach ($EventName in $EventNames) {
    Register-ObjectEvent $Watcher $EventName `
        -SourceIdentifier "FileWatcher_$EventName" `
        -Action $Action | Out-Null
}

try {
    while ($true) { Start-Sleep -Seconds 1 }
}
finally {
    foreach ($EventName in $EventNames) {
        Unregister-Event -SourceIdentifier "FileWatcher_$EventName" -ErrorAction SilentlyContinue
    }
    $Watcher.Dispose()
    Write-Host "`nMonitor stopped. Log saved to: $LogFile" -ForegroundColor Green
}
