<#
.SYNOPSIS
    Scans common malware staging directories for suspicious files.

.DESCRIPTION
    Checks %TEMP%, %APPDATA%, %LOCALAPPDATA%, and C:\Windows\Temp for:

        - Files larger than a configurable size threshold (default 50MB)
          which may indicate staged payloads or exfiltration archives
        - Executable or script files (.exe, .ps1, .bat, .vbs, .bin, .dat)
          carrying Hidden or System file attributes

    Useful as a rapid first-pass during incident triage before running
    a full AV scan or forensic collection.

.PARAMETER SizeLimitMB
    File size threshold in MB. Files exceeding this are flagged. Default: 50

.PARAMETER AdditionalPaths
    Additional directories to include in the scan beyond the defaults.

.PARAMETER ExportPath
    Optional. Full path for CSV export of flagged files.

.EXAMPLE
    .\Search-Payloads.ps1
    Scans default locations with 50MB threshold.

.EXAMPLE
    .\Search-Payloads.ps1 -SizeLimitMB 10 -AdditionalPaths "C:\ProgramData","D:\Staging"
    Lower threshold with additional scan paths.

.EXAMPLE
    .\Search-Payloads.ps1 -ExportPath "C:\IR\payload_hits.csv"
    Exports findings to CSV for evidence documentation.

.NOTES
    Author:   Dax Lewis
    Requires: PowerShell 5.1+, Run as Administrator for full visibility
    Note:     Does not execute or modify any files found
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateRange(1, 10000)]
    [int]$SizeLimitMB = 50,

    [Parameter()]
    [string[]]$AdditionalPaths = @(),

    [Parameter()]
    [string]$ExportPath
)

$DefaultPaths = @(
    $env:TEMP,
    $env:APPDATA,
    $env:LOCALAPPDATA,
    "C:\Windows\Temp"
)

$SearchPaths = ($DefaultPaths + $AdditionalPaths) | Where-Object { Test-Path $_ }
$SuspiciousExtensions = @('.exe','.bat','.ps1','.vbs','.bin','.dat','.js','.hta','.cmd')
$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "--- PAYLOAD SCAN STARTING ---" -ForegroundColor Cyan
Write-Host "Size threshold : >$($SizeLimitMB)MB"
Write-Host "Paths          : $($SearchPaths.Count) directories`n"

foreach ($Path in $SearchPaths) {
    Write-Host "Scanning: $Path" -ForegroundColor Gray

    Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $Item     = $_
        $SizeMB   = [math]::Round($Item.Length / 1MB, 2)
        $IsHidden = $Item.Attributes -match 'Hidden|System'
        $IsSuspiciousExt = $Item.Extension -in $SuspiciousExtensions

        $Flag = $null

        if ($SizeMB -gt $SizeLimitMB) {
            $Flag = "LARGE FILE (${SizeMB}MB)"
        }
        elseif ($IsSuspiciousExt -and $IsHidden) {
            $Flag = "HIDDEN EXECUTABLE/SCRIPT"
        }

        if ($Flag) {
            Write-Host " [!] $Flag : $($Item.FullName)" -ForegroundColor Red
            Write-Host "     Size: ${SizeMB}MB | Attributes: $($Item.Attributes)" -ForegroundColor Yellow

            $Findings.Add([PSCustomObject]@{
                Flag            = $Flag
                FullName        = $Item.FullName
                Name            = $Item.Name
                Extension       = $Item.Extension
                SizeMB          = $SizeMB
                Attributes      = $Item.Attributes.ToString()
                CreationTime    = $Item.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                LastWriteTime   = $Item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                ScannedAt       = (Get-Date -Format 'yyyy-MM-dd HH:mm')
            })
        }
    }
}

Write-Host "`n--- SCAN COMPLETE ---" -ForegroundColor Cyan
Write-Host "Findings: $($Findings.Count) item(s) flagged"

if ($ExportPath -and $Findings.Count -gt 0) {
    $Findings | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to: $ExportPath" -ForegroundColor Green
}

if ($Findings.Count -eq 0) {
    Write-Host "No suspicious files found in scanned paths." -ForegroundColor Green
}
else {
    $Findings
}
