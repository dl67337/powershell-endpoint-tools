<#
.SYNOPSIS
    Generates a patch compliance summary report across multiple endpoints.

.DESCRIPTION
    Evaluates patch posture for a list of machines by checking last update
    install date, pending update count, and OS build version. Outputs a
    per-host compliance summary with a Pass/Fail/Warning status based on
    configurable thresholds. Designed to complement SCCM/WSUS reporting
    for ad-hoc compliance spot checks.

.PARAMETER ComputerName
    List of hostnames to evaluate. Accepts pipeline input or a text file
    via Get-Content.

.PARAMETER MaxDaysSinceUpdate
    Number of days since last successful update before flagging as non-compliant.
    Default is 30.

.PARAMETER ExportPath
    Optional. Full path for CSV export.

.PARAMETER PassThru
    Switch. Outputs full result objects rather than the formatted summary table.

.EXAMPLE
    .\Get-PatchComplianceReport.ps1 -ComputerName "SRV-APP-001","SRV-DB-002"
    Evaluates two servers with default 30-day threshold.

.EXAMPLE
    Get-Content C:\hostlist.txt | .\Get-PatchComplianceReport.ps1 -MaxDaysSinceUpdate 14 -ExportPath "C:\Reports\compliance.csv"
    Reads hosts from a file, uses a 14-day threshold, exports to CSV.

.NOTES
    Author:      Dax Lewis
    Requires:    PowerShell 5.1+, WinRM on targets, local admin rights
    Integrates:  Output can be imported directly into Power BI for dashboard refresh
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory, ValueFromPipeline = $true)]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$MaxDaysSinceUpdate = 30,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [switch]$PassThru
)

begin {
    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()
}

process {
    foreach ($Computer in $ComputerName) {
        Write-Verbose "Evaluating: $Computer"

        try {
            $Data = Invoke-Command -ComputerName $Computer -ErrorAction Stop -ScriptBlock {

                # OS info
                $OS = Get-CimInstance Win32_OperatingSystem
                $CS = Get-CimInstance Win32_ComputerSystem

                # Last installed update
                $Session     = New-Object -ComObject Microsoft.Update.Session
                $Searcher    = $Session.CreateUpdateSearcher()
                $TotalCount  = $Searcher.GetTotalHistoryCount()
                $LastInstall = $null

                if ($TotalCount -gt 0) {
                    $History = $Searcher.QueryHistory(0, $TotalCount) |
                        Where-Object { $_.ResultCode -eq 2 } |
                        Sort-Object Date -Descending |
                        Select-Object -First 1

                    if ($History) { $LastInstall = $History.Date }
                }

                # Pending updates
                try {
                    $PendingResult  = $Searcher.Search("IsInstalled=0 and IsHidden=0")
                    $PendingCount   = $PendingResult.Updates.Count
                    $CriticalPending = ($PendingResult.Updates |
                        Where-Object { $_.MsrcSeverity -eq 'Critical' }).Count
                }
                catch {
                    $PendingCount    = -1
                    $CriticalPending = -1
                }

                # Uptime
                $Uptime = (Get-Date) - $OS.LastBootUpTime

                [PSCustomObject]@{
                    ComputerName     = $env:COMPUTERNAME
                    OSCaption        = $OS.Caption
                    OSBuild          = $OS.BuildNumber
                    LastBootUp       = $OS.LastBootUpTime.ToString('yyyy-MM-dd')
                    UptimeDays       = [math]::Round($Uptime.TotalDays, 1)
                    LastUpdateInstall= if ($LastInstall) { $LastInstall.ToString('yyyy-MM-dd') } else { 'Unknown' }
                    DaysSinceUpdate  = if ($LastInstall) { [math]::Round(((Get-Date) - $LastInstall).TotalDays) } else { 999 }
                    PendingUpdates   = $PendingCount
                    CriticalPending  = $CriticalPending
                    Manufacturer     = $CS.Manufacturer
                    Model            = $CS.Model
                    CollectedAt      = (Get-Date -Format 'yyyy-MM-dd HH:mm')
                }
            }

            # Compliance evaluation
            $Status = switch ($true) {
                { $Data.DaysSinceUpdate -gt $MaxDaysSinceUpdate }  { 'NON-COMPLIANT'; break }
                { $Data.CriticalPending -gt 0 }                    { 'NON-COMPLIANT'; break }
                { $Data.PendingUpdates -gt 5 }                     { 'WARNING'; break }
                { $Data.UptimeDays -gt 30 }                        { 'WARNING'; break }
                default                                             { 'COMPLIANT' }
            }

            $Data | Add-Member -NotePropertyName 'ComplianceStatus' -NotePropertyValue $Status
            $Results.Add($Data)
        }
        catch {
            Write-Warning "[$Computer] Unreachable or error: $_"
            $Results.Add([PSCustomObject]@{
                ComputerName      = $Computer
                OSCaption         = 'N/A'
                OSBuild           = 'N/A'
                LastBootUp        = 'N/A'
                UptimeDays        = $null
                LastUpdateInstall = 'N/A'
                DaysSinceUpdate   = $null
                PendingUpdates    = $null
                CriticalPending   = $null
                Manufacturer      = 'N/A'
                Model             = 'N/A'
                CollectedAt       = (Get-Date -Format 'yyyy-MM-dd HH:mm')
                ComplianceStatus  = 'UNREACHABLE'
            })
        }
    }
}

end {
    if ($ExportPath) {
        $Results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported $($Results.Count) records to $ExportPath" -ForegroundColor Green
    }

    if ($PassThru) {
        $Results
        return
    }

    # Summary table
    $Compliant    = ($Results | Where-Object ComplianceStatus -eq 'COMPLIANT').Count
    $Warning      = ($Results | Where-Object ComplianceStatus -eq 'WARNING').Count
    $NonCompliant = ($Results | Where-Object ComplianceStatus -eq 'NON-COMPLIANT').Count
    $Unreachable  = ($Results | Where-Object ComplianceStatus -eq 'UNREACHABLE').Count
    $Total        = $Results.Count

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " PATCH COMPLIANCE SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " Total Evaluated : $Total"
    Write-Host " Compliant       : $Compliant" -ForegroundColor Green
    Write-Host " Warning         : $Warning" -ForegroundColor Yellow
    Write-Host " Non-Compliant   : $NonCompliant" -ForegroundColor Red
    Write-Host " Unreachable     : $Unreachable" -ForegroundColor Gray
    Write-Host " Compliance Rate : $([math]::Round($Compliant / [math]::Max($Total,1) * 100, 1))%" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $Results | Select-Object ComputerName, OSCaption, LastUpdateInstall,
        DaysSinceUpdate, PendingUpdates, CriticalPending, ComplianceStatus |
        Sort-Object ComplianceStatus, DaysSinceUpdate -Descending |
        Format-Table -AutoSize
}
