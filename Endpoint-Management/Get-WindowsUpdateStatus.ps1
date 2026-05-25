<#
.SYNOPSIS
    Reports Windows Update status and pending updates for one or more endpoints.

.DESCRIPTION
    Queries the Windows Update Agent API to return currently installed updates,
    pending updates awaiting installation, and last scan/install timestamps.
    Useful for patch gap identification and compliance spot-checking outside
    of a full SCCM/WSUS report cycle.

.PARAMETER ComputerName
    One or more hostnames to query. Defaults to local machine.

.PARAMETER PendingOnly
    Switch. Returns only updates pending installation, skipping installed history.

.PARAMETER ExportPath
    Optional. Full path for CSV export.

.PARAMETER DaysBack
    How many days of update history to retrieve. Default is 30.

.EXAMPLE
    .\Get-WindowsUpdateStatus.ps1
    Returns update status for the local machine.

.EXAMPLE
    .\Get-WindowsUpdateStatus.ps1 -ComputerName "WKS-CORP-001" -PendingOnly
    Returns only pending updates for a single remote workstation.

.EXAMPLE
    .\Get-WindowsUpdateStatus.ps1 -ComputerName "SRV-APP-001","SRV-DB-002" -ExportPath "C:\Reports\update_status.csv" -DaysBack 60
    Queries two servers for 60 days of history and exports to CSV.

.NOTES
    Author:      Dax Lewis
    Requires:    PowerShell 5.1+, WinRM enabled on remote targets
    Permissions: Local admin on target machines
#>

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [switch]$PendingOnly,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30
)

begin {
    $Results   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $CutoffDate = (Get-Date).AddDays(-$DaysBack)
}

process {
    foreach ($Computer in $ComputerName) {
        Write-Verbose "Querying update status: $Computer"

        try {
            $ScriptBlock = {
                param ($PendingOnly, $CutoffDate)

                $Output = [System.Collections.Generic.List[PSCustomObject]]::new()

                # Pending updates
                $UpdateSession  = New-Object -ComObject Microsoft.Update.Session
                $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

                try {
                    $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and IsHidden=0")

                    foreach ($Update in $SearchResult.Updates) {
                        $Output.Add([PSCustomObject]@{
                            ComputerName  = $env:COMPUTERNAME
                            Status        = 'Pending'
                            Title         = $Update.Title
                            KB            = ($Update.KBArticleIDs | ForEach-Object { "KB$_" }) -join ', '
                            Severity      = $Update.MsrcSeverity
                            Categories    = ($Update.Categories | Select-Object -ExpandProperty Name) -join ', '
                            SizeMB        = [math]::Round($Update.MaxDownloadSize / 1MB, 1)
                            InstalledDate = $null
                            CollectedAt   = (Get-Date -Format 'yyyy-MM-dd HH:mm')
                        })
                    }
                }
                catch {
                    Write-Warning "Pending update search failed: $_"
                }

                # Installed history
                if (-not $PendingOnly) {
                    $HistoryCount  = $UpdateSearcher.GetTotalHistoryCount()
                    $UpdateHistory = $UpdateSearcher.QueryHistory(0, $HistoryCount)

                    foreach ($Entry in $UpdateHistory) {
                        if ($Entry.Date -lt $CutoffDate) { continue }
                        if ($Entry.ResultCode -ne 2) { continue } # 2 = Succeeded

                        $Output.Add([PSCustomObject]@{
                            ComputerName  = $env:COMPUTERNAME
                            Status        = 'Installed'
                            Title         = $Entry.Title
                            KB            = [regex]::Match($Entry.Title, 'KB\d+').Value
                            Severity      = $null
                            Categories    = $null
                            SizeMB        = $null
                            InstalledDate = $Entry.Date.ToString('yyyy-MM-dd')
                            CollectedAt   = (Get-Date -Format 'yyyy-MM-dd HH:mm')
                        })
                    }
                }

                $Output
            }

            if ($Computer -eq $env:COMPUTERNAME) {
                $Data = & $ScriptBlock $PendingOnly $CutoffDate
            }
            else {
                $Data = Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock `
                    -ArgumentList $PendingOnly, $CutoffDate -ErrorAction Stop
            }

            if ($Data) { $Results.AddRange(@($Data)) }

            $PendingCount   = ($Data | Where-Object Status -eq 'Pending').Count
            $InstalledCount = ($Data | Where-Object Status -eq 'Installed').Count
            Write-Verbose "[$Computer] Pending: $PendingCount | Installed (${DaysBack}d): $InstalledCount"
        }
        catch {
            Write-Warning "[$Computer] Failed: $_"
            $Results.Add([PSCustomObject]@{
                ComputerName  = $Computer
                Status        = 'ERROR'
                Title         = $_.Exception.Message
                KB            = $null
                Severity      = $null
                Categories    = $null
                SizeMB        = $null
                InstalledDate = $null
                CollectedAt   = (Get-Date -Format 'yyyy-MM-dd HH:mm')
            })
        }
    }
}

end {
    if ($ExportPath) {
        $Results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported $($Results.Count) records to $ExportPath" -ForegroundColor Green
    }
    else {
        $Results
    }
}
