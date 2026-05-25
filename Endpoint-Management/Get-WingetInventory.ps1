<#
.SYNOPSIS
    Retrieves installed software via winget and identifies packages with
    available updates.

.DESCRIPTION
    Uses the Windows Package Manager (winget) to enumerate installed packages
    and check for available upgrades. Useful for identifying software that
    falls outside traditional Windows Update or SCCM patch cycles -- such as
    third-party applications like browsers, runtimes, and developer tools.

    Can target the local machine or remote endpoints via PSRemoting.

.PARAMETER ComputerName
    One or more hostnames to query. Defaults to local machine.

.PARAMETER UpdatesOnly
    Switch. Returns only packages that have an available upgrade.

.PARAMETER ExportPath
    Optional. Full path for CSV export.

.EXAMPLE
    .\Get-WingetInventory.ps1
    Returns all winget-managed packages on the local machine.

.EXAMPLE
    .\Get-WingetInventory.ps1 -UpdatesOnly
    Returns only packages with available upgrades on the local machine.

.EXAMPLE
    .\Get-WingetInventory.ps1 -ComputerName "WKS-CORP-042" -UpdatesOnly -ExportPath "C:\Reports\winget_updates.csv"
    Checks a remote workstation for available upgrades and exports to CSV.

.NOTES
    Author:      Dax Lewis
    Requires:    PowerShell 5.1+, winget (App Installer) installed on targets
                 WinRM enabled for remote queries
    Notes:       winget must be available in system PATH on target machines.
                 On shared/server OS builds, App Installer may not be present.
#>

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [switch]$UpdatesOnly,

    [Parameter()]
    [string]$ExportPath
)

begin {
    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $ParseWinget = {
        param ($UpdatesOnly)

        function Invoke-WingetCommand {
            param ($Args)
            $Output = & winget @Args 2>&1
            return $Output
        }

        # Check winget is available
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Warning "winget not found on $env:COMPUTERNAME"
            return
        }

        $CollectedAt = Get-Date -Format 'yyyy-MM-dd HH:mm'
        $Packages = [System.Collections.Generic.List[PSCustomObject]]::new()

        if ($UpdatesOnly) {
            # Get packages with available upgrades
            $Raw = Invoke-WingetCommand @('upgrade', '--include-unknown')

            $InTable = $false
            foreach ($Line in $Raw) {
                if ($Line -match '^-+') { $InTable = $true; continue }
                if (-not $InTable) { continue }
                if ([string]::IsNullOrWhiteSpace($Line)) { continue }

                # Parse fixed-width winget output
                if ($Line -match '^(.{1,45})\s{2,}(\S+)\s{2,}(\S+)\s{2,}(\S+)\s*(\S*)') {
                    $Packages.Add([PSCustomObject]@{
                        ComputerName     = $env:COMPUTERNAME
                        Name             = $Matches[1].Trim()
                        Id               = $Matches[2].Trim()
                        InstalledVersion = $Matches[3].Trim()
                        AvailableVersion = $Matches[4].Trim()
                        Source           = $Matches[5].Trim()
                        UpdateAvailable  = $true
                        CollectedAt      = $CollectedAt
                    })
                }
            }
        }
        else {
            # Get all installed packages
            $Raw = Invoke-WingetCommand @('list', '--include-unknown')

            # Also check for available upgrades to flag them
            $UpgradeRaw = Invoke-WingetCommand @('upgrade', '--include-unknown')
            $UpgradeIds = @{}

            $InUpgradeTable = $false
            foreach ($Line in $UpgradeRaw) {
                if ($Line -match '^-+') { $InUpgradeTable = $true; continue }
                if (-not $InUpgradeTable) { continue }
                if ($Line -match '^\s*(\S+)\s') {
                    $UpgradeIds[$Matches[1]] = $true
                }
            }

            $InTable = $false
            foreach ($Line in $Raw) {
                if ($Line -match '^-+') { $InTable = $true; continue }
                if (-not $InTable) { continue }
                if ([string]::IsNullOrWhiteSpace($Line)) { continue }

                if ($Line -match '^(.{1,45})\s{2,}(\S+)\s{2,}(\S+)\s*(\S*)') {
                    $Id = $Matches[2].Trim()
                    $Packages.Add([PSCustomObject]@{
                        ComputerName     = $env:COMPUTERNAME
                        Name             = $Matches[1].Trim()
                        Id               = $Id
                        InstalledVersion = $Matches[3].Trim()
                        AvailableVersion = if ($UpgradeIds[$Id]) { 'Update available' } else { 'Current' }
                        Source           = $Matches[4].Trim()
                        UpdateAvailable  = [bool]$UpgradeIds[$Id]
                        CollectedAt      = $CollectedAt
                    })
                }
            }
        }

        $Packages
    }
}

process {
    foreach ($Computer in $ComputerName) {
        Write-Verbose "Querying winget: $Computer"

        try {
            if ($Computer -eq $env:COMPUTERNAME) {
                $Data = & $ParseWinget $UpdatesOnly
            }
            else {
                $Data = Invoke-Command -ComputerName $Computer `
                    -ScriptBlock $ParseWinget `
                    -ArgumentList $UpdatesOnly `
                    -ErrorAction Stop
            }

            if ($Data) { $Results.AddRange(@($Data)) }
            Write-Verbose "[$Computer] Found $(@($Data).Count) packages"
        }
        catch {
            Write-Warning "[$Computer] Failed: $_"
        }
    }
}

end {
    $Output = $Results | Sort-Object ComputerName, Name

    if ($ExportPath) {
        $Output | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported $($Output.Count) records to $ExportPath" -ForegroundColor Green
    }
    else {
        $Output
    }

    $UpdateCount = ($Output | Where-Object UpdateAvailable -eq $true).Count
    if ($UpdateCount -gt 0) {
        Write-Verbose "$UpdateCount package(s) have available updates"
    }
}
