<#
.SYNOPSIS
    Collects installed software inventory from one or more endpoints.

.DESCRIPTION
    Queries the Windows registry (HKLM and HKCU) for installed applications
    on local or remote machines. Outputs a structured object suitable for
    pipeline use, CSV export, or SCCM/Tenable correlation workflows.

.PARAMETER ComputerName
    One or more hostnames or IP addresses to query. Defaults to local machine.

.PARAMETER ExportPath
    Optional. Full path for CSV export. Example: C:\Reports\software_inventory.csv

.PARAMETER ExcludeUpdates
    Switch. When specified, filters out Windows Update entries and hotfixes
    to reduce noise in the output.

.EXAMPLE
    .\Get-SoftwareInventory.ps1
    Runs against the local machine and outputs to console.

.EXAMPLE
    .\Get-SoftwareInventory.ps1 -ComputerName "SRV-APP-001","SRV-DB-002" -ExportPath "C:\Reports\inventory.csv"
    Queries two remote hosts and exports results to CSV.

.EXAMPLE
    Get-Content .\hostlist.txt | .\Get-SoftwareInventory.ps1 -ExcludeUpdates
    Pipes a list of hostnames and excludes update/hotfix entries.

.NOTES
    Author:      Dax Lewis
    Requires:    PowerShell 5.1+, Remote Registry service on target machines
    Permissions: Local admin on target machines for remote queries
#>

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [switch]$ExcludeUpdates
)

begin {
    $RegistryPaths = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Get-RegistrySoftware {
        param ($Computer, $Hive, $Path)

        try {
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive, $Computer)
            $Key = $Reg.OpenSubKey($Path)
            if (-not $Key) { return }

            foreach ($SubKeyName in $Key.GetSubKeyNames()) {
                $SubKey = $Key.OpenSubKey($SubKeyName)
                $Name   = $SubKey.GetValue('DisplayName')
                if (-not $Name) { continue }

                [PSCustomObject]@{
                    ComputerName    = $Computer
                    DisplayName     = $Name
                    Version         = $SubKey.GetValue('DisplayVersion')
                    Publisher       = $SubKey.GetValue('Publisher')
                    InstallDate     = $SubKey.GetValue('InstallDate')
                    InstallLocation = $SubKey.GetValue('InstallLocation')
                    UninstallString = $SubKey.GetValue('UninstallString')
                    Architecture    = if ($Path -match 'WOW6432') { 'x86' } else { 'x64' }
                    CollectedAt     = (Get-Date -Format 'yyyy-MM-dd HH:mm')
                }
            }
        }
        catch {
            Write-Warning "[$Computer] Registry access failed: $_"
        }
    }
}

process {
    foreach ($Computer in $ComputerName) {
        Write-Verbose "Querying: $Computer"

        foreach ($Path in $RegistryPaths) {
            $Software = Get-RegistrySoftware -Computer $Computer `
                -Hive ([Microsoft.Win32.RegistryHive]::LocalMachine) -Path $Path
            if ($Software) { $Results.AddRange(@($Software)) }
        }
    }
}

end {
    $Output = $Results | Sort-Object ComputerName, DisplayName

    if ($ExcludeUpdates) {
        $Output = $Output | Where-Object {
            $_.DisplayName -notmatch 'Update|Hotfix|KB\d{6,}'
        }
    }

    if ($ExportPath) {
        $Output | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported $($Output.Count) records to $ExportPath" -ForegroundColor Green
    }
    else {
        $Output
    }

    Write-Verbose "Total records returned: $($Output.Count)"
}
