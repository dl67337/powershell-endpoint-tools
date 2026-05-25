<#
.SYNOPSIS
    Performs a rapid forensic triage of a Windows endpoint.

.DESCRIPTION
    Read-only forensic collection script covering the most common attacker
    persistence and lateral movement indicators. Captures:

        1. WMI Event Subscriptions (fileless malware persistence)
        2. Active SMB Sessions and suspicious TCP connections
        3. Registry autorun keys and IFEO debugger hooks
        4. Suspicious process parent-child relationships
        5. Scheduled task analysis
        6. Local user and administrator group membership
        7. PowerShell console history

    Does NOT make any changes to the system. All output is written to a
    timestamped report file on the Desktop and mirrored to the console.

.PARAMETER OutputPath
    Directory to write the report file. Defaults to the current user's Desktop.

.PARAMETER NoConsole
    Switch. Suppresses console output -- writes to report file only.
    Useful for silent collection via remote execution.

.EXAMPLE
    .\Invoke-ForensicTriage.ps1
    Runs triage on the local machine, outputs to Desktop.

.EXAMPLE
    .\Invoke-ForensicTriage.ps1 -OutputPath "C:\IR\Evidence"
    Writes report to a specified evidence directory.

.EXAMPLE
    Invoke-Command -ComputerName "SRV-APP-001" -FilePath .\Invoke-ForensicTriage.ps1
    Runs triage remotely via PSRemoting.

.NOTES
    Author:      Dax Lewis
    Requires:    PowerShell 5.1+, Run as Administrator
    Read-only:   This script makes no changes to the system
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter()]
    [string]$OutputPath = [Environment]::GetFolderPath('Desktop'),

    [Parameter()]
    [switch]$NoConsole
)

$ErrorActionPreference = "SilentlyContinue"
$Timestamp  = Get-Date -Format "yyyyMMdd-HHmmss"
$Hostname   = $env:COMPUTERNAME
$ReportFile = Join-Path $OutputPath "Forensic_Report_${Hostname}_${Timestamp}.txt"

function Write-Log {
    param (
        [string]$Message,
        [string]$Color = 'Green'
    )
    $Line = "[$(Get-Date -Format 'HH:mm:ss')] $Message"
    Add-Content -Path $ReportFile -Value $Line
    if (-not $NoConsole) {
        Write-Host $Line -ForegroundColor $Color
    }
}

function Write-Section {
    param ([string]$Title)
    $Sep = "=" * 60
    Add-Content -Path $ReportFile -Value "`n$Sep`n SECTION: $Title`n$Sep"
    if (-not $NoConsole) {
        Write-Host "`n[$Title]" -ForegroundColor Cyan
    }
}

# --- HEADER ---
Write-Log "FORENSIC TRIAGE STARTED ON: $Hostname"
Write-Log "User Context : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "OS Version   : $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Log "Report File  : $ReportFile"

# --- 1. WMI PERSISTENCE ---
Write-Section "WMI EVENT SUBSCRIPTIONS (Fileless Persistence)"
try {
    $Consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer

    if ($Consumers) {
        foreach ($C in $Consumers) {
            Write-Log " [!] WMI CONSUMER FOUND: $($C.Name)" 'Red'
            Write-Log "     Class   : $($C.__CLASS)"
            if ($C.CommandLineTemplate) {
                Write-Log "     Command : $($C.CommandLineTemplate)" 'Yellow'
            }
            if ($C.ScriptText) {
                $Snippet = $C.ScriptText.Substring(0, [math]::Min(200, $C.ScriptText.Length))
                Write-Log "     Script  : $Snippet" 'Yellow'
            }
        }
    }
    else {
        Write-Log "No WMI Event Consumers found. (Expected on clean systems)"
    }
}
catch {
    Write-Log "WMI query error: $_" 'Red'
}

# --- 2. SMB & NETWORK ---
Write-Section "ACTIVE NETWORK SESSIONS (Lateral Movement Indicators)"
try {
    $SMBSessions = Get-SmbSession
    if ($SMBSessions) {
        foreach ($S in $SMBSessions) {
            Write-Log " [!] INBOUND SMB SESSION: $($S.ClientComputerName) / $($S.ClientUserName)" 'Yellow'
        }
    }
    else {
        Write-Log "No active inbound SMB sessions."
    }

    $SuspiciousPorts = '445|135|5985|5986|4444|1337'
    $Connections = Get-NetTCPConnection | Where-Object {
        $_.State -eq 'Established' -and $_.RemotePort -match $SuspiciousPorts
    }
    foreach ($Con in $Connections) {
        $Proc = Get-Process -Id $Con.OwningProcess -ErrorAction SilentlyContinue
        Write-Log " [!] SUSPICIOUS CONNECTION: $($Con.LocalAddress):$($Con.LocalPort) -> $($Con.RemoteAddress):$($Con.RemotePort)" 'Red'
        Write-Log "     Process : $($Proc.Name) (PID: $($Con.OwningProcess))"
    }
}
catch {
    Write-Log "Network query error: $_" 'Red'
}

# --- 3. REGISTRY PERSISTENCE ---
Write-Section "REGISTRY PERSISTENCE (Autoruns & IFEO Hooks)"
$RegKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($Key in $RegKeys) {
    $Props = Get-ItemProperty $Key -ErrorAction SilentlyContinue
    if (-not $Props) { continue }

    $Props.PSObject.Properties | Where-Object {
        $_.Name -notmatch '^PS' -and
        $_.Value -match '\.js|powershell|cmd\.exe|wscript|cscript|AppData|Temp'
    } | ForEach-Object {
        Write-Log " [!] SUSPICIOUS RUN KEY: [$Key] $($_.Name)" 'Red'
        Write-Log "     Value: $($_.Value)" 'Yellow'
    }
}

# IFEO Debugger hooks
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*" |
    Where-Object { $_.Debugger } | ForEach-Object {
        Write-Log " [!] IFEO DEBUGGER HOOK: $($_.PSChildName) -> $($_.Debugger)" 'Red'
    }

# Services with suspicious image paths
Write-Log "Scanning services for PowerShell/CMD in ImagePath..."
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" |
    Where-Object { $_.ImagePath -match 'powershell|cmd\.exe|wscript|cscript' } | ForEach-Object {
        Write-Log " [!] SUSPICIOUS SERVICE: $($_.PSChildName)" 'Red'
        Write-Log "     Path: $($_.ImagePath)" 'Yellow'
    }

# --- 4. PROCESS ANOMALIES ---
Write-Section "PROCESS PARENT-CHILD ANOMALIES"
$Procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, CommandLine

foreach ($P in $Procs) {
    $Parent = $Procs | Where-Object { $_.ProcessId -eq $P.ParentProcessId }

    $Indicators = @(
        @{ Condition = ($Parent.Name -match 'firefox|chrome|msedge' -and $P.Name -match 'powershell|cmd|wscript'); Label = 'BROWSER SPAWNING SHELL' },
        @{ Condition = ($Parent.Name -match 'WmiPrvSE' -and $P.Name -match 'powershell|cmd'); Label = 'WMI LATERAL MOVEMENT' },
        @{ Condition = ($Parent.Name -eq 'svchost.exe' -and $P.Name -match 'powershell|cmd'); Label = 'SVCHOST SPAWNING SHELL' }
    )

    foreach ($I in $Indicators) {
        if ($I.Condition) {
            Write-Log " [!] $($I.Label): $($Parent.Name) ($($Parent.ProcessId)) -> $($P.Name) ($($P.ProcessId))" 'Red'
            if ($P.CommandLine) { Write-Log "     Command: $($P.CommandLine)" 'Yellow' }
        }
    }
}

# --- 5. SCHEDULED TASKS ---
Write-Section "SUSPICIOUS SCHEDULED TASKS"
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
    $Action = $_.Actions
    if ($Action.Execute -match 'powershell|wscript|cscript|cmd' -or
        $Action.Arguments -match 'EncodedCommand|Hidden|AppData|Temp') {
        Write-Log " [!] TASK: $($_.TaskName)" 'Yellow'
        Write-Log "     Execute  : $($Action.Execute)"
        Write-Log "     Arguments: $($Action.Arguments)"
    }
}

# --- 6. LOCAL ACCOUNTS ---
Write-Section "LOCAL USERS & ADMINISTRATOR GROUP"
Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object {
    Write-Log "ENABLED USER: $($_.Name) (Last Logon: $($_.LastLogon))"
}
Write-Log "--- Administrator Group Members ---"
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
    Write-Log "  ADMIN: $($_.Name) [$($_.ObjectClass)]" 'Yellow'
}

# --- 7. POWERSHELL HISTORY ---
Write-Section "POWERSHELL CONSOLE HISTORY (Last 10 Commands)"
$HistPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $HistPath) {
    Get-Content $HistPath -Tail 10 | ForEach-Object { Write-Log "  >> $_" }
}
else {
    Write-Log "No PowerShell history file found."
}

# --- FOOTER ---
Write-Log "--- TRIAGE COMPLETE ---"
Write-Log "Report saved to: $ReportFile"
