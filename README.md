# PowerShell Endpoint Tools

A collection of PowerShell scripts for endpoint management, incident response, and ransomware triage in enterprise Windows environments. Built around actual workflows using SCCM/MECM, Active Directory, Windows Update, and Tenable vulnerability management pipelines.

---

## Repository Structure

```
powershell-endpoint-tools/
|-Endpoint-Management/     # Patch compliance, inventory, and software auditing
|- Incident-Response/      # Forensic triage, temp folder monitoring, payload scanning
```

---

## Endpoint Management

Scripts for routine endpoint hygiene, patch compliance reporting, and software inventory.

| Script | Description |
|---|---|
| `Get-SoftwareInventory.ps1` | Registry-based software inventory across local or remote endpoints |
| `Get-WindowsUpdateStatus.ps1` | Pending and installed update history via Windows Update Agent API |
| `Get-PatchComplianceReport.ps1` | Per-host patch compliance scoring with Pass/Warning/Non-Compliant status |
| `Get-WingetInventory.ps1` | Installed package inventory and available upgrades via winget |

### Quick Examples

```powershell
# Inventory all software on a remote host, exclude Windows Update noise
.\Endpoint-Management\Get-SoftwareInventory.ps1 -ComputerName "SRV-APP-001" -ExcludeUpdates

# Patch compliance across a host list with 14-day threshold
Get-Content .\hostlist.txt | .\Endpoint-Management\Get-PatchComplianceReport.ps1 -MaxDaysSinceUpdate 14 -ExportPath "C:\Reports\compliance.csv"

# Check for available winget upgrades
.\Endpoint-Management\Get-WingetInventory.ps1 -UpdatesOnly
```

---

## Incident Response

Read-only forensic and monitoring scripts for initial triage and live investigation.

| Script | Description |
|---|---|
| `Invoke-ForensicTriage.ps1` | Full endpoint triage -- WMI persistence, registry autoruns, suspicious processes, scheduled tasks, local accounts, and PowerShell history |
| `Watch-TempFolder.ps1` | Real-time %TEMP% folder monitor with hidden/system file alerting |
| `Search-Payloads.ps1` | Scans common malware staging paths for large files and hidden executables |

### Quick Examples

```powershell
# Run full forensic triage, write report to Desktop
.\Incident-Response\Invoke-ForensicTriage.ps1

# Output report to evidence directory
.\Incident-Response\Invoke-ForensicTriage.ps1 -OutputPath "C:\IR\Evidence"

# Monitor temp folder including subdirectories
.\Incident-Response\Watch-TempFolder.ps1 -IncludeSubdirectories

# Scan for payloads with lower size threshold
.\Incident-Response\Search-Payloads.ps1 -SizeLimitMB 10 -ExportPath "C:\IR\findings.csv"
```

## Requirements

| Requirement | Scripts |
|---|---|
| WinRM enabled on targets | All remote `ComputerName` operations |
| Local admin on targets | `Get-SoftwareInventory.ps1`, `Get-PatchComplianceReport.ps1` |
| winget installed | `Get-WingetInventory.ps1` |
| PowerShell 5.1+ | All scripts |

---

## Related Projects
- [Vulnerability Risk Dashboard](https://github.com/dl67337/vulnerability-risk-dashboard) -- Power BI executive reporting built from Tenable scan data
- [Vulnerability Data Analysis](https://github.com/dl67337/vulnerability-data-analysis) -- Python analysis of CVE trends and remediation velocity
