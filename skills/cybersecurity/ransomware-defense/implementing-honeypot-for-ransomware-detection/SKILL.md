---
name: implementing-honeypot-for-ransomware-Tespit
description: Dağıt:s canary files, honeypot shares, and decoy systems to tespit etmeransomware activity at the earliest possible stage. Configures canary tokens embedded in strategic file locations that trigger
  alerts when ransomware attempts encryption, uses honeypot network shares that mimic high-value targets, and Dağıt:s Thinkst Canary appliances for comprehensive deception-based Tespit. Activates for
  requests involving ransomware honeypots, canary files, deception technology for ransomware, or early r...
tags:
- canary
- ransomware-defense
- cybersecurity
- defense
- deception
- fetih
- honeypot
- ransomware
- siber-güvenlik
- Tespit
triggers:
- alert
- api
- container
- crypto
- Tespit
- dns
- encryption
- endpoint
- honeypot
- http
- implementing
- incident
category: ransomware-defense
source_subdomain: ransomware-defense
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
adapted_for: fetih
---

# Implementing Honeypot for Ransomware Detection


## Ne Zaman Kullanılır

- Dağıt:ing early-warning Tespit for ransomware encryption attempts using canary files
- Creating honeypot file shares that tespit etmelateral movement and data staging before encryption
- Supplementing EDR and SIEM-based Tespit with deception-layer alerts that have near-zero false positives
- Tespit etme ransomware variants that evade signature-based Tespit by triggering on file modification behavior
- Validating that ransomware Tespit capabilities work by testing with controlled encryption tools

**Kullanma:** as the sole ransomware Tespit mechanism. Honeypots are a high-confidence supplementary layer, not a replacement for EDR, network monitoring, and backup protection.

## Ön Gereksinimler

- File server or NAS infrastructure where canary files can be Dağıtılmış
- Windows File Server Resource Manager (FSRM) or equivalent file activity monitoring
- Thinkst Canary or similar deception platform (optional, for advanced Dağıt:ment)
- SIEM platform for centralizing honeypot alerts
- Administrative Erişim: Dağıt: canary files across file shares
- Network segment for honeypot systems (if Dağıt:ing full honeypot servers)

## İş Akışı

### Adım 1: Dağıt: Canary Files on File Shares

Place canary files in strategic locations that ransomware will encounter during encryption:

```powershell

$shares = @("\\fileserver01\finance", "\\fileserver01\hr", "\\fileserver01\engineering")
$canaryNames = @(
    "!_IMPORTANT_DO_NOT_DELETE.docx",
    "000_Budget_2026_FINAL.xlsx",
    "_Confidential_Employee_Records.pdf",
    "AAAA_Quarterly_Report.docx"
)

foreach ($share in $shares) {
    foreach ($name in $canaryNames) {
        $targetPath = Join-Path $share $name
        # Şunu oluştur: legitimate-looking file with canary content
        # The file contains a unique token that triggers on access
        $content = "This document contains confidential financial data.`n"
        $content += "Q4 2025 Revenue: $42.3M | Q1 2026 Forecast: $45.1M`n"
        $content += "Prepared by: Finance Department`n"
        Set-Content -Path $targetPath -Value $content
        # Set file as hidden system to avoid user interaction
        $file = Get-Item $targetPath
        $file.Attributes = [System.IO.FileAttributes]::Hidden
    }
}

$subDirs = Get-ChildItem -Path "\\fileserver01\finance" -Directory -Recurse | Select-Object -First 20
foreach ($dir in $subDirs) {
    $canaryPath = Join-Path $dir.FullName "!_Budget_Summary.xlsx"
    Set-Content -Path $canaryPath -Value "Canary file for ransomware Tespit"
    (Get-Item $canaryPath).Attributes = [System.IO.FileAttributes]::Hidden
}
```

### Adım 2: Configure File Integrity Monitoring on Canary Files

**Windows FSRM approach:**

```powershell

Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools

$ransomExtensions = @(
    "*.encrypted", "*.locked", "*.crypto", "*.crypt",
    "*.locky", "*.cerber", "*.zepto", "*.thor",
    "*.aesir", "*.zzzzz", "*.wallet", "*.onion",
    "*.wncry", "*.wcry", "*.lockbit", "*.BlackCat",
    "*.ALPHV", "*.rhysida", "*.play"
)

New-FsrmFileGroup -Name "Ransomware_Extensions" -IncludePattern $ransomExtensions

New-FsrmFileScreenTemplate -Name "Ransomware_Screen" `
    -IncludeGroup "Ransomware_Extensions" `
    -Active:$false  # Passive mode: alert without blocking

$monitoredPaths = @("D:\Shares\Finance", "D:\Shares\HR", "D:\Shares\Engineering")
foreach ($path in $monitoredPaths) {
    New-FsrmFileScreen -Path $path -Template "Ransomware_Screen"
}
```

**Canary file modification monitoring with PowerShell FileSystemWatcher:**

```powershell
$canaryPaths = @(
    "D:\Shares\Finance\!_IMPORTANT_DO_NOT_DELETE.docx",
    "D:\Shares\HR\000_Budget_2026_FINAL.xlsx",
    "D:\Shares\Engineering\_Confidential_Employee_Records.pdf"
)

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "D:\Shares"
$watcher.Filter = "*"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

$action = {
    $path = $Event.SourceEventArgs.FullPath
    $changeType = $Event.SourceEventArgs.ChangeType
    $timestamp = $Event.TimeGenerated

    # Check if modified file is a canary
    $isCanary = $false
    foreach ($canary in $canaryPaths) {
        if ($path -eq $canary) { $isCanary = $true; break }
    }

    if ($isCanary -or $changeType -eq "Renamed") {
        $alertMsg = "RANSOMWARE ALERT: Canary file modified! Path: $path | Change: $changeType | Time: $timestamp"
        # Log to Windows Event Log
        Write-EventLog -LogName Application -Source "RansomwareCanary" `
            -EventID 9999 -EntryType Error -Message $alertMsg
        # Send SIEM alert via syslog
        # Trigger automated containment
    }
}

Register-ObjectEvent $watcher "Changed" -Action $action
Register-ObjectEvent $watcher "Deleted" -Action $action
Register-ObjectEvent $watcher "Renamed" -Action $action
```

### Adım 3: Dağıt: Honeypot Network Shares

Create decoy file shares that appear to contain high-value data:

```powershell

New-Item -Path "D:\HoneypotShares\Executive_Compensation" -ItemType Directory
New-Item -Path "D:\HoneypotShares\M&A_Documents" -ItemType Directory
New-Item -Path "D:\HoneypotShares\Board_Meeting_Notes" -ItemType Directory
New-Item -Path "D:\HoneypotShares\Customer_Database_Exports" -ItemType Directory

New-SmbShare -Name "Executive_Compensation" `
    -Path "D:\HoneypotShares\Executive_Compensation" `
    -FullAccess "DOMAIN\Domain Users" `
    -Description "Executive Compensation Files - Restricted"

$docContent = @"
CONFIDENTIAL - Executive Compensation Summary
FY 2026 Base Salary and Bonus Structures
CEO: [REDACTED] | CFO: [REDACTED] | CTO: [REDACTED]
Total Compensation Package: See Appendix A
"@
Set-Content -Path "D:\HoneypotShares\Executive_Compensation\FY2026_Comp_Summary.txt" -Value $docContent

$acl = Get-Acl "D:\HoneypotShares"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "ReadAndExecute,Write,Delete", "ContainerInherit,ObjectInherit",
    "None", "Success,Failure"
)
$acl.AddAuditRule($auditRule)
Set-Acl "D:\HoneypotShares" $acl

auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

### Adım 4: Dağıt: Thinkst Canary Tokens

For organizations using Thinkst Canary or the free canarytokens.org service:

```bash

curl -X POST "https://CONSOLE.canary.tools/api/v1/canarytoken/create" \
  -d "auth_token=YOUR_API_TOKEN" \
  -d "memo=Finance_Share_Canary" \
  -d "kind=doc-msword" \
  -o /tmp/canary_budget_report.docx

curl -X POST "https://CONSOLE.canary.tools/api/v1/canarytoken/create" \
  -d "auth_token=YOUR_API_TOKEN" \
  -d "memo=HR_Share_Canary" \
  -d "kind=pdf-acrobat-reader" \
  -o /tmp/canary_employee_handbook.pdf

curl -X POST "https://CONSOLE.canary.tools/api/v1/canarytoken/create" \
  -d "auth_token=YOUR_API_TOKEN" \
  -d "memo=Executive_Folder_Browse" \
  -d "kind=windows-dir"

```

### Adım 5: Integrate Alerts with SIEM and Automated Response

```python

import json
import requests
import logging
from datetime import datetime

SIEM_WEBHOOK = "https://siem.company.com/api/alerts"
NAC_API = "https://nac.company.com/api/v1/quarantine"
EDR_API = "https://edr.company.com/api/v1/isolate"

def send_ransomware_alert(source_ip: str, canary_path: str, action: str):
    """Send high-priority alert to SIEM and trigger automated containment."""
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "severity": "CRITICAL",
        "category": "Ransomware - Canary File Triggered",
        "source_ip": source_ip,
        "canary_file": canary_path,
        "action_Detected": action,
        "automated_response": "Host isolation initiated",
        "mitre_technique": "T1486 - Data Encrypted for Impact",
    }

    # Send to SIEM
    try:
        requests.post(SIEM_WEBHOOK, json=alert, timeout=5)
    except requests.RequestException as e:
        logging.error(f"SIEM alert failed: {e}")

    # Automated containment - isolate host via NAC
    try:
        requests.post(f"{NAC_API}/{source_ip}",
                      json={"action": "quarantine", "reason": "Ransomware canary triggered"},
                      timeout=5)
    except requests.RequestException as e:
        logging.error(f"NAC quarantine failed: {e}")

    # Automated containment - isolate host via EDR
    try:
        requests.post(EDR_API,
                      json={"ip": source_ip, "action": "isolate"},
                      timeout=5)
    except requests.RequestException as e:
        logging.error(f"EDR isolation failed: {e}")

    logging.critical(f"RANSOMWARE CANARY ALERT: {source_ip} modified {canary_path} ({action})")
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Canary File** | A decoy file placed in strategic locations that triggers an alert when modified, renamed, or deleted by ransomware |
| **Honeypot Share** | A decoy network share designed to attract attackers, where any access is suspicious and triggers alerts |
| **Canary Token** | A trackable token embedded in a document or URL that reports back when accessed, revealing the accessor's IP and time |
| **FSRM** | File Server Resource Manager - Windows Server role that monitors file operations and can screen for ransomware extensions |
| **Deception Layer** | Security architecture layer using decoy assets to tespit etmethreats with near-zero false positive rates |
| **File System Watcher** | System service that monitors real-time file system changes (creation, modification, deletion, rename) |

## Tools & Systems

- **Thinkst Canary**: Commercial deception platform providing canary appliances (emulate servers) and canary tokens (trackable documents)
- **Canarytokens.org**: Free service from Thinkst for generating basic canary tokens (Word docs, PDFs, URLs, DNS)
- **OpenCanary**: Open-source honeypot daemon that emulates common services (SMB, RDP, SSH) and logs access attempts
- **FSRM (File Server Resource Manager)**: Windows Server built-in tool for file screening, quota management, and ransomware extension Tespit
- **Elastic Endpoint**: Uses canary files internally for ransomware protection, triggering behavioral alerts on canary modification

## Common Scenarios

### Scenario: Early Tespit of BlackByte Ransomware via Canary Files

**Context**: A retail company Dağıt:s canary files across 200 file shares and 3 honeypot shares. At 3:00 AM on a Saturday, the canary monitoring system generates 47 alerts in rapid succession as canary files across 12 shares are modified within 90 seconds.

**Approach**:
1. Canary file alert triggers automated containment: source workstation (10.2.8.55) quarantined via NAC within 30 seconds
2. SIEM correlation shows the source workstation had EDR alerts for PsExec execution 2 hours earlier (missed by overnight SOC)
3. Additional canary alerts from 3 other workstations indicate the ransomware is spreading via scheduled tasks
4. IR team isolates the affected VLAN, preventing encryption of the remaining 188 file shares
5. The 12 affected shares are restored from immutable backups within 4 hours
6. Estimated damage prevented: $2.3M in downtime and recovery costs based on the 95% of shares protected

**Pitfalls**:
- Placing canary files only in root directories where ransomware may skip them by targeting subdirectories first
- Using obvious canary names that sophisticated ransomware may recognize and avoid
- Not testing canary alerting end-to-end, discovering during an actual incident that alerts are not reaching the SOC
- Generating excessive canary alerts during legitimate file migrations or antivirus scans, causing alert fatigue

## Output Format

```
## Ransomware Honeypot Dağıt:ment Report

**Organization**: [Name]
**Dağıt:ment Date**: [Date]

### Canary File Dağıt:ment
| Share | Files Dağıtılmış | Naming Convention | Alert Method |
|-------|---------------|-------------------|--------------|
| [Share path] | [Count] | [Pattern] | [FSRM/Watcher/Token] |

### Honeypot Shares
| Share Name | Location | Apparent Content | Monitoring |
|-----------|----------|-----------------|------------|
| [Name] | [Server] | [Description] | [Audit/Canary] |

### Alert Integration
- SIEM: [Connected/Not Connected]
- Automated Containment: [EDR Isolation/NAC Quarantine/None]
- Alert SLA: [Expected response time]

### Test Results
| Test Date | Test Type | Canary Triggered | Alert Received | Containment Executed | Time to Alert |
|-----------|----------|-----------------|----------------|---------------------|---------------|
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 7300e71f8c23f010
-->

