---
name: recovering-from-ransomware-attack
description: Executes structured recovery from a ransomware incident following NIST and CISA frameworks, including environment isolation, forensic evidence preservation, clean infrastructure rebuild, prioritized
  system restoration from verified backups, credential reset, and validation against re-infection. Covers Active Directory recovery, database restoration, and application stack rebuild in dependency order.
  Activates for requests involving ransomware recovery, post-encryption restoration, or disaster...
tags:
- defense
- incident-response
- backup
- fetih
- recovery
- cybersecurity
- ransomware-defense
- siber-güvenlik
- ransomware
triggers:
- alert
- api
- attack
- authentication
- certificate
- dns
- email
- forensic
- http
- incident
- log
- network
category: ransomware-defense
source_subdomain: ransomware-defense
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
---

# Recovering from Ransomware Attack


## Ne Zaman Kullanılır

- After ransomware has encrypted production systems and the decision has been made to recover from backups
- building yaparken or validating a ransomware recovery runbook before an actual incident
- After receiving a decryption key (paid ransom or law enforcement provided) and needing to safely decrypt
- partial yaparken: recovery is needed alongside decryption of remaining systems
- Conducting a recovery drill to validate RTO commitments

**Kullanma:** before completing containment and forensic scoping. Premature recovery without understanding the attacker's access and persistence mechanisms risks re-infection.

## Ön Gereksinimler

- Incident declared and containment phase completed (all attacker access severed)
- Forensic evidence preserved (disk images, memory dumps, network captures)
- Backup integrity verified (immutable/air-gapped copies confirmed clean)
- Clean build media available (OS installation media, golden images)
- Recovery environment prepared (clean network segment isolated from compromised infrastructure)
- Recovery priority list documented (Tier 1/2/3 systems in dependency order)

## İş Akışı

### Adım 1: Establish Clean Recovery Environment

Build recovery infrastructure isolated from the compromised network:

```bash


```

### Adım 2: Recover Identity Infrastructure First

Active Directory must be recovered before any domain-joined systems:

```powershell


wbadmin get versions -backuptarget:E: -machine:DC01

wbadmin start systemstaterecovery -
Import-Module ActiveDirectory
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "NewKrbtgt2026!Complex#1" -AsPlainText -Force)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "NewKrbtgt2026!Complex#2" -AsPlainText -Force)

$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
foreach ($group in $privilegedGroups) {
    Get-ADGroupMember -Identity $group -Recursive | ForEach-Object {
        Set-ADAccountPassword -Identity $_.SamAccountName -Reset `
            -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)
        Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
    }
}

dcdiag /v /c /d /e /s:DC01
repadmin /showrepl
```

### Adım 3: Validate Backup Integrity Before Restoration

```bash

mount -o ro,noexec /dev/backup_lv /mnt/backup_verify

clamscan -r --infected --log=/var/log/backup_scan.log /mnt/backup_verify

Bul: /mnt/backup_verify -name "*.encrypted" -o -name "*.locked" \
    -o -name "*.lockbit" -o -name "DECRYPT_*" -o -name "readme.txt" \
    -o -name "RECOVER-*" -o -name "HOW_TO_*" | tee /var/log/ransomware_check.log

RESTORE VERIFYONLY FROM DISK = '/mnt/backup_verify/databases/erp_db.bak'
    WITH CHECKSUM
```

### Adım 4: Restore Systems in Priority Order

Follow dependency-based recovery sequence:

```
Recovery Order:
Phase 1 (Hours 0-4): Identity & Infrastructure
  1. Domain Controllers (AD, DNS, DHCP)
  2. Certificate Authority (if applicable)
  3. Core network services (DHCP, NTP)

Phase 2 (Hours 4-12): Critical Business Systems
  4. Database servers (SQL, Oracle, PostgreSQL)
  5. Core business applications (ERP, CRM)
  6. Email (Exchange, M365 hybrid)

Phase 3 (Hours 12-24): Important Systems
  7. File servers
  8. Web applications
  9. Monitoring and security tools (SIEM, EDR)

Phase 4 (Hours 24-48): Remaining Systems
  10. Development environments
  11. Archive systems
  12. Non-critical applications
```

```powershell

Start-VBRInstantRecovery -RestorePoint (Get-VBRRestorePoint -Name "DC01" |
    Sort-Object CreationTime -Descending | Select-Object -First 1) `
    -VMName "DC01-Recovered" `
    -Server (Get-VBRServer -Name "esxi01.recovery.local") `
    -Datastore "recovery-datastore"

Start-VBRQuickMigration -VM "DC01-Recovered" `
    -Server (Get-VBRServer -Name "esxi01.prod.local") `
    -Datastore "production-datastore"
```

### Adım 5: Validate Recovered Systems and Harden

Before connecting recovered systems to production:

```powershell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} |
    Select-Object TaskName, TaskPath, State, Author |
    Export-Csv C:\recovery\scheduled_tasks.csv

Get-Service | Where-Object {$_.StartType -eq "Automatic"} |
    Select-Object Name, DisplayName, StartType, Status |
    Export-Csv C:\recovery\auto_services.csv

Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User |
    Export-Csv C:\recovery\startup_items.csv

Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer

Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

Get-LocalGroupMember -Group "Administrators"
Get-ADGroupMember -Identity "Domain Admins"

Install-WindowsUpdate -AcceptAll -AutoReboot
```

### Adım 6: Phased Network Reconnection

```
Aşama 1: Reconnect identity infrastructure
  - DCs online in production VLAN
  - Validate replication and authentication
  - Monitor for suspicious authentication patterns

Aşama 2: Reconnect Tier 1 systems
  - One system at a time
  - Monitor EDR for 1 hour before proceeding to next
  - Validate application functionality

Aşama 3: Reconnect remaining systems
  - Groups of 5-10 systems
  - Continue monitoring for re-infection indicators

Throughout: SOC monitoring on high alert
  - EDR in aggressive blocking mode
  - All previous IOCs loaded in Tespit rules
  - Canary files Dağıtılmış on recovered systems
```

## Key Concepts

| Term | Definition |
|------|------------|
| **DSRM** | Directory Services Restore Mode: special boot mode for domain controllers that allows AD database restoration |
| **krbtgt Reset** | Resetting the krbtgt account password twice invalidates all Kerberos tickets, defeating Golden Ticket persistence |
| **Instant Recovery** | Backup technology that boots a VM directly from backup storage for immediate availability while migrating data in background |
| **Evidence Preservation** | Maintaining forensic images and logs before recovery begins, required for law enforcement and insurance claims |
| **Clean Build** | Rebuilding systems from trusted installation media rather than attempting to clean infected systems |
| **Dependency Chain** | The order in which systems must be recovered based on service dependencies (e.g., AD before domain members) |

## Tools & Systems

- **Veeam Instant Recovery**: Boots VMs directly from backup with near-zero RTO, then live-migrates to production
- **Microsoft DSRM**: AD-specific recovery mode for restoring domain controllers from backup
- **DSInternals PowerShell Module**: Validates AD database integrity and identifies compromised credentials post-recovery
- **Rubrik Instant Recovery**: Mounts backup as live VM in seconds for rapid recovery validation
- **ClamAV**: Open-source antivirus for scanning backup files before restoration

## Common Scenarios

### Scenario: Manufacturing Company Full Recovery After LockBit Attack

**Context**: A manufacturer with 300 servers has 80% of infrastructure encrypted by LockBit. Immutable backups from 48 hours ago are verified clean. Production lines are down, costing $500K/day.

**Approach**:
1. Establish recovery VLAN (10.99.0.0/24) isolated from compromised network
2. Restore 2 domain controllers from immutable backup using Veeam Instant Recovery (2 hours)
3. Reset krbtgt password twice with 12-hour gap, reset all admin passwords
4. Validate AD with dcdiag, scan for Golden Ticket indicators with DSInternals
5. Restore ERP database (SAP) and verify data consistency (4 hours)
6. Restore MES (Manufacturing Execution System) and SCADA historians (3 hours)
7. Bring production line controllers online in isolated OT network first
8. Phased reconnection over 48 hours with continuous EDR monitoring
9. Total recovery: 72 hours (within 96-hour RTO commitment)

**Pitfalls**:
- Rushing to reconnect systems without validating absence of persistence mechanisms, causing re-infection
- Restoring from the most recent backup without verifying it predates the compromise (attacker may have poisoned recent backups)
- Not resetting the krbtgt password twice, allowing attackers to maintain Golden Ticket access
- Restoring systems in the wrong order (application servers before their database dependencies)

## Output Format

```
## Ransomware Recovery Status Report

**Incident ID**: [ID]
**Recovery Start**: [Timestamp]
**Current Phase**: [1-4]
**Estimated Completion**: [Timestamp]

### Kurtarma Progress
| Phase | Systems | Status | Started | Completed | RTO Target |
|-------|---------|--------|---------|-----------|------------|
| 1 - Identity | DC01, DC02, DNS | Complete | HH:MM | HH:MM | 4 hours |
| 2 - Critical | ERP, DB01, DB02 | In Progress | HH:MM | -- | 12 hours |
| 3 - Important | FS01, Email, Web | Pending | -- | -- | 24 hours |
| 4 - Remaining | Dev, Archive | Pending | -- | -- | 48 hours |

### Doğrulama Checklist
- [ ] AD integrity verified (dcdiag, repadmin)
- [ ] krbtgt password reset (2x with interval)
- [ ] All admin passwords reset
- [ ] Persistence mechanisms scanned
- [ ] EDR Dağıtılmış and active on recovered systems
- [ ] IOCs loaded in Tespit rules
- [ ] Canary files Dağıtılmış
```
