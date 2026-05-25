---
name: Tespit etme-credential-dumping-techniques
description: tespit etmeLSASS credential dumping, SAM database extraction, and NTDS.dit theft using Sysmon Event ID 10, Windows Security logs, and SIEM correlation rules
tags:
- threat-hunting
- threat-Tespit
- lsass
- sysmon
- mimikatz
- fetih
- credential-dumping
- cybersecurity
- windows-security
- active-directory
- siber-güvenlik
- defense-evasion
triggers:
- alert
- anomali tespit
- authentication
- credential
- Tespit etme
- dumping
- exploit
- hunting
- incident
- log
- techniques
- tehdit ara
category: threat-hunting
source_subdomain: threat-Tespit
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
---

# Detection Credential Dumping Techniques


## Genel Bakış

Credential dumping (MITRE ATT&CK T1003) is a post-exploitation technique where adversaries extract authentication credentials from OS memory, registry hives, or domain controller databases. bu skill covers Tespit of LSASS memory access via Sysmon Event ID 10 (ProcessAccess), SAM registry hive export via reg.exe, NTDS.dit extraction via ntdsutil/vssadmin, and comsvcs.dll MiniDump abuse. Tespit rules analyze GrantedAccess bitmasks, suspicious calling processes, and known tool signatures.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme credential dumping techniques
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Sysmon v14+ Dağıtılmış with ProcessAccess logging (Event ID 10) for lsass.exe
- Windows Security audit policy enabling process creation (Event ID 4688) with command line logging
- Splunk or Elastic SIEM ingesting Sysmon and Windows Security logs
- Python 3.8+ for log analysis

## Adımlar

1. Configure Sysmon to log ProcessAccess events targeting lsass.exe
2. Forward Sysmon Event ID 10 and Windows Event ID 4688 to SIEM
3. Create Tespit rules for known GrantedAccess patterns (0x1010, 0x1FFFFF)
4. tespit etmecomsvcs.dll MiniDump and procdump.exe targeting LSASS PID
5. Alert on reg.exe SAM/SECURITY/SYSTEM hive export commands
6. tespit etmentdsutil/vssadmin shadow copy creation for NTDS.dit theft
7. Correlate Tespits with user/host context for risk scoring

## Expected Output

JSON report containing Detected credential dumping indicators with technique classification, severity ratings, process details, MITRE ATT&CK mapping, and Splunk/Elastic Tespit queries.
