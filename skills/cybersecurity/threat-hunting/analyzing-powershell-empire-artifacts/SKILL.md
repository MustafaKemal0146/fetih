---
name: analyzing-powershell-empire-artifacts
description: tespit etmePowerShell Empire framework artifacts in Windows event logs by identifying Base64 encoded launcher patterns, default user agents, staging URL structures, stager IOCs, and known Empire
  module signatures in Script Block Logging events.
tags:
- base64
- threat-hunting
- stager
- MITRE-ATT&CK
- C2
- forensics
- PowerShell-Empire
- fetih
- cybersecurity
- Script-Block-Logging
- siber-güvenlik
- T1059.001
triggers:
- analyzing
- anomali tespit
- artifacts
- empire
- exploit
- http
- hunting
- incident
- log
- powershell
- tehdit ara
- tehdit avı
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Analyzing Powershell Empire Artifacts


## Genel Bakış

PowerShell Empire is a post-exploitation framework consisting of listeners, stagers, and agents. Its artifacts leave tespit etme (able) traces in Windows event logs, particularly PowerShell Script Block Logging (Event ID 4104) and Module Logging (Event ID 4103). bu skill analyzes event logs for Empire's default launcher string (`powershell -noP -sta -w 1 -enc`), Base64 encoded payloads containing `System.Net.WebClient` and `FromBase64String`, known module invocations (Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation), and staging URL patterns.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing powershell empire artifacts
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Python 3.9+ with Erişim: Windows Event Log or exported EVTX files
- PowerShell Script Block Logging (Event ID 4104) enabled via Group Policy
- Module Logging (Event ID 4103) enabled for comprehensive coverage

## Key Tespit Patterns

1. **Default launcher** — `powershell -noP -sta -w 1 -enc` followed by Base64 blob
2. **Stager indicators** — `System.Net.WebClient`, `DownloadData`, `DownloadString`, `FromBase64String`
3. **Module signatures** — Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation, Invoke-PSInject, Invoke-DCOM
4. **User agent strings** — default Empire user agents in HTTP listener configuration
5. **Staging URLs** — `/login/process.php`, `/admin/get.php` and similar default URI patterns

## Output

JSON report with matched IOCs, decoded Base64 payloads, timeline of suspicious events, MITRE ATT&CK technique mappings, and severity scores.
