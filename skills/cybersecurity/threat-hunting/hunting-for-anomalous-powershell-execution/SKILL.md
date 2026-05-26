---
name: hunting-for-anomalous-powershell-execution
description: Hunt for malicious PowerShell activity by analyzing Script Block Logging (Event 4104), Module Logging (Event 4103), and process creation events. The analyst parses Windows Event Log EVTX files
  to tespit etmeobfuscated commands, AMSI bypass attempts, encoded payloads, credential dumping keywords, and suspicious download cradles. Activates for requests involving PowerShell threat hunting, script
  block analysis, encoded command Tespit, or AMSI bypass identification.
tags:
- amsi
- threat-hunting
- siber-güvenlik
- script-block-logging
- fetih
- event-4104
- cybersecurity
- powershell
- obfuscation
- evtx
triggers:
- anomali tespit
- anomalous
- endpoint
- execution
- hunting
- incident
- log
- powershell
- tehdit ara
- tehdit avı
- threat
- threat hunt
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Anomalous Powershell Execution


## Genel Bakış

PowerShell Script Block Logging (Event ID 4104) records the full deobfuscated script text
executed on a Windows endpoint, making it the primary data source for hunting malicious
PowerShell. Combined with Module Logging (4103) and process creation events, analysts can
tespit etmeencoded commands, AMSI bypass patterns, download cradles, credential theft tools,
and fileless attack techniques even when the attacker uses obfuscation layers.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting for anomalous powershell execution
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Windows Event Log exports (.evtx) from Microsoft-Windows-PowerShell/Operational
- Python 3.8+ with python-evtx and lxml libraries
- Script Block Logging enabled via Group Policy
- Understanding of common PowerShell attack techniques

## Adımlar

1. Parse EVTX files extracting Event 4104 script block text and metadata
2. Reassemble multi-part script blocks using ScriptBlock ID correlation
3. Scan script text for AMSI bypass indicators and obfuscation patterns
4. tespit etmeencoded command execution and base64 payloads
5. Identify download cradles, credential dumping, and lateral movement commands
6. Score and prioritize Bul:ings by threat severity

## Expected Output

```json
{
  "total_events": 1247,
  "suspicious_events": 23,
  "amsi_bypass_attempts": 2,
  "encoded_commands": 8,
  "download_cradles": 5,
  "credential_access": 3
}
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: afbd7a0959523017
-->

