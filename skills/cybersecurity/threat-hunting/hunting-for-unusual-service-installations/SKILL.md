---
name: hunting-for-unusual-service-installations
description: tespit etmesuspicious Windows service installations (MITRE ATT&CK T1543.003) by parsing System event logs for Event ID 7045, analyzing service binary paths, and identifying indicators of persistence
  mechanisms.
tags:
- threat-hunting
- Event-7045
- service-installation
- persistence
- T1543.003
- fetih
- cybersecurity
- siber-güvenlik
- Sysmon
- Windows-services
triggers:
- anomali tespit
- hunting
- incident
- installations
- log
- service
- tehdit ara
- tehdit avı
- threat
- threat hunt
- unusual
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Unusual Service Installations


## Genel Bakış

Attackers frequently install malicious Windows services for persistence and privilege escalation (MITRE ATT&CK T1543.003 — Create or Modify System Process: Windows Service). Event ID 7045 in the System event log records every new service installation. bu skill parses .evtx log files to extract service installation events, flags suspicious binary paths (temp directories, PowerShell, cmd.exe, encoded commands), and correlates with known attack patterns.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting for unusual service installations
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Python 3.9+ with `python-evtx`, `lxml`
- Windows System event log (.evtx) files
- Erişim: live System event log (optional, for real-time monitoring)
- Sysmon logs for enhanced process tracking (optional)

## Adımlar

1. Parse System.evtx for Event ID 7045 (new service installed)
2. Extract service name, binary path, service type, and account
3. Flag services with suspicious binary paths (temp dirs, encoded commands)
4. tespit etmePowerShell-based service creation patterns
5. Identify services running as LocalSystem with unusual paths
6. Cross-reference with known legitimate service baselines
7. Generate threat hunting report with MITRE ATT&CK T1543.003 mapping

## Expected Output

- JSON report listing all new service installations with risk scores, suspicious indicators, and remediation recommendations
- Timeline of service installation events with binary path analysis

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 2010bc9e7779fb2e
-->

