---
name: hunting-for-startup-folder-persistence
description: tespit etmeT1547.001 startup folder persistence by monitoring Windows startup directories for suspicious file creation, analyzing autoruns entries, and using Python watchdog for real-time filesystem
  monitoring.
tags:
- threat-hunting
- T1547.001
- autoruns
- filesystem-monitoring
- siber-güvenlik
- persistence
- watchdog
- fetih
- cybersecurity
- startup-folder
triggers:
- alert
- anomali tespit
- folder
- hunting
- incident
- log
- persistence
- startup
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
---

# Hunting for Startup Folder Persistence


## Genel Bakış

Attackers use Windows startup folders for persistence (MITRE ATT&CK T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder). Files placed in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` or `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` execute automatically at user logon. bu skill scans startup directories for suspicious files, monitors for real-time changes using Python watchdog, and analyzes file metadata to tespit etmepersistence implants.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting for startup folder persistence
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Python 3.9+ with `watchdog`, `pefile` (optional for PE analysis)
- Erişim: Windows startup folders (user and all-users)
- Windows Event Logs for Event ID 4663 correlation (optional)

## Adımlar

1. Enumerate all files in user and system startup directories
2. Analyze file types, creation timestamps, and digital signatures
3. Flag suspicious file extensions (.bat, .vbs, .ps1, .lnk, .exe)
4. Check for recently created files (< 7 days) as potential implants
5. Monitor startup folders in real-time using watchdog FileSystemEventHandler
6. Correlate with known legitimate startup entries
7. Generate threat hunting report with T1547.001 MITRE mapping

## Expected Output

- JSON report listing all startup folder contents with risk scores, file metadata, and suspicious indicators
- Real-time monitoring alerts for new file creation in startup directories
