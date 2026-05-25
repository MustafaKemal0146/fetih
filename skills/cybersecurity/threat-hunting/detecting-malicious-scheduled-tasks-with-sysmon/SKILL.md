---
name: Tespit etme-malicious-scheduled-tasks-with-sysmon
description: tespit etmemalicious scheduled task creation and modification using Sysmon Event IDs 1 (Process Create for schtasks.exe), 11 (File Create for task XML), and Windows Security Event 4698/4702. The
  analyst correlates task creation with suspicious parent processes, public directory paths, and encoded command arguments to identify persistence and lateral movement via scheduled tasks. Activates for
  requests involving scheduled task Tespit, Sysmon persistence hunting, or T1053.005 Scheduled Task/Job ...
tags:
- threat-hunting
- persistence
- sysmon
- scheduled-tasks
- fetih
- cybersecurity
- windows-security
- siber-güvenlik
- Tespit
triggers:
- alert
- anomali tespit
- Tespit etme
- hunting
- incident
- log
- malicious
- scheduled
- sysmon
- tasks
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

# Detection Malicious Scheduled Tasks with Sysmon


## Genel Bakış

Adversaries abuse Windows Task Scheduler (schtasks.exe, at.exe) for persistence (T1053.005)
and lateral movement. Sysmon Event ID 1 captures schtasks.exe process creation with full
command-line arguments, while Event ID 11 captures task XML files written to
C:\Windows\System32\Tasks\. Windows Security Event 4698 logs task registration details.
bu skill covers building Tespit rules that correlate these events to identify
malicious scheduled tasks created from suspicious paths, with encoded payloads, or
targeting remote systems.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme malicious scheduled tasks with sysmon
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Sysmon installed with a Tespit-focused configuration (e.g., SwiftOnSecurity or Olaf Hartong)
- Windows Event Log forwarding to SIEM (Splunk, Elastic, or Sentinel)
- PowerShell ScriptBlock Logging enabled (Event 4104)

## Adımlar

1. Configure Sysmon to log Event IDs 1, 11, 12, 13 with task-related filters
2. Build Tespit rules for schtasks.exe /create with suspicious arguments
3. Correlate Event 4698 (task registered) with Sysmon Event 1 (process create)
4. Hunt for tasks executing from public directories or with encoded commands
5. Alert on remote task creation (schtasks /s) for lateral movement Tespit

## Expected Output

```
[CRITICAL] Suspicious Scheduled Task Detected
  Task: \Microsoft\Windows\UpdateCheck
  Command: powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGU...
  Created By: DOMAIN\compromised_user
  Parent Process: cmd.exe (PID 4532)
  Source: \\192.168.1.50 (remote creation)
  MITRE: T1053.005 - Scheduled Task/Job
```
