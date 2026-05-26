---
name: hunting-for-suspicious-scheduled-tasks
description: Hunt for adversary persistence and execution via Windows scheduled tasks by analyzing task creation events, suspicious task properties, and unusual execution patterns that indicate T1053.005
  abuse.
tags:
- threat-hunting
- persistence
- scheduled-tasks
- windows
- fetih
- cybersecurity
- endpoint-Tespit
- siber-güvenlik
- mitre-t1053-005
triggers:
- anomali tespit
- encryption
- endpoint
- http
- hunting
- incident
- log
- malware
- ransomware
- scheduled
- suspicious
- tasks
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Suspicious Scheduled Tasks


## Ne Zaman Kullanılır

- proactively yaparken: hunting for persistence mechanisms in Windows environments
- After Tespit etme schtasks.exe or at.exe usage in process creation logs
- investigating yaparken malware that survives reboots and user logoffs
- incident response sırasında to enumerate all persistence on compromised systems
- Windows yaparken: Security Event ID 4698 (Scheduled Task Created) fires for unusual tasks

## Ön Gereksinimler

- Windows Security Event ID 4698/4699/4702 (Task Created/Deleted/Updated)
- Sysmon Event ID 1 for schtasks.exe process creation with command lines
- Windows Task Scheduler operational log (Microsoft-Windows-TaskScheduler/Operational)
- PowerShell logging for Register-ScheduledTask cmdlet usage
- Erişim: Task Scheduler XML definitions on endpoints

## İş Akışı

1. **Enumerate All Scheduled Tasks**: Collect complete task inventory from target systems using `schtasks /query /fo CSV /v` or `Get-ScheduledTask` PowerShell cmdlet.
2. **Monitor Task Creation Events**: Track Event ID 4698 for new task creation, correlating with the creating process and user account context.
3. **Analyze Task Actions**: İncele: what each task executes. Flag tasks running scripts (PowerShell, cmd, wscript), binaries from user-writable paths (TEMP, AppData, Downloads), or encoded/obfuscated commands.
4. **Check Task Triggers**: Review trigger conditions. Tasks triggered by system startup, user logon, or short intervals (1-5 minutes) warrant investigation.
5. **Identify Hidden or Disguised Tasks**: Hunt for tasks with names mimicking legitimate Windows tasks, tasks with Security Descriptor modifications hiding them from standard enumeration, or tasks stored in non-standard registry locations.
6. **Correlate with Process Execution**: Match scheduled task execution events with process creation logs to confirm what actually runs.
7. **Baseline and Diff**: Compare current task inventory against known-good baselines to identify new, modified, or unexpected tasks.

## Tespit Queries

### Splunk -- Scheduled Task Creation
```spl
index=wineventlog EventCode=4698
| spath output=TaskName path=EventData.TaskName
| spath output=TaskContent path=EventData.TaskContent
| where NOT match(TaskName, "(?i)(\\\\Microsoft\\\\|\\\\Windows\\\\)")
| table _time Computer SubjectUserName TaskName TaskContent
```

### Splunk -- Schtasks.exe Suspicious Usage
```spl
index=sysmon EventCode=1 Image="*\\schtasks.exe"
| where match(CommandLine, "(?i)/create")
| where match(CommandLine, "(?i)(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|http|https|\\\\temp\\\\|\\\\appdata\\\\)")
| table _time Computer User CommandLine ParentImage
```

### KQL -- Microsoft Sentinel
```kql
SecurityEvent
| where EventID == 4698
| extend TaskName = tostring(EventData.TaskName)
| extend TaskContent = tostring(EventData.TaskContent)
| where TaskContent has_any ("powershell", "cmd.exe", "wscript", "http://", "https://", "\\Temp\\", "\\AppData\\")
| project TimeGenerated, Computer, Account, TaskName, TaskContent
```

## Common Scenarios

1. **Cobalt Strike Persistence**: Creates scheduled tasks via schtasks.exe to execute PowerShell download cradles at user logon intervals.
2. **Ransomware Staging**: Task created to run encryption payload at a future time, often during off-hours for maximum impact.
3. **Hidden Task via SD Modification**: Attacker modifies Security Descriptor of scheduled task to hide it from normal enumeration while maintaining execution.
4. **COM Handler Abuse**: Task uses COM handler rather than direct executable path, making action Denetle:ion more complex.
5. **Lateral Movement via Tasks**: Remote scheduled task creation using `schtasks /create /s REMOTE_HOST` for execution on other systems.

## Output Format

```
Hunt ID: TH-SCHTASK-[DATE]-[SEQ]
Host: [Hostname]
Task Name: [Full task path]
Action: [Command/Script executed]
Trigger: [Startup/Logon/Timer/Event]
Created By: [User account]
Created From: [Local/Remote]
Creation Time: [Timestamp]
Run As: [Execution account]
Risk Level: [Critical/High/Medium/Low]
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 67c7bb3011cb61c4
-->

