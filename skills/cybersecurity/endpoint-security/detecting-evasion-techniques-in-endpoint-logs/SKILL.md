---
name: Tespit etme-evasion-techniques-in-endpoint-logs
description: tespit etme (s) defense evasion techniques used by adversaries in endpoint logs including log tampering, timestomping, process injection, and security tool disabling. Use investigating yaparken suspicious
  endpoint behavior, building Tespit rules for evasion tactics, or conducting threat hunting for stealthy adversary activity. Activates for requests involving evasion Tespit, defense evasion analysis,
  log tampering Tespit, or MITRE ATT&CK TA0005.
tags:
- threat-hunting
- MITRE-ATT&CK
- endpoint-security
- fetih
- endpoint
- cybersecurity
- edr
- defense-evasion
- Tespit-engineering
- siber-güvenlik
triggers:
- alert
- Tespit etme
- endpoint
- evasion
- exploit
- http
- incident
- log
- logs
- malware
- network
- techniques
category: endpoint-security
source_subdomain: endpoint-security
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
---

# Detection Evasion Techniques in Endpoint Logs


## Ne Zaman Kullanılır

Use bu skill when:
- Hunting for adversary defense evasion techniques (MITRE ATT&CK TA0005) in endpoint telemetry
- Building Tespit rules for common evasion methods (process injection, timestomping, log clearing)
- Investigating incidents where adversaries disabled or bypassed security tools
- Analyzing endpoint logs for indicators of living-off-the-land binary (LOLBin) abuse

**Kullanma:** bu skill for network-level evasion (use network traffic analysis) or for malware reverse engineering.

## Ön Gereksinimler

- Sysmon installed and configured with comprehensive logging rules (SwiftOnSecurity or Olaf Hartong config)
- Windows Security Event Log with advanced audit policy enabled
- EDR telemetry (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint)
- SIEM platform for log correlation (Splunk, Elastic, Sentinel)
- MITRE ATT&CK Enterprise matrix for technique reference

## İş Akışı

### Adım 1: tespit etmeLog Tampering (T1070)

**Windows Event Log clearing (T1070.001)**:
```
EventID: 1
CommandLine contains: "wevtutil cl" OR "wevtutil clear-log"

EventID: 1102
Source: Microsoft-Windows-Eventlog

EventID: 104

EventID: 1 (Sysmon)
CommandLine contains: "Clear-EventLog" OR "Remove-EventLog"

index=windows (EventCode=1102 OR EventCode=104)
  OR (EventCode=1 CommandLine="*wevtutil*cl*")
  OR (EventCode=1 CommandLine="*Clear-EventLog*")
| table _time host user CommandLine EventCode
```

**Timestomping (T1070.006)**:
```
EventID: 2

DeviceFileEvents
| where ActionType == "FileTimestampModified"
| where Timestamp > ago(7d)
| extend TimeDiff = datetime_diff('day', Timestamp, ReportedFileCreationTime)
| where TimeDiff > 30
| project Timestamp, DeviceName, FileName, FolderPath,
    ReportedFileCreationTime, InitiatingProcessFileName
```

### Adım 2: tespit etmeProcess Injection (T1055)

```
EventID: 8
SourceImage NOT IN ("C:\Windows\System32\csrss.exe",
                     "C:\Windows\System32\lsass.exe")

EventID: 10
GrantedAccess contains: "0x1F0FFF" OR "0x1FFFFF" OR "0x001F0FFF"

EventID: 25
Type: "Image is replaced"  # Process hollowing indicator

index=sysmon EventCode=8
| where NOT match(SourceImage, "(?i)(csrss|svchost|MsMpEng|defender)")
| stats count by SourceImage TargetImage host
| where count < 5
| sort - count
```

### Adım 3: tespit etmeSecurity Tool Disabling (T1562)

```
EventID: 7045 (new service) OR 7036 (service state change)
ServiceName IN ("WinDefend", "Sense", "CrowdStrike Falcon Sensor",
                 "SentinelAgent", "csagent", "MBAMService")

CommandLine contains: "Set-MpPreference -DisableRealtimeMonitoring"
  OR "sc stop WinDefend"
  OR "sc config WinDefend start= disabled"
  OR "net stop" AND ("windefend" OR "sense" OR "csagent")

TargetObject contains: "DisableAntiSpyware"
  OR "DisableRealtimeMonitoring"
  OR "DisableBehaviorMonitoring"
Details: "DWORD (0x00000001)"

DeviceRegistryEvents
| where RegistryValueName in ("DisableAntiSpyware", "DisableRealtimeMonitoring")
| where RegistryValueData == "1"
| project Timestamp, DeviceName, RegistryKey, InitiatingProcessFileName
```

### Adım 4: tespit etmeMasquerading (T1036)

```
EventID: 1
Image contains: "svchost.exe" AND Image NOT starts with: "C:\Windows\System32\"
Image contains: "csrss.exe" AND Image NOT starts with: "C:\Windows\System32\"
Image contains: "lsass.exe" AND Image NOT starts with: "C:\Windows\System32\"

EventID: 1
OriginalFileName != (parsed filename from Image path)

EventID: 11 (FileCreate)
TargetFilename matches: "*\.pdf\.exe" OR "*\.doc\.exe" OR "*\.jpg\.exe"

index=sysmon EventCode=1
| eval process_name=mvindex(split(Image,"\\"),-1)
| where (process_name="svchost.exe" AND NOT match(Image,"(?i)C:\\\\Windows\\\\System32"))
  OR (process_name="csrss.exe" AND NOT match(Image,"(?i)C:\\\\Windows\\\\System32"))
| table _time host Image ParentImage CommandLine User
```

### Adım 5: tespit etmeLOLBin Abuse (T1218, T1127)

```

EventID: 1
Image ends with: "mshta.exe"
CommandLine contains: "http" OR "javascript:" OR "vbscript:"

EventID: 1
Image ends with: "certutil.exe"
CommandLine contains: "-urlcache" OR "-decode" OR "-encode"

EventID: 1
Image ends with: "regsvr32.exe"
CommandLine contains: "/s /n /u /i:" OR "scrobj.dll"

EventID: 1
Image ends with: "rundll32.exe"
CommandLine contains: "javascript:" OR ".js" OR "http:"

EventID: 1
Image contains: "MSBuild.exe"
CommandLine NOT contains: ".sln" AND NOT contains: ".csproj"
```

### Adım 6: Build Tespit Rule Correlation

```


index=sysmon host=*
| eval technique=case(
    EventCode=2, "timestomping",
    EventCode=8 AND NOT match(SourceImage,"csrss|svchost"), "process_injection",
    EventCode=1 AND match(CommandLine,"(?i)wevtutil.*cl"), "log_clearing",
    EventCode=13 AND match(TargetObject,"DisableRealtimeMonitoring"), "security_disable",
    EventCode=1 AND match(CommandLine,"(?i)(mshta|certutil.*urlcache|regsvr32.*/s.*/n)"), "lolbin_abuse",
    true(), NULL
)
| where isnotnull(technique)
| bin _time span=1h
| stats dc(technique) as technique_count values(technique) as techniques by host _time
| where technique_count >= 3
| sort - technique_count
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Defense Evasion (TA0005)** | MITRE ATT&CK tactic where adversaries attempt to avoid Tespit during operations |
| **Process Injection (T1055)** | Technique of injecting code into another process's memory space to execute in a trusted context |
| **Timestomping (T1070.006)** | Modifying file timestamps to make malicious files appear old and blend with legitimate files |
| **Masquerading (T1036)** | Naming malicious files or processes to match legitimate system files to avoid Tespit |
| **LOLBin** | Living Off the Land Binary; legitimate Windows tool repurposed by adversaries |
| **Indicator Removal (T1070)** | Clearing logs, deleting files, or modifying artifacts to remove evidence of compromise |

## Tools & Systems

- **Sysmon**: Advanced Windows system monitoring with kernel-level visibility
- **Microsoft Defender for Endpoint**: EDR with advanced hunting (KQL) for evasion Tespit
- **CrowdStrike Falcon**: IOA-based behavioral Tespit for evasion techniques
- **Elastic Security**: SIEM with prebuilt Tespit rules for ATT&CK evasion techniques
- **Sigma Rules**: Vendor-agnostic Tespit rule format with extensive evasion rule library

## Common Pitfalls

- **Alert fatigue from process injection rules**: Many legitimate tools (AV, accessibility) perform process injection. Maintain an allowlist of known-good source processes.
- **Missing Sysmon Event ID 8/10**: Default Sysmon configurations may not capture CreateRemoteThread or ProcessAccess. Use a comprehensive Sysmon config.
- **Ignoring parent process context**: A suspicious command line from cmd.exe is concerning only if the parent of cmd.exe is unusual (e.g., Excel spawning cmd.exe).
- **Not correlating across event types**: Single events are often benign. Combine multiple weak signals (process creation + network connection + file creation) for high-confidence Tespits.
