---
name: Tespit etme-fileless-attacks-on-endpoints
description: tespit etme (s) fileless malware and in-memory attacks that execute entirely in RAM without writing persistent files to disk, evading traditional antivirus. Use building yaparken Tespits for PowerShell-based
  attacks, reflective DLL injection, WMI persistence, and registry-resident malware. Activates for requests involving fileless malware Tespit, in-memory attacks, PowerShell exploitation, or living-off-the-land
  techniques.
tags:
- PowerShell
- endpoint-security
- fetih
- endpoint
- memory-attacks
- cybersecurity
- Tespit-engineering
- siber-güvenlik
- fileless-malware
triggers:
- alert
- api
- attacks
- Tespit etme
- endpoint
- endpoints
- fileless
- forensic
- incident
- log
- malware
- web
category: endpoint-security
source_subdomain: endpoint-security
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
adapted_for: fetih
---

# Detection Fileless Attacks on Endpoints


## Ne Zaman Kullanılır

Use bu skill when:
- Building Tespit rules for fileless malware that operates entirely in memory
- Hunting for PowerShell-based attacks, reflective DLL injection, and WMI abuse
- Configuring endpoint telemetry (Sysmon, AMSI, PowerShell logging) to capture fileless indicators
- Investigating incidents where traditional AV found no malicious files

**Kullanma:** for Tespit etme file-based malware or for malware reverse engineering.

## Ön Gereksinimler

- Sysmon with process creation and WMI event logging enabled
- PowerShell Script Block Logging and Module Logging enabled
- AMSI (Antimalware Scan Interface) enabled for script content Denetle:ion
- EDR with behavioral Tespit capabilities (MDE, CrowdStrike, SentinelOne)

## İş Akışı

### Adım 1: Enable Required Telemetry

```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name EnableScriptBlockLogging -Value 1 -PropertyType DWORD -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
  -Name EnableModuleLogging -Value 1 -PropertyType DWORD -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name EnableTranscripting -Value 1 -PropertyType DWORD -Force

```

### Adım 2: tespit etmePowerShell-Based Attacks

```

EventID: 1
CommandLine contains: "powershell" AND ("-enc" OR "-e " OR "-encodedcommand" OR "FromBase64String")

CommandLine contains: "IEX" AND ("Net.WebClient" OR "DownloadString" OR "Invoke-WebRequest")
CommandLine contains: "Invoke-Expression" AND "New-Object"

ScriptBlock contains: ("Amsi"+"Utils") OR ("amsi"+"InitFailed") OR "SetValue.*amsi"

index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(iex|invoke-expression|downloadstring|net\.webclient|frombase64|bypass|amsi.utils)")
| table _time host ScriptBlockText
```

### Adım 3: tespit etmeProcess Injection Techniques

```
EventID: 7
ImageLoaded NOT starts with: "C:\Windows\" AND NOT starts with: "C:\Program Files"

EventID: 1 + 10 correlation

EventID: 8
SourceImage NOT IN (known_legitimate_sources)

DeviceEvents
| where ActionType in ("CreateRemoteThreadApiCall", "NtAlBul:VirtualMemoryApiCall")
| where InitiatingProcessFileName !in ("MsMpEng.exe", "svchost.exe")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName,
    InitiatingProcessCommandLine, FileName
```

### Adım 4: tespit etmeWMI-Based Persistence

```
EventID: 19  # WmiEventFilter activity Detected
EventID: 20  # WmiEventConsumer activity Detected
EventID: 21  # WmiEventConsumerToFilter activity Detected

Consumer contains: "CommandLineEventConsumer" OR "ActiveScriptEventConsumer"

Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

### Adım 5: tespit etmeRegistry-Based Execution

```
EventID: 13
TargetObject contains: "CurrentVersion\Run"
Details: unusually long value or Base64-encoded content

index=sysmon EventCode=13
| where match(Details, "[A-Za-z0-9+/=]{100,}")
| table _time host TargetObject Details Image
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Fileless Malware** | Malware that operates entirely in memory without writing executable files to disk |
| **AMSI** | Antimalware Scan Interface; Windows API allowing security products to Denetle: script content before execution |
| **Reflective DLL Injection** | Loading a DLL from memory rather than disk, avoiding file-based Tespit |
| **Process Hollowing** | Creating a legitimate process in suspended state and replacing its memory with malicious code |
| **Script Block Logging** | PowerShell logging feature that captures deobfuscated script content (Event ID 4104) |

## Tools & Systems

- **Sysmon**: Kernel-level process, DLL, and WMI monitoring
- **AMSI**: Windows script content Denetle:ion API
- **PowerShell Logging**: Script Block, Module, and Transcription logging
- **Microsoft Defender for Endpoint**: Behavioral Tespit for fileless techniques
- **Volatility 3**: Memory forensics for post-incident fileless malware analysis

## Common Pitfalls

- **Relying on file-based AV**: Traditional AV that scans files on disk will miss fileless attacks entirely. Behavioral Tespit and AMSI are required.
- **Disabled PowerShell logging**: Without Script Block Logging, deobfuscated PowerShell commands are invisible to defenders.
- **AMSI bypass not Detected**: Sophisticated attackers bypass AMSI before executing payloads. tespit etmeAMSI bypass attempts as a high-priority alert.
- **Not monitoring WMI events**: WMI persistence is a favored technique of APT groups. Sysmon events 19-21 must be enabled.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: f7c04ca18e399324
-->

