---
name: performing-windows-artifact-analysis-with-eric-zimmerman-tools
description: Perform comprehensive Windows forensic artifact analysis using Eric Zimmerman's open-source EZ Tools suite including KAPE, MFTECmd, PECmd, LECmd, JLECmd, and Timeline Explorer for parsing registry
  hives, prefetch files, event logs, and file system metadata.
tags:
- mftecmd
- ez-tools
- eric-zimmerman
- windows-forensics
- lecmd
- timeline-explorer
- registry-forensics
- artifact-analysis
- digital-forensics
- jlecmd
- fetih
- pecmd
- cybersecurity
- kape
- siber-güvenlik
- dfir
triggers:
- adli bilişim
- analysis
- artifact
- dijital delil
- disk imajı
- eric
- forensic
- forensics
- hash
- http
- incident
- log
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
adapted_for: fetih
---

# Performing Windows Artifact Analysis with Eric Zimmerman Tools


## Genel Bakış

Eric Zimmerman's EZ Tools suite is a collection of open-source forensic utilities that have become the global standard for Windows digital forensics investigations. Originally developed by a former FBI agent and current SANS instructor, these tools parse and analyze critical Windows artifacts including the Master File Table ($MFT), registry hives, prefetch files, event logs, shortcut (LNK) files, and jump lists. The suite integrates with KAPE (Kroll Artifact Parser and Extractor) for automated artifact collection and processing, producing structured CSV output that can be ingested into Timeline Explorer for visual analysis. EZ Tools are widely used by law enforcement, corporate incident responders, and forensic consultants worldwide.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing windows artifact analysis with eric zimmerman tools
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Windows 10/11 or Windows Server 2016+ analysis workstation
- .NET 6 Runtime kurulu (required for EZ Tools v2.x+)
- Administrative privileges on the analysis workstation
- Forensic disk image or triage collection from target system
- At least 8 GB RAM (16 GB recommended for large datasets)
- Familiarity with NTFS file system structures and Windows internals

## Tool Suite Components

### KAPE (Kroll Artifact Parser and Extractor)

KAPE is the primary orchestration tool that automates artifact collection (Targets) and processing (Modules). It uses configuration files (.tkape and .mkape) to define what artifacts to collect and which EZ Tools to run against them.

**Installation and Setup:**

```powershell

C:\Tools\KAPE\gkape.exe  # GUI version
C:\Tools\KAPE\kape.exe   # CLI version

C:\Tools\KAPE\Get-KAPEUpdate.ps1
```

**Running KAPE Collection and Processing:**

```powershell
kape.exe --tsource E: --tdest C:\Cases\Case001\Collection --target KapeTriage --mdest C:\Cases\Case001\Processed --module !EZParser

kape.exe --tsource E: --tdest C:\Cases\Case001\Collection --target FileSystem,RegistryHives,EventLogs --mdest C:\Cases\Case001\Processed --module MFTECmd,RECmd,EvtxECmd

kape.exe --tsource C: --tdest D:\LiveTriage\Collection --target KapeTriage --mdest D:\LiveTriage\Processed --module !EZParser --vhdx LiveTriageImage
```

### MFTECmd - Master File Table Parser

MFTECmd parses the NTFS $MFT, $J (USN Journal), $Boot, $SDS, and $LogFile into human-readable CSV format.

```powershell
MFTECmd.exe -f "C:\Cases\Evidence\$MFT" --csv C:\Cases\Output --csvf MFT_output.csv

MFTECmd.exe -f "C:\Cases\Evidence\$J" --csv C:\Cases\Output --csvf USNJournal_output.csv

MFTECmd.exe -f "C:\Cases\Evidence\$Boot" --csv C:\Cases\Output --csvf Boot_output.csv

MFTECmd.exe -f "C:\Cases\Evidence\$SDS" --csv C:\Cases\Output --csvf SDS_output.csv
```

**Key Fields in MFT Output:**

| Field | Description |
|-------|-------------|
| EntryNumber | MFT record number |
| ParentEntryNumber | Parent directory MFT record |
| InUse | Whether the record is active or deleted |
| FileName | Name of the file or directory |
| Created0x10 | $STANDARD_INFORMATION creation timestamp |
| Created0x30 | $FILE_NAME creation timestamp |
| LastModified0x10 | $STANDARD_INFORMATION modification timestamp |
| IsDirectory | Boolean indicating directory or file |
| FileSize | Logical file size in bytes |
| Extension | File extension |

### PECmd - Prefetch File Parser

PECmd parses Windows Prefetch files (.pf) to provide evidence of program execution, including run counts and timestamps.

```powershell
PECmd.exe -d "C:\Cases\Evidence\Windows\Prefetch" --csv C:\Cases\Output --csvf Prefetch_output.csv

PECmd.exe -f "C:\Cases\Evidence\Windows\Prefetch\CMD.EXE-4A81B364.pf" --json C:\Cases\Output

PECmd.exe -d "C:\Cases\Evidence\Windows\Prefetch" -k "powershell,cmd,wscript,cscript,mshta" --csv C:\Cases\Output --csvf SuspiciousExec.csv
```

### RECmd - Registry Explorer Command Line

RECmd processes Windows registry hives using batch files that define which keys and values to extract.

```powershell
RECmd.exe --bn C:\Tools\KAPE\Modules\bin\RECmd\BatchExamples\RECmd_Batch_MC.reb -d "C:\Cases\Evidence\Registry" --csv C:\Cases\Output --csvf Registry_output.csv

RECmd.exe -f "C:\Cases\Evidence\Users\suspect\NTUSER.DAT" --bn C:\Tools\KAPE\Modules\bin\RECmd\BatchExamples\RECmd_Batch_MC.reb --csv C:\Cases\Output

RECmd.exe -f "C:\Cases\Evidence\Registry\SYSTEM" --bn C:\Tools\KAPE\Modules\bin\RECmd\BatchExamples\RECmd_Batch_MC.reb --csv C:\Cases\Output
```

### EvtxECmd - Windows Event Log Parser

EvtxECmd parses Windows Event Log (.evtx) files into structured CSV format with customizable event ID maps.

```powershell
EvtxECmd.exe -d "C:\Cases\Evidence\Windows\System32\winevt\Logs" --csv C:\Cases\Output --csvf EventLogs_output.csv

EvtxECmd.exe -f "C:\Cases\Evidence\Security.evtx" --csv C:\Cases\Output --csvf Security_output.csv

EvtxECmd.exe -d "C:\Cases\Evidence\Logs" --csv C:\Cases\Output --maps C:\Tools\KAPE\Modules\bin\EvtxECmd\Maps
```

### LECmd and JLECmd - Shortcut and Jump List Parsers

```powershell
LECmd.exe -d "C:\Cases\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Cases\Output --csvf LNK_output.csv

JLECmd.exe -d "C:\Cases\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv C:\Cases\Output --csvf JumpLists_auto.csv

JLECmd.exe -d "C:\Cases\Evidence\Users\suspect\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" --csv C:\Cases\Output --csvf JumpLists_custom.csv
```

### SBECmd - Shellbag Explorer Command Line

```powershell
SBECmd.exe -d "C:\Cases\Evidence\Registry" --csv C:\Cases\Output --csvf Shellbags_output.csv

SBECmd.exe --live --csv C:\Cases\Output --csvf LiveShellbags_output.csv
```

### Timeline Explorer - Visual Analysis

Timeline Explorer is the GUI tool for analyzing CSV output from all EZ Tools. It supports filtering, sorting, column grouping, and conditional formatting.

```powershell
TimelineExplorer.exe "C:\Cases\Output\MFT_output.csv"
```

**Key Timeline Explorer Features:**
- Column-level filtering with regular expressions
- Conditional formatting for timestamp anomalies
- Multi-column sorting for chronological analysis
- Export filtered results to new CSV files
- Bookmarking rows of interest

## Investigation Workflow

### Adım 1: Artifact Collection with KAPE

```powershell
kape.exe --tsource E: --tdest C:\Cases\Case001\Collected --target KapeTriage --vhdx TriageImage --zv false
```

### Adım 2: Artifact Processing with EZ Tools

```powershell
kape.exe --msource C:\Cases\Case001\Collected --mdest C:\Cases\Case001\Processed --module !EZParser
```

### Adım 3: Timeline Analysis

1. Open processed CSV files in Timeline Explorer
2. Sort by timestamp columns to establish chronological order
3. Filter for specific file extensions, paths, or event IDs
4. Cross-reference MFT timestamps with event log entries
5. Identify timestomping by comparing $SI and $FN timestamps
6. Document Bul:ings with bookmarks and exported filtered views

### Adım 4: Timestomping Tespit

```powershell
```

## Forensic Artifacts Reference

| Tool | Artifact | Location |
|------|----------|----------|
| MFTECmd | $MFT | Root of NTFS volume |
| MFTECmd | $J (USN Journal) | $Extend\$UsnJrnl:$J |
| PECmd | Prefetch files | C:\Windows\Prefetch\*.pf |
| RECmd | NTUSER.DAT | C:\Users\{user}\NTUSER.DAT |
| RECmd | SYSTEM hive | C:\Windows\System32\config\SYSTEM |
| RECmd | SAM hive | C:\Windows\System32\config\SAM |
| RECmd | SOFTWARE hive | C:\Windows\System32\config\SOFTWARE |
| EvtxECmd | Event logs | C:\Windows\System32\winevt\Logs\*.evtx |
| LECmd | LNK files | C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\ |
| JLECmd | Jump lists | C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\ |
| SBECmd | Shellbags | NTUSER.DAT and UsrClass.dat registry hives |

## Common Investigation Scenarios

### Malware Execution Evidence
1. Parse Prefetch with PECmd to identify executed binaries
2. Cross-reference with MFT for file creation timestamps
3. Check Amcache.hve with RECmd for SHA1 hashes of executables
4. Correlate with Event Log entries for process creation (Event ID 4688)

### Data Exfiltration Investigation
1. Parse USN Journal with MFTECmd for file rename/delete operations
2. Analyze LNK files with LECmd for recently accessed documents
3. Review Shellbags with SBECmd for directory browsing activity
4. Check for USB device connections in SYSTEM registry with RECmd

### Lateral Movement Tespit
1. Parse Security.evtx with EvtxECmd for logon events (4624, 4625)
2. Analyze RDP-related event logs (Microsoft-Windows-TerminalServices)
3. Cross-reference with network share access from SMB logs
4. Review scheduled tasks and services for persistence mechanisms

## Output Format and Integration

All EZ Tools produce CSV output that can be:
- Analyzed in Timeline Explorer for visual investigation
- Imported into Splunk, Elastic, or other SIEM platforms
- Processed by Python/PowerShell scripts for automated analysis
- Combined into super timelines using log2timeline/Plaso

## References

- Eric Zimmerman's Tools: https://ericzimmerman.github.io/
- KAPE Documentation: https://ericzimmerman.github.io/KapeDocs/
- SANS EZ Tools Training: https://www.sans.org/tools/ez-tools
- SANS FOR508: Advanced Incident Response and Threat Hunting
- SANS FOR498: Battlefield Forensics & Data Acquisition

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 1ade99d0a05c6cae
-->

