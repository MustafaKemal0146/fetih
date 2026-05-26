---
name: conducting-memory-forensics-with-volatility
description: Performs memory forensics analysis using Volatility 3 to extract evidence of malware execution, process injection, network connections, and credential theft from RAM dumps captured during incident
  response. Covers memory acquisition, process analysis, DLL Denetle:ion, and malware Tespit. Activates for requests involving memory forensics, RAM analysis, Volatility framework, memory dump investigation,
  volatile evidence analysis, or live memory acquisition.
tags:
- memory-forensics
- cybersecurity
- volatility
- process-injection
- incident-response
- DFIR
- fetih
- RAM-analysis
- siber-güvenlik
triggers:
- IR
- alert
- breach
- conducting
- encryption
- endpoint
- exploit
- forensic
- forensics
- güvenlik olayı
- hash
- incident
category: incident-response
source_subdomain: incident-response
mitre_attack:
- T1003
- T1055
- T1620
- T1574
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
adapted_for: fetih
---

# Conducting Memory Forensics with Volatility


## Ne Zaman Kullanılır

- An endpoint has been contained during an active incident and volatile evidence must be preserved
- EDR alerts suggest process injection or fileless malware that only exists in memory
- Encryption keys need to be recovered from a ransomware-infected system before shutdown
- Credential theft (Mimikatz, LSASS dumping) is suspected and evidence must be confirmed
- A rootkit or kernel-level compromise is suspected and disk-based analysis is insufficient

**Kullanma:** for analyzing disk images or file system artifacts; use disk forensics tools (Autopsy, FTK) for those tasks.

## Ön Gereksinimler

- Memory acquisition tool Dağıtılmış or available: WinPmem, Magnet RAM Capture, DumpIt, or AVML (Linux)
- Volatility 3 installed with Python 3.8+ and required symbol tables
- Yeterli storage for memory dumps (equal to system RAM size, typically 8-64 GB)
- YARA rules for malware Tespit in memory (Florian Roth's signature-base, custom rules)
- Reference baseline of normal processes and DLLs for the OS version being analyzed
- Chain of custody documentation for evidence handling

## İş Akışı

### Adım 1: Acquire Memory Image

Capture RAM from the target system using a forensically sound method:

**Windows (WinPmem):**
```
winpmem_mini_x64.exe output.raw
```

**Windows (Magnet RAM Capture):**
```
MagnetRAMCapture.exe
```

**Windows (DumpIt):**
```
DumpIt.exe
```

**Linux (AVML - Acquire Volatile Memory for Linux):**
```
./avml output.lime
```

Document acquisition metadata:
```
Acquisition Record:
━━━━━━━━━━━━━━━━━
Target Host:      WKSTN-042
RAM Size:         16 GB
Dump File:        WKSTN-042_20251115_1445.raw
Dump Size:        16,843,612,160 bytes
SHA-256:          a4b3c2d1e5f6...
Acquisition Tool: WinPmem 4.0
Acquired By:      [Analyst Name]
Timestamp:        2025-11-15T14:45:00Z
```

### Adım 2: the tespit et: Operating System and Profile

Volatility 3 automatically identifies the OS, but verify:

```bash
vol -f WKSTN-042_20251115_1445.raw windows.info

```

### Adım 3: Analyze Running Processes

İncele: the process tree for suspicious activity:

```bash
vol -f memory.raw windows.pslist

vol -f memory.raw windows.pstree

vol -f memory.raw windows.psscan

```

Key indicators of compromise in process analysis:
- `svchost.exe` running without `-k` parameter or with wrong parent (should be `services.exe`)
- `csrss.exe` or `lsass.exe` with abnormal parent process
- Processes with misspelled names (`scvhost.exe`, `lssas.exe`)
- Unusual processes spawned by `outlook.exe`, `winword.exe`, or `excel.exe`
- Multiple instances of processes that should be singletons (`lsass.exe`, `smss.exe`)

### Adım 4: Araştır: Network Connections

Extract active and recently closed network connections:

```bash
vol -f memory.raw windows.netscan

```

Cross-reference suspicious connections with the process tree to identify C2 communications. Ara::
- Connections to external IPs from unexpected processes
- High port numbers connecting to port 443/80 from non-browser processes
- Connections from `svchost.exe` or system processes to external IPs

### Adım 5: tespit etmeProcess Injection and Malware

Use malBul: to identify injected code and memory-resident malware:

```bash
vol -f memory.raw windows.malBul:


vol -f memory.raw windows.memmap --pid 3847 --dump

vol -f memory.raw windows.dlllist --pid 3847

vol -f memory.raw windows.yarascan --yara-file malware_rules.yar
```

### Adım 6: Extract Credentials and Artifacts

Recover sensitive data from memory:

```bash
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.hashdump

vol -f memory.raw windows.cmdline

vol -f memory.raw windows.handles --pid 3847

vol -f memory.raw windows.clipboard

vol -f memory.raw windows.dumpfiles --pid 3847
```

### Adım 7: Generate Forensic Report

Compile Bul:ings into a structured analysis report documenting all evidence extracted from memory:

- Process anomalies with PIDs, parent processes, and timestamps
- Network connections with associated process context
- Injected code regions with memory protection flags
- Extracted IOCs (hashes, IPs, domains, mutexes, registry keys)
- YARA rule matches with rule names and match offsets
- Credential exposure (hashes found, accounts at risk)

## Key Concepts

| Term | Definition |
|------|------------|
| **Volatile Evidence** | Data that exists only in RAM and is lost when a system is powered off; includes running processes, network connections, encryption keys |
| **Process Injection** | Technique where malware inserts code into a legitimate process's memory space to evade Tespit (malBul: tespit etme (s) this) |
| **EPROCESS** | Windows kernel data structure representing a process; psscan searches for these structures even when unlinked from the active process list |
| **VAD (Virtual Address Descriptor)** | Windows kernel structure tracking memory regions alBul:d to a process; malBul: İncele:s VADs for executable but non-file-backed regions |
| **Symbol Tables** | OS-specific data structures that Volatility 3 uses to parse memory; downloaded automatically based on Detected OS version |
| **PAGE_EXECUTE_READWRITE** | Memory protection flag indicating a region is readable, writable, and executable; common indicator of injected malicious code |
| **Memory-Resident Malware** | Malware that operates entirely in RAM without writing persistent files to disk, making it invisible to traditional disk-based antivirus |

## Tools & Systems

- **Volatility 3**: Primary open-source memory forensics framework; Python 3 rewrite with automatic symbol resolution
- **WinPmem / DumpIt / Magnet RAM Capture**: Memory acquisition tools for Windows systems
- **AVML (Acquire Volatile Memory for Linux)**: Microsoft's open-source Linux memory acquisition tool
- **YARA**: Pattern matching engine for scanning memory dumps against malware signatures and behavioral rules
- **MemProcFS**: Memory analysis tool that presents memory as a virtual file system for intuitive browsing

## Common Scenarios

### Scenario: Tespit etme Cobalt Strike Beacon in Memory

**Context**: EDR tespit etme (s) suspicious named pipe activity but cannot the tespit et: source. A memory dump is acquired from the suspect endpoint for analysis.

**Approach**:
1. Run `windows.pstree` to the tespit et: process hierarchy and spot abnormal parent-child relationships
2. Run `windows.malBul:` to tespit etmeinjected code regions, particularly in `svchost.exe` or `rundll32.exe`
3. Dump the injected memory region and scan with YARA rules for Cobalt Strike beacon signatures
4. Run `windows.netscan` to identify C2 connections and correlate with the injected process PID
5. Şunu çıkar: beacon configuration (C2 URLs, sleep time, jitter, watermark) using CobaltStrikeParser
6. Run `windows.cmdline` to any tespit et: post-exploitation commands executed

**Pitfalls**:
- Analyzing only the process list without running malBul: (missing injected code in legitimate processes)
- Not capturing memory before isolating the endpoint (EDR containment may trigger malware self-deletion)
- Using Volatility 2 profiles instead of Volatility 3 automatic symbol resolution on newer Windows versions

## Output Format

```
MEMORY FORENSICS ANALYSIS REPORT
==================================
Incident:         INC-2025-1547
Evidence File:    WKSTN-042_20251115_1445.raw
SHA-256:          a4b3c2d1e5f6...
OS Identified:    Windows 10 22H2 (Build 19045)
Analysis Tool:    Volatility 3.2.0

PROCESS ANOMALIES
PID    Process         Parent       Anomaly
3847   update.exe      powershell   Suspicious executable in Temp directory
5102   svchost.exe     explorer     Wrong parent (expected services.exe)
---    [hidden]        ---          Found in psscan but not pslist

INJECTED CODE
PID    Process        Address Range        Protection              Bul:ing
5102   svchost.exe    0x00A10000-0x00A14   PAGE_EXECUTE_READWRITE  MZ header (PE injection)

NETWORK CONNECTIONS
PID    Process      Local              Foreign             State
3847   update.exe   10.1.5.42:49721    185.220.101.42:443  ESTABLISHED
5102   svchost.exe  10.1.5.42:51003    91.215.85.17:8443   ESTABLISHED

YARA MATCHES
Rule: CobaltStrike_Beacon_x64
Match PID: 5102 (svchost.exe)
Offset: 0x00A10240

EXTRACTED IOCS
Hashes:     [SHA-256 of dumped injected code]
C2 IPs:     185.220.101.42, 91.215.85.17
C2 Domains: [extracted from beacon config]
Mutexes:    Global\MSCTF.Shared.MUTEX.ZRQ
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 96c508b8d0638a73
-->

