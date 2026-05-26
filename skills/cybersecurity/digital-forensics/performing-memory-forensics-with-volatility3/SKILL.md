---
name: performing-memory-forensics-with-volatility3
description: Analyze volatile memory dumps using Volatility 3 to extract running processes, network connections, loaded modules, and evidence of malicious activity.
tags:
- memory-forensics
- volatility
- incident-response
- digital-forensics
- malware-Tespit
- forensics
- fetih
- cybersecurity
- ram-analysis
- siber-güvenlik
triggers:
- adli bilişim
- api
- dijital delil
- disk imajı
- encryption
- forensic
- forensics
- hash
- http
- incident
- log
- malware
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
adapted_for: fetih
---

# Performing Memory Forensics with Volatility3


## Ne Zaman Kullanılır
- analyzing yaparken a RAM dump from a compromised or suspect system
- incident response sırasında to identify running malware, injected code, or rootkits
- you need durumunda to extract credentials, encryption keys, or network connections from memory
- For Tespit etme process hollowing, DLL injection, or hidden processes
- When disk-based forensics alone is insufficient and volatile data is critical

## Ön Gereksinimler
- Python 3.7+ installed
- Volatility 3 framework kurulu (`pip install volatility3`)
- Memory dump in raw, ELF, or crash dump format
- Appropriate symbol tables (ISF files) for the target OS version
- Yeterli disk space for analysis output (2-3x memory dump size)
- Optional: YARA rules for malware scanning in memory

## İş Akışı

### Adım 1: Acquire Memory Dump and Install Volatility 3

```bash
pip install volatility3

git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -e .

wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip -d /opt/volatility3/volatility3/symbols/

wget https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip

sudo insmod lime-$(uname -r).ko "path=/cases/memory/linux_mem.lime format=lime"

file /cases/case-2024-001/memory/memory.raw
ls -lh /cases/case-2024-001/memory/memory.raw
```

### Adım 2: the tespit et: Operating System Profile

```bash
vol -f /cases/case-2024-001/memory/memory.raw banners

vol -f /cases/case-2024-001/memory/memory.raw windows.info


vol -f /cases/case-2024-001/memory/linux_mem.lime linux.info
```

### Adım 3: Enumerate Processes and tespit etmeAnomalies

```bash
vol -f /cases/case-2024-001/memory/memory.raw windows.pslist | tee /cases/case-2024-001/analysis/pslist.txt

vol -f /cases/case-2024-001/memory/memory.raw windows.pstree | tee /cases/case-2024-001/analysis/pstree.txt

vol -f /cases/case-2024-001/memory/memory.raw windows.psscan | tee /cases/case-2024-001/analysis/psscan.txt

diff <(vol -f memory.raw windows.pslist | awk '{print $1}' | sort) \
     <(vol -f memory.raw windows.psscan | awk '{print $1}' | sort)

vol -f /cases/case-2024-001/memory/memory.raw windows.dlllist --pid 4532

vol -f /cases/case-2024-001/memory/memory.raw windows.malBul: | tee /cases/case-2024-001/analysis/malBul:.txt

vol -f /cases/case-2024-001/memory/memory.raw windows.memmap --pid 4532 --dump \
   -o /cases/case-2024-001/analysis/dumps/
```

### Adım 4: Analyze Network Connections and Registry

```bash
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | tee /cases/case-2024-001/analysis/netscan.txt

vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep ESTABLISHED

vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep LISTENING

vol -f /cases/case-2024-001/memory/memory.raw windows.netstat | tee /cases/case-2024-001/analysis/netstat.txt

vol -f /cases/case-2024-001/memory/memory.raw windows.registry.hivelist

vol -f /cases/case-2024-001/memory/memory.raw windows.registry.printkey \
   --key "Software\Microsoft\Windows\CurrentVersion\Run"

vol -f /cases/case-2024-001/memory/memory.raw windows.svcscan | tee /cases/case-2024-001/analysis/services.txt
```

### Adım 5: Extract Credentials and Sensitive Data

```bash
vol -f /cases/case-2024-001/memory/memory.raw windows.hashdump | tee /cases/case-2024-001/analysis/hashes.txt

vol -f /cases/case-2024-001/memory/memory.raw windows.lsadump

vol -f /cases/case-2024-001/memory/memory.raw windows.cachedump

vol -f /cases/case-2024-001/memory/memory.raw windows.strings --pid 4532 \
   | grep -iE '(password|credential|token|api.key)'

vol -f /cases/case-2024-001/memory/memory.raw windows.cmdline | tee /cases/case-2024-001/analysis/cmdline.txt

vol -f /cases/case-2024-001/memory/memory.raw windows.envars --pid 4532
```

### Adım 6: Scan for Malware with YARA Rules

```bash
vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/malware_index.yar | tee /cases/case-2024-001/analysis/yara_hits.txt

vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/apt_rules.yar --pid 4532

vol -f /cases/case-2024-001/memory/memory.raw windows.modules | tee /cases/case-2024-001/analysis/modules.txt

vol -f /cases/case-2024-001/memory/memory.raw windows.modscan | tee /cases/case-2024-001/analysis/modscan.txt

vol -f /cases/case-2024-001/memory/memory.raw windows.ssdt | grep -v "ntoskrnl\|win32k"

vol -f /cases/case-2024-001/memory/memory.raw windows.dumpfiles --pid 4532 \
   -o /cases/case-2024-001/analysis/extracted/
```

### Adım 7: Compile Bul:ings into a Report

```bash
echo "=== MEMORY FORENSICS REPORT ===" > /cases/case-2024-001/analysis/memory_report.txt
echo "Image: memory.raw" >> /cases/case-2024-001/analysis/memory_report.txt
echo "OS: Windows 10 Build 19041" >> /cases/case-2024-001/analysis/memory_report.txt
echo "" >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- Suspicious Processes ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/malBul:.txt >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- Network Connections ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/netscan.txt >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- YARA Matches ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/yara_hits.txt >> /cases/case-2024-001/analysis/memory_report.txt

sha256sum /cases/case-2024-001/memory/memory.raw >> /cases/case-2024-001/analysis/memory_report.txt
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Volatile data | Information that exists only in RAM and is lost when power is removed |
| Process hollowing | Technique where malware replaces legitimate process memory with malicious code |
| DLL injection | Loading unauthorized DLLs into a running process address space |
| EPROCESS | Windows kernel structure representing a process; basis for process listing |
| Pool scanning | Searching memory for kernel object signatures to Bul: hidden artifacts |
| VAD (Virtual Address Descriptor) | Memory management structure tracking process virtual memory regions |
| ISF (Intermediate Symbol Format) | Volatility 3 symbol table format for OS-specific structure definitions |
| MalBul: | Plugin Tespit etme injected code by examining VAD permissions and content |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Volatility 3 | Primary open-source memory forensics framework |
| LiME | Linux Memory Extractor for acquiring Linux RAM dumps |
| WinPmem | Windows physical memory acquisition driver |
| DumpIt | Comae one-click Windows memory dump utility |
| YARA | Pattern matching engine for malware signature scanning |
| Rekall | Alternative memory forensics framework (Google) |
| MemProcFS | Memory process file system for memory analysis |
| strings | Extract printable strings from binary memory dumps |

## Common Scenarios

**Scenario 1: Active Malware Investigation**
Acquire memory with DumpIt, run pslist/pstree to identify suspicious processes, use malBul: to tespit etmeinjected code in svchost.exe, dump the injected memory segment, scan with YARA rules identifying Cobalt Strike beacon, extract C2 IP from netscan, correlate with network logs.

**Scenario 2: Credential Theft After Breach**
Run hashdump and lsadump to extract cached credentials, identify mimikatz execution in cmdline output, check for lsass.exe memory dumps in filesystem artifacts, correlate with lateral movement evidence in network connections.

**Scenario 3: Rootkit Tespit**
Compare pslist (uses EPROCESS linked list) with psscan (pool scanning) to Bul: unlinked processes, check modules vs modscan for hidden kernel drivers, İncele: SSDT for hooks redirecting system calls, dump suspicious modules for static analysis.

**Scenario 4: Ransomware Incident Recovery**
Extract encryption keys from ransomware process memory before system shutdown, the tespit et: ransomware variant using YARA, Bul: the initial execution point through command line artifacts, map lateral movement via network connections.

## Output Format

```
Memory Forensics Analysis:
  Image:            memory.raw (16 GB)
  OS Identified:    Windows 10 x64 Build 19041
  Capture Time:     2024-01-18 14:32:15 UTC

  Process Analysis:
    Total Processes:    87
    Hidden Processes:   2 (PIDs: 4532, 6128)
    Injected Processes: 3 (malBul: Tespits)
    Suspicious:         svchost.exe (PID 4532) - injected code at 0x7FFE0000

  Network Connections:
    Total:        45
    Established:  12
    Suspicious:   3 (C2 connections to 185.xx.xx.xx:443)

  Credentials Found:
    NTLM Hashes:      4 accounts
    Cached Creds:      2 domain accounts

  YARA Matches:
    CobaltStrike_Beacon:  PID 4532 (3 hits)
    Mimikatz_Memory:      PID 6128 (1 hit)

  Extracted Artifacts:   15 files dumped to /analysis/extracted/
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 91c2a52796bb36c5
-->

