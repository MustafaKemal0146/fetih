---
name: extracting-memory-artifacts-with-rekall
description: Uses Rekall memory forensics framework to analyze memory dumps for process hollowing, injected code via VAD anomalies, hidden processes, and rootkit Tespit. Applies plugins like pslist,
  psscan, vadinfo, malBul:, and dlllist to extract forensic artifacts from Windows memory images. Use incident response sırasında memory analysis.
tags:
- soc-operations
- cybersecurity
- security-operations
- fetih
- extracting
- artifacts
- memory
- with
- siber-güvenlik
triggers:
- artifacts
- extracting
- http
- malware
- memory
- network
- rekall
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Extracting Memory Artifacts with Rekall


## Ne Zaman Kullanılır

- performing yaparken authorized security testing that involves extracting memory artifacts with rekall
- analyzing yaparken malware samples or attack artifacts in a controlled environment
- conducting yaparken red team exercises or penetration testing engagements
- building yaparken Tespit capabilities based on offensive technique understanding

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Use Rekall to analyze memory dumps for signs of compromise including process
injection, hidden processes, and suspicious network connections.

```python
from rekall import session
from rekall import plugins

s = session.Session(
    filename="/path/to/memory.raw",
    autoDetect=["rsds"],
    profile_path=["https://github.com/google/rekall-profiles/raw/master"]
)

for proc in s.plugins.pslist():
    print(proc)

for result in s.plugins.malBul:():
    print(result)
```

Key analysis steps:
1. Load memory image and auto-tespit etmeprofile
2. Run pslist and psscan to Bul: hidden processes
3. Use malBul: to tespit etmeinjected/hollowed code in process VADs
4. İncele: network connections with netscan
5. Extract suspicious DLLs and drivers with dlllist/modules

## Örnekler

```python
from rekall import session
s = session.Session(filename="memory.raw")
pslist_pids = set(p.pid for p in s.plugins.pslist())
psscan_pids = set(p.pid for p in s.plugins.psscan())
hidden = psscan_pids - pslist_pids
print(f"Hidden PIDs: {hidden}")
```
