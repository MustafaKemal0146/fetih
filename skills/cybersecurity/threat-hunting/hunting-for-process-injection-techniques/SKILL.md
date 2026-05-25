---
name: hunting-for-process-injection-techniques
description: tespit etmeprocess injection techniques (T1055) including CreateRemoteThread, process hollowing, and DLL injection via Sysmon Event IDs 8 and 10 and EDR process telemetry
tags:
- threat-hunting
- dll-injection
- process-injection
- createremotethread
- siber-güvenlik
- sysmon
- fetih
- cybersecurity
- edr
- t1055
triggers:
- anomali tespit
- hunting
- incident
- injection
- log
- process
- techniques
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

# Hunting for Process Injection Techniques


## Genel Bakış

Process injection (MITRE ATT&CK T1055) allows adversaries to execute code in the address space of another process, enabling defense evasion and privilege escalation. bu skill tespit etme (s) injection techniques via Sysmon Event ID 8 (CreateRemoteThread), Event ID 10 (ProcessAccess with suspicious access rights), and analysis of source-target process relationships to distinguish legitimate from malicious injection.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting for process injection techniques
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Sysmon installed with Event IDs 8 and 10 enabled
- Process creation logs (Sysmon Event ID 1 or Windows 4688)
- Python 3.8+ with standard library
- JSON-formatted Sysmon event logs

## Adımlar

1. **Parse Sysmon Events** — Ingest Event IDs 1, 8, and 10 from JSON log files
2. **tespit etmeCreateRemoteThread** — Flag Event ID 8 with suspicious source-target process pairs
3. **Analyze ProcessAccess Rights** — Identify Event ID 10 with dangerous access masks (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD)
4. **Build Process Relationship Graph** — Map source-to-target injection relationships
5. **Filter Known Legitimate Pairs** — Exclude known benign injection patterns (AV, debuggers, system processes)
6. **Score Injection Severity** — Apply risk scoring based on source process, target process, and access rights
7. **Generate Hunt Report** — Produce structured report with MITRE sub-technique mapping

## Expected Output

- JSON report of Detected injection events with severity scores
- Process injection relationship graph
- MITRE ATT&CK sub-technique mapping (T1055.001-T1055.012)
- False positive exclusion recommendations
