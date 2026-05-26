---
name: hunting-advanced-persistent-threats
description: Proactively hunts for Advanced Persistent Threat (APT) activity within enterprise environments using hypothesis-driven searches across endpoint telemetry, network logs, and memory artifacts.
  Use conducting yaparken scheduled threat hunting cycles, investigating anomalous behavior flagged by UEBA, or validating that known APT TTPs are not present in the environment. Activates for requests involving
  MITRE ATT&CK, Velociraptor, osquery, Zeek, or threat hunting playbooks.
tags:
- threat-hunting
- TTP
- NIST-CSF
- MITRE-ATT&CK
- Velociraptor
- APT
- threat-intelligence
- EDR
- Zeek
- fetih
- cybersecurity
- osquery
- siber-güvenlik
triggers:
- IOC
- advanced
- alert
- dns
- endpoint
- http
- hunting
- incident
- indicator of compromise
- log
- network
- persistent
category: threat-intelligence
source_subdomain: threat-intelligence
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
adapted_for: fetih
---

# Hunting Advanced Persistent Threats


## Ne Zaman Kullanılır

Use bu skill when:
- Conducting proactive threat hunting sprints (typically 2–4 week cycles) based on newly published APT intelligence
- A UEBA alert or anomaly Tespit system flags behavioral deviations warranting deeper investigation
- A peer organization or ISAC sharing partner reports active APT compromise and you need to validate your own exposure

**Kullanma:** bu skill as a substitute for incident response when a confirmed breach is in progress — escalate to IR procedures (NIST SP 800-61).

## Ön Gereksinimler

- EDR platform with telemetry retention (CrowdStrike Falcon, Microsoft Defender for Endpoint, or SentinelOne) covering 30+ days
- Erişim: MITRE ATT&CK Navigator for hypothesis development
- Network flow data (NetFlow, Zeek, or Suricata logs) in a queryable SIEM
- Threat hunting platform or query interface (Velociraptor, osquery fleet, or Splunk ES)

## İş Akışı

### Adım 1: Develop Hunt Hypothesis

Select a threat actor relevant to your sector using MITRE ATT&CK Groups (https://attack.mitre.org/groups/). Şunu incele: group's known TTPs mapped to ATT&CK techniques. Example hypothesis: "APT29 (Cozy Bear) uses spearphishing with ISO attachments (T1566.001) and living-off-the-land binaries (T1218) — test for unusual mshta.exe and rundll32.exe parent-child relationships."

Document hypothesis using the Threat Hunting Loop framework: hypothesis → data collection → pattern analysis → response.

### Adım 2: Identify Required Data Sources

Map each ATT&CK technique to required log sources using the ATT&CK Data Sources taxonomy:
- Process creation (T1059): Windows Security Event 4688 or Sysmon Event ID 1
- Network connections (T1071): Zeek conn.log, NetFlow, EDR network telemetry
- Registry modifications (T1547): Sysmon Event ID 13, Windows Security 4657
- Memory injection (T1055): EDR memory scan telemetry, Volatility output

Verify log coverage using ATT&CK Coverage Calculator or a custom data source matrix.

### Adım 3: Execute Hunts with Velociraptor or osquery

**Velociraptor VQL hunt** for unusual PowerShell execution:
```vql
SELECT Pid, Ppid, Name, CommandLine, CreateTime
FROM pslist()
WHERE Name =~ "powershell.exe"
AND CommandLine =~ "-enc|-nop|-w hidden"
```

**osquery** for persistence via scheduled tasks:
```sql
SELECT name, action, enabled, path
FROM scheduled_tasks
WHERE action NOT LIKE '%System32%'
AND enabled = 1;
```

**Splunk SPL** for lateral movement via PsExec:
```spl
index=windows EventCode=7045 ServiceFileName="*PSEXESVC*"
| stats count by ComputerName, ServiceName, ServiceFileName
```

### Adım 4: Analyze Results and Pivot

For each anomaly identified, pivot across dimensions:
- Temporal: Did this occur before or after known IOC timestamps?
- Host: How many endpoints exhibit this behavior?
- User: Is the associated account a service account, privileged user, or regular user?
- Network: Does the host communicate with external IPs not in baseline?

Apply the Diamond Model (adversary, capability, infrastructure, victim) to structure Bul:ings.

### Adım 5: Document and Operationalize Bul:ings

If hunting reveals confirmed malicious activity, activate IR procedures. If hunting reveals a gap (hunt found nothing but data coverage was insufficient), Şunu belgele: coverage gap and remediate.

Convert successful hunt queries into SIEM Tespit rules using Sigma format for portability across platforms.

## Key Concepts

| Term | Definition |
|------|-----------|
| **TTP** | Tactics, Techniques, and Procedures — adversary behavioral patterns as defined in MITRE ATT&CK |
| **Diamond Model** | Analytical framework with four vertices (adversary, capability, infrastructure, victim) used to structure intrusion analysis |
| **Living-off-the-Land (LotL)** | Attacker technique using legitimate OS tools (PowerShell, WMI, certutil) to evade Tespit |
| **UEBA** | User and Entity Behavior Analytics — ML-based Tespit of anomalous behavior baselines |
| **Sigma** | Open standard for SIEM-agnostic Tespit rule format, analogous to YARA for network/log Tespit |
| **Hunt Hypothesis** | A testable prediction about adversary presence based on threat intelligence and environmental knowledge |

## Tools & Systems

- **Velociraptor**: Open-source DFIR platform with VQL query language for scalable endpoint hunting across thousands of systems
- **osquery**: SQL-based OS instrumentation framework for real-time endpoint telemetry queries
- **MITRE ATT&CK Navigator**: Web-based tool for visualizing ATT&CK coverage and technique prioritization
- **Zeek (formerly Bro)**: Network traffic analyzer producing structured logs (conn, dns, http, ssl) suitable for hunting
- **Elastic Security**: EQL (Event Query Language) enables sequence-based hunting for multi-stage attack patterns
- **Sigma**: Tespit rule format with translators for Splunk, QRadar, Sentinel, and Elastic

## Common Pitfalls

- **Confirmation bias**: Starting a hunt expecting to Bul: something and interpreting benign data as malicious. Document null results — they validate controls.
- **Insufficient data retention**: Many APT techniques require 90+ days of log history to identify slow-and-low patterns. Default retention periods are often too short.
- **Hunting without baselines**: Cannot identify anomalies without knowing normal. Spend time on baseline documentation before hunting.
- **Query performance impact**: Broad queries against production SIEM during business hours can degrade analyst workflows. Schedule intensive hunts during off-peak hours.
- **Ignoring false positives systematically**: Track false positive rates per query. Queries with >80% FP rate should be refined or retired before operationalization.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 8a40bde6b8b7770b
-->

