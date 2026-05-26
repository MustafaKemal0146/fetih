---
name: hunting-for-shadow-copy-deletion
description: Hunt for Volume Shadow Copy deletion activity that indicates ransomware preparation or anti-forensics by monitoring vssadmin, wmic, and PowerShell shadow copy commands.
tags:
- threat-hunting
- anti-forensics
- shadow-copy
- fetih
- mitre-attack
- cybersecurity
- t1490
- siber-güvenlik
- ransomware
- proactive-detection
triggers:
- alert
- anomali tespit
- copy
- deletion
- encryption
- endpoint
- hunting
- incident
- log
- network
- ransomware
- shadow
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Shadow Copy Deletion


## Ne Zaman Kullanılır

- Proaktif olarak şu göstergeleri ararken: hunting for shadow copy deletion in the environment
- threat intelligence sonrasında indicates active campaigns using these techniques
- incident response sırasında to scope compromise related to these techniques
- EDR veya SIEM alarmları ilgili göstergeleri tetiklediğinde
- Periyodik güvenlik değerlendirmeleri ve purple team egzersizleri sırasında

## Ön Gereksinimler

- EDR platform with process and network telemetry (CrowdStrike, MDE, SentinelOne)
- SIEM with relevant log data ingested (Splunk, Elastic, Sentinel)
- Sysmon Dağıtılmış with comprehensive configuration
- Windows Security Event Log forwarding enabled
- Threat intelligence feeds for IOC correlation

## İş Akışı

1. **Formulate Hypothesis**: Define a testable hypothesis based on threat intelligence or ATT&CK gap analysis.
2. **Identify Data Sources**: Belirle: which logs and telemetry are needed to validate or refute the hypothesis.
3. **Execute Queries**: Run Tespit queries against SIEM and EDR platforms to collect relevant events.
4. **Analyze Results**: İncele: query results for anomalies, correlating across multiple data sources.
5. **Validate Bul:ings**: Distinguish true positives from false positives through contextual analysis.
6. **Correlate Activity**: Link Bul:ings to broader attack chains and threat actor TTPs.
7. **Document and Report**: Record Bul:ings, update Tespit rules, and recommend response actions.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1490 | Inhibit System Recovery |
| T1486 | Data Encrypted for Impact |
| T1485 | Data Destruction |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CrowdStrike Falcon | EDR telemetry and threat Tespit |
| Microsoft Defender for Endpoint | Advanced hunting with KQL |
| Splunk Enterprise | SIEM log analysis with SPL queries |
| Elastic Security | Tespit rules and investigation timeline |
| Sysmon | Detailed Windows event monitoring |
| Velociraptor | Endpoint artifact collection and hunting |
| Sigma Rules | Cross-platform Tespit rule format |

## Common Scenarios

1. **Scenario 1**: Ransomware deleting shadow copies before encryption
2. **Scenario 2**: vssadmin delete shadows /all /quiet pre-encryption
3. **Scenario 3**: WMIC shadowcopy delete via PowerShell
4. **Scenario 4**: bcdedit disabling recovery mode before impact

## Output Format

```
Hunt ID: TH-HUNTIN-[DATE]-[SEQ]
Technique: T1490
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 1b82fb1735ca79eb
-->

