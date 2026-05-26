---
name: Tespit etme-mimikatz-execution-patterns
description: tespit etmeMimikatz execution through command-line patterns, LSASS access signatures, binary indicators, and in-memory Tespit of known modules.
tags:
- threat-hunting
- siber-güvenlik
- mimikatz
- fetih
- mitre-attack
- credential-dumping
- cybersecurity
- edr
- t1003
- proactive-detection
triggers:
- alert
- anomali tespit
- Tespit etme
- endpoint
- execution
- hunting
- incident
- log
- mimikatz
- network
- password
- patterns
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Detection Mimikatz Execution Patterns


## Ne Zaman Kullanılır

- Proaktif olarak şu göstergeleri ararken: Tespit etme mimikatz execution patterns in the environment
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
| T1003.001 | LSASS Memory |
| T1003.006 | DCSync |
| T1558.003 | Kerberoasting |
| T1558.001 | Golden Ticket |

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

1. **Scenario 1**: Standard sekurlsa::logonpasswords credential dump
2. **Scenario 2**: PowerShell Invoke-Mimikatz reflective loading
3. **Scenario 3**: DCSync from non-DC host
4. **Scenario 4**: Golden ticket creation for persistence

## Output Format

```
Hunt ID: TH-Detect-[DATE]-[SEQ]
Technique: T1003.001
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
  hash: 39ce7e132ba67945
-->

