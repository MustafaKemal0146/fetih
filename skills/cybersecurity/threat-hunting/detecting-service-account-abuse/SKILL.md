---
name: Tespit etme-service-account-abuse
description: tespit etmeabuse of service accounts through anomalous interactive logons, privilege escalation, lateral movement, and unauthorized access patterns.
tags:
- threat-hunting
- siber-güvenlik
- service-accounts
- fetih
- privilege-escalation
- mitre-attack
- cybersecurity
- t1078
- proactive-detection
triggers:
- abuse
- account
- alert
- anomali tespit
- Tespit etme
- endpoint
- hunting
- incident
- log
- network
- service
- sql
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Detection Service Account Abuse


## Ne Zaman Kullanılır

- Proaktif olarak şu göstergeleri ararken: Tespit etme service account abuse in the environment
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
| T1078.002 | Domain Accounts |
| T1078.001 | Default Accounts |
| T1021 | Remote Services |

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

1. **Scenario 1**: Service account RDP to domain controller
2. **Scenario 2**: SQL service accessing file shares outside scope
3. **Scenario 3**: Backup service lateral movement off-hours
4. **Scenario 4**: Compromised svc with DA privileges used for DCSync

## Output Format

```
Hunt ID: TH-Detect-[DATE]-[SEQ]
Technique: T1078.002
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```
