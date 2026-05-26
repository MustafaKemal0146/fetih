---
name: hunting-for-living-off-the-cloud-techniques
description: Hunt for adversary abuse of legitimate cloud services for C2, data staging, and exfiltration including abuse of Azure, AWS, GCP services, and SaaS platforms.
tags:
- threat-hunting
- lotc
- cloud-abuse
- c2
- saas
- fetih
- mitre-attack
- cybersecurity
- siber-güvenlik
- proactive-detection
triggers:
- alert
- anomali tespit
- api
- cloud
- endpoint
- hunting
- incident
- living
- log
- malware
- network
- techniques
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Living Off the Cloud Techniques


## Ne Zaman Kullanılır

- Proaktif olarak şu göstergeleri ararken: hunting for living off the cloud techniques in the environment
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
| T1102 | Web Service |
| T1567 | Exfiltration Over Web Service |
| T1537 | Transfer Data to Cloud Account |

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

1. **Scenario 1**: C2 over Discord webhooks for command delivery
2. **Scenario 2**: Data exfiltration to Telegram bot API
3. **Scenario 3**: Malware using Azure Functions for dynamic C2
4. **Scenario 4**: Staging stolen data on Google Docs or Notion pages

## Output Format

```
Hunt ID: TH-HUNTIN-[DATE]-[SEQ]
Technique: T1102
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
  hash: cc4d810e6ed18576
-->

