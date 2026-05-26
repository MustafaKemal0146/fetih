---
name: hunting-for-spearphishing-indicators
description: Hunt for spearphishing campaign indicators across email logs, endpoint telemetry, and network data to tespit etmetargeted email attacks.
tags:
- threat-hunting
- spearphishing
- t1566
- initial-access
- fetih
- mitre-attack
- cybersecurity
- email-security
- siber-güvenlik
- proactive-detection
triggers:
- alert
- anomali tespit
- endpoint
- hunting
- incident
- indicators
- log
- network
- phishing
- spearphishing
- tehdit ara
- tehdit avı
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Spearphishing Indicators


## Ne Zaman Kullanılır

- Proaktif olarak şu göstergeleri ararken: hunting for spearphishing indicators in the environment
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
| T1566.001 | Spearphishing Attachment |
| T1566.002 | Spearphishing Link |
| T1566.003 | Spearphishing via Service |

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

1. **Scenario 1**: Macro-enabled Excel executing PowerShell downloader
2. **Scenario 2**: HTML smuggling delivering ISO with LNK payload
3. **Scenario 3**: Credential harvesting link as SharePoint notification
4. **Scenario 4**: QR code phishing in PDF attachment

## Output Format

```
Hunt ID: TH-HUNTIN-[DATE]-[SEQ]
Technique: T1566.001
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
  hash: 02c85b629cf9cd2b
-->

