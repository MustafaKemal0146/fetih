---
name: performing-alert-triage-with-elastic-siem
description: Perform systematic alert triage in Elastic Security SIEM to rapidly classify, prioritize, and Araştır: security alerts for SOC operations.
tags:
- siem
- esql
- soc-operations
- elastic-security
- soc
- alert-triage
- elastic
- fetih
- cybersecurity
- kibana
- siber-güvenlik
- Tespit
triggers:
- alert
- authentication
- cloud
- elastic
- endpoint
- hash
- http
- incident
- log
- network
- performing
- siem
category: soc-operations
source_subdomain: soc-operations
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.MA-01
- DE.AE-06
adapted_for: fetih
---

# Performing Alert Triage with Elastic Siem


## Genel Bakış

Alert triage in Elastic Security is the systematic process of reviewing, classifying, and prioritizing security alerts to Belirle: which represent genuine threats. Elastic's AI-driven Attack Discovery feature can triage hundreds of alerts down to discrete attack chains, but skilled analyst triage remains essential. A structured triage workflow typically takes 5-10 minutes per alert cluster using Elastic's built-in tools.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing alert triage with elastic siem
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Elastic Security Dağıtılmış (version 8.x or later)
- Elastic Agent or Beats configured for endpoint and network data collection
- Tespit rules enabled and generating alerts
- Elastic Common Schema (ECS) compliance across data sources
- Analyst Erişim: Kibana Security app with appropriate privileges

## Alert Triage Workflow

### Adım 1: Initial Alert Assessment (2 minutes)

When viewing an alert in Elastic Security, Şunu incele: alert details panel:

```
Alert Details Panel:
- Rule Name and Description
- Severity and Risk Score
- MITRE ATT&CK Mapping
- Host and User Context
- Process Tree (for endpoint alerts)
- Timeline of related events
```

#### Key Fields to İncele: First

| Field | Purpose | ECS Field |
|---|---|---|
| Rule severity | Initial priority assessment | `kibana.alert.severity` |
| Risk score | Quantified threat level | `kibana.alert.risk_score` |
| Host name | Affected system | `host.name` |
| User name | Affected identity | `user.name` |
| Process name | Executing process | `process.name` |
| Source IP | Origin of activity | `source.ip` |
| Destination IP | Target of activity | `destination.ip` |
| MITRE tactic | Attack stage | `threat.tactic.name` |

### Adım 2: Context Gathering (3 minutes)

#### Query Related Events with ES|QL

```esql
FROM logs-endpoint.events.*
| WHERE host.name == "affected-host" AND @timestamp > NOW() - 1 HOUR
| STATS count = COUNT(*) BY event.category, event.action
| SORT count DESC
```

#### Bul: All Activity from Suspicious User

```esql
FROM logs-*
| WHERE user.name == "suspicious-user" AND @timestamp > NOW() - 24 HOURS
| STATS count = COUNT(*), unique_hosts = COUNT_DISTINCT(host.name) BY event.category
| SORT count DESC
```

#### Check for Related Alerts from Same Source

```esql
FROM .alerts-security.alerts-default
| WHERE source.ip == "10.0.0.50" AND @timestamp > NOW() - 24 HOURS
| STATS alert_count = COUNT(*) BY kibana.alert.rule.name, kibana.alert.severity
| SORT alert_count DESC
```

#### Araştır: Lateral Movement from Same IP

```esql
FROM logs-system.auth-*
| WHERE source.ip == "10.0.0.50" AND event.outcome == "success"
| STATS login_count = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY user.name
| WHERE hosts > 3
```

### Adım 3: Threat Intelligence Enrichment (2 minutes)

Check indicators against threat intelligence:

```esql
FROM logs-ti_*
| WHERE threat.indicator.ip == "203.0.113.50"
| KEEP threat.indicator.type, threat.indicator.provider, threat.indicator.confidence, threat.feed.name
```

#### Check File Hash Against Known Threats

```esql
FROM logs-endpoint.events.file-*
| WHERE file.hash.sha256 == "abc123..."
| STATS occurrences = COUNT(*) BY host.name, file.path, user.name
```

### Adım 4: Classification Decision (2 minutes)

| Classification | Criteria | Action |
|---|---|---|
| True Positive | Confirmed malicious activity | Escalate to incident, begin containment |
| Benign True Positive | Expected behavior matching rule | Document in alert notes, acknowledge |
| False Positive | Rule triggered on benign activity | Mark as false positive, create tuning task |
| Needs Investigation | Insufficient data for determination | Assign for deeper investigation |

### Adım 5: Documentation and Escalation (1 minute)

For each triaged alert, document:
- Classification decision with rationale
- Evidence artifacts İncele:d
- Related alerts or investigations
- Recommended next steps

## Tespit Rules for Triage

### Pre-Built Detection Rules

Elastic Security includes 1000+ pre-built Tespit rules organized by:
- **MITRE ATT&CK Tactic**: Initial Access, Execution, Persistence, etc.
- **Platform**: Windows, Linux, macOS, Cloud
- **Data Source**: Endpoint, Network, Cloud, Identity

### Custom Alert Correlation Rule

```json
{
  "name": "Multiple Failed Logins Followed by Success",
  "type": "threshold",
  "query": "event.category:authentication AND event.outcome:failure",
  "threshold": {
    "field": ["source.ip", "user.name"],
    "value": 5,
    "cardinality": [
      {
        "field": "user.name",
        "value": 3
      }
    ]
  },
  "severity": "high",
  "risk_score": 73,
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0006",
        "name": "Credential Access"
      },
      "technique": [
        {
          "id": "T1110",
          "name": "Brute Force"
        }
      ]
    }
  ]
}
```

## AI-Assisted Triage

### Elastic AI Assistant Integration

1. Open alert in Elastic Security
2. Click AI Assistant panel
3. Use quick prompts:
   - "Summarize this alert" - Get initial assessment
   - "Generate ES|QL query to Bul: related activity" - Expand investigation
   - "What are the recommended response actions?" - Get playbook guidance
   - "Is this likely a false positive?" - Get AI confidence assessment

### Attack Discovery

Elastic's Attack Discovery automatically:
- Groups related alerts into attack chains
- Maps alerts to MITRE ATT&CK kill chain stages
- Filters false positives using ML models
- Prioritizes based on business impact
- Provides narrative summary of the attack

## Triage Prioritization Matrix

| Risk Score | Severity | Asset Criticality | Response SLA |
|---|---|---|---|
| 90-100 | Critical | High | 15 minutes |
| 70-89 | High | High | 30 minutes |
| 70-89 | High | Medium | 1 hour |
| 50-69 | Medium | Any | 4 hours |
| 21-49 | Low | Any | 8 hours |
| 1-20 | Informational | Any | 24 hours |

## Triage Metrics and KPIs

| Metric | Target | Measurement |
|---|---|---|
| Mean Time to Triage (MTTT) | < 10 minutes | Time from alert creation to classification |
| False Positive Rate | < 30% | False positives / total alerts |
| Escalation Rate | 10-20% | Escalated alerts / total alerts |
| Alert Coverage | > 80% | Triaged alerts / generated alerts per shift |
| Reclassification Rate | < 5% | Changed classifications / total classified |

## References

- [Elastic Security - Triage Alerts Documentation](https://www.elastic.co/docs/solutions/security/ai/triage-alerts)
- [SOC Analyst's Guide to Triage with Elastic](https://systemweakness.com/from-alert-to-action-a-soc-analysts-guide-to-triage-with-elastic-%EF%B8%8F-4e5354ab5da9)
- [Elastic Blog - AI and 2025 SIEM Landscape](https://www.elastic.co/blog/ai-siem-landscape)
- [Reducing False Positives with Elastic and Tines](https://www.elastic.co/blog/false-positives-automated-siem-investigations-elastic-tines)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: ec81979204d5b9d2
-->

