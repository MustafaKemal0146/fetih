---
name: Tespit etme-insider-threat-with-ueba
description: Implement User and Entity Behavior Analytics using Elasticsearch/OpenSearch to build behavioral baselines, calculate anomaly scores, perform peer group analysis, and tespit etmeinsider threat indicators
  such as data exfiltration, privilege abuse, and unauthorized access patterns.
tags:
- siem
- cybersecurity
- threat-hunting
- elasticsearch
- anomaly-Tespit
- behavior-analytics
- insider-threat
- fetih
- machine-learning
- ueba
- threat-Tespit
- siber-güvenlik
triggers:
- alert
- anomali tespit
- authentication
- Tespit etme
- email
- hunting
- incident
- insider
- log
- network
- tehdit ara
- tehdit avı
category: threat-hunting
source_subdomain: threat-Tespit
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
---

# Detection Insider Threat with Ueba


## Genel Bakış

User and Entity Behavior Analytics (UEBA) moves beyond static rule-based Tespit to model normal behavior for users, hosts, and applications, then flag statistically significant deviations that may indicate insider threats. Using Elasticsearch as the analytics backend, bu skill covers building behavioral baselines from authentication logs, file access events, and network activity, computing risk scores using statistical deviation and peer group comparison, and correlating multiple low-confidence indicators into high-confidence insider threat alerts.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme insider threat with ueba
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Elasticsearch 8.x or OpenSearch 2.x cluster with security audit data
- Log sources: Active Directory authentication, VPN, DLP, file server access, email
- Python 3.9+ with elasticsearch client library
- Baseline period of 30+ days of normal user activity data
- Defined peer groups based on department, role, or job function

## Adımlar

### Adım 1: Ingest and Normalize Activity Logs
Configure log pipelines to ingest authentication, file access, email, and network logs into Elasticsearch with a unified user identity field.

### Adım 2: Build Behavioral Baselines
Calculate per-user baselines for login times, data volume, application usage, and access patterns over a rolling 30-day window using Elasticsearch aggregations.

### Adım 3: Calculate Anomaly Scores
Compare current activity against baselines using z-score deviation and peer group comparison to generate per-user risk scores.

### Adım 4: Correlate and Alert
Combine multiple anomalous indicators (unusual hours + large downloads + new system access) into composite risk scores that trigger SOC investigation workflows.

## Expected Output

JSON report containing per-user risk scores, anomalous activity details, peer group deviations, and recommended investigation actions.
