---
name: Tespit etme-insider-data-exfiltration-via-dlp
description: tespit etme (s) insider data exfiltration by analyzing DLP policy violations, file access patterns, upload volume anomalies, and off-hours activity in endpoint and cloud logs. Uses pandas for behavioral
  analytics and statistical baselines. Use investigating yaparken insider threats or building user behavior analytics for data loss prevention.
tags:
- soc-operations
- exfiltration
- insider
- security-operations
- data
- fetih
- Tespit etme
- cybersecurity
- siber-güvenlik
triggers:
- alert
- cloud
- data
- Tespit etme
- email
- endpoint
- exfiltration
- incident
- insider
- log
- threat
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
adapted_for: fetih
---

# Detection Insider Data Exfiltration via Dlp


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme insider data exfiltration via dlp
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Analyze endpoint activity logs, cloud storage access, and email DLP events to tespit etmedata exfiltration patterns using behavioral baselines and statistical anomaly Tespit.

```python
import pandas as pd

df = pd.read_csv("file_activity.csv", parse_dates=["timestamp"])
baseline = df.groupby(["user", df["timestamp"].dt.date])["bytes_transferred"].sum()
user_avg = baseline.groupby("user").mean()

today = df[df["timestamp"].dt.date == pd.Timestamp.today().date()]
today_totals = today.groupby("user")["bytes_transferred"].sum()
anomalies = today_totals[today_totals > user_avg * 3]
```

Key indicators:
1. Upload volume exceeding 3x daily baseline
2. Erişim: files outside normal scope
3. Bulk downloads before resignation
4. Off-hours file access patterns
5. USB/external device usage spikes

## Örnekler

```python
df["hour"] = df["timestamp"].dt.hour
off_hours = df[(df["hour"] < 6) | (df["hour"] > 22)]
suspicious = off_hours.groupby("user").size().sort_values(ascending=False)
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 099567cd4248336e
-->

