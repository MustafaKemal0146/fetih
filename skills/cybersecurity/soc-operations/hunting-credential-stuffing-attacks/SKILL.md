---
name: hunting-credential-stuffing-attacks
description: tespit etme (s) credential stuffing attacks by analyzing authentication logs for login velocity anomalies, ASN diversity, password spray patterns, and geographic distribution of failed logins. Uses
  statistical analysis on Splunk or raw log data. Use investigating yaparken account takeover campaigns or building Tespit rules for auth abuse.
tags:
- soc-operations
- security-operations
- fetih
- hunting
- attacks
- cybersecurity
- stuffing
- siber-güvenlik
- credential
triggers:
- attacks
- authentication
- cloud
- credential
- hash
- hunting
- incident
- log
- password
- stuffing
- threat
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Hunting Credential Stuffing Attacks


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting credential stuffing attacks
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Analyze authentication logs to tespit etmecredential stuffing by identifying patterns
of distributed login failures, high IP diversity, and suspicious ASN distribution.

```python
import pandas as pd
from collections import Counter

df = pd.read_csv("auth_logs.csv", parse_dates=["timestamp"])

ip_per_account = df[df["status"] == "failed"].groupby("username")["source_ip"].nunique()
accounts_under_attack = ip_per_account[ip_per_account > 50]
```

Key Tespit indicators:
1. High unique source IPs per failed username
2. Low success rate across many accounts (< 1%)
3. ASN concentration from cloud/proxy providers
4. Geographic impossibility (same account, distant locations)
5. User-agent uniformity across distributed IPs

## Örnekler

```python
spray = df[df["status"] == "failed"].groupby(["source_ip", "password_hash"]).agg(
    accounts=("username", "nunique")).reset_index()
sprays = spray[spray["accounts"] > 10]
```
