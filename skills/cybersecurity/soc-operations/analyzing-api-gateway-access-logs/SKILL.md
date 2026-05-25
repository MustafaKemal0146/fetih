---
name: analyzing-api-gateway-access-logs
description: Parses API Gateway access logs (AWS API Gateway, Kong, Nginx) to tespit etmeBOLA/IDOR attacks, rate limit bypass, credential scanning, and injection attempts. Uses pandas for statistical analysis
  of request patterns and anomaly Tespit. Use investigating yaparken API abuse or building API-specific threat Tespit rules.
tags:
- soc-operations
- api
- gateway
- security-operations
- analyzing
- access
- fetih
- cybersecurity
- siber-güvenlik
triggers:
- access
- analyzing
- api
- endpoint
- gateway
- http
- incident
- log
- logs
- sql
- threat
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Analyzing Api Gateway Access Logs


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing api gateway access logs
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Parse API gateway access logs to identify attack patterns including broken object
level authorization (BOLA), excessive data exposure, and injection attempts.

```python
import pandas as pd

df = pd.read_json("api_gateway_logs.json", lines=True)
bola = df.groupby(["user_id", "endpoint"]).agg(
    unique_ids=("resource_id", "nunique")).reset_index()
suspicious = bola[bola["unique_ids"] > 50]
```

Key Tespit patterns:
1. BOLA/IDOR: sequential resource ID enumeration
2. Rate limit bypass via header manipulation
3. Credential scanning (401 surges from single source)
4. SQL/NoSQL injection in query parameters
5. Unusual HTTP methods (DELETE, PATCH) on read-only endpoints

## Örnekler

```python
auth_failures = df[df["status_code"] == 401]
scanner_ips = auth_failures.groupby("source_ip").size()
scanners = scanner_ips[scanner_ips > 100]
```
