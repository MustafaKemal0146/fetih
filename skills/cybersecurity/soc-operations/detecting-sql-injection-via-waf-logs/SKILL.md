---
name: Tespit etme-sql-injection-via-waf-logs
description: Analyze WAF (ModSecurity/AWS WAF/Cloudflare) logs to tespit etmeSQL injection attack campaigns. Parses ModSecurity audit logs and JSON WAF event logs to identify SQLi patterns (UNION SELECT, OR
  1=1, SLEEP(), BENCHMARK()), tracks attack sources, correlates multi-stage injection attempts, and generates incident reports with OWASP classification.
tags:
- soc-operations
- cybersecurity
- security-operations
- fetih
- Tespit etme
- sql
- via
- siber-güvenlik
- injection
triggers:
- api
- cloud
- Tespit etme
- incident
- injection
- log
- logs
- password
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

# Detection Sql Injection via Waf Logs


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme sql injection via waf logs
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests`
2. Collect WAF logs (ModSecurity audit log, AWS WAF JSON logs, or Cloudflare firewall events).
3. Run the agent to parse and analyze:
   - tespit etmeSQLi payloads via 15+ regex patterns
   - Classify attacks by OWASP injection type (classic, blind, time-based, UNION-based)
   - Identify persistent attackers by IP clustering
   - Correlate multi-request injection campaigns
   - Calculate attack success probability based on response codes

```bash
python scripts/agent.py --log-file /var/log/modsec_audit.log --format modsecurity --output sqli_report.json
```

## Örnekler

### ModSecurity SQLi Tespit
```
Rule 942100 triggered: SQL Injection Attack Detected via libinjection
URI: /api/users?id=1' UNION SELECT username,password FROM users--
Source IP: 203.0.113.42 (47 requests in 5 minutes)
Classification: UNION-based SQLi campaign
```
