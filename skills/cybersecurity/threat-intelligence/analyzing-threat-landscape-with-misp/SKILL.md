---
name: analyzing-threat-landscape-with-misp
description: Şunu analiz et: threat landscape using MISP (Malware Information Sharing Platform) by querying event statistics, attribute distributions, threat actor galaxy clusters, and tag trends over time.
  Uses PyMISP to pull event data, compute IOC type breakdowns, identify top threat actors and malware families, and generate threat landscape reports with temporal trends.
tags:
- threat-intelligence
- landscape
- analyzing
- threat
- fetih
- cybersecurity
- with
- siber-güvenlik
triggers:
- IOC
- analyzing
- api
- hash
- http
- incident
- indicator of compromise
- landscape
- misp
- phishing
- tehdit aktörü
- tehdit istihbaratı
category: threat-intelligence
source_subdomain: threat-intelligence
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
---

# Analyzing Threat Landscape with Misp


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing threat landscape with misp
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with threat intelligence concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install pymisp`
2. Configure MISP URL and API key.
3. Run the agent to generate threat landscape analysis:
   - Pull event statistics by threat level and date range
   - Analyze attribute type distributions (IP, domain, hash, URL)
   - Identify top MITRE ATT&CK techniques from event tags
   - Track threat actor activity via galaxy clusters
   - Generate temporal trend analysis of IOC submissions

```bash
python scripts/agent.py --misp-url https://misp.local --api-key YOUR_KEY --days 90 --output landscape_report.json
```

## Örnekler

### Threat Landscape Summary
```
Period: Last 90 days
Events analyzed: 1,247
Top threat level: High (43%)
Top attribute type: ip-dst (31%), domain (22%), sha256 (18%)
Top MITRE technique: T1566 Phishing (89 events)
Top threat actor: APT28 (34 events)
```
