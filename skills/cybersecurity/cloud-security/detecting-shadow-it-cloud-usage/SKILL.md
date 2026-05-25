---
name: Tespit etme-shadow-it-cloud-usage
description: tespit etmeunauthorized SaaS and cloud service usage (shadow IT) by analyzing proxy logs, DNS query logs, and netflow data using Python pandas for traffic pattern analysis and domain classification.
tags:
- pandas
- proxy-logs
- netflow
- SaaS-discovery
- DNS-analysis
- shadow-IT
- fetih
- cloud-security
- cybersecurity
- siber-güvenlik
triggers:
- AWS
- Azure
- GCP
- bulut güvenliği
- cloud
- cloud security
- Tespit etme
- dns
- email
- incident
- log
- network
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detection Shadow It Cloud Usage


## Genel Bakış

Shadow IT refers to unauthorized SaaS applications and cloud services used without IT approval. bu skill analyzes proxy logs, DNS query logs, and firewall/netflow data to identify unauthorized cloud service usage, classify discovered domains against known SaaS categories, measure data transfer volumes, and flag high-risk services based on security posture and compliance requirements.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme shadow it cloud usage
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Python 3.9+ with `pandas`, `tldextract`
- Proxy logs (Squid, Zscaler, or Palo Alto format) or DNS query logs
- SaaS application catalog/blocklist for classification
- Network firewall logs with FQDN resolution (optional)

## Adımlar

1. Parse proxy access logs and extract destination domains with traffic volumes
2. Parse DNS query logs to identify resolved cloud service domains
3. Aggregate traffic by domain using pandas — total bytes, request counts, unique users
4. Classify domains against known SaaS categories (storage, email, dev tools, AI)
5. Flag unauthorized services not on the approved application list
6. Calculate risk scores based on data volume, user count, and service category
7. Generate shadow IT discovery report with remediation recommendations

## Expected Output

- JSON report listing discovered cloud services with traffic volumes, user counts, risk scores, and approval status
- Top unauthorized services ranked by data exfiltration risk
