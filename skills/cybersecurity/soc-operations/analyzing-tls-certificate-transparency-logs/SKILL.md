---
name: analyzing-tls-certificate-transparency-logs
description: Queries Certificate Transparency logs via crt.sh and pycrtsh to tespit etmephishing domains, unauthorized certificate issuance, and shadow IT. Monitors newly issued certificates for typosquatting
  and brand impersonation using Levenshtein distance. Use for proactive phishing domain Tespit and certificate monitoring.
tags:
- soc-operations
- transparency
- security-operations
- certificate
- analyzing
- fetih
- cybersecurity
- siber-güvenlik
- tls
triggers:
- analyzing
- certificate
- incident
- log
- logs
- phishing
- threat
- transparency
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
adapted_for: fetih
---

# Analyzing Tls Certificate Transparency Logs


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing tls certificate transparency logs
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Query crt.sh Certificate Transparency database to Bul: certificates issued for
domains similar to your organization's brand, Tespit etme phishing infrastructure.

```python
from pycrtsh import Crtsh

c = Crtsh()
certs = c.search("example.com")
for cert in certs:
    print(cert["id"], cert["name_value"])

details = c.get(certs[0]["id"], type="id")
```

Key analysis steps:
1. Query crt.sh for all certificates matching your domain pattern
2. Identify certificates with typosquatting variations (Levenshtein distance)
3. Flag certificates from unexpected CAs
4. Monitor for wildcard certificates on suspicious subdomains
5. Cross-reference with known phishing infrastructure

## Örnekler

```python
from pycrtsh import Crtsh
c = Crtsh()
certs = c.search("%.example.com")
for cert in certs:
    print(f"Issuer: {cert.get('issuer_name')}, Domain: {cert.get('name_value')}")
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 21cbf7ea56fd7ec0
-->

