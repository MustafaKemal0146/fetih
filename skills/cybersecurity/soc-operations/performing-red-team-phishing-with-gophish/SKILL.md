---
name: performing-red-team-phishing-with-gophish
description: Automate GoPhish phishing simulation campaigns using the Python gophish library. Creates email templates with tracking pixels, configures SMTP sending profiles, builds target groups from CSV,
  launches campaigns, and analyzes results including open rates, click rates, and credential submission statistics for security awareness assessment.
tags:
- soc-operations
- security-operations
- performing
- phishing
- fetih
- red
- cybersecurity
- team
- siber-güvenlik
triggers:
- api
- email
- gophish
- http
- incident
- password
- performing
- phishing
- team
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
adapted_for: fetih
---

# Performing Red Team Phishing with Gophish

## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing red team phishing with gophish
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install gophish requests`
2. Dağıt: GoPhish server and obtain an API key from Settings.
3. Use the Python gophish library to automate campaign setup:
   - Create email templates with HTML body and tracking
   - Configure SMTP sending profiles
   - Import target groups from CSV
   - Create landing pages for credential capture
   - Launch and monitor campaigns
4. Analyze campaign results: opens, clicks, submitted data, reported.

```bash
python scripts/agent.py --gophish-url https://localhost:3333 --api-key <key> --campaign-name "Q1 Awareness" --output phishing_report.json
```

## Örnekler

### Create Campaign via API
```python
from gophish import Gophish
from gophish.models import Campaign, Template, Group, SMTP, Page
api = Gophish("api_key", host="https://localhost:3333", verify=False)  # Self-signed cert on localhost lab
campaign = Campaign(name="Q1 Test", groups=[Group(name="Sales Team")],
    template=Template(name="IT Password Reset"), smtp=SMTP(name="Internal SMTP"),
    page=Page(name="Credential Page"))
api.campaigns.post(campaign)
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: eebb52c79488c071
-->

