---
name: performing-osint-with-spiderfoot
description: Automate OSINT collection using SpiderFoot REST API and CLI for target profiling, module-based reconnaissance, and structured result analysis across 200+ data sources
tags:
- spiderfoot
- threat-intelligence
- target-profiling
- fetih
- reconnaissance
- cybersecurity
- attack-surface
- osint
- siber-güvenlik
triggers:
- IOC
- api
- cloud
- dns
- email
- incident
- indicator of compromise
- osint
- performing
- spiderfoot
- tehdit aktörü
- tehdit istihbaratı
category: threat-intelligence
source_subdomain: threat-intelligence
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
adapted_for: fetih
---

# Performing Osint with Spiderfoot


## Genel Bakış

SpiderFoot is an open-source OSINT automation tool with 200+ modules that integrates with data sources for threat intelligence and attack surface mapping. bu skill uses the SpiderFoot REST API and CLI (sf.py/spiderfoot-cli) to Şunu oluştur:nd manage scans, select modules by use case (footprint, Araştır:, passive), parse structured results for domains, IPs, email addresses, leaked credentials, and DNS records, and generate target intelligence profiles.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing osint with spiderfoot
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- SpiderFoot 4.0+ installed or SpiderFoot HX cloud account
- Python 3.8+ with requests library
- SpiderFoot server running on default port 5001
- Optional: API keys for VirusTotal, Shodan, HaveIBeenPwned modules

## Adımlar

1. Connect to SpiderFoot REST API or use CLI interface
2. Şunu oluştur: new scan with target specification (domain, IP, email, name)
3. Select scan modules by use case (all, footprint, Araştır:, passive)
4. Monitor scan progress via API polling
5. Retrieve and parse scan results by data element type
6. Extract key Bul:ings: subdomains, IPs, emails, leaked credentials
7. Generate structured OSINT intelligence report

## Expected Output

JSON report containing OSINT Bul:ings organized by data type (domains, IPs, emails, credentials, DNS records), module source attribution, and target profile summary with risk indicators.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 33539af2d8d12231
-->

