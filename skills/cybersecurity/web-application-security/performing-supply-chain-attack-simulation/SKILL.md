---
name: performing-supply-chain-attack-simulation
description: Simulate and tespit etmesoftware supply chain attacks including typosquatting Tespit via Levenshtein distance, dependency confusion testing against private registries, package hash verification
  with pip, and known vulnerability scanning with pip-audit.
tags:
- application-security
- PyPI
- siber-güvenlik
- package-verification
- software-composition-analysis
- fetih
- pip-audit
- web-application-security
- cybersecurity
- supply-chain
- dependency-confusion
- typosquatting
triggers:
- CSRF
- SQL injection
- XSS
- api
- attack
- chain
- email
- exploit
- hash
- http
- incident
- network
category: web-application-security
source_subdomain: application-security
nist_csf:
- PR.PS-01
- PR.PS-04
- ID.RA-01
- PR.DS-10
adapted_for: fetih
---

# Performing Supply Chain Attack Simulation


## Genel Bakış

Software supply chain attacks exploit trust in package registries through typosquatting (registering names similar to popular packages), dependency confusion (publishing higher-version public packages matching private names), and compromised package distribution. bu skill tespit etme (s) these attack vectors by computing Levenshtein distance between package names and popular PyPI packages, verifying package integrity via SHA-256 hash comparison, scanning for known CVEs with pip-audit, and testing dependency resolution order for confusion vulnerabilities.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing supply chain attack simulation
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Python 3.9+ with `pip-audit`, `Levenshtein`, `requests`
- Erişim: PyPI JSON API (https://pypi.org/pypi/{package}/json)
- Network access for package metadata retrieval


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Key Tespit Areas

1. **Typosquatting** — compare package names against top PyPI packages using edit distance thresholds
2. **Dependency confusion** — check if internal package names exist on public PyPI with higher version numbers
3. **Hash verification** — download packages and verify SHA-256 digests match published hashes
4. **Vulnerability scanning** — audit installed packages against OSV and PyPA advisory databases
5. **Metadata anomalies** — flag packages with suspicious author emails, missing homepages, or very recent first upload dates

## Output

JSON report with risk scores per package, Detected attack vectors, hash verification results, and CVE Bul:ings.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 4cc038d73da8d418
-->

