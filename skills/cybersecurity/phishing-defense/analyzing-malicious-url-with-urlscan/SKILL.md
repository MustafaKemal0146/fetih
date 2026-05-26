---
name: analyzing-malicious-url-with-urlscan
description: URLScan.io is a free service for scanning and analyzing suspicious URLs. It captures screenshots, DOM content, HTTP transactions, JavaScript behavior, and network connections of web pages in
  an isolat
tags:
- url-analysis
- cybersecurity
- dmarc
- phishing-defense
- threat-intelligence
- phishing
- fetih
- awareness
- social-engineering
- email-security
- siber-güvenlik
triggers:
- analyzing
- api
- certificate
- endpoint
- hash
- http
- incident
- log
- malicious
- network
- phishing
- threat
category: phishing-defense
source_subdomain: phishing-defense
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
adapted_for: fetih
---

# Analyzing Malicious Url with Urlscan


## Genel Bakış
URLScan.io is a free service for scanning and analyzing suspicious URLs. It captures screenshots, DOM content, HTTP transactions, JavaScript behavior, and network connections of web pages in an isolated environment. bu skill covers using URLScan's web interface and API to Araştır: phishing URLs, credential harvesting pages, and malicious redirects without exposing the analyst's system to risk.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing malicious url with urlscan
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler
- URLScan.io account (free tier available, API key for automation)
- Python 3.8+ with requests library
- Understanding of HTTP protocols and web technologies
- Familiarity with phishing URL patterns

## Key Concepts

### URLScan Capabilities
1. **Safe browsing**: Renders URLs in isolated Chromium instance
2. **Screenshot capture**: Visual snapshot of the rendered page
3. **DOM analysis**: Full HTML content after JavaScript execution
4. **Network log**: All HTTP requests made by the page (HAR format)
5. **Certificate analysis**: SSL/TLS certificate details
6. **Technology Tespit**: Identifies web frameworks and libraries
7. **IP/ASN mapping**: Infrastructure intelligence
8. **Verdict**: Community and automated classification

### Phishing URL Red Flags
- Newly registered domains (< 30 days)
- Free hosting services (Wix, GitHub Pages, Firebase)
- URL shorteners hiding final destination
- Excessive subdomain depth (login.microsoft.com.evil.com)
- Brand name in subdomain or path, not domain
- Non-standard ports
- Data URIs or base64-encoded content
- JavaScript-heavy pages with minimal HTML

## İş Akışı

### Adım 1: Submit URL to URLScan
```
Web: Şuraya git: https://urlscan.io and submit the suspicious URL
API: POST https://urlscan.io/api/v1/scan/
     Header: API-Key: your-api-key
     Body: {"url": "https://suspicious-url.com", "visibility": "private"}
```

### Adım 2: Analyze Results
- Review screenshot for brand impersonation
- Check redirects and final destination URL
- İncele: DOM for credential input forms
- Review network requests for data exfiltration endpoints
- Check SSL certificate validity and issuer

### Adım 3: Extract IOCs
- Domains and IPs contacted
- URLs in redirect chain
- SHA-256 hashes of page resources
- JavaScript file hashes

### Adım 4: Cross-Reference with Threat Intelligence
Use the `scripts/process.py` to automate URL scanning, extract IOCs, and cross-reference with VirusTotal, PhishTank, and Google Safe Browsing.

## Tools & Resources
- **URLScan.io**: https://urlscan.io/
- **URLScan API**: https://urlscan.io/docs/api/
- **VirusTotal URL Scanner**: https://www.virustotal.com/
- **PhishTank**: https://phishtank.org/
- **Google Safe Browsing**: https://transparencyreport.google.com/safe-browsing/search
- **Any.Run**: https://any.run/ (interactive sandbox)
- **Hybrid Analysis**: https://www.hybrid-analysis.com/

## Doğrulama
- Successfully scan a suspicious URL via API
- Extract screenshot and identify brand impersonation
- Document complete redirect chain
- Generate IOC list from scan results
- Cross-reference Bul:ings with at least 2 threat intelligence sources

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 984115b0d331411b
-->

