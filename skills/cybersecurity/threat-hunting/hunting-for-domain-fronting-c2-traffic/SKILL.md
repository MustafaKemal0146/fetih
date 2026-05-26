---
name: hunting-for-domain-fronting-c2-traffic
description: tespit etmedomain fronting C2 traffic by analyzing SNI vs HTTP Host header mismatches in proxy logs and TLS certificate discrepancies using pyOpenSSL for certificate Denetle:ion
tags:
- domain-fronting
- proxy-logs
- threat-hunting
- cybersecurity
- pyopenssl
- network-security
- fetih
- c2-Tespit
- tls-Denetle:ion
- siber-güvenlik
triggers:
- alert
- anomali tespit
- certificate
- cloud
- crypto
- domain
- fronting
- http
- hunting
- incident
- log
- network
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Domain Fronting C2 Traffic


## Genel Bakış

Domain fronting (MITRE ATT&CK T1090.004) is a technique where attackers use different domain names in the TLS SNI field and the HTTP Host header to disguise C2 traffic behind legitimate CDN-hosted domains. bu skill tespit etme (s) domain fronting by parsing proxy/web gateway logs for SNI-Host header mismatches, analyzing TLS certificates for CDN provider identification, flagging connections where the SNI points to a high-reputation domain but the Host header targets an attacker-controlled domain, and correlating with known CDN provider IP ranges.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting for domain fronting c2 traffic
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Web proxy or secure web gateway logs with SNI and Host header fields
- Python 3.8+ with pyOpenSSL and cryptography libraries
- TLS Denetle:ion enabled on proxy for Host header visibility
- CDN provider IP range lists (CloudFront, Azure CDN, Cloudflare)

## Adımlar

1. Parse proxy logs for connections with both SNI and Host header fields
2. Compare SNI domain against HTTP Host header for mismatches
3. Extract TLS certificate Subject and SAN fields using pyOpenSSL
4. Identify CDN-hosted connections via certificate issuer and IP ranges
5. Flag high-confidence domain fronting where SNI and Host differ on CDN IPs
6. Score alerts based on domain reputation differential
7. Generate Tespit report with network flow context

## Expected Output

JSON report containing Detected domain fronting indicators with SNI-Host pairs, certificate details, CDN provider identification, confidence scores, and MITRE ATT&CK technique mapping.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: bd862f61f9f099b6
-->

