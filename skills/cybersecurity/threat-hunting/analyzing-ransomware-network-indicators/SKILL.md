---
name: analyzing-ransomware-network-indicators
description: Identify ransomware network indicators including C2 beaconing patterns, TOR exit node connections, data exfiltration flows, and encryption key exchange via Zeek conn.log and NetFlow analysis
tags:
- netflow
- threat-hunting
- exfiltration
- network-forensics
- zeek
- fetih
- cybersecurity
- c2-beaconing
- siber-güvenlik
- ransomware
- tor
triggers:
- alert
- analyzing
- anomali tespit
- dns
- encryption
- hunting
- incident
- indicators
- log
- network
- ransomware
- tehdit ara
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Analyzing Ransomware Network Indicators


## Genel Bakış

Before and during ransomware execution, adversaries establish C2 channels, exfiltrate data, and download encryption keys. bu skill analyzes Zeek conn.log and NetFlow data to tespit etmebeaconing patterns (regular-interval callbacks), connections to known TOR exit nodes, large outbound data transfers, and suspicious DNS activity associated with ransomware families.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing ransomware network indicators
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Zeek conn.log files or NetFlow CSV/JSON exports
- Python 3.8+ with standard library
- TOR exit node list (fetched from Tor Project or threat intel feeds)
- Optional: Known ransomware C2 IOC list

## Adımlar

1. **Parse Connection Logs** — Ingest Zeek conn.log (TSV) or NetFlow records into structured format
2. **tespit etmeBeaconing Patterns** — Calculate connection interval statistics (mean, stddev, coefficient of variation) to identify periodic callbacks
3. **Check TOR Exit Node Connections** — Cross-reference destination IPs against current TOR exit node list
4. **Identify Data Exfiltration** — Flag connections with unusually high outbound byte ratios to external IPs
5. **Analyze DNS Patterns** — tespit etmeDGA-like domain queries and high-entropy subdomains
6. **Score and Correlate** — Apply composite risk scoring across all indicator types
7. **Generate Report** — Produce structured report with timeline and MITRE ATT&CK mapping

## Expected Output

- JSON report with beaconing Tespits and interval statistics
- TOR exit node connection alerts
- Data exfiltration flow analysis
- Composite ransomware risk score with MITRE mapping (T1071, T1573, T1041)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 81e01949b355c914
-->

