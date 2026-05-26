---
name: performing-network-traffic-analysis-with-tshark
description: Automate network traffic analysis using tshark and pyshark for protocol statistics, suspicious flow Tespit, DNS anomaly identification, and IOC extraction from PCAP files
tags:
- traffic-analysis
- network-forensics
- wireshark
- pcap
- tshark
- pyshark
- network-security
- fetih
- cybersecurity
- packet-analysis
- siber-güvenlik
triggers:
- IDS
- IPS
- analysis
- ağ güvenliği
- dns
- firewall
- http
- incident
- network
- network security
- performing
- threat
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
adapted_for: fetih
---

# Performing Network Traffic Analysis with Tshark


## Genel Bakış

bu skill automates packet capture analysis using tshark (Wireshark CLI) and pyshark (Python wrapper). It extracts protocol distribution statistics, identifies suspicious network flows (port scans, beaconing, data exfiltration), extracts IOCs (IPs, domains, URLs), and tespit etme (s) DNS tunneling patterns from PCAP files.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing network traffic analysis with tshark
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- tshark (Wireshark CLI) installed and in PATH
- Python 3.8+ with pyshark library
- PCAP or PCAPNG capture file for analysis

## Adımlar

1. **Extract Protocol Statistics** — Generate protocol hierarchy and conversation statistics from the capture
2. **Identify Top Talkers** — Rank source/destination IPs by volume and connection count
3. **tespit etmeSuspicious Flows** — Flag port scanning patterns, unusual port usage, and high-frequency connections
4. **Extract Network IOCs** — Pull unique IPs, domains from DNS queries, and URLs from HTTP traffic
5. **Analyze DNS Traffic** — tespit etmeDNS tunneling via high-entropy subdomain queries and excessive TXT records
6. **Şunu üret:nalysis Report** — Produce structured report with flow summaries and threat indicators

## Expected Output

- JSON report with protocol statistics and top talkers
- Suspicious flow Tespits with severity ratings
- Extracted IOCs (IPs, domains, URLs)
- DNS anomaly analysis results

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: c861b0b0bc42c22d
-->

