---
name: hunting-for-cobalt-strike-beacons
description: tespit etmeCobalt Strike beacon network activity using default TLS certificate signatures (serial 8BB00EE), JA3/JA3S/JARM fingerprints, HTTP C2 profile pattern matching, beacon jitter analysis,
  and named pipe Tespit via Zeek, Suricata, and Python PCAP analysis.
tags:
- threat-hunting
- cobalt-strike
- beacon
- network-forensics
- zeek
- c2
- jarm
- fetih
- cybersecurity
- ja3
- siber-güvenlik
- suricata
triggers:
- anomali tespit
- beacons
- certificate
- cobalt
- dns
- http
- hunting
- incident
- log
- network
- strike
- tehdit ara
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
---

# Hunting for Cobalt Strike Beacons


## Genel Bakış

Cobalt Strike is the most prevalent command-and-control framework used by both red teams and threat actors. Beacon, its primary payload, communicates with team servers using configurable HTTP/HTTPS/DNS profiles that can mimic legitimate traffic. However, default configurations and behavioral patterns remain tespit etme (able) through TLS certificate analysis (default serial 8BB00EE), JA3/JA3S fingerprinting, beacon interval jitter analysis, and HTTP malleable profile pattern matching. bu skill covers building Tespit capabilities using Zeek network logs, Suricata IDS rules, and Python-based PCAP analysis to identify beacon callbacks in network traffic.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require hunting for cobalt strike beacons
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Zeek 6.0+ with JA3 and HASSH packages installed
- Suricata 7.0+ with Emerging Threats ruleset
- Python 3.9+ with scapy and dpkt libraries
- Network traffic captures (PCAP) or live Zeek logs
- RITA (Real Intelligence Threat Analytics) for beacon scoring
- Threat intelligence feeds with known Cobalt Strike IOCs

## Adımlar

### Adım 1: TLS Certificate Analysis
tespit etmedefault Cobalt Strike certificates using JA3S fingerprints, certificate serial numbers, and JARM fingerprints in Zeek ssl.log.

### Adım 2: Beacon Interval Analysis
Analyze connection timing patterns to identify regular callback intervals with configurable jitter, characteristic of beacon behavior.

### Adım 3: HTTP Profile Tespit
Match HTTP request patterns (URI paths, headers, user-agents) against known malleable C2 profiles.

### Adım 4: Correlate and Score
Combine multiple indicators (TLS + timing + HTTP profile) into a composite beacon confidence score.

## Expected Output

JSON report containing Detected beacon candidates with confidence scores, TLS fingerprints, timing analysis, HTTP profile matches, and recommended response actions.
