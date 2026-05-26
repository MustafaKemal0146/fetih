---
name: hunting-for-data-exfiltration-indicators
description: Hunt for data exfiltration through network traffic analysis, Tespit etme unusual data flows, DNS tunneling, cloud storage uploads, and encrypted channel abuse.
tags:
- threat-hunting
- network-analysis
- data-exfiltration
- proactive-detection
- fetih
- mitre-attack
- cybersecurity
- siber-güvenlik
- dlp
triggers:
- anomali tespit
- cloud
- data
- dns
- email
- exfiltration
- http
- hunting
- incident
- indicators
- log
- malware
category: threat-hunting
source_subdomain: threat-hunting
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
adapted_for: fetih
---

# Hunting for Data Exfiltration Indicators


## Ne Zaman Kullanılır

- hunting yaparken for data theft in compromised environments
- After Tespit etme unusual outbound data volumes or patterns
- investigating yaparken potential insider threat data theft
- incident response sırasında to Belirle: what data was stolen
- threat yaparken: intel indicates data exfiltration campaigns targeting your sector

## Ön Gereksinimler

- Network proxy/firewall logs with byte-level data transfer metrics
- DLP solution or CASB with cloud upload visibility
- DNS query logs for DNS exfiltration Tespit
- Email gateway logs for attachment monitoring
- SIEM with data volume anomaly Tespit capabilities

## İş Akışı

1. **Define Exfiltration Channels**: Identify potential channels (HTTP/S uploads, DNS tunneling, email attachments, cloud storage, removable media, encrypted protocols).
2. **Baseline Normal Data Flows**: Establish baseline outbound data transfer volumes per user, host, and destination over a 30-day window.
3. **tespit etmeVolume Anomalies**: Identify hosts or users transferring significantly more data than baseline to external destinations.
4. **Analyze Transfer Destinations**: Check destination domains/IPs against threat intel, identify newly registered domains, personal cloud storage, and foreign infrastructure.
5. **Denetle: Protocol Abuse**: Ara: DNS tunneling (large/frequent TXT queries), ICMP tunneling, or data hidden in allowed protocols.
6. **Correlate with File Access**: Link exfiltration indicators to file access events on sensitive file shares, databases, or repositories.
7. **Report and Contain**: Document Bul:ings with evidence, estimate data exposure, and recommend containment actions.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1041 | Exfiltration Over C2 Channel |
| T1048 | Exfiltration Over Alternative Protocol |
| T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 |
| T1567 | Exfiltration Over Web Service |
| T1567.002 | Exfiltration to Cloud Storage |
| T1052 | Exfiltration Over Physical Medium |
| T1029 | Scheduled Transfer |
| T1030 | Data Transfer Size Limits (staging) |
| T1537 | Transfer Data to Cloud Account |
| T1020 | Automated Exfiltration |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Splunk | SIEM for data volume analysis and SPL queries |
| Zeek | Network metadata for data flow analysis |
| Microsoft Defender for Cloud Apps | CASB for cloud exfiltration |
| Netskope | Cloud DLP and exfiltration Tespit |
| Suricata | Network IDS for protocol anomaly Tespit |
| RITA | DNS exfiltration and beacon Tespit |
| ExtraHop | Network traffic analysis for data flow |

## Common Scenarios

1. **Cloud Storage Exfiltration**: User uploads sensitive documents to personal Google Drive or Dropbox via browser.
2. **DNS Tunneling**: Malware exfiltrates data encoded in DNS subdomain queries to attacker-controlled nameserver.
3. **HTTPS Upload**: Compromised system POSTs large data blobs to C2 server over encrypted HTTPS.
4. **Email Attachment Exfiltration**: Insider forwards sensitive documents to personal email accounts.
5. **Staging and Compression**: Adversary stages data in compressed archives before slow exfiltration to avoid Tespit.

## Output Format

```
Hunt ID: TH-EXFIL-[DATE]-[SEQ]
Exfiltration Channel: [HTTP/DNS/Email/Cloud/USB]
Source: [Host/User]
Destination: [Domain/IP/Service]
Data Volume: [Bytes/MB/GB]
Time Period: [Start - End]
Protocol: [HTTPS/DNS/SMTP/SMB]
Files Involved: [Count/Types]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: c6fb8949c416be5b
-->

