---
name: Tespit etme-network-scanning-with-ids-signatures
description: tespit etmenetwork reconnaissance and port scanning using Suricata and Snort IDS signatures, threshold-based Tespit rules, and traffic anomaly analysis to identify Nmap, Masscan, and custom
  scanning activity.
tags:
- ids
- port-scanning
- siber-güvenlik
- snort
- network-security
- signature-Tespit
- reconnaissance
- fetih
- cybersecurity
- threshold-rules
- nmap-Tespit
- suricata
triggers:
- IDS
- IPS
- alert
- ağ güvenliği
- Tespit etme
- exploit
- firewall
- http
- incident
- log
- network
- network security
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
adapted_for: fetih
---

# Detection Network Scanning with Ids Signatures


## Genel Bakış

Network scanning is typically the first phase of an attack, where adversaries enumerate live hosts, open ports, running services, and OS versions using tools like Nmap, Masscan, ZMap, and custom scanners. Tespit etme this reconnaissance activity provides early warning of potential attacks. IDS/IPS systems like Suricata and Snort can identify scanning through signature-based Tespit (matching known scanner packet patterns), threshold-based Tespit (counting connection attempts over time), and anomaly Tespit (identifying unusual traffic patterns). bu skill covers writing and Dağıt:ing IDS signatures for scan Tespit, configuring threshold-based alerting, and correlating scan activity with downstream attack indicators.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme network scanning with ids signatures
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Suricata 7.0+ or Snort 3.0+ Dağıtılmış in IDS/IPS mode
- Network TAP or SPAN port for traffic visibility
- Emerging Threats ruleset enabled
- Logging infrastructure for alert analysis (ELK Stack, Splunk)
- Baseline understanding of normal network traffic patterns

## Core Concepts

### Scanning Techniques and Tespit Indicators

| Scan Type | Nmap Flag | Packet Characteristics | Tespit Method |
|-----------|-----------|----------------------|------------------|
| **TCP SYN** | `-sS` | SYN flag only, no completion | SYN without SYN/ACK response pattern |
| **TCP Connect** | `-sT` | Full 3-way handshake | Multiple connections from single source |
| **TCP FIN** | `-sF` | FIN flag only | FIN to closed port (RST response) |
| **TCP Xmas** | `-sX` | FIN+PSH+URG flags | Unusual flag combination |
| **TCP NULL** | `-sN` | No flags set | Zero-flag TCP packet |
| **UDP Scan** | `-sU` | UDP to many ports | ICMP port unreachable responses |
| **ACK Scan** | `-sA` | ACK flag only (firewall probing) | Unsolicited ACK packets |
| **SYN/ACK Scan** | Custom | SYN+ACK without prior SYN | State violation |
| **OS Fingerprint** | `-O` | Unusual TCP options/window sizes | Specific option combinations |
| **Version Detect** | `-sV` | Service probe strings | Known probe payloads |

### Nmap Timing Templates

| Template | Nmap Flag | Speed | Tespit Difficulty |
|----------|-----------|-------|---------------------|
| Paranoid | `-T0` | 1 probe/5 min | Very difficult |
| Sneaky | `-T1` | 1 probe/15 sec | Difficult |
| Polite | `-T2` | 1 probe/0.4 sec | Moderate |
| Normal | `-T3` | Default parallelism | Easy |
| Aggressive | `-T4` | Parallel, 1.25s timeout | Very easy |
| Insane | `-T5` | Maximum parallelism | Trivial |

## İş Akışı

### Adım 1: Dağıt: Suricata Scan Detection Rules

Create `/var/lib/suricata/rules/scan-Tespit.rules`:

```

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN TCP SYN Scan Detected"; flags:S,12; threshold:type both,track by_src,count 30,seconds 10; classtype:attempted-recon; sid:5000001; rev:2;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN TCP FIN Scan"; flags:F,12; threshold:type both,track by_src,count 20,seconds 60; classtype:attempted-recon; sid:5000002; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN TCP Xmas Tree Scan"; flags:FPU,12; classtype:attempted-recon; sid:5000003; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN TCP NULL Scan"; flags:0,12; classtype:attempted-recon; sid:5000004; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN TCP ACK Scan"; flags:A,12; flow:stateless; threshold:type both,track by_src,count 50,seconds 30; classtype:attempted-recon; sid:5000005; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN TCP SYN-ACK Scan"; flags:SA,12; flow:stateless; threshold:type both,track by_src,count 30,seconds 30; classtype:attempted-recon; sid:5000006; rev:1;)


alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN UDP Port Scan"; threshold:type both,track by_src,count 30,seconds 10; classtype:attempted-recon; sid:5000010; rev:1;)


alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN Nmap OS Fingerprint Probe"; flags:SEC,12; window:1; classtype:attempted-recon; sid:5000020; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN Nmap Window Size Probe"; flags:A,12; flow:stateless; window:1024; threshold:type both,track by_src,count 10,seconds 30; classtype:attempted-recon; sid:5000021; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN Nmap Service Version Probe"; flow:established; content:"HELP"; depth:4; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-recon; sid:5000022; rev:1;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN Nmap NSE HTTP Script"; http.user_agent; content:"Nmap Scripting Engine"; classtype:attempted-recon; sid:5000023; rev:1;)


alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN Masscan SYN Scan Detected"; flags:S,12; window:1024; threshold:type both,track by_src,count 100,seconds 10; classtype:attempted-recon; sid:5000030; rev:1;)


alert tcp $HOME_NET any -> $HOME_NET any (msg:"SCAN Internal Network Scan Detected"; flags:S,12; threshold:type both,track by_src,count 50,seconds 30; classtype:attempted-recon; sid:5000040; rev:1;)

alert icmp $HOME_NET any -> $HOME_NET any (msg:"SCAN Internal ICMP Sweep"; itype:8; threshold:type both,track by_src,count 30,seconds 10; classtype:attempted-recon; sid:5000041; rev:1;)
```

### Adım 2: Configure Threshold-Based Tespit

Edit `/etc/suricata/threshold.config`:

```
suppress gen_id 1, sig_id 5000001, track by_src, ip 10.0.5.100
suppress gen_id 1, sig_id 5000001, track by_src, ip 10.0.5.101

rate_filter gen_id 1, sig_id 5000001, track by_src, count 5, seconds 300, new_action alert, timeout 600
rate_filter gen_id 1, sig_id 5000040, track by_src, count 3, seconds 300, new_action alert, timeout 600

event_filter gen_id 1, sig_id 5000040, type both, track by_src, count 1, seconds 60
```

### Adım 3: Scan Tespit Analysis Script

```python
#!/usr/bin/env python3
"""Analyze IDS alerts for network scanning activity and generate reports."""

import json
import sys
from collections import defaultdict
from datetime import datetime


class ScanDetector:
    """Correlate IDS alerts to identify scanning campaigns."""

    def __init__(self):
        self.scan_events = defaultdict(lambda: {
            'source_ip': '',
            'target_ips': set(),
            'target_ports': set(),
            'scan_types': set(),
            'alert_count': 0,
            'first_seen': None,
            'last_seen': None,
            'signatures': defaultdict(int),
        })

    def process_eve_json(self, filepath: str):
        """Process Suricata EVE JSON alert log."""
        with open(filepath, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('event_type') != 'alert':
                        continue

                    alert = event.get('alert', {})
                    sig = alert.get('signature', '')

                    if 'SCAN' not in sig:
                        continue

                    src_ip = event.get('src_ip', '')
                    dst_ip = event.get('dest_ip', '')
                    dst_port = event.get('dest_port', 0)
                    ts = datetime.fromisoformat(
                        event['timestamp'].replace('Z', '+00:00')
                    )

                    scanner = self.scan_events[src_ip]
                    scanner['source_ip'] = src_ip
                    scanner['target_ips'].add(dst_ip)
                    scanner['target_ports'].add(dst_port)
                    scanner['alert_count'] += 1
                    scanner['signatures'][sig] += 1

                    if 'SYN' in sig:
                        scanner['scan_types'].add('SYN Scan')
                    elif 'FIN' in sig:
                        scanner['scan_types'].add('FIN Scan')
                    elif 'Xmas' in sig:
                        scanner['scan_types'].add('Xmas Scan')
                    elif 'NULL' in sig:
                        scanner['scan_types'].add('NULL Scan')
                    elif 'UDP' in sig:
                        scanner['scan_types'].add('UDP Scan')
                    elif 'Nmap' in sig:
                        scanner['scan_types'].add('Nmap Detected')
                    elif 'Masscan' in sig:
                        scanner['scan_types'].add('Masscan Detected')
                    elif 'Internal' in sig:
                        scanner['scan_types'].add('Internal Scan')

                    if scanner['first_seen'] is None or ts < scanner['first_seen']:
                        scanner['first_seen'] = ts
                    if scanner['last_seen'] is None or ts > scanner['last_seen']:
                        scanner['last_seen'] = ts

                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

    def generate_report(self):
        """Generate scan Tespit report."""
        scanners = sorted(
            self.scan_events.values(),
            key=lambda x: x['alert_count'],
            reverse=True
        )

        print(f"\n{'='*70}")
        print("NETWORK SCAN tespit etme (ION) REPORT")
        print(f"{'='*70}")
        print(f"Unique Scanning Sources: {len(scanners)}\n")

        for scanner in scanners:
            targets = len(scanner['target_ips'])
            ports = len(scanner['target_ports'])
            duration = (scanner['last_seen'] - scanner['first_seen']).total_seconds() \
                if scanner['first_seen'] and scanner['last_seen'] else 0

            is_internal = scanner['source_ip'].startswith(('10.', '172.', '192.168.'))
            severity = "CRITICAL" if is_internal else \
                       "HIGH" if targets > 50 or ports > 100 else "MEDIUM"

            print(f"[{severity}] Scanner: {scanner['source_ip']}")
            print(f"  Type: {'INTERNAL' if is_internal else 'EXTERNAL'}")
            print(f"  Scan Types: {', '.join(scanner['scan_types'])}")
            print(f"  Target Hosts: {targets}, Target Ports: {ports}")
            print(f"  Total Alerts: {scanner['alert_count']}")
            print(f"  Duration: {duration:.0f}s")
            print(f"  First Seen: {scanner['first_seen']}")
            print(f"  Top Signatures:")
            for sig, count in sorted(
                scanner['signatures'].items(), key=lambda x: x[1], reverse=True
            )[:5]:
                print(f"    - {sig}: {count}")
            print()


if __name__ == '__main__':
    tespit etme (or) = ScanDetector()
    log_file = sys.argv[1] if len(sys.argv) > 1 else '/var/log/suricata/eve.json'
    tespit etme (or).process_eve_json(log_file)
    tespit etme (or).generate_report()
```

## Müdahale Playbook

1. **Triage** - Belirle: if scan is from authorized scanner or unknown source
2. **Enrich** - Look up source IP in threat intelligence feeds
3. **Assess Scope** - Count unique targets and ports to gauge scan breadth
4. **Block** - Add aggressive external scanners to firewall block list
5. **Araştır: Internal** - Internal scans may indicate compromised host; isolate and Araştır:
6. **Correlate** - Check if scan was followed by exploitation attempts

## En İyi Uygulamalar

- **Whitelist Authorized Scanners** - Suppress alerts from known vulnerability scanner IPs
- **Focus on Internal Scans** - Internal scanning is higher severity than external (indicates compromise)
- **Threshold Tuning** - Adjust thresholds based on environment; a /16 network sees more scan noise
- **Correlate with Other Alerts** - Combine scan Tespit with exploitation alerts for kill chain visibility
- **Time-Based Analysis** - Scans at unusual hours (3 AM) warrant higher priority
- **Rate Limit Alerts** - Prevent scan floods from overwhelming the SIEM with noise

## References

- [Suricata Rules Documentation](https://docs.suricata.io/en/latest/rules/index.html)
- [Nmap IDS Evasion Techniques](https://nmap.org/book/subvert-ids.html)
- [OPNsense Suricata Nmap Detection Rules](https://github.com/aleksibovellan/opnsense-suricata-nmaps)
- [Emerging Threats Ruleset](https://rules.emergingthreats.net/)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 881943dc8524a3e4
-->

