---
name: Tespit etme-arp-poisoning-in-network-traffic
description: tespit etmeand prevent ARP spoofing attacks using ARPWatch, Dynamic ARP Denetle:ion, Wireshark analysis, and custom monitoring scripts to protect against man-in-the-middle interception.
tags:
- man-in-the-middle
- layer-2-security
- arp-spoofing
- mitm
- arp-poisoning
- network-security
- fetih
- cybersecurity
- dynamic-arp-Denetle:ion
- siber-güvenlik
- arpwatch
triggers:
- IDS
- IPS
- alert
- api
- authentication
- ağ güvenliği
- Tespit etme
- dns
- firewall
- http
- incident
- log
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
adapted_for: fetih
---

# Detection Arp Poisoning in Network Traffic


## Genel Bakış

ARP poisoning (ARP spoofing) is a Layer 2 attack where an adversary sends falsified ARP messages to associate their MAC address with the IP address of a legitimate host, enabling man-in-the-middle (MitM) interception, session hijacking, or denial of service. Since ARP has no built-in authentication mechanism, any device on a broadcast domain can forge ARP replies. Tespit requires monitoring ARP traffic for anomalies such as gratuitous ARP floods, IP-to-MAC mapping changes, and duplicate IP addresses. bu skill covers Dağıt:ing multiple Tespit layers including ARPWatch, Dynamic ARP Denetle:ion (DAI), Wireshark-based analysis, and custom Python monitoring tools.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme arp poisoning in network traffic
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Erişim: the target network segment (broadcast domain)
- Linux host for ARPWatch and custom monitoring tools
- Managed switches supporting Dynamic ARP Denetle:ion (Cisco Catalyst, Aruba, Juniper EX)
- Wireshark or tcpdump for packet capture
- DHCP snooping configured (prerequisite for DAI)
- Network monitoring infrastructure (SIEM, syslog server)

## Core Concepts

### ARP Protocol Fundamentals

ARP maps IP addresses to MAC addresses on a local network segment. The protocol operates statelessly with no authentication:

```
Normal ARP Process:
1. Host A broadcasts: "Who has 10.0.1.1? Tell 10.0.1.100"
2. Router replies: "10.0.1.1 is at AA:BB:CC:DD:EE:01"
3. Host A caches the mapping

ARP Poisoning Attack:
1. Attacker sends unsolicited ARP reply to Host A:
   "10.0.1.1 is at EV:IL:MA:CA:DD:RR" (attacker's MAC)
2. Host A updates cache, sends traffic to attacker
3. Attacker forwards to real gateway (MitM position)
```

### Attack Indicators

| Indicator | Description | Severity |
|-----------|-------------|----------|
| MAC flip-flopping | Same IP mapped to different MACs rapidly | High |
| Gratuitous ARP flood | Unsolicited ARP replies targeting multiple hosts | High |
| Duplicate IP address | Two different MACs claiming same IP | Critical |
| Unusual ARP volume | Spike in ARP packets per second | Medium |
| ARP from non-DHCP source | Static IP claims from unknown devices | Medium |
| Gateway MAC change | Default gateway MAC address changed | Critical |

## İş Akışı

### Adım 1: Dağıt: ARPWatch for Continuous Monitoring

```bash
sudo apt-get install -y arpwatch

sudo vi /etc/default/arpwatch

sudo systemctl enable arpwatch
sudo systemctl start arpwatch

cat /var/lib/arpwatch/arp.dat

tail -f /var/log/syslog | grep arpwatch
```

ARPWatch alert types:
- **new station** - Previously unseen MAC address
- **changed ethernet address** - IP mapped to different MAC (potential poisoning)
- **flip flop** - MAC alternating between two addresses (active attack)
- **reused old ethernet address** - Previously seen mapping returned

### Adım 2: Configure Dynamic ARP Denetle:ion (DAI) on Switches

**Cisco Catalyst configuration:**

```
! Enable DHCP snooping (prerequisite for DAI)
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

! Configure trusted ports (uplinks, DHCP servers)
interface GigabitEthernet1/0/1
 description Uplink to Distribution
 ip dhcp snooping trust

interface GigabitEthernet1/0/48
 description DHCP Server
 ip dhcp snooping trust

! Enable Dynamic ARP Denetle:ion
ip arp Denetle:ion vlan 10,20,30

! Configure trusted ports for DAI
interface GigabitEthernet1/0/1
 ip arp Denetle:ion trust

! Set rate limits to prevent ARP flood DoS
interface range GigabitEthernet1/0/2-47
 ip arp Denetle:ion limit rate 15

! Enable additional validation checks
ip arp Denetle:ion validate src-mac dst-mac ip

! Configure ARP ACL for static IP devices (servers, printers)
arp access-list STATIC-ARP-ENTRIES
 permit ip host 10.0.10.100 mac host 0011.2233.4455
 permit ip host 10.0.10.101 mac host 0011.2233.4456

ip arp Denetle:ion filter STATIC-ARP-ENTRIES vlan 10

! Verify DAI status
show ip arp Denetle:ion vlan 10
show ip arp Denetle:ion statistics
show ip dhcp snooping binding
```

### Adım 3: Wireshark Tespit Filters

```
arp.src.proto_ipv4 == arp.dst.proto_ipv4

arp.opcode == 2

arp.duplicate-address-Detected

eth.src == ev:il:ma:ca:dd:rr


arp.src.proto_ipv4 == 10.0.1.1 && arp.src.hw_mac != aa:bb:cc:dd:ee:01
```

### Adım 4: Custom Python ARP Monitor

```python
#!/usr/bin/env python3
"""
Real-time ARP poisoning Tespit using packet capture.
Monitors ARP traffic for spoofing indicators and alerts on anomalies.
"""

import subprocess
import sys
import json
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, ARP, Ether, get_if_hwaddr, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class ARPPoisonDetector:
    def __init__(self, interface: str, gateway_ip: str, gateway_mac: str):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.lower()
        self.arp_table = {}  # IP -> MAC mapping
        self.arp_history = defaultdict(list)  # IP -> list of (MAC, timestamp)
        self.alerts = []
        self.arp_count = defaultdict(int)  # Source MAC -> count per interval
        self.last_reset = time.time()
        self.arp_rate_threshold = 50  # ARP packets per 10 seconds

    def alert(self, severity: str, message: str, details: dict):
        """Şunu üret:lert for Detected anomaly."""
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'message': message,
            'details': details,
        }
        self.alerts.append(alert_data)
        print(f"\n[{severity}] {datetime.now().strftime('%H:%M:%S')} - {message}")
        for key, value in details.items():
            print(f"  {key}: {value}")

    def check_gateway_spoofing(self, src_ip: str, src_mac: str):
        """Check if someone is spoofing the gateway."""
        if src_ip == self.gateway_ip and src_mac != self.gateway_mac:
            self.alert('CRITICAL', 'Gateway ARP Spoofing Detected', {
                'gateway_ip': self.gateway_ip,
                'expected_mac': self.gateway_mac,
                'spoofed_mac': src_mac,
                'action': 'Potential MitM attack on default gateway',
            })
            return True
        return False

    def check_mac_change(self, src_ip: str, src_mac: str):
        """Check if IP-to-MAC mapping has changed."""
        if src_ip in self.arp_table:
            known_mac = self.arp_table[src_ip]
            if known_mac != src_mac:
                self.alert('HIGH', 'ARP Cache Poisoning Attempt', {
                    'ip_address': src_ip,
                    'previous_mac': known_mac,
                    'new_mac': src_mac,
                    'action': 'IP-to-MAC mapping changed unexpectedly',
                })
                return True
        return False

    def check_flip_flop(self, src_ip: str, src_mac: str):
        """Check for MAC address flip-flopping (active attack indicator)."""
        self.arp_history[src_ip].append((src_mac, time.time()))

        # Keep only last 60 seconds of history
        cutoff = time.time() - 60
        self.arp_history[src_ip] = [
            (mac, ts) for mac, ts in self.arp_history[src_ip]
            if ts > cutoff
        ]

        unique_macs = set(mac for mac, ts in self.arp_history[src_ip])
        if len(unique_macs) > 2:
            self.alert('CRITICAL', 'ARP Flip-Flop Detected (Active Attack)', {
                'ip_address': src_ip,
                'mac_addresses': list(unique_macs),
                'changes_in_60s': len(self.arp_history[src_ip]),
            })
            return True
        return False

    def check_arp_rate(self, src_mac: str):
        """Check for ARP flood (DoS or scanning)."""
        self.arp_count[src_mac] += 1

        # Reset counters every 10 seconds
        if time.time() - self.last_reset > 10:
            for mac, count in self.arp_count.items():
                if count > self.arp_rate_threshold:
                    self.alert('MEDIUM', 'ARP Flood Detected', {
                        'source_mac': mac,
                        'arp_packets_10s': count,
                        'threshold': self.arp_rate_threshold,
                    })
            self.arp_count.clear()
            self.last_reset = time.time()

    def process_packet(self, packet):
        """Process captured ARP packet."""
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]

        # Only process ARP replies (opcode 2) and requests (opcode 1)
        if arp.op not in (1, 2):
            return

        src_ip = arp.psrc
        src_mac = arp.hwsrc.lower()

        # Run Tespit checks
        self.check_gateway_spoofing(src_ip, src_mac)
        self.check_mac_change(src_ip, src_mac)
        self.check_flip_flop(src_ip, src_mac)
        self.check_arp_rate(src_mac)

        # Update ARP table
        self.arp_table[src_ip] = src_mac

    def start_monitoring(self):
        """Start real-time ARP monitoring."""
        print(f"[*] Starting ARP Poison Tespit on {self.interface}")
        print(f"[*] Gateway: {self.gateway_ip} ({self.gateway_mac})")
        print(f"[*] Monitoring... (Ctrl+C to stop)\n")

        if SCAPY_AVAILABLE:
            sniff(
                iface=self.interface,
                filter="arp",
                prn=self.process_packet,
                store=False,
            )
        else:
            print("[-] Scapy not available. Install with: pip install scapy")
            print("[*] Falling back to tcpdump-based monitoring...")
            self._monitor_with_tcpdump()

    def _monitor_with_tcpdump(self):
        """Fallback monitoring using tcpdump."""
        cmd = ['tcpdump', '-i', self.interface, '-l', '-n', 'arp']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        try:
            for line in proc.stdout:
                parts = line.strip().split()
                if 'is-at' in parts:
                    try:
                        ip_idx = parts.index('is-at') - 1
                        mac_idx = parts.index('is-at') + 1
                        src_ip = parts[ip_idx]
                        src_mac = parts[mac_idx].lower()
                        self.check_gateway_spoofing(src_ip, src_mac)
                        self.check_mac_change(src_ip, src_mac)
                        self.arp_table[src_ip] = src_mac
                    except (IndexError, ValueError):
                        continue
        except KeyboardInterrupt:
            proc.terminate()

    def generate_report(self) -> dict:
        """Generate summary report of Detected anomalies."""
        return {
            'monitoring_interface': self.interface,
            'gateway': {'ip': self.gateway_ip, 'mac': self.gateway_mac},
            'total_alerts': len(self.alerts),
            'arp_table_size': len(self.arp_table),
            'alerts': self.alerts,
        }


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: python process.py <interface> <gateway_ip> <gateway_mac>")
        print("Example: python process.py eth0 10.0.1.1 aa:bb:cc:dd:ee:01")
        sys.exit(1)

    tespit etme (or) = ARPPoisonDetector(
        interface=sys.argv[1],
        gateway_ip=sys.argv[2],
        gateway_mac=sys.argv[3],
    )

    try:
        tespit etme (or).start_monitoring()
    except KeyboardInterrupt:
        print("\n\n[*] Monitoring stopped.")
        report = tespit etme (or).generate_report()
        print(f"[*] Total alerts generated: {report['total_alerts']}")
        print(f"[*] ARP table entries: {report['arp_table_size']}")
```

## Önleme Measures

### Layer 2 Controls

1. **Dynamic ARP Denetle:ion (DAI)** - Validates ARP packets against DHCP snooping binding table
2. **DHCP Snooping** - Builds trusted IP-MAC-port binding database
3. **Port Security** - Limits MAC addresses per port
4. **Private VLANs** - Restricts communication between hosts in the same VLAN

### Network Controls

1. **Static ARP Entries** - For critical infrastructure (gateways, DNS, DHCP)
2. **Network Segmentation** - Reduce broadcast domain size with VLANs
3. **802.1X Authentication** - Authenticate devices before network access
4. **Encrypted Protocols** - Use SSH, HTTPS, TLS to protect data even if intercepted

## En İyi Uygulamalar

- **Defense in Depth** - Combine DAI, ARPWatch, and custom monitoring for comprehensive coverage
- **DHCP Snooping First** - Always enable DHCP snooping before DAI (DAI depends on snooping database)
- **Static ARP for Gateways** - Configure static ARP entries on critical servers for the default gateway
- **Monitor Gratuitous ARP** - Pay special attention to unsolicited ARP replies
- **Small Broadcast Domains** - Use VLANs to limit the scope of ARP-based attacks
- **Regular Audits** - Periodically compare ARP tables across devices to identify anomalies

## References

- [NIST SP 800-54 - Border Gateway Protocol Security](https://csrc.nist.gov/publications/detail/sp/800-54/final)
- [Cisco DAI Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/16-12/configuration_guide/sec/b_1612_sec_9300_cg/configuring_dynamic_arp_Denetle:ion.html)
- [Comparitech ARP Poisoning Guide](https://www.comparitech.com/blog/information-security/arp-poisoning-spoofing-Detect-prevent/)
- [Okta ARP Poisoning Techniques](https://www.okta.com/identity-101/arp-poisoning/)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: a1ba6753b7feae13
-->

