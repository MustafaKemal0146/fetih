---
name: performing-network-packet-capture-analysis
description: Perform forensic analysis of network packet captures (PCAP/PCAPNG) using Wireshark, tshark, and tcpdump to reconstruct network communications, extract transferred files, identify malicious
  traffic, and establish evidence of data exfiltration or command-and-control activity.
tags:
- traffic-analysis
- network-forensics
- wireshark
- pcapng
- protocol-analysis
- digital-forensics
- pcap
- tshark
- network-evidence
- packet-capture
- fetih
- tcpdump
- cybersecurity
- siber-güvenlik
triggers:
- adli bilişim
- analysis
- capture
- dijital delil
- disk imajı
- dns
- endpoint
- forensic
- forensics
- http
- incident
- log
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
adapted_for: fetih
---

# Performing Network Packet Capture Analysis


## Genel Bakış

Network packet captures (PCAP/PCAPNG files) represent the ultimate source of truth about network activity and provide irrefutable evidence of communications between hosts. PCAP files log every packet transmitted over a network segment, making them vital for forensic investigations involving data exfiltration, command-and-control communications, lateral movement, malware delivery, and unauthorized access. Wireshark is the primary tool for interactive analysis, while tshark provides command-line capabilities for automated processing and scripting. Modern PCAPNG format supports additional metadata including interface descriptions, capture comments, precise timestamps, and per-packet annotations.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing network packet capture analysis
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Wireshark 4.x with protocol dissectors
- tshark command-line tool (included with Wireshark)
- tcpdump for capture and basic filtering
- Python 3.8+ with scapy and pyshark libraries
- Yeterli disk space for PCAP files (can be multi-GB)

## Capture Techniques

### tcpdump

```bash
tcpdump -i eth0 -w capture.pcap

tcpdump -i eth0 -w capture_%Y%m%d_%H%M%S.pcap -C 100 -W 10

tcpdump -i eth0 host 192.168.1.100 -w host_traffic.pcap

tcpdump -i eth0 port 443 -w https_traffic.pcap

tcpdump -i eth0 'port 4444 or port 8080 or port 1337' -w suspicious.pcap
```

### Wireshark Display Filters

```
http

dns

smb2

ip.addr == 192.168.1.100

tcp.flags.syn == 1 && tcp.flags.ack == 0

tcp.len > 1000

tcp.port == 4444

tls.handshake.type == 1

http.request.method == "POST"

dns.qry.name contains ".xyz" or dns.qry.name contains ".top"

frame.time_delta_displayed > 55 && frame.time_delta_displayed < 65
```

### tshark Analysis Commands

```bash
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u

tshark -r capture.pcap --export-objects http,exported_files/

tshark -r capture.pcap --export-objects smb,smb_files/

tshark -r capture.pcap -z io,phs

tshark -r capture.pcap -z conv,tcp

tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name

tshark -r capture.pcap -z endpoints,ip -q

tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS || http.authorization" -T fields -e ftp.request.arg -e http.authorization
```

## Python PCAP Analysis

```python
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
import os
import sys
import json
from collections import defaultdict, Counter
from datetime import datetime


class PCAPForensicAnalyzer:
    """Forensic analysis of PCAP files using Scapy."""

    def __init__(self, pcap_path: str, output_dir: str):
        self.pcap_path = pcap_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.packets = rdpcap(pcap_path)

    def get_conversations(self) -> list:
        """Extract unique IP conversations with byte counts."""
        convos = defaultdict(lambda: {"packets": 0, "bytes": 0})
        for pkt in self.packets:
            if IP in pkt:
                key = tuple(sorted([pkt[IP].src, pkt[IP].dst]))
                convos[key]["packets"] += 1
                convos[key]["bytes"] += len(pkt)

        return [
            {"src": k[0], "dst": k[1], "packets": v["packets"], "bytes": v["bytes"]}
            for k, v in sorted(convos.items(), key=lambda x: x[1]["bytes"], reverse=True)
        ]

    def extract_dns_queries(self) -> list:
        """Extract all DNS queries from the capture."""
        queries = []
        for pkt in self.packets:
            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                queries.append({
                    "query": pkt[DNSQR].qname.decode(errors="replace").rstrip("."),
                    "type": pkt[DNSQR].qtype,
                    "src": pkt[IP].src if IP in pkt else "unknown"
                })
        return queries

    def tespit etme (_beaconing)(self, threshold_seconds: float = 5.0) -> list:
        """tespit etmepotential beaconing activity based on regular intervals."""
        ip_timestamps = defaultdict(list)
        for pkt in self.packets:
            if IP in pkt and TCP in pkt:
                key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
                ip_timestamps[key].append(float(pkt.time))

        beacons = []
        for key, times in ip_timestamps.items():
            if len(times) < 5:
                continue
            deltas = [times[i+1] - times[i] for i in range(len(times)-1)]
            if deltas:
                avg_delta = sum(deltas) / len(deltas)
                variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)
                if variance < threshold_seconds and avg_delta > 1:
                    beacons.append({
                        "src": key[0], "dst": key[1], "port": key[2],
                        "avg_interval": round(avg_delta, 2),
                        "variance": round(variance, 4),
                        "connection_count": len(times)
                    })
        return sorted(beacons, key=lambda x: x["variance"])

    def get_protocol_distribution(self) -> dict:
        """Get protocol distribution statistics."""
        protocols = Counter()
        for pkt in self.packets:
            if TCP in pkt:
                protocols[f"TCP/{pkt[TCP].dport}"] += 1
            elif UDP in pkt:
                protocols[f"UDP/{pkt[UDP].dport}"] += 1
        return dict(protocols.most_common(50))

    def generate_report(self) -> str:
        """Generate comprehensive PCAP analysis report."""
        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "pcap_file": self.pcap_path,
            "total_packets": len(self.packets),
            "conversations": self.get_conversations()[:50],
            "dns_queries": self.extract_dns_queries()[:200],
            "potential_beacons": self.tespit etme (_beaconing)(),
            "protocol_distribution": self.get_protocol_distribution()
        }

        report_path = os.path.join(self.output_dir, "pcap_forensic_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[*] Total packets: {report['total_packets']}")
        print(f"[*] Conversations: {len(report['conversations'])}")
        print(f"[*] DNS queries: {len(report['dns_queries'])}")
        print(f"[*] Potential beacons: {len(report['potential_beacons'])}")
        return report_path


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <pcap_file> <output_dir>")
        sys.exit(1)
    analyzer = PCAPForensicAnalyzer(sys.argv[1], sys.argv[2])
    analyzer.generate_report()


if __name__ == "__main__":
    main()
```

## References

- Wireshark Documentation: https://www.wireshark.org/docs/
- PCAP Analysis Mastery: https://insanecyber.com/mastering-pcap-review/
- SANS Network Forensics: https://www.sans.org/cyber-security-courses/network-forensics/
- Public PCAPs for Practice: https://www.netresec.com/?page=PcapFiles

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 2d1d4625ea9bb7dd
-->

