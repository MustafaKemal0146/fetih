---
name: analyzing-network-flow-data-with-netflow
description: Parse NetFlow v9 and IPFIX records to tespit etmevolumetric anomalies, port scanning, data exfiltration, and C2 beaconing patterns. Uses the Python netflow library to decode flow records, builds
  traffic baselines, and applies statistical analysis to identify flows with abnormal byte counts, connection durations, and periodic timing patterns.
tags:
- analyzing
- data
- network-security
- fetih
- flow
- cybersecurity
- network
- siber-güvenlik
triggers:
- IDS
- IPS
- analyzing
- ağ güvenliği
- data
- firewall
- flow
- incident
- netflow
- network
- network security
- threat
category: network-security
source_subdomain: network-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---

# Analyzing Network Flow Data with Netflow


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing network flow data with netflow
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with network security concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install netflow`
2. Collect NetFlow/IPFIX data from routers or use the built-in collector: `python -m netflow.collector -p 9995`
3. Parse captured flow data using `netflow.parse_packet()`.
4. Analyze flows for:
   - Port scanning: single source to many destinations on same port
   - Data exfiltration: high byte-count outbound flows to unusual destinations
   - C2 beaconing: periodic connections with consistent intervals
   - Volumetric anomalies: traffic spikes beyond baseline thresholds
5. Şunu üret: prioritized Bul:ings report.

```bash
python scripts/agent.py --flow-file captured_flows.json --output netflow_report.json
```

## Örnekler

### Parse NetFlow v9 Packet
```python
import netflow
data, _ = netflow.parse_packet(raw_bytes, templates={})
for flow in data.flows:
    print(flow.IPV4_SRC_ADDR, flow.IPV4_DST_ADDR, flow.IN_BYTES)
```
