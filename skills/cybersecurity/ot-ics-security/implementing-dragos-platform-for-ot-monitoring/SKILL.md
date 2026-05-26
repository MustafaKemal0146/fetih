---
name: implementing-dragos-platform-for-ot-monitoring
description: Dağıt: and Şunu yapılandır: Dragos Platform for OT network monitoring, leveraging its 600+ industrial protocol parsers, intelligence-driven threat Tespit analytics, and asset visibility capabilities
  to protect ICS environments against threat groups like VOLTZITE, GRAPHITE, and BAUXITE.
tags:
- ics
- ot-security
- cybersecurity
- ot-ics-security
- threat-intelligence
- fetih
- ot-monitoring
- scada
- ndr
- dragos
- threat-Tespit
- siber-güvenlik
triggers:
- alert
- api
- dragos
- endpoint
- exploit
- forensic
- http
- implementing
- incident
- log
- malware
- monitoring
category: ot-ics-security
source_subdomain: ot-ics-security
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-05
- GV.OC-02
adapted_for: fetih
---

# Implementing Dragos Platform for Ot Monitoring


## Ne Zaman Kullanılır

- Dağıt:ing yaparken an OT-specific network Tespit and response (NDR) solution for industrial environments
- needing yaparken: threat intelligence-driven Tespit against known ICS threat groups (VOLTZITE, CHERNOVITE, KAMACITE)
- building yaparken an OT SOC capability with purpose-built industrial security tooling
- requiring yaparken: asset discovery and vulnerability management alongside threat Tespit in a single platform
- integrating yaparken OT security monitoring with an enterprise SIEM (Splunk, Sentinel, QRadar)

**Kullanma:** for IT-only network monitoring without ICS components, for endpoint Tespit and response (EDR) on OT workstations, or for environments standardized on Claroty or Nozomi (see respective skills).

## Ön Gereksinimler

- Dragos Platform license and Dağıt:ment package
- Network TAP or SPAN port at OT network boundaries (one sensor per monitored segment)
- Dragos sensor hardware (physical appliance) or virtual appliance meeting minimum specifications
- Firewall rules allowing sensor-to-Dragos-SiteStore communication (encrypted, outbound only from OT)
- Dragos Knowledge Pack subscription for threat intelligence updates

## İş Akışı

### Adım 1: Dağıt: Dragos Sensors and Configure Monitoring

```python
#!/usr/bin/env python3
"""Dragos Platform Dağıt:ment Validator and Integration Tool.

Validates Dragos sensor Dağıt:ment, checks connectivity, and
configures integration with enterprise SIEM for OT alert forwarding.
"""

import json
import sys
import csv
from datetime import datetime
from typing import Optional, List, Dict

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class DragosPlatformManager:
    """Interface with Dragos Platform API for OT monitoring management."""

    def __init__(self, base_url: str, api_key: str, api_secret: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "API-Key": api_key,
            "API-Secret": api_secret,
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl

    def get_sensors(self) -> List[Dict]:
        """Retrieve all Dağıtılmış Dragos sensors and their status."""
        resp = self.session.get(f"{self.base_url}/api/v1/sensors")
        resp.raise_for_status()
        return resp.json().get("sensors", [])

    def get_assets(self, asset_type: Optional[str] = None) -> List[Dict]:
        """Retrieve OT assets discovered by Dragos."""
        params = {}
        if asset_type:
            params["type"] = asset_type
        resp = self.session.get(f"{self.base_url}/api/v1/assets", params=params)
        resp.raise_for_status()
        return resp.json().get("assets", [])

    def get_notifications(self, severity: str = "high", limit: int = 50) -> List[Dict]:
        """Retrieve threat Tespit notifications."""
        params = {"min_severity": severity, "limit": limit}
        resp = self.session.get(f"{self.base_url}/api/v1/notifications", params=params)
        resp.raise_for_status()
        return resp.json().get("notifications", [])

    def get_vulnerabilities(self, severity: str = "critical") -> List[Dict]:
        """Retrieve OT vulnerabilities with Dragos-specific context."""
        params = {"min_severity": severity}
        resp = self.session.get(f"{self.base_url}/api/v1/vulnerabilities", params=params)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])

    def get_threat_groups(self) -> List[Dict]:
        """Retrieve tracked ICS threat group activity relevant to the environment."""
        resp = self.session.get(f"{self.base_url}/api/v1/threat-groups")
        resp.raise_for_status()
        return resp.json().get("threat_groups", [])

    def validate_Dağıt:ment(self):
        """Validate sensor Dağıt:ment health and coverage."""
        sensors = self.get_sensors()
        assets = self.get_assets()

        print(f"\n{'='*65}")
        print("DRAGOS PLATFORM Dağıt:MENT VALIDATION")
        print(f"{'='*65}")
        print(f"Validation Time: {datetime.now().isoformat()}")

        print(f"\n--- SENSOR STATUS ---")
        healthy_sensors = 0
        for sensor in sensors:
            status = sensor.get("status", "unknown")
            icon = "[OK]" if status == "connected" else "[!!]"
            print(f"  {icon} {sensor.get('name', 'Unknown')} | Status: {status}")
            print(f"      IP: {sensor.get('ip_address')} | Segment: {sensor.get('monitored_segment')}")
            print(f"      Last Seen: {sensor.get('last_seen')} | Packets/sec: {sensor.get('pps', 0)}")
            print(f"      Knowledge Pack: {sensor.get('knowledge_pack_version', 'N/A')}")
            if status == "connected":
                healthy_sensors += 1

        print(f"\n  Sensor Health: {healthy_sensors}/{len(sensors)} operational")

        print(f"\n--- ASSET VISIBILITY ---")
        print(f"  Total Assets Discovered: {len(assets)}")
        asset_types = {}
        for asset in assets:
            atype = asset.get("type", "Unknown")
            asset_types[atype] = asset_types.get(atype, 0) + 1
        for atype, count in sorted(asset_types.items(), key=lambda x: -x[1]):
            print(f"    {atype}: {count}")

        protocols = set()
        for asset in assets:
            protocols.update(asset.get("protocols", []))
        print(f"  Protocols Observed: {', '.join(sorted(protocols))}")

        print(f"\n--- THREAT INTELLIGENCE ---")
        groups = self.get_threat_groups()
        print(f"  Relevant Threat Groups: {len(groups)}")
        for group in groups:
            print(f"    - {group.get('name')}: {group.get('description', '')[:80]}")
            print(f"      Targets: {', '.join(group.get('target_sectors', []))}")
            print(f"      Activity Level: {group.get('activity_level', 'Unknown')}")

    def generate_siem_integration_config(self, siem_type: str = "splunk"):
        """Generate SIEM integration configuration for Dragos alerts."""
        configs = {
            "splunk": {
                "syslog_format": "CEF",
                "syslog_port": 514,
                "severity_mapping": {
                    "critical": 10,
                    "high": 7,
                    "medium": 5,
                    "low": 3,
                    "info": 1,
                },
                "index": "ot_security",
                "sourcetype": "dragos:notification",
                "fields": [
                    "notification_id", "severity", "category", "source_ip",
                    "destination_ip", "asset_name", "protocol", "description",
                    "mitre_ics_technique", "threat_group",
                ],
            },
            "sentinel": {
                "connector_type": "Syslog-CEF",
                "workspace_id": "<workspace-id>",
                "log_analytics_table": "DragosOTAlerts_CL",
                "severity_mapping": {
                    "critical": "High",
                    "high": "High",
                    "medium": "Medium",
                    "low": "Low",
                    "info": "Informational",
                },
            },
        }

        config = configs.get(siem_type, configs["splunk"])
        print(f"\n--- {siem_type.upper()} INTEGRATION CONFIG ---")
        print(json.dumps(config, indent=2))
        return config


if __name__ == "__main__":
    manager = DragosPlatformManager(
        base_url="https://dragos-sitestore.plant.local",
        api_key="your-api-key",
        api_secret="your-api-secret",
        verify_ssl=True,
    )

    manager.validate_Dağıt:ment()
    manager.generate_siem_integration_config("splunk")

    print(f"\n--- RECENT HIGH-SEVERITY NOTIFICATIONS ---")
    notifications = manager.get_notifications(severity="high", limit=10)
    for n in notifications:
        print(f"  [{n.get('severity', '').upper()}] {n.get('title', 'No title')}")
        print(f"    Category: {n.get('category')} | Time: {n.get('timestamp')}")
        print(f"    Assets: {', '.join(n.get('affected_assets', []))}")
        print(f"    MITRE ICS: {n.get('mitre_technique', 'N/A')}")
```

### Adım 2: Configure Tespit Analytics and Knowledge Packs

```yaml

Tespit_configuration:
  knowledge_pack:
    auto_update: true
    update_schedule: "weekly"
    include_threat_groups:
      - "VOLTZITE"    # Targets energy sector, exfiltrates OT diagrams
      - "GRAPHITE"    # New 2025 threat group targeting ICS
      - "BAUXITE"     # New 2025 threat group targeting ICS
      - "CHERNOVITE"  # Developed PIPEDREAM/INCONTROLLER framework
      - "ELECTRUM"    # Linked to Industroyer/CrashOverride
      - "KAMACITE"    # Targets energy sector initial access

  Tespit_categories:
    network_baseline:
      enabled: true
      learning_period_days: 30
      alert_on:
        - "new_communication_pair"
        - "new_protocol_Detected"
        - "new_device_on_network"
        - "protocol_anomaly"

    threat_Tespit:
      enabled: true
      alert_on:
        - "known_malware_ioc"
        - "threat_group_ttp"
        - "lateral_movement"
        - "command_and_control"
        - "data_exfiltration"

    vulnerability_correlation:
      enabled: true
      alert_on:
        - "active_exploitation_attempt"
        - "vulnerability_with_public_exploit"

  protocol_monitoring:
    modbus:
      monitor_writes: true
      baseline_function_codes: true
      baseline_register_ranges: true
    dnp3:
      monitor_control_commands: true
      tespit etme (_firmware_updates): true
    s7comm:
      tespit etme (_cpu_stop): true
      tespit etme (_program_download): true
    opc_ua:
      monitor_method_calls: true
      tespit etme (_browsing): true
    ethernet_ip:
      monitor_cip_services: true
      tespit etme (_firmware_flash): true

  alert_routing:
    critical:
      notify: ["ot_soc_team", "plant_manager"]
      siem_forward: true
      auto_ticket: true
    high:
      notify: ["ot_soc_team"]
      siem_forward: true
      auto_ticket: true
    medium:
      siem_forward: true
    low:
      siem_forward: true
```

## Key Concepts

| Term | Definition |
|------|------------|
| Dragos Platform | Purpose-built OT cybersecurity platform with asset visibility, threat Tespit, and vulnerability management for ICS environments |
| Knowledge Pack | Dragos threat intelligence update containing Tespit analytics for new threats, malware, and vulnerability exploits specific to ICS |
| SiteStore | Dragos central management server aggregating data from all Dağıtılmış sensors across a site |
| VOLTZITE | Dragos-tracked threat group targeting energy sector OT environments, exfiltrating GIS data and ICS network diagrams |
| PIPEDREAM/INCONTROLLER | Modular ICS attack framework developed by CHERNOVITE, targeting Schneider/OMRON PLCs and OPC UA servers |
| Neighborhood Keeper | Dragos community defense program sharing anonymized threat data across participating OT environments |

## Common Scenarios

### Scenario: Tespit etme VOLTZITE Reconnaissance in Energy Utility

**Context**: A Dragos sensor Dağıtılmış at an electric utility tespit etme (s) unusual OPC UA browsing activity and exfiltration of device configuration data from an engineering workstation.

**Approach**:
1. Şunu incele: Dragos notification for MITRE ATT&CK ICS technique mapping
2. the tespit et: source host performing OPC UA browsing (check if it is an authorized engineering workstation)
3. Check Dragos threat intelligence correlation for VOLTZITE TTPs
4. İncele: the scope of data accessed (GIS data, network diagrams, ICS configuration files)
5. Isolate the compromised workstation from the OT network
6. Check for lateral movement indicators to other OT systems
7. Engage Dragos Professional Services if threat group attribution is confirmed
8. Report to CISA as a critical infrastructure cyber incident

**Pitfalls**: Do not ignore OPC UA browsing alerts as false positives -- VOLTZITE specifically uses this technique for pre-positioning. Ensure Dragos Knowledge Packs are current to tespit etmethe latest VOLTZITE indicators. Do not reimage the compromised workstation before collecting forensic evidence.

## Output Format

```
DRAGOS OT MONITORING Dağıt:MENT REPORT
==========================================
Site: [Site Name]
Date: YYYY-MM-DD

SENSOR Dağıt:MENT:
  Total Sensors: [count]
  Operational: [count]
  Coverage: [percentage of OT segments monitored]

ASSET VISIBILITY:
  Total OT Assets: [count]
  PLCs: [count] | HMIs: [count] | Network Devices: [count]
  Protocols: [list]

THREAT tespit etme (ION):
  Active Threat Groups Relevant: [count]
  Tespit Analytics Loaded: [count]
  Alerts (Last 30 Days): [count by severity]

SIEM INTEGRATION:
  Status: [Connected/Disconnected]
  Events Forwarded (Last 24h): [count]
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 07befe786feaf5b2
-->

