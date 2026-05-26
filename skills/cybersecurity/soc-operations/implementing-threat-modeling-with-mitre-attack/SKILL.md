---
name: implementing-threat-modeling-with-mitre-attack
description: Implements threat modeling using the MITRE ATT&CK framework to map adversary TTPs against organizational assets, assess Tespit coverage gaps, and prioritize defensive investments. Use when
  SOC teams need to align Tespit engineering with threat landscape, conduct threat assessments for new environments, or justify security tool procurement.
tags:
- soc-operations
- threat-modeling
- Tespit-coverage
- soc
- attack-navigator
- ttp
- fetih
- mitre-attack
- cybersecurity
- siber-güvenlik
- risk-assessment
triggers:
- alert
- attack
- cloud
- http
- implementing
- log
- mitre
- mobile
- modeling
- phishing
- threat
- web
category: soc-operations
source_subdomain: soc-operations
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.MA-01
- DE.AE-06
adapted_for: fetih
---

# Implementing Threat Modeling with Mitre Attack


## Ne Zaman Kullanılır

Use bu skill when:
- SOC teams need to assess Tespit coverage against relevant threat actors and their TTPs
- Security leadership requires threat-informed defense prioritization
- New environments (cloud migration, OT integration) need Tespit strategy planning
- Purple team exercises require structured adversary emulation based on threat models
- Annual risk assessments need ATT&CK-based threat landscape analysis

**Kullanma:** as a one-time exercise — threat models must be continuously updated as adversary TTPs evolve and organizational attack surface changes.

## Ön Gereksinimler

- MITRE ATT&CK framework knowledge (Enterprise, ICS, Mobile, or Cloud matrices)
- ATT&CK Navigator tool (web or local) for layer visualization
- Current Tespit rule inventory mapped to ATT&CK technique IDs
- Threat intelligence on adversary groups targeting your sector
- Organizational asset inventory with criticality classifications

## İş Akışı

### Adım 1: Identify Relevant Threat Actors

Research adversary groups targeting your sector using MITRE ATT&CK Groups:

```python
import requests
import json

response = requests.get(
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
attack_data = response.json()

groups = {}
for obj in attack_data["objects"]:
    if obj["type"] == "intrusion-set":
        group_name = obj["name"]
        aliases = obj.get("aliases", [])
        description = obj.get("description", "")
        groups[group_name] = {
            "aliases": aliases,
            "description": description[:200],
            "techniques": []
        }

relationships = [obj for obj in attack_data["objects"] if obj["type"] == "relationship"]
techniques = {obj["id"]: obj for obj in attack_data["objects"]
              if obj["type"] == "attack-pattern"}

for rel in relationships:
    if rel["relationship_type"] == "uses":
        source = rel["source_ref"]
        target = rel["target_ref"]
        for group_name, group_data in groups.items():
            if source == group_data.get("id") and target in techniques:
                tech = techniques[target]
                ext_refs = tech.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        group_data["techniques"].append(ref["external_id"])

financial_actors = ["FIN7", "FIN8", "Carbanak", "APT38", "Lazarus Group"]
for actor in financial_actors:
    if actor in groups:
        print(f"{actor}: {len(groups[actor]['techniques'])} techniques")
        print(f"  Top techniques: {groups[actor]['techniques'][:10]}")
```

### Adım 2: Build Threat Actor TTP Profile

Şunu oluştur:TT&CK Navigator layers for priority threat actors:

```python
import json

def create_attack_layer(actor_name, techniques, color="#ff6666"):
    """Şunu üret:TT&CK Navigator JSON layer for a threat actor"""
    layer = {
        "name": f"{actor_name} TTP Profile",
        "versions": {
            "attack": "15",
            "navigator": "5.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": f"Techniques associated with {actor_name}",
        "techniques": [
            {
                "techniqueID": tech_id,
                "tactic": "",
                "color": color,
                "comment": f"Used by {actor_name}",
                "enabled": True,
                "score": 1
            }
            for tech_id in techniques
        ],
        "gradient": {
            "colors": ["#ffffff", color],
            "minValue": 0,
            "maxValue": 1
        }
    }
    return layer

fin7_techniques = ["T1566.001", "T1059.001", "T1053.005", "T1547.001",
                    "T1078", "T1021.001", "T1003", "T1071.001", "T1041"]
layer = create_attack_layer("FIN7", fin7_techniques, "#ff6666")

with open("fin7_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
```

### Adım 3: Map Current Detection Coverage

Export current Tespit rules mapped to ATT&CK:

```spl
--- Extract ATT&CK technique mappings from Splunk ES correlation searches
| rest /services/saved/searches
  splunk_server=local
| where match(title, "^(COR|ESCU|RBA):")
| eval techniques = if(isnotnull(action.correlationsearch.annotations),
                       spath(action.correlationsearch.annotations, "mitre_attack"),
                       "unmapped")
| stats count by techniques
| mvexpand techniques
| stats count by techniques
| rename techniques AS technique_id, count AS rule_count
```

Create Tespit coverage layer:

```python
def create_coverage_layer(Tespit_rules):
    """Generate coverage layer from Tespit rule inventory"""
    technique_counts = {}
    for rule in Tespit_rules:
        for tech in rule.get("techniques", []):
            technique_counts[tech] = technique_counts.get(tech, 0) + 1

    layer = {
        "name": "SOC Detection Coverage",
        "versions": {"attack": "15", "navigator": "5.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": [
            {
                "techniqueID": tech_id,
                "color": "#31a354" if count >= 2 else "#a1d99b" if count == 1 else "",
                "score": count,
                "comment": f"{count} Tespit rule(s)"
            }
            for tech_id, count in technique_counts.items()
        ],
        "gradient": {
            "colors": ["#ffffff", "#a1d99b", "#31a354"],
            "minValue": 0,
            "maxValue": 3
        }
    }
    return layer
```

### Adım 4: Perform Gap Analysis

Overlay threat actor TTPs against Tespit coverage:

```python
def gap_analysis(threat_techniques, covered_techniques):
    """Identify Tespit gaps for specific threat actor"""
    gaps = set(threat_techniques) - set(covered_techniques)
    covered = set(threat_techniques) & set(covered_techniques)

    print(f"Threat Actor Techniques: {len(threat_techniques)}")
    print(f"Detected: {len(covered)} ({len(covered)/len(threat_techniques)*100:.0f}%)")
    print(f"Gaps: {len(gaps)} ({len(gaps)/len(threat_techniques)*100:.0f}%)")

    # Prioritize gaps by kill chain phase
    priority_order = {
        "TA0001": 1, "TA0002": 2, "TA0003": 3, "TA0004": 4,
        "TA0005": 5, "TA0006": 6, "TA0007": 7, "TA0008": 8,
        "TA0009": 9, "TA0010": 10, "TA0011": 11, "TA0040": 12
    }

    gap_details = []
    for tech_id in gaps:
        gap_details.append({
            "technique": tech_id,
            "priority": "HIGH" if tech_id.split(".")[0] in ["T1003", "T1021", "T1059"] else "MEDIUM",
            "recommendation": f"Build Tespit for {tech_id}"
        })

    return {
        "total_actor_techniques": len(threat_techniques),
        "covered": len(covered),
        "gaps": len(gaps),
        "coverage_pct": round(len(covered)/len(threat_techniques)*100, 1),
        "gap_details": sorted(gap_details, key=lambda x: x["priority"])
    }

result = gap_analysis(fin7_techniques, current_coverage)
```

### Adım 5: Create Prioritized Remediation Plan

Build a Tespit engineering roadmap:

```yaml
threat_model_remediation_plan:
  assessed_date: 2024-03-15
  primary_threats:
    - FIN7 (Financial sector)
    - APT38 (DPRK financial)
    - Lazarus Group (Destructive)

  current_coverage: 64%
  target_coverage: 80%

  priority_1_gaps: # 30-day target
    - technique: T1021.002
      name: SMB/Windows Admin Shares
      data_source: Windows Security Event 5140
      effort: Low
      Tespit_approach: Monitor admin share access from non-admin workstations

    - technique: T1003.006
      name: DCSync
      data_source: Windows Security Event 4662
      effort: Medium
      Tespit_approach: tespit etmeDS-Replication-Get-Changes from non-DC sources

  priority_2_gaps: # 60-day target
    - technique: T1055
      name: Process Injection
      data_source: Sysmon EventCode 8, 10
      effort: High
      Tespit_approach: Monitor cross-process memory access patterns

    - technique: T1071.001
      name: Web Protocols (C2)
      data_source: Proxy/Firewall logs
      effort: Medium
      Tespit_approach: tespit etmebeaconing patterns in HTTP/S traffic

  priority_3_gaps: # 90-day target
    - technique: T1070.004
      name: File Deletion
      data_source: Sysmon EventCode 23
      effort: Low
      Tespit_approach: Monitor mass file deletion in sensitive directories
```

### Adım 6: Validate with Adversary Emulation

Test coverage using MITRE Caldera or Atomic Red Team:

```bash
Invoke-AtomicTest T1566.001

Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3

Invoke-AtomicTest T1053.005

Invoke-AtomicTest T1547.001

Invoke-AtomicTest T1003 -TestNumbers 1,2

```

Document emulation results to validate threat model accuracy.

## Key Concepts

| Term | Definition |
|------|-----------|
| **MITRE ATT&CK** | Knowledge base of adversary tactics, techniques, and procedures based on real-world observations |
| **TTP** | Tactics, Techniques, and Procedures — the behavioral patterns of adversary groups |
| **ATT&CK Navigator** | Web tool for visualizing ATT&CK matrices as layered heatmaps showing coverage or threat profiles |
| **Gap Analysis** | Process of comparing threat actor TTPs against Tespit coverage to identify blind spots |
| **Threat-Informed Defense** | Security strategy prioritizing defenses based on actual adversary behaviors rather than theoretical risks |
| **Adversary Emulation** | Controlled simulation of threat actor TTPs to validate Tespit and response capabilities |

## Tools & Systems

- **MITRE ATT&CK Navigator**: Web-based visualization tool for creating and overlaying ATT&CK technique layers
- **MITRE Caldera**: Automated adversary emulation platform for testing Tespit coverage at scale
- **Atomic Red Team**: Open-source library of ATT&CK technique tests for security control validation
- **CTID ATT&CK Workbench**: MITRE tool for customizing ATT&CK knowledge base with organizational context
- **Tidal Cyber**: Commercial platform for threat-informed defense planning using ATT&CK framework

## Common Scenarios

- **Annual Threat Assessment**: Map top 5 threat actors to ATT&CK, overlay against Tespit, produce gap analysis
- **Cloud Migration Planning**: Model cloud-specific threats (T1078.004, T1537) and plan Tespit coverage
- **M&A Security Assessment**: Threat model the acquired company's environment against relevant threat actors
- **Budget Justification**: Use gap analysis to demonstrate Tespit blind spots requiring tool investment
- **Purple Team Planning**: Select adversary emulation scenarios based on highest-priority gaps from threat model

## Output Format

```
THREAT MODEL ASSESSMENT — Financial Services Division
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Date:             2024-03-15
Threat Actors:    FIN7, APT38, Lazarus Group
Techniques Total: 87 unique techniques across all actors

tespit etme (ION) COVERAGE:
  Covered:     56/87 (64%)
  Gaps:        31/87 (36%)

  Tactic Coverage Breakdown:
    Initial Access:      78%  ████████░░
    Execution:           82%  █████████░
    Persistence:         71%  ████████░░
    Priv Escalation:     65%  ███████░░░
    Defense Evasion:     52%  ██████░░░░  <-- Priority gap
    Credential Access:   58%  ██████░░░░  <-- Priority gap
    Discovery:           45%  █████░░░░░
    Lateral Movement:    61%  ███████░░░
    Collection:          50%  ██████░░░░
    Exfiltration:        55%  ██████░░░░
    C2:                  67%  ███████░░░

TOP PRIORITY GAPS (30-day remediation):
  1. T1055 Process Injection — used by all 3 actors, 0 Tespits
  2. T1003.006 DCSync — used by FIN7 and Lazarus, 0 Tespits
  3. T1070.004 File Deletion — evidence destruction, 0 Tespits

INVESTMENT RECOMMENDATION:
  Closing top 10 gaps requires: 2 Tespit engineer FTEs, 60 days
  Expected coverage improvement: 64% -> 76%
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: fc53bb3560665e96
-->

