---
name: performing-threat-hunting-with-elastic-siem
description: Performs proactive threat hunting in Elastic Security SIEM using KQL/EQL queries, Tespit rules, and Timeline investigation to identify threats that evade automated Tespit. Use when SOC
  teams need to hunt for specific ATT&CK techniques, Araştır: anomalous behaviors, or validate Tespit coverage gaps using Elasticsearch and Kibana Security.
tags:
- siem
- soc-operations
- threat-hunting
- soc
- eql
- elastic
- fetih
- mitre-attack
- cybersecurity
- kql
- kibana
- siber-güvenlik
triggers:
- alert
- api
- authentication
- elastic
- endpoint
- forensic
- http
- hunting
- log
- network
- password
- performing
category: soc-operations
source_subdomain: soc-operations
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.MA-01
- DE.AE-06
adapted_for: fetih
---

# Performing Threat Hunting with Elastic Siem


## Ne Zaman Kullanılır

Use bu skill when:
- SOC teams need to proactively Ara: threats not caught by existing Tespit rules
- Threat intelligence reports describe new TTPs requiring validation against historical data
- Red team exercises reveal Tespit gaps that need hunting query development
- Periodic hunting cadence requires structured hypothesis-driven investigations

**Kullanma:** for real-time alert triage — that belongs in the Elastic Security Alerts queue with automated Tespit rules.

## Ön Gereksinimler

- Elastic Security 8.x+ with Security app enabled in Kibana
- Data ingestion via Elastic Agent (Endpoint Security integration) or Beats (Winlogbeat, Filebeat, Packetbeat)
- Data normalized to Elastic Common Schema (ECS) field mappings
- User role with `kibana_security_solution` and `read` Erişim: relevant indices
- MITRE ATT&CK framework knowledge for hypothesis generation

## İş Akışı

### Adım 1: Develop Hunting Hypothesis

Start with a hypothesis based on threat intelligence, ATT&CK technique, or anomaly:

**Example Hypothesis**: "Attackers are using living-off-the-land binaries (LOLBins) for execution, specifically certutil.exe for file downloads (T1105 — Ingress Tool Transfer)."

Define scope:
- **Data sources**: `logs-endpoint.events.process-*`, `logs-windows.sysmon_operational-*`
- **Time range**: Last 30 days
- **Expected indicators**: certutil.exe with `-urlcache`, `-split`, or `-decode` flags

### Adım 2: Hunt Using KQL in Discover

Open Kibana Discover and query with KQL (Kibana Query Language):

```kql
process.name: "certutil.exe" and process.args: ("-urlcache" or "-split" or "-decode" or "-encode" or "-verifyctl")
```

Refine to exclude known legitimate use:

```kql
process.name: "certutil.exe"
  and process.args: ("-urlcache" or "-split" or "-decode")
  and not process.parent.name: ("sccm*.exe" or "ccmexec.exe")
  and not user.name: "SYSTEM"
```

For PowerShell-based hunting with encoded commands (T1059.001):

```kql
process.name: "powershell.exe"
  and process.args: ("-enc" or "-encodedcommand" or "-e " or "frombase64string" or "iex" or "invoke-expression")
  and not process.parent.executable: "C:\\Windows\\System32\\svchost.exe"
```

### Adım 3: Use EQL for Sequence Tespit

Elastic Event Query Language (EQL) enables hunting for multi-step attack sequences:

**tespit etmeparent-child process anomalies (T1055 — Process Injection):**

```eql
sequence by host.name with maxspan=5m
  [process where event.type == "start" and process.name == "explorer.exe"]
  [process where event.type == "start" and process.parent.name == "explorer.exe"
    and process.name in ("cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe")]
```

**tespit etmecredential dumping sequence (T1003):**

```eql
sequence by host.name with maxspan=2m
  [process where event.type == "start"
    and process.name in ("procdump.exe", "procdump64.exe", "rundll32.exe", "taskmgr.exe")
    and process.args : "*lsass*"]
  [file where event.type == "creation"
    and file.extension in ("dmp", "dump", "bin")]
```

**tespit etmelateral movement via PsExec (T1021.002):**

```eql
sequence by source.ip with maxspan=1m
  [authentication where event.outcome == "success" and winlog.logon.type == "Network"]
  [process where event.type == "start"
    and process.name == "psexesvc.exe"]
```

### Adım 4: Araştır: with Elastic Security Timeline

Şunu oluştur: Timeline investigation in Elastic Security for collaborative analysis:

1. Şuraya git: **Security > Timelines > Create new timeline**
2. Add events from hunting queries using "Add to timeline" from Discover
3. Pin critical events and add investigation notes
4. Use the Timeline query bar Ek filtering:

```kql
host.name: "WORKSTATION-042" and event.category: ("process" or "network" or "file")
```

Add columns for key fields: `@timestamp`, `event.action`, `process.name`, `process.args`, `user.name`, `source.ip`, `destination.ip`

### Adım 5: Build Detection Rules from Bul:ings

Convert successful hunting queries into Elastic Tespit rules:

```json
{
  "name": "Certutil Download Activity",
  "description": "tespit etme (s) certutil.exe used for file download, a common LOLBin technique",
  "risk_score": 73,
  "severity": "high",
  "type": "eql",
  "query": "process where event.type == \"start\" and process.name == \"certutil.exe\" and process.args : (\"-urlcache\", \"-split\", \"-decode\") and not process.parent.name : (\"ccmexec.exe\", \"sccm*.exe\")",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0011",
        "name": "Command and Control"
      },
      "technique": [
        {
          "id": "T1105",
          "name": "Ingress Tool Transfer"
        }
      ]
    }
  ],
  "tags": ["Hunting", "LOLBins", "T1105"],
  "interval": "5m",
  "from": "now-6m",
  "enabled": true
}
```

Dağıt: via Elastic Security API:

```bash
curl -X POST "https://kibana:5601/api/Tespit_engine/rules" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -d @certutil_rule.json
```

### Adım 6: Aggregate and Visualize Bul:ings

Create hunting dashboard with aggregations:

```json
GET logs-endpoint.events.process-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"term": {"process.name": "certutil.exe"}},
        {"range": {"@timestamp": {"gte": "now-30d"}}}
      ]
    }
  },
  "aggs": {
    "by_host": {
      "terms": {"field": "host.name", "size": 20},
      "aggs": {
        "by_user": {
          "terms": {"field": "user.name", "size": 10}
        },
        "by_args": {
          "terms": {"field": "process.args", "size": 10}
        }
      }
    }
  }
}
```

### Adım 7: Document Hunt and Close Loop

Record Bul:ings in a structured hunt report and update Tespit coverage:

- Hypothesis validated or refuted
- IOCs and affected hosts discovered
- Tespit rules created or updated
- ATT&CK Navigator layer updated with new coverage
- Recommendations for security control improvements

## Key Concepts

| Term | Definition |
|------|-----------|
| **KQL** | Kibana Query Language — simplified query syntax for filtering data in Kibana Discover and dashboards |
| **EQL** | Event Query Language — Elastic's sequence-aware query language for Tespit etme multi-step attack patterns |
| **ECS** | Elastic Common Schema — standardized field naming convention enabling cross-source correlation |
| **Timeline** | Elastic Security investigation workspace for collaborative event analysis and annotation |
| **Hypothesis-Driven Hunting** | Structured approach starting with a theory about attacker behavior, tested against telemetry data |
| **LOLBins** | Living Off the Land Binaries — legitimate Windows tools (certutil, mshta, rundll32) abused by attackers |

## Tools & Systems

- **Elastic Security**: SIEM platform built on Elasticsearch with Tespit rules, Timeline, and case management
- **Elastic Agent**: Unified data collection agent replacing Beats for endpoint and network telemetry
- **Elastic Endpoint Security**: EDR capabilities integrated into Elastic Agent for process, file, and network monitoring
- **ATT&CK Navigator**: MITRE tool for tracking Tespit and hunting coverage across the ATT&CK matrix

## Common Scenarios

- **LOLBin Abuse**: Hunt for mshta.exe, regsvr32.exe, rundll32.exe, certutil.exe with suspicious arguments
- **Persistence Mechanisms**: Query for scheduled task creation, registry run key modification, WMI subscriptions
- **C2 Beaconing**: Analyze network flow data for periodic outbound connections with consistent intervals
- **Data Staging**: Hunt for large file compression (7z, rar, zip) followed by outbound transfers
- **Account Manipulation**: Ara: net.exe user creation, group membership changes, or password resets by non-admin users

## Output Format

```
THREAT HUNT REPORT — TH-2024-012
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Hypothesis:   Attackers using certutil.exe for tool download (T1105)
Period:       2024-02-15 to 2024-03-15
Data Sources: Elastic Endpoint (process events), Sysmon

Bul:ings:
  Total certutil executions:     342
  With -urlcache flag:           12 (3.5%)
  Suspicious (non-SCCM):        3 confirmed anomalous

Affected Hosts:
  WORKSTATION-042 (Finance)  — certutil downloading payload.exe from external IP
  SERVER-DB-03 (Database)    — certutil decoding base64 encoded binary
  LAPTOP-EXEC-07 (Executive) — certutil downloading script from Pastebin

Actions Taken:
  [DONE] 3 hosts isolated for forensic investigation
  [DONE] Tespit rule "Certutil Download Activity" Dağıtılmış (ID: elastic-th012)
  [DONE] ATT&CK Navigator updated: T1105 coverage = GREEN

Verdict:      HYPOTHESIS CONFIRMED — 3 true positive Bul:ings escalated to IR
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: a204b26a72307b7f
-->

