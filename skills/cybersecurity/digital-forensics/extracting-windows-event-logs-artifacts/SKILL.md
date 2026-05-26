---
name: extracting-windows-event-logs-artifacts
description: Extract, parse, and analyze Windows Event Logs (EVTX) using Chainsaw, Hayabusa, and EvtxECmd to tespit etmelateral movement, persistence, and privilege escalation.
tags:
- hayabusa
- windows-event-logs
- incident-response
- digital-forensics
- forensics
- fetih
- chainsaw
- sigma-rules
- cybersecurity
- siber-güvenlik
- evtx
triggers:
- adli bilişim
- alert
- artifacts
- authentication
- dijital delil
- disk imajı
- encryption
- endpoint
- event
- extracting
- forensic
- forensics
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
adapted_for: fetih
---

# Extracting Windows Event Logs Artifacts


## Ne Zaman Kullanılır
- investigating yaparken security incidents on Windows systems through event log analysis
- For Tespit etme lateral movement, privilege escalation, and persistence mechanisms
- performing yaparken threat hunting across Windows event log data
- compliance sırasında audits requiring review of authentication and access events
- building yaparken forensic timelines from Windows system activity

## Ön Gereksinimler
- Windows Event Log files (EVTX format) from forensic image or live system
- Chainsaw, Hayabusa, or EvtxECmd for parsing and Tespit
- Sigma rules for automated threat Tespit
- Understanding of critical Windows Event IDs
- Python with python-evtx or evtx library for custom parsing
- PowerShell for live system analysis (if applicable)

## İş Akışı

### Adım 1: Collect Windows Event Log Files

```bash
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

mkdir -p /cases/case-2024-001/evtx/
cp /mnt/evidence/Windows/System32/winevt/Logs/*.evtx /cases/case-2024-001/evtx/


ls -lhS /cases/case-2024-001/evtx/ | head -20

sha256sum /cases/case-2024-001/evtx/*.evtx > /cases/case-2024-001/evtx/evtx_hashes.txt
```

### Adım 2: Run Chainsaw for Sigma-Based Tespit

```bash
wget https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip
unzip chainsaw_all_platforms+rules.zip -d /opt/chainsaw

/opt/chainsaw/chainsaw hunt /cases/case-2024-001/evtx/ \
   -s /opt/chainsaw/sigma/rules/ \
   --mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml \
   --output /cases/case-2024-001/analysis/chainsaw_results.txt

/opt/chainsaw/chainsaw hunt /cases/case-2024-001/evtx/ \
   -s /opt/chainsaw/sigma/rules/ \
   --mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml \
   --csv \
   --output /cases/case-2024-001/analysis/chainsaw_results/

/opt/chainsaw/chainsaw hunt /cases/case-2024-001/evtx/ \
   -s /opt/chainsaw/sigma/rules/ \
   --mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml \
   --json \
   --output /cases/case-2024-001/analysis/chainsaw_results.json

/opt/chainsaw/chainsaw search /cases/case-2024-001/evtx/ \
   -s "mimikatz" --json

/opt/chainsaw/chainsaw search /cases/case-2024-001/evtx/ \
   -e 4688 --json | head -100
```

### Adım 3: Run Hayabusa for Fast Timeline Generation

```bash
wget https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-linux-x64-musl.zip
unzip hayabusa-linux-x64-musl.zip -d /opt/hayabusa

/opt/hayabusa/hayabusa csv-timeline \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/hayabusa_timeline.csv \
   -p verbose

/opt/hayabusa/hayabusa json-timeline \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/hayabusa_timeline.json

/opt/hayabusa/hayabusa csv-timeline \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/hayabusa_critical.csv \
   -p verbose \
   --min-level critical

/opt/hayabusa/hayabusa metrics \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/hayabusa_metrics.csv

/opt/hayabusa/hayabusa logon-summary \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/logon_summary.csv
```

### Adım 4: Parse Specific Critical Event IDs

```bash
pip install evtx

python3 << 'PYEOF'
import json
from evtx import PyEvtxParser

parser = PyEvtxParser("/cases/case-2024-001/evtx/Security.evtx")

critical_events = {
    '4624': 'Successful Logon',
    '4625': 'Failed Logon',
    '4634': 'Logoff',
    '4648': 'Explicit Credential Logon',
    '4672': 'Special Privileges Assigned',
    '4688': 'Process Created',
    '4689': 'Process Exited',
    '4697': 'Service Installed',
    '4698': 'Scheduled Task Created',
    '4720': 'User Account Created',
    '4724': 'Password Reset Attempted',
    '4728': 'Member Added to Global Group',
    '4732': 'Member Added to Local Group',
    '4756': 'Member Added to Universal Group',
    '1102': 'Audit Log Cleared',
    '4688': 'New Process Created'
}

results = {eid: [] for eid in critical_events}

for record in parser.records_json():
    data = json.loads(record['data'])
    event_id = str(data['Event']['System']['EventID'])

    if event_id in critical_events:
        event_data = data['Event'].get('EventData', {})
        results[event_id].append({
            'timestamp': data['Event']['System']['TimeCreated']['#attributes']['SystemTime'],
            'event_id': event_id,
            'description': critical_events[event_id],
            'data': event_data
        })

for eid, events in results.items():
    if events:
        print(f"\n[{eid}] {critical_events[eid]}: {len(events)} events")
        for e in events[:3]:
            print(f"  {e['timestamp']}: {json.dumps(e['data'], default=str)[:200]}")
        if len(events) > 3:
            print(f"  ... and {len(events)-3} more")

with open('/cases/case-2024-001/analysis/critical_events.json', 'w') as f:
    json.dump(results, f, indent=2, default=str)
PYEOF
```

### Adım 5: tespit etmeSpecific Attack Patterns

```bash
python3 << 'PYEOF'
import json
from evtx import PyEvtxParser

parser = PyEvtxParser("/cases/case-2024-001/evtx/Security.evtx")

print("=== PASS-THE-HASH INDICATORS ===")
print("Looking for: Event 4624, Logon Type 9, NTLM authentication\n")

for record in parser.records_json():
    data = json.loads(record['data'])
    event_id = str(data['Event']['System']['EventID'])

    if event_id == '4624':
        event_data = data['Event'].get('EventData', {})
        logon_type = str(event_data.get('LogonType', ''))
        auth_package = str(event_data.get('AuthenticationPackageName', ''))
        logon_process = str(event_data.get('LogonProcessName', ''))

        # Pass-the-Hash indicators
        if logon_type == '9' and 'NTLM' in auth_package:
            timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
            target = event_data.get('TargetUserName', 'Unknown')
            source_ip = event_data.get('IpAddress', 'N/A')
            print(f"  [{timestamp}] PtH: User={target}, IP={source_ip}, Auth={auth_package}")

        # Network logon with NTLM (lateral movement)
        if logon_type == '3' and 'NTLM' in auth_package:
            timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
            target = event_data.get('TargetUserName', 'Unknown')
            source_ip = event_data.get('IpAddress', 'N/A')
            workstation = event_data.get('WorkstationName', 'N/A')
            print(f"  [{timestamp}] Network NTLM: User={target}, IP={source_ip}, WS={workstation}")
PYEOF

python3 << 'PYEOF'
import json
from evtx import PyEvtxParser

for log_file in ['Security.evtx', 'System.evtx']:
    path = f"/cases/case-2024-001/evtx/{log_file}"
    try:
        parser = PyEvtxParser(path)
        for record in parser.records_json():
            data = json.loads(record['data'])
            event_id = str(data['Event']['System']['EventID'])
            if event_id in ('1102', '104'):  # Security log cleared, System log cleared
                timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
                print(f"LOG CLEARED: [{timestamp}] EventID {event_id} in {log_file}")
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| EVTX format | Binary XML-based Windows Event Log format introduced in Vista/Server 2008 |
| Event ID | Numeric identifier for specific event types (e.g., 4624 = successful logon) |
| Logon types | Classification of authentication methods (2=interactive, 3=network, 10=RDP) |
| Sigma rules | Generic Tespit signatures that map to specific SIEM/log queries |
| Sysmon | Microsoft system monitoring driver providing detailed process and network events |
| Audit policy | GPO settings controlling which events Windows records |
| Event forwarding (WEF) | Windows mechanism for centralized event log collection |
| EVTX channels | Separate log files for different event categories and applications |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Chainsaw | Sigma-based EVTX analysis and threat hunting tool |
| Hayabusa | Fast Windows Event Log forensic timeline generator |
| EvtxECmd | Eric Zimmerman command-line EVTX parser with CSV/JSON output |
| python-evtx | Python library for EVTX file parsing |
| LogParser | Microsoft SQL-like query engine for Windows logs |
| Event Log Explorer | GUI tool for browsing and analyzing EVTX files |
| KAPE | Automated triage collection including event logs |
| Velociraptor | Endpoint agent with EVTX collection and hunting artifacts |

## Common Scenarios

**Scenario 1: Tespit etme Lateral Movement**
Filter for Event 4624 with Logon Type 3 (network) and Type 10 (RDP), identify unusual source-destination pairs, check for Event 4648 (explicit credentials) indicating pass-the-hash, correlate with process creation events (4688) on target systems.

**Scenario 2: Privilege Escalation Tespit**
Ara: Event 4672 (special privileges assigned) for unexpected users, check for Event 4728/4732 (group membership changes) adding users to admin groups, Ara: Event 4697 (service installed) indicating new system-level access, correlate with 4720 (account creation).

**Scenario 3: PowerShell Attack Tespit**
Analyze PowerShell Operational log for Script Block Logging (Event 4104), Ara: encoded commands in Event 4688 (process creation with command line), tespit etmeAMSI bypass attempts, identify download cradles and invocation of known attack tools.

**Scenario 4: Ransomware Incident Reconstruction**
Build timeline starting from initial access (4624 from external IP), trace privilege escalation through group membership changes, identify service installations for persistence, Bul: process creation events for encryption executable, tespit etmevolume shadow copy deletion in System log.

## Output Format

```
Windows Event Log Analysis Summary:
  System: DC01.corp.local (Windows Server 2019)
  Log Files Analyzed: 15 EVTX files
  Total Events: 2,456,789
  Analysis Period: 2024-01-10 to 2024-01-20

  Chainsaw Tespits:
    Critical:  12 (Mimikatz usage, PsExec, log clearing)
    High:      34 (Network NTLM logons, encoded PowerShell)
    Medium:    89 (Unusual service installations, scheduled tasks)
    Low:       234 (Informational)

  Hayabusa Timeline:
    Total Alerts: 369
    Unique Rules Triggered: 45
    Top Rules:
      - Suspicious NTLM Authentication (34 hits)
      - PowerShell Download Cradle (12 hits)
      - Service Installation Suspicious Path (8 hits)

  Critical Bul:ings:
    2024-01-15 14:32 - RDP brute force (234 failed, 1 success from 203.0.113.45)
    2024-01-15 14:45 - Admin account created (svcbackup) - Event 4720
    2024-01-16 02:30 - PsExec service kurulu: DC01 - Event 4697
    2024-01-18 03:00 - Security log cleared - Event 1102

  Reports:
    Chainsaw: /analysis/chainsaw_results/
    Hayabusa: /analysis/hayabusa_timeline.csv
    Critical Events: /analysis/critical_events.json
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: ccb34a80667cb24c
-->

