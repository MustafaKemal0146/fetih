---
name: performing-timeline-reconstruction-with-plaso
description: Build comprehensive forensic super-timelines using Plaso (log2timeline) to correlate events across file systems, logs, and artifacts into a unified chronological view.
tags:
- plaso
- digital-forensics
- timeline-analysis
- forensics
- fetih
- super-timeline
- cybersecurity
- log2timeline
- event-correlation
- siber-güvenlik
triggers:
- adli bilişim
- authentication
- cloud
- dijital delil
- disk imajı
- email
- encryption
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

# Performing Timeline Reconstruction with Plaso


## Ne Zaman Kullanılır
- building yaparken a comprehensive forensic timeline from multiple evidence sources
- For correlating events across file system metadata, event logs, browser history, and registry
- During complex investigations requiring chronological reconstruction of activities
- standard yaparken: log analysis is insufficient to establish the sequence of events
- For presenting investigation Bul:ings in a visual, chronological format

## Ön Gereksinimler
- Plaso (log2timeline/psort) kurulu: forensic workstation
- Forensic disk image(s) in raw (dd), E01, or VMDK format
- Yeterli storage for Plaso output (can be 10x+ the image size)
- Minimum 8GB RAM (16GB+ recommended for large images)
- Timeline Explorer (Eric Zimmerman) or Timesketch for visualization
- Understanding of timestamp types (MACB: Modified, Accessed, Changed, Born)

## İş Akışı

### Adım 1: Install Plaso and Prepare the Environment

```bash
sudo add-apt-repository ppa:gift/stable
sudo apt-get update
sudo apt-get install plaso-tools

pip install plaso

docker pull log2timeline/plaso

log2timeline.py --version
psort.py --version

mkdir -p /cases/case-2024-001/timeline/

img_stat /cases/case-2024-001/images/evidence.dd
```

### Adım 2: Generate the Plaso Storage File with log2timeline

```bash
log2timeline.py \
   --storage-file /cases/case-2024-001/timeline/evidence.plaso \
   /cases/case-2024-001/images/evidence.dd

log2timeline.py \
   --parsers "winevtx,prefetch,mft,usnjrnl,lnk,recycle_bin,chrome_history,firefox_history,winreg" \
   --storage-file /cases/case-2024-001/timeline/evidence.plaso \
   /cases/case-2024-001/images/evidence.dd

cat << 'EOF' > /cases/case-2024-001/timeline/filter.txt
/Windows/System32/winevt/Logs
/Windows/Prefetch
/Users/*/NTUSER.DAT
/Users/*/AppData/Local/Google/Chrome
/Users/*/AppData/Roaming/Mozilla/Firefox
/$MFT
/$UsnJrnl:$J
/Windows/System32/config
EOF

log2timeline.py \
   --filter-file /cases/case-2024-001/timeline/filter.txt \
   --storage-file /cases/case-2024-001/timeline/evidence.plaso \
   /cases/case-2024-001/images/evidence.dd

docker run --rm -v /cases:/cases log2timeline/plaso log2timeline \
   --storage-file /cases/case-2024-001/timeline/evidence.plaso \
   /cases/case-2024-001/images/evidence.dd

log2timeline.py \
   --storage-file /cases/case-2024-001/timeline/combined.plaso \
   /cases/case-2024-001/images/workstation.dd

log2timeline.py \
   --storage-file /cases/case-2024-001/timeline/combined.plaso \
   /cases/case-2024-001/images/server.dd
```

### Adım 3: Filter and Export Timeline with psort

```bash
psort.py \
   -o l2tcsv \
   -w /cases/case-2024-001/timeline/full_timeline.csv \
   /cases/case-2024-001/timeline/evidence.plaso

psort.py \
   -o l2tcsv \
   -w /cases/case-2024-001/timeline/incident_window.csv \
   /cases/case-2024-001/timeline/evidence.plaso \
   "date > '2024-01-15 00:00:00' AND date < '2024-01-20 23:59:59'"

psort.py \
   -o json_line \
   -w /cases/case-2024-001/timeline/timeline.jsonl \
   /cases/case-2024-001/timeline/evidence.plaso

psort.py \
   -o l2tcsv \
   -w /cases/case-2024-001/timeline/registry_events.csv \
   /cases/case-2024-001/timeline/evidence.plaso \
   "source_short == 'REG'"

psort.py \
   -o l2tcsv \
   -w /cases/case-2024-001/timeline/evtx_events.csv \
   /cases/case-2024-001/timeline/evidence.plaso \
   "source_short == 'EVT'"

psort.py \
   -o dynamic \
   -w /cases/case-2024-001/timeline/timeline_explorer.csv \
   /cases/case-2024-001/timeline/evidence.plaso
```

### Adım 4: Analyze Timeline with Timesketch

```bash
git clone https://github.com/google/timesketch.git
cd timesketch
docker compose up -d

timesketch_importer \
   --host http://localhost:5000 \
   --username analyst \
   --password password \
   --sketch_id 1 \
   --timeline_name "Case 2024-001 Workstation" \
   /cases/case-2024-001/timeline/evidence.plaso

timesketch_importer \
   --host http://localhost:5000 \
   --username analyst \
   --sketch_id 1 \
   --timeline_name "Case 2024-001" \
   /cases/case-2024-001/timeline/timeline.jsonl

```

### Adım 5: Perform Targeted Timeline Analysis

```bash
python3 << 'PYEOF'
import csv
from collections import defaultdict
from datetime import datetime

events_by_hour = defaultdict(list)
source_counts = defaultdict(int)

with open('/cases/case-2024-001/timeline/incident_window.csv', 'r', errors='ignore') as f:
    reader = csv.DictReader(f)
    total = 0
    for row in reader:
        total += 1
        timestamp = row.get('datetime', row.get('date', ''))
        source = row.get('source_short', row.get('source', 'Unknown'))
        description = row.get('message', row.get('desc', ''))

        source_counts[source] += 1

        # Group by hour for activity patterns
        try:
            dt = datetime.strptime(timestamp[:19], '%Y-%m-%dT%H:%M:%S')
            hour_key = dt.strftime('%Y-%m-%d %H:00')
            events_by_hour[hour_key].append({
                'time': timestamp,
                'source': source,
                'description': description[:200]
            })
        except (ValueError, TypeError):
            pass

print(f"Total events in incident window: {total}\n")

print("=== EVENTS BY SOURCE TYPE ===")
for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  {source}: {count}")

print("\n=== ACTIVITY BY HOUR ===")
for hour in sorted(events_by_hour.keys()):
    count = len(events_by_hour[hour])
    bar = '#' * min(count // 10, 50)
    print(f"  {hour}: {count:>6} events {bar}")

avg = total / max(len(events_by_hour), 1)
print(f"\n=== ANOMALOUS HOURS (>{avg*3:.0f} events) ===")
for hour in sorted(events_by_hour.keys()):
    if len(events_by_hour[hour]) > avg * 3:
        print(f"  {hour}: {len(events_by_hour[hour])} events (SPIKE)")
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Super-timeline | Unified chronological view combining all artifact timestamps from multiple sources |
| MACB timestamps | Modified, Accessed, Changed (metadata), Born (created) - four key file timestamp types |
| Plaso storage file | SQLite-based intermediate format storing parsed events before export |
| L2T CSV | Log2timeline CSV format with standardized columns for timeline events |
| Parser | Plaso module extracting timestamps from a specific artifact type (e.g., winevtx, prefetch) |
| Psort | Plaso sorting and filtering tool for post-processing storage files |
| Timesketch | Google open-source collaborative timeline analysis platform |
| Pivot points | Known timestamps (e.g., malware execution) used to focus investigation scope |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| log2timeline (Plaso) | Primary timeline generation engine parsing 100+ artifact types |
| psort | Plaso output filtering, sorting, and export utility |
| Timesketch | Web-based collaborative forensic timeline analysis platform |
| Timeline Explorer | Eric Zimmerman's Windows GUI for CSV timeline analysis |
| KAPE | Automated triage collection feeding into Plaso processing |
| mactime (TSK) | Simpler timeline generation from Sleuth Kit bodyfiles |
| Excel/Sheets | Manual timeline review for small filtered datasets |
| Elastic/Kibana | Alternative visualization platform for JSONL timeline data |

## Common Scenarios

**Scenario 1: Ransomware Attack Reconstruction**
Process the full disk image with Plaso, filter to the week before encryption was discovered, the tespit et: initial access vector from browser history and event logs, trace privilege escalation through registry and Prefetch, map lateral movement from network logon events, pinpoint encryption start from MFT timestamps showing mass file modifications.

**Scenario 2: Data Theft Investigation**
Create super-timeline from suspect's workstation, filter for USB device connection events, file access timestamps, and cloud storage browser activity, build a narrative showing data staging, compression, and exfiltration, present timeline to legal team with tagged evidence points.

**Scenario 3: Multi-System Breach Analysis**
Process disk images from all affected systems into a single Plaso storage file, import into Timesketch for collaborative analysis, Ara: lateral movement patterns across system timelines, the tespit et: patient-zero system and initial compromise vector, map the full attack chain across the environment.

**Scenario 4: Insider Threat After-Hours Activity**
Filter timeline to non-business hours only, identify file access patterns outside normal working times, correlate with authentication events (badge access, VPN logon), Ara: data Erişim: sensitive directories during these periods, build evidence package for HR/legal.

## Output Format

```
Timeline Reconstruction Summary:
  Evidence Sources:
    Disk Image: evidence.dd (500 GB, NTFS)
    Plaso Storage: evidence.plaso (2.3 GB)

  Processing Statistics:
    Total events extracted: 4,567,890
    Parsers used: 45 (winevtx, prefetch, mft, usnjrnl, lnk, chrome, firefox, winreg, ...)
    Processing time: 3h 45m

  Incident Window (2024-01-15 to 2024-01-20):
    Events in window: 234,567
    Event Sources:
      MFT:          89,234
      Event Logs:   45,678
      USN Journal:  56,789
      Registry:     23,456
      Prefetch:     1,234
      Browser:      5,678
      LNK Files:    2,345
      Other:        10,153

  Key Timeline Events:
    2024-01-15 14:32 - Phishing email opened (browser)
    2024-01-15 14:33 - Malicious document downloaded
    2024-01-15 14:35 - PowerShell executed (Prefetch + Event Log)
    2024-01-15 14:36 - C2 connection established (Registry + Event Log)
    2024-01-16 02:30 - Mimikatz execution (Prefetch)
    2024-01-16 02:45 - Lateral movement to DC (Event Log)
    2024-01-17 03:00 - Data exfiltration (MFT + USN Journal)
    2024-01-18 03:00 - Log clearing (Event Log)

  Exported Files:
    Full Timeline:     /timeline/full_timeline.csv (4.5M rows)
    Incident Window:   /timeline/incident_window.csv (234K rows)
    Timesketch Import: /timeline/timeline.jsonl
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 11351876488e4254
-->

