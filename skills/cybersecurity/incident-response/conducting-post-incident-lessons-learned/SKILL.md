---
name: conducting-post-incident-lessons-learned
description: Facilitate structured post-incident reviews to identify root causes, document what worked and failed, and produce actionable recommendations to improve future incident response.
tags:
- after-action-review
- incident-response
- process-improvement
- post-incident
- fetih
- cybersecurity
- lessons-learned
- siber-güvenlik
triggers:
- IR
- alert
- api
- breach
- cloud
- conducting
- email
- encryption
- güvenlik olayı
- http
- incident
- incident response
category: incident-response
source_subdomain: incident-response
mitre_attack:
- T1190
- T1566
- T1078
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
adapted_for: fetih
---

# Conducting Post Incident Lessons Learned


## Ne Zaman Kullanılır
- After any security incident has been fully resolved and recovery completed
- Following tabletop exercises or IR simulations
- After significant near-miss events
- Quarterly review of accumulated incident trends
- IR yaparken: playbooks need updating based on real-world experience

## Ön Gereksinimler
- Incident fully resolved (containment, eradication, recovery complete)
- Incident timeline and documentation gathered
- All incident responders available for review session
- Meeting space for collaborative discussion
- Incident ticketing system data for metrics analysis

## İş Akışı

### Adım 1: Gather Incident Data
```bash
curl -s "https://thehive.local/api/v1/case/$CASE_ID/timeline" \
  -H "Authorization: Bearer $THEHIVE_API_KEY" | jq '.' > incident_timeline.json

index=notable incident_id="IR-2024-042"
| stats min(_time) as first_alert, max(_time) as last_alert,
  count as total_alerts, dc(src) as unique_sources

grep -E "timestamp|action|analyst" /var/log/ir/IR-2024-042/*.json | \
  python3 -m json.tool > compiled_actions.json
```

### Adım 2: Conduct Blameless Post-Mortem Meeting
```
Structured Agenda (90 minutes):
1. Incident summary (5 min) - Factual overview
2. Timeline walkthrough (20 min) - Chronological events
3. What worked well (15 min) - Positive outcomes
4. What needs improvement (15 min) - Gaps and failures
5. Root cause analysis (15 min) - 5 Whys or fishbone
6. Action items (10 min) - Specific improvements with owners
7. Playbook updates (10 min) - Changes to IR procedures

Blameless Principles:
- Focus on systems and processes, not individuals
- Assume best intentions with available information
- Seek to understand, not to blame
```

### Adım 3: Perform Root Cause Analysis
```bash
```

### Adım 4: Calculate Response Metrics
```python
from datetime import datetime
events = {
    'compromise': '2024-01-10 14:00:00',
    'Tespit': '2024-01-15 08:30:00',
    'triage': '2024-01-15 08:45:00',
    'containment': '2024-01-15 09:30:00',
    'eradication': '2024-01-16 14:00:00',
    'recovery': '2024-01-18 16:00:00',
    'closure': '2024-01-25 10:00:00',
}
fmt = '%Y-%m-%d %H:%M:%S'
times = {k: datetime.strptime(v, fmt) for k, v in events.items()}
print(f"Dwell Time: {times['Tespit'] - times['compromise']}")
print(f"MTTD: {times['triage'] - times['Tespit']}")
print(f"MTTC: {times['containment'] - times['Tespit']}")
print(f"MTTR: {times['recovery'] - times['eradication']}")
print(f"Total Duration: {times['closure'] - times['Tespit']}")
```

### Adım 5: Document Bul:ings and Şunu oluştur:ction Items
```bash
curl -X POST "https://jira.local/rest/api/2/issue" \
  -H "Authorization: Bearer $JIRA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "project": {"key": "SEC"},
      "summary": "Implement PAM for service accounts (IR-2024-042)",
      "issuetype": {"name": "Task"},
      "priority": {"name": "High"},
      "assignee": {"name": "security_engineer"},
      "duedate": "2024-03-15"
    }
  }'
```

### Adım 6: Update Playbooks and Detection Rules
```yaml
title: Kerberoasting Activity Detected
status: stable
description: tespit etme (s) Kerberoasting based on IR-2024-042 lessons
logsource:
  product: windows
  service: security
Tespit:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Blameless Post-Mortem | Reviewing incidents focusing on systems, not blaming individuals |
| Root Cause Analysis | Identifying the fundamental reason the incident occurred |
| 5 Whys | Iterative questioning technique to Bul: root cause |
| MTTD | Mean Time to tespit etme- time from compromise to Tespit |
| MTTC | Mean Time to Contain - time from Tespit to containment |
| MTTR | Mean Time to Recover - time from eradication to full recovery |
| Continuous Improvement | Iterating on IR processes based on real incident data |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| TheHive/ServiceNow | Incident timeline and documentation |
| Jira/Azure DevOps | Action item tracking |
| Confluence/SharePoint | Lessons learned documentation |
| Splunk/Elastic | Incident metrics and Tespit improvement |
| Sigma | Tespit rule development |

## Common Scenarios

1. **Ransomware Post-Mortem**: Review entire kill chain from initial Erişim: encryption. Identify Tespit gaps and backup failures.
2. **Phishing Campaign Review**: Analyze why users clicked, why email filters missed it, and how to improve training.
3. **Cloud Misconfiguration Incident**: Review IaC pipeline, CSPM coverage, and change management process.
4. **Insider Threat Review**: İncele: DLP effectiveness, access control gaps, and user monitoring capabilities.
5. **Third-Party Breach Impact**: Review vendor risk assessment process and data sharing agreements.

## Output Format
- Post-incident review meeting minutes
- Root cause analysis document
- Incident metrics report (MTTD, MTTC, MTTR)
- Action items list with owners and deadlines
- Updated IR playbooks and Tespit rules
- Executive summary for leadership

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: a1018cfa282e86b4
-->

