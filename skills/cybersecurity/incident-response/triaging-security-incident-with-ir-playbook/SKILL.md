---
name: triaging-security-incident-with-ir-playbook
description: Classify and prioritize security incidents using structured IR playbooks to Belirle: severity, assign response teams, and initiate appropriate response procedures.
tags:
- playbook
- soc
- incident-response
- triage
- fetih
- cybersecurity
- severity-classification
- siber-güvenlik
triggers:
- IR
- alert
- api
- breach
- cloud
- email
- endpoint
- exploit
- güvenlik olayı
- hash
- http
- incident
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
---

# Triaging Security Incident with Ir Playbook


## Ne Zaman Kullanılır
- New security alert received from SIEM, EDR, or other Tespit sources
- SOC analyst needs to Belirle: if an alert is a true positive requiring response
- Incident needs severity classification and team assignment
- Multiple concurrent incidents require prioritization
- Automated triage rules need validation or tuning

## Ön Gereksinimler
- SIEM platform with alert correlation (Splunk, Elastic, QRadar, Sentinel)
- Incident response playbook library (by incident type)
- Severity classification matrix approved by CISO
- On-call rotation and escalation procedures
- Ticketing system for incident tracking (ServiceNow, Jira, TheHive)
- Threat intelligence feeds for IOC enrichment

## İş Akışı

### Adım 1: Receive and Acknowledge Alert
```bash
index=notable status=new severity IN ("critical","high")
| table _time, rule_name, src, dest, severity, description
| sort -_time

curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" \
  "https://thehive.local/api/v1/query?name=list-alerts" \
  -H "Content-Type: application/json" \
  -d '{"query":[{"_name":"listAlert"},{"_name":"filter","_field":"status","_value":"New"}]}'

curl -X POST "https://splunk.local:8089/services/notable_update" \
  -H "Authorization: Bearer $SPLUNK_TOKEN" \
  -d "ruleUIDs=$RULE_UID&status=1&comment=Triage+initiated+by+analyst"
```

### Adım 2: Enrich Alert Data
```bash
curl -s "https://www.virustotal.com/api/v3/ip_addresses/$SRC_IP" \
  -H "x-apikey: $VT_API_KEY" | jq '.data.attributes.last_analysis_stats'

curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$SRC_IP&maxAgeInDays=90" \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | jq '.data'

curl -s "https://www.virustotal.com/api/v3/files/$FILE_HASH" \
  -H "x-apikey: $VT_API_KEY" | jq '.data.attributes.last_analysis_stats'

curl -s "https://cmdb.local/api/assets?ip=$DEST_IP" \
  -H "Authorization: Bearer $CMDB_TOKEN" | jq '.asset_criticality, .owner, .environment'
```

### Adım 3: Classify Incident Type
```bash

grep -i "$ALERT_SIGNATURE" /opt/ir/playbooks/trigger_conditions.yaml

curl -s "https://attack.mitre.org/api/techniques/$TECHNIQUE_ID" | jq '.name, .tactic'
```

### Adım 4: Assign Severity Level
```bash

python3 -c "
severity_score = 0
severity_score += 4  # Critical server
severity_score += 3  # PCI data
severity_score += 2  # Single system
severity_score += 4  # Active threat

if severity_score >= 12: print('CRITICAL - P1')
elif severity_score >= 9: print('HIGH - P2')
elif severity_score >= 6: print('MEDIUM - P3')
else: print('LOW - P4')
print(f'Score: {severity_score}/16')
"
```

### Adım 5: Select and Initiate Playbook
```bash
cat /opt/ir/playbooks/ransomware_playbook.yaml
cat /opt/ir/playbooks/phishing_playbook.yaml
cat /opt/ir/playbooks/unauthorized_access_playbook.yaml

curl -X POST "https://thehive.local/api/v1/case" \
  -H "Authorization: Bearer $THEHIVE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "IR-2024-XXX: [Incident Type] - [Brief Description]",
    "description": "Triage summary and initial Bul:ings",
    "severity": 3,
    "tlp": 2,
    "pap": 2,
    "tags": ["ransomware", "triage-complete"],
    "customFields": {
      "playbook": {"string": "ransomware_v2"},
      "affected_systems": {"integer": 5}
    }
  }'
```

### Adım 6: Assign Response Team
```bash
curl -s "https://pagerduty.com/api/v2/oncalls?schedule_ids[]=$SCHEDULE_ID" \
  -H "Authorization: Token token=$PD_TOKEN" | jq '.oncalls[].user.summary'


curl -X POST "https://events.pagerduty.com/v2/enqueue" \
  -H "Content-Type: application/json" \
  -d '{
    "routing_key": "'$PD_ROUTING_KEY'",
    "event_action": "trigger",
    "payload": {
      "summary": "P1 Security Incident: Ransomware Detected on PROD-DB-01",
      "severity": "critical",
      "source": "SIEM-Splunk",
      "custom_details": {"incident_id": "IR-2024-042", "playbook": "ransomware_v2"}
    }
  }'
```

### Adım 7: Document Triage Decision and Hand Off
```bash
curl -X PATCH "https://thehive.local/api/v1/case/$CASE_ID" \
  -H "Authorization: Bearer $THEHIVE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "InProgress",
    "customFields": {
      "triage_analyst": {"string": "analyst_name"},
      "triage_time": {"date": '$(date +%s000)'},
      "severity_justification": {"string": "Critical asset + active threat + PCI data"}
    }
  }'
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| True Positive | Alert correctly identifying a real security incident |
| False Positive | Alert incorrectly flagging benign activity as malicious |
| Severity Classification | Ranking incident priority based on impact and urgency |
| Playbook Selection | Choosing the appropriate response procedure based on incident type |
| IOC Enrichment | Adding context to indicators from threat intelligence sources |
| Escalation Threshold | Criteria triggering escalation to higher severity or management |
| Triage SLA | Time target for initial assessment (typically 15-30 min for critical) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Splunk/Elastic/QRadar | SIEM alert correlation and querying |
| TheHive/SIRP | Incident case management and playbook tracking |
| VirusTotal/AbuseIPDB | IOC reputation and enrichment |
| PagerDuty/OpsGenie | On-call management and alerting |
| MITRE ATT&CK | Technique classification and mapping |
| Cortex XSOAR | SOAR platform for automated triage workflows |

## Common Scenarios

1. **Brute Force Alert**: Multiple failed logins from single IP. Enrich IP reputation, check geo-location, verify if account was compromised, assign P3 if unsuccessful.
2. **Malware Tespit on Endpoint**: AV/EDR quarantined malware. Verify quarantine success, check for lateral movement, assign P2 if persistence Detected.
3. **Suspicious Outbound Traffic**: Large data transfer to unknown external IP. Check if known cloud service, verify data classification, assign P1 if exfiltration confirmed.
4. **Phishing Email Reported**: User reports suspicious email. Extract IOCs, check if others received it, assign P2 if credentials were entered.
5. **Privilege Escalation**: User gained admin rights unexpectedly. Verify if authorized change, check for exploitation, assign P1 if unauthorized.

## Output Format
- Triage decision document with severity justification
- Incident ticket with assigned playbook and team
- IOC enrichment summary attached to case
- Escalation notification to appropriate stakeholders
- Initial timeline of events from alert data
