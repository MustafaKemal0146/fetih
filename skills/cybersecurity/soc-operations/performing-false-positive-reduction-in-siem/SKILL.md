---
name: performing-false-positive-reduction-in-siem
description: Perform systematic SIEM false positive reduction through rule tuning, threshold adjustment, correlation refinement, and threat intelligence enrichment to combat alert fatigue.
tags:
- siem
- soc-operations
- alert-tuning
- soc
- correlation
- fetih
- cybersecurity
- alert-fatigue
- false-positive
- Tespit-engineering
- siber-güvenlik
triggers:
- alert
- 'false'
- http
- incident
- log
- performing
- positive
- reduction
- siem
- threat
category: soc-operations
source_subdomain: soc-operations
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.MA-01
- DE.AE-06
adapted_for: fetih
---

# Performing False Positive Reduction in Siem


## Genel Bakış

False positive alerts are non-malicious events that trigger security rules, overwhelming SOC analysts with noise. Studies show that up to 45% of SIEM alerts are false positives, and a typical SOC analyst can only Araştır: 20-25 alerts per shift effectively. Reducing false positives requires systematic tuning across thresholds, correlation logic, allowlists, enrichment, and continuous validation. SIEM rules should be reviewed on a quarterly cycle at minimum.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing false positive reduction in siem
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with soc operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## False Positive Reduction Techniques

### 1. the tespit et: Noisiest Rules

```spl
index=notable
| stats count by rule_name
| sort -count
| head 10
| eval pct=round(count / total * 100, 1)
```

```spl
index=notable
| stats count as total
    count(eval(status_label="Closed - False Positive")) as false_positives
    count(eval(status_label="Closed - True Positive")) as true_positives
    by rule_name
| eval fp_rate=round(false_positives / total * 100, 1)
| sort -fp_rate
| where total > 10
```

### 2. Threshold Tuning

```spl
index=wineventlog EventCode=4625
| stats count by src_ip
| where count > 5

index=wineventlog EventCode=4625
| bin _time span=10m
| stats count dc(TargetUserName) as unique_accounts by src_ip, _time
| where count > 20 AND unique_accounts > 3
```

### 3. Allowlist/Exclusion Management

```spl
| inputlookup fp_allowlist.csv
| fields src_ip, reason, approved_by, expiry_date

index=wineventlog EventCode=4625
| lookup fp_allowlist src_ip OUTPUT reason as allowlisted_reason
| where isnull(allowlisted_reason)
| stats count dc(TargetUserName) as unique_accounts by src_ip
| where count > 20 AND unique_accounts > 3
```

### 4. Correlation Enhancement

```spl
index=wineventlog EventCode=4688 New_Process_Name="*powershell.exe"
| eval severity="medium"

index=wineventlog EventCode=4688 New_Process_Name="*powershell.exe"
| join src_ip type=left [
    search index=wineventlog EventCode=4625
    | stats count as failed_logins by src_ip
]
| join Computer type=left [
    search index=sysmon EventCode=3
    | stats dc(DestinationIp) as unique_external_connections by Computer
    | where unique_external_connections > 10
]
| where isnotnull(failed_logins) OR unique_external_connections > 10
| eval severity=case(
    failed_logins > 10 AND unique_external_connections > 10, "critical",
    failed_logins > 5 OR unique_external_connections > 5, "high",
    true(), "medium"
)
```

### 5. Time-Based Exclusions

```spl
| eval hour=strftime(_time, "%H")
| eval day=strftime(_time, "%A")
| where NOT (hour >= "02" AND hour <= "04" AND day="Sunday")

| lookup scheduled_tasks_allowlist process_name, schedule_time
    OUTPUT is_scheduled
| where isnull(is_scheduled)
```

### 6. Behavioral Baseline Integration

```spl
index=wineventlog EventCode=4624
| bin _time span=1h
| stats count as logins dc(Computer) as unique_hosts by TargetUserName, _time
| eventstats avg(logins) as avg_logins stdev(logins) as stdev_logins
    avg(unique_hosts) as avg_hosts stdev(unique_hosts) as stdev_hosts
    by TargetUserName
| where logins > (avg_logins + 3 * stdev_logins)
    OR unique_hosts > (avg_hosts + 3 * stdev_hosts)
```

### 7. Threat Intelligence Filtering

```spl
index=firewall action=allowed direction=outbound
| lookup ip_threat_intel_lookup ip as dest_ip OUTPUT threat_type, confidence
| where isnotnull(threat_type) AND confidence > 70
```

## Tuning Process Framework

### Adım 1: Identify (Weekly)
- Pull top 10 rules by alert volume
- Calculate FP rate for each
- Identify rules with FP rate > 30%

### Adım 2: Analyze (Weekly)
- Sample 20 false positives per rule
- Categorize root cause of each FP
- Identify common patterns

### Adım 3: Tune (Bi-weekly)
- Adjust thresholds based on baseline data
- Add allowlist entries for benign patterns
- Enhance correlation logic
- Add enrichment context

### Adım 4: Validate (Monthly)
- Run Atomic Red Team tests to verify true positives still trigger
- Calculate new FP rate after tuning
- Document tuning rationale
- Review with Tespit engineering team

### Adım 5: Report (Quarterly)
- FP reduction metrics per rule
- Overall alert volume trends
- Analyst productivity improvements
- Rules retired or replaced

## Doğrulama Testing

```bash
Invoke-AtomicTest T1110.001 -TestNumbers 1
```

```spl
index=notable rule_name="Brute Force Tespit"
earliest=-24h
| stats count
| where count > 0
```

## FP Reduction Metrics

| Metric | Formula | Target |
|---|---|---|
| False Positive Rate | FP / (FP + TP) * 100 | < 20% |
| Alert Volume Reduction | (Old Volume - New Volume) / Old Volume * 100 | 30-50% per quarter |
| Mean Triage Time | Total triage time / Total alerts | < 8 minutes |
| Rule Precision | TP / (TP + FP) | > 0.80 |
| Analyst Satisfaction | Survey score | > 4/5 |

## References

- [CyberSierra - Tune SIEM Alerts to Eliminate False Positives](https://cybersierra.co/blog/reduce-false-positives-siem/)
- [ConnectWise - 9 Ways to Eliminate SIEM False Positives](https://www.connectwise.com/blog/9-ways-to-eliminate-siem-false-positives)
- [Prophet Security - Alert Tuning Best Practices](https://www.prophetsecurity.ai/blog/security-operations-center-soc-best-practices-alert-tuning)
- [ManageEngine - Reducing SIEM Alert False Positives](https://www.manageengine.com/log-management/siem/reducing-siem-alert-false-positives.html)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: a8ced7bc03331ef0
-->

