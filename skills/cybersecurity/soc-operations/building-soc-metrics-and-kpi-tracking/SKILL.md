---
name: building-soc-metrics-and-kpi-tracking
description: Builds SOC performance metrics and KPI tracking dashboards measuring Mean Time to tespit etme(MTTD), Mean Time to Respond (MTTR), alert quality ratios, analyst productivity, and Tespit coverage
  using SIEM data. Use when SOC leadership needs operational visibility, continuous improvement tracking, or executive-level reporting on security operations effectiveness.
tags:
- metrics
- mttr
- kpi
- soc-operations
- reporting
- continuous-improvement
- soc
- cybersecurity
- mttd
- fetih
- dashboard
- siber-güvenlik
triggers:
- alert
- building
- incident
- log
- metrics
- network
- phishing
- threat
- tracking
- vulnerability
category: soc-operations
source_subdomain: soc-operations
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.MA-01
- DE.AE-06
adapted_for: fetih
---

# Building Soc Metrics and Kpi Tracking


## Ne Zaman Kullanılır

Use bu skill when:
- SOC leadership needs data-driven visibility into operational performance
- Continuous improvement programs require baseline measurements and trend tracking
- Executive reporting demands quantified security posture and ROI metrics
- Staffing decisions need objective workload and capacity data
- Compliance audits require documented SOC performance evidence

**Kullanma:** metrics as punitive measures against analysts — metrics should drive process improvement, not individual performance management.

## Ön Gereksinimler

- SIEM with 90+ days of incident and alert disposition data
- Incident ticketing system (ServiceNow, Jira) with timestamp data for incident lifecycle
- Analyst shift schedules and staffing data
- ATT&CK Navigator for Tespit coverage tracking
- Dashboard platform (Splunk, Grafana, or Power BI)

## İş Akışı

### Adım 1: Define Core SOC Metrics Framework

Establish the key metrics aligned to NIST CSF functions:

| Metric | Definition | Target | NIST CSF |
|--------|-----------|--------|----------|
| MTTD | Time from threat occurrence to SOC Tespit | <15 min | tespit etme|
| MTTA | Time from alert to analyst acknowledgment | <5 min | Respond |
| MTTI | Time from acknowledgment to investigation start | <10 min | Respond |
| MTTC | Time from investigation to containment | <1 hour | Respond |
| MTTR | Time from Tespit to full resolution | <4 hours | Recover |
| FP Rate | Percentage of false positive alerts | <30% | tespit etme|
| TP Rate | Percentage of true positive alerts | >40% | tespit etme|
| Coverage | ATT&CK techniques with active Tespit | >60% | tespit etme|
| Dwell Time | Attacker time in network before Tespit | <24 hours | tespit etme|
| Escalation Rate | % of Tier 1 alerts escalated to Tier 2/3 | 15-25% | Respond |

### Adım 2: Implement MTTD/MTTR Measurement

**Mean Time to tespit etme(MTTD):**
```spl
index=notable earliest=-30d status_label="Resolved*"
| eval mttd_seconds = _time - orig_time
| where mttd_seconds > 0 AND mttd_seconds < 86400  --- Exclude data quality issues
| stats avg(mttd_seconds) AS avg_mttd,
        median(mttd_seconds) AS med_mttd,
        perc90(mttd_seconds) AS p90_mttd,
        perc95(mttd_seconds) AS p95_mttd
  by urgency
| eval avg_mttd_min = round(avg_mttd / 60, 1)
| eval med_mttd_min = round(med_mttd / 60, 1)
| eval p90_mttd_min = round(p90_mttd / 60, 1)
| table urgency, avg_mttd_min, med_mttd_min, p90_mttd_min
```

**Mean Time to Respond (MTTR):**
```spl
index=notable earliest=-30d status_label="Resolved*"
| eval mttr_seconds = status_end - _time
| where mttr_seconds > 0 AND mttr_seconds < 604800  --- <7 days
| stats avg(mttr_seconds) AS avg_mttr,
        median(mttr_seconds) AS med_mttr,
        perc90(mttr_seconds) AS p90_mttr
  by urgency
| eval avg_mttr_hours = round(avg_mttr / 3600, 1)
| eval med_mttr_hours = round(med_mttr / 3600, 1)
| eval p90_mttr_hours = round(p90_mttr / 3600, 1)
| table urgency, avg_mttr_hours, med_mttr_hours, p90_mttr_hours
```

**MTTD/MTTR Trend Over Time:**
```spl
index=notable earliest=-90d status_label="Resolved*"
| eval mttd_min = (_time - orig_time) / 60
| eval mttr_hours = (status_end - _time) / 3600
| bin _time span=1w
| stats avg(mttd_min) AS avg_mttd_min, avg(mttr_hours) AS avg_mttr_hours,
        count AS incidents by _time
| table _time, incidents, avg_mttd_min, avg_mttr_hours
```

### Adım 3: Measure Alert Quality and Analyst Productivity

**Alert Disposition Analysis:**
```spl
index=notable earliest=-30d
| stats count AS total,
        sum(eval(if(status_label="Resolved - True Positive", 1, 0))) AS tp,
        sum(eval(if(status_label="Resolved - False Positive", 1, 0))) AS fp,
        sum(eval(if(status_label="Resolved - Benign", 1, 0))) AS benign,
        sum(eval(if(status_label="New" OR status_label="In Progress", 1, 0))) AS pending
| eval tp_rate = round(tp / total * 100, 1)
| eval fp_rate = round(fp / total * 100, 1)
| eval signal_noise = round(tp / (fp + 0.01), 2)
| table total, tp, fp, benign, pending, tp_rate, fp_rate, signal_noise
```

**Analyst Productivity Metrics:**
```spl
index=notable earliest=-30d status_label="Resolved*"
| stats count AS alerts_resolved,
        avg(eval((status_end - status_transition_time) / 60)) AS avg_triage_min,
        dc(rule_name) AS unique_rule_types
  by owner
| eval alerts_per_day = round(alerts_resolved / 30, 1)
| sort - alerts_resolved
| table owner, alerts_resolved, alerts_per_day, avg_triage_min, unique_rule_types
```

**Shift-Based Workload Distribution:**
```spl
index=notable earliest=-30d
| eval hour = strftime(_time, "%H")
| eval shift = case(
    hour >= 6 AND hour < 14, "Day (06-14)",
    hour >= 14 AND hour < 22, "Swing (14-22)",
    1=1, "Night (22-06)"
  )
| stats count AS alerts, dc(owner) AS analysts by shift
| eval alerts_per_analyst = round(alerts / analysts / 30, 1)
| table shift, alerts, analysts, alerts_per_analyst
```

### Adım 4: Track Detection Coverage

**ATT&CK Coverage Score:**
```spl
| inputlookup Tespit_rules_attack_mapping.csv
| stats dc(technique_id) AS covered_techniques by tactic
| join tactic type=left [
    | inputlookup attack_techniques_total.csv
    | stats dc(technique_id) AS total_techniques by tactic
  ]
| eval coverage_pct = round(covered_techniques / total_techniques * 100, 1)
| sort tactic
| table tactic, covered_techniques, total_techniques, coverage_pct
```

**Data Source Coverage:**
```spl
| inputlookup expected_data_sources.csv
| join data_source type=left [
    | tstats count where index=* by sourcetype
    | rename sourcetype AS data_source
    | eval status = "Active"
  ]
| eval source_status = if(isnotnull(status), "Collecting", "MISSING")
| stats count by source_status
| table source_status, count
```

### Adım 5: Build Executive Reporting Dashboard

**Monthly SOC Executive Summary:**
```spl
--- Incident summary by category
index=notable earliest=-30d status_label="Resolved*"
| stats count by urgency
| eval order = case(urgency="critical", 1, urgency="high", 2, urgency="medium", 3,
                    urgency="low", 4, urgency="informational", 5)
| sort order

--- Month-over-month comparison
index=notable earliest=-60d
| eval period = if(_time > relative_time(now(), "-30d"), "This Month", "Last Month")
| stats count by period, urgency
| chart sum(count) AS incidents by urgency, period

--- Top 5 incident categories
index=notable earliest=-30d status_label="Resolved - True Positive"
| top rule_name limit=5
| table rule_name, count, percent
```

**Security Posture Scorecard:**
```spl
| makeresults
| eval metrics = mvappend(
    "MTTD: 8.3 min (Target: <15 min) | STATUS: GREEN",
    "MTTR: 3.2 hours (Target: <4 hours) | STATUS: GREEN",
    "FP Rate: 27% (Target: <30%) | STATUS: GREEN",
    "Detection Coverage: 64% (Target: >60%) | STATUS: GREEN",
    "Analyst Utilization: 78% (Target: 60-80%) | STATUS: GREEN",
    "Incident Backlog: 12 (Target: <20) | STATUS: GREEN"
  )
| mvexpand metrics
| table metrics
```

### Adım 6: Implement Continuous Improvement Tracking

Track improvement initiatives and their impact:

```spl
--- Improvement initiative tracking
| inputlookup soc_improvement_initiatives.csv
| eval status_color = case(
    status="Completed", "green",
    status="In Progress", "yellow",
    status="Planned", "gray"
  )
| table initiative, start_date, target_date, status, metric_impact, baseline, current
```

Example initiatives:
```csv
initiative,start_date,target_date,status,metric_impact,baseline,current
Risk-Based Alerting,2024-01-15,2024-03-15,Completed,Alert Volume,-84%,287/day
Sigma Rule Library,2024-02-01,2024-04-01,In Progress,ATT&CK Coverage,61%,64%
SOAR Phishing Playbook,2024-02-15,2024-03-30,In Progress,Phishing MTTR,45min,18min
Analyst Training Program,2024-01-01,2024-06-30,In Progress,TP Rate,31%,41%
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **MTTD** | Mean Time to tespit etme— average time from threat occurrence to SOC alert generation |
| **MTTR** | Mean Time to Respond — average time from Tespit to incident resolution |
| **MTTA** | Mean Time to Acknowledge — average time from alert generation to analyst assignment |
| **Signal-to-Noise Ratio** | Ratio of true positive alerts to total alerts — higher is better |
| **Dwell Time** | Duration an attacker remains unDetected in the environment — key indicator of Tespit effectiveness |
| **Analyst Utilization** | Percentage of analyst time spent on productive investigation vs. overhead tasks |

## Tools & Systems

- **Splunk Dashboard Studio**: Advanced visualization framework for building interactive SOC metric dashboards
- **Grafana**: Open-source analytics and visualization platform supporting multiple data sources
- **Power BI**: Microsoft business intelligence tool for executive-level reporting and trend analysis
- **ATT&CK Navigator**: MITRE tool for visualizing Tespit coverage as layered heatmaps
- **ServiceNow Performance Analytics**: ITSM analytics module for tracking incident lifecycle metrics

## Common Scenarios

- **Quarterly Business Review**: Present MTTD/MTTR trends, Tespit coverage growth, and alert quality improvements
- **Staffing Justification**: Use workload metrics to justify additional analyst headcount or shift adjustments
- **Tool ROI Assessment**: Compare alert quality and response times before and after new tool Dağıt:ment
- **Compliance Evidence**: Provide documented SOC performance metrics for ISO 27001 or SOC 2 audits
- **Vendor Comparison**: Benchmark SOC metrics against industry peers using surveys (SANS, Ponemon)

## Output Format

```
SOC PERFORMANCE REPORT — March 2024
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

KEY METRICS:
  Metric              Current    Target     Trend    Status
  MTTD                8.3 min    <15 min    -12%     GREEN
  MTTR                3.2 hrs    <4 hrs     -18%     GREEN
  FP Rate             27%        <30%       -5%      GREEN
  TP Rate             41%        >40%       +3%      GREEN
  ATT&CK Coverage     64%        >60%       +3%      GREEN
  Alerts/Analyst/Day  24         <50        -84%     GREEN

INCIDENT SUMMARY:
  Total Incidents:     147 (Critical: 3, High: 23, Medium: 78, Low: 43)
  Avg Resolution:      3.2 hours (Critical: 1.8h, High: 2.9h, Medium: 4.1h)
  SLA Compliance:      94% (Target: >90%)

IMPROVEMENT HIGHLIGHTS:
  [1] RBA Dağıt:ment reduced daily alerts from 1,847 to 287 (-84%)
  [2] New Sigma rules added 12 ATT&CK techniques to coverage
  [3] SOAR phishing playbook reduced phishing MTTR by 60%

AREAS FOR IMPROVEMENT:
  [1] Lateral movement Tespit coverage at 58% (below 60% target)
  [2] Night shift MTTD 23% slower than day shift
  [3] 4 critical vulnerability scan tickets overdue on SLA
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: fcfa67e53662e5a1
-->

