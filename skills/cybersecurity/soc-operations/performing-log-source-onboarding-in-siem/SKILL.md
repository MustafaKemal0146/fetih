---
name: performing-log-source-onboarding-in-siem
description: Perform structured log source onboarding into SIEM platforms by configuring collectors, parsers, normalization, and validation for complete security visibility.
tags:
- siem
- soc-operations
- cybersecurity
- soc
- data-ingestion
- normalization
- fetih
- log-management
- parsing
- log-onboarding
- siber-güvenlik
triggers:
- alert
- authentication
- cloud
- dns
- email
- endpoint
- http
- incident
- log
- malware
- network
- onboarding
category: soc-operations
source_subdomain: soc-operations
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.MA-01
- DE.AE-06
---

# Performing Log Source Onboarding in Siem


## Genel Bakış

Log source onboarding is the systematic process of integrating new data sources into a SIEM platform to enable security monitoring and Tespit. Proper onboarding requires planning data sources, configuring collection agents, building parsers, normalizing fields to a common schema, and validating data quality. According to the UK NCSC, onboarding should prioritize log sources that provide the highest security value relative to their ingestion cost.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing log source onboarding in siem
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- SIEM platform Dağıtılmış (Splunk, Elastic, Sentinel, QRadar, or similar)
- Network access from source systems to SIEM collectors
- Administrative access on source systems for agent installation
- Common Information Model (CIM) or equivalent schema documentation
- Change management approval for production system modifications

## Log Source Priority Framework

### Tier 1 - Critical (Onboard First)

| Source | Log Type | Security Value |
|---|---|---|
| Active Directory | Security Event Logs | Authentication, privilege escalation |
| Firewalls | Traffic logs | Network access, C2 Tespit |
| EDR/AV | Endpoint alerts | Malware, process execution |
| VPN/Remote Access | Connection logs | Unauthorized access |
| DNS Servers | Query logs | C2 beaconing, data exfiltration |
| Email Gateway | Email security logs | Phishing, BEC |

### Tier 2 - High Priority

| Source | Log Type | Security Value |
|---|---|---|
| Web Proxy | HTTP/HTTPS logs | Web-based attacks, data exfiltration |
| Cloud platforms (AWS/Azure/GCP) | Audit logs | Cloud security posture |
| Database servers | Audit/query logs | Data access, SQL injection |
| DHCP/IPAM | Address allocation | Asset tracking |
| File servers | Access logs | Data access monitoring |

### Tier 3 - Standard

| Source | Log Type | Security Value |
|---|---|---|
| Application servers | App logs | Application-level attacks |
| Print servers | Print logs | Data loss prevention |
| Badge/physical access | Access logs | Physical security correlation |
| Network devices (switches/routers) | Syslog | Network anomalies |

## Onboarding Process

### Adım 1: Discovery and Assessment

```
1. the tespit et: log source:
   - System type and version
   - Log format (syslog, CEF, JSON, Windows Events, etc.)
   - Log volume estimate (EPS - events per second)
   - Network location and firewall requirements

2. Assess security value:
   - What threats can this source help Detect?
   - Which MITRE ATT&CK techniques does it cover?
   - Is there an existing SIEM parser?

3. Estimate ingestion cost:
   - Daily volume in GB
   - License impact (per-GB or per-EPS pricing)
   - Storage retention requirements
```

### Adım 2: Configure Log Collection

#### Syslog-Based Collection (Firewalls, Network Devices)

```conf

module(load="imudp")
input(type="imudp" port="514" ruleset="siem_forwarding")

module(load="imtcp")
input(type="imtcp" port="514" ruleset="siem_forwarding")

module(load="imtcp" StreamDriver.AuthMode="x509/name"
       StreamDriver.Mode="1" StreamDriver.Name="gtls")
input(type="imtcp" port="6514" ruleset="siem_forwarding")

ruleset(name="siem_forwarding") {
    # Forward to SIEM
    action(type="omfwd" target="siem.company.com" port="9514"
           protocol="tcp" queue.type="LinkedList"
           queue.filename="siem_fwd" queue.maxdiskspace="1g"
           queue.saveonshutdown="on" action.resumeRetryCount="-1")
}
```

#### Windows Event Log Collection (Splunk Universal Forwarder)

```conf
[WinEventLog://Security]
disabled = 0
index = wineventlog
sourcetype = WinEventLog:Security
evt_resolve_ad_obj = 1
checkpointInterval = 5

[WinEventLog://System]
disabled = 0
index = wineventlog
sourcetype = WinEventLog:System

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = wineventlog
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = wineventlog
sourcetype = XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
```

#### Cloud Log Collection (AWS CloudTrail)

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "CloudTrailToSIEM": {
      "Type": "AWS::CloudTrail::Trail",
      "Properties": {
        "TrailName": "siem-cloudtrail",
        "S3BucketName": "company-cloudtrail-logs",
        "IsLogging": true,
        "IsMultiRegionTrail": true,
        "IncludeGlobalServiceEvents": true,
        "EnableLogFileValidation": true,
        "EventSelectors": [
          {
            "ReadWriteType": "All",
            "IncludeManagementEvents": true,
            "DataResources": [
              {
                "Type": "AWS::S3::Object",
                "Values": ["arn:aws:s3"]
              }
            ]
          }
        ]
      }
    }
  }
}
```

### Adım 3: Parse and Normalize

#### Custom Parser Example (Splunk props.conf/transforms.conf)

```conf
[custom:firewall:logs]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%dT%H:%M:%S%z
MAX_TIMESTAMP_LOOKAHEAD = 30
TRANSFORMS-firewall = firewall_extract_fields
FIELDALIAS-src = src_addr AS src_ip
FIELDALIAS-dst = dst_addr AS dest_ip
EVAL-action = case(fw_action=="allow", "allowed", fw_action=="deny", "blocked", true(), "unknown")
EVAL-vendor_product = "Custom Firewall"
LOOKUP-geo = geo_ip_lookup ip AS dest_ip OUTPUT country, city, latitude, longitude

[firewall_extract_fields]
REGEX = ^(\S+)\s+(\S+)\s+action=(\w+)\s+src=(\S+):(\d+)\s+dst=(\S+):(\d+)\s+proto=(\w+)\s+bytes=(\d+)
FORMAT = timestamp::$1 hostname::$2 fw_action::$3 src_addr::$4 src_port::$5 dst_addr::$6 dst_port::$7 protocol::$8 bytes::$9
```

#### CIM Field Mapping

| Raw Field | CIM Field | Data Model |
|---|---|---|
| src_addr | src_ip | Network_Traffic |
| dst_addr | dest_ip | Network_Traffic |
| dst_port | dest_port | Network_Traffic |
| fw_action | action | Network_Traffic |
| bytes_sent + bytes_recv | bytes | Network_Traffic |
| user_name | user | Authentication |
| login_result | action | Authentication |
| process_path | process | Endpoint |

### Adım 4: Validate Data Quality

```spl
index=new_source earliest=-1h
| stats count by sourcetype, host, source

index=new_source earliest=-1h
| stats count(src_ip) as has_src count(dest_ip) as has_dest count(action) as has_action count by sourcetype
| eval src_coverage=round(has_src/count*100,1)
| eval dest_coverage=round(has_dest/count*100,1)
| eval action_coverage=round(has_action/count*100,1)

| datamodel Network_Traffic search
| search sourcetype=new_sourcetype
| stats count by source, sourcetype

index=new_source earliest=-1h
| eval time_diff=abs(_time - _indextime)
| stats avg(time_diff) as avg_lag max(time_diff) as max_lag by host
| where avg_lag > 300
```

### Adım 5: Enable Detection Coverage

```spl
index=new_source sourcetype=new_sourcetype
| tstats count from datamodel=Authentication by _time span=1h
| timechart span=1h count

[New Source - Authentication Anomaly]
search = index=new_source sourcetype=new_sourcetype action=failure \
| stats count by src_ip, user \
| where count > 10
```

## Onboarding Checklist

- [ ] Log source assessed and approved
- [ ] Network connectivity verified
- [ ] Collection agent/method configured
- [ ] Log forwarding confirmed
- [ ] Parser/field extraction configured
- [ ] CIM compliance validated
- [ ] Data model acceleration enabled
- [ ] Volume within license budget
- [ ] Retention policy configured
- [ ] Tespit rules enabled/created
- [ ] Dashboard updated
- [ ] Documentation completed
- [ ] SOC team notified

## References

- [UK NCSC - Onboarding Systems and Log Sources](https://www.ncsc.gov.uk/collection/building-a-security-operations-centre/onboarding-systems-and-log-sources)
- [Sumo Logic - Cloud SIEM Onboarding Checklist](https://help.sumologic.com/docs/cse/get-started-with-cloud-siem/onboarding-checklist-cse/)
- [SIEM Logging Best Practices - Coralogix](https://coralogix.com/guides/siem/siem-logging/)
- [Huntress - SIEM Implementation Guide](https://www.huntress.com/siem-guide/siem-implementation-guide)
