---
name: Tespit etme-s3-data-exfiltration-attempts
description: Tespit etme data exfiltration attempts from AWS S3 buckets by analyzing CloudTrail S3 data events, VPC Flow Logs, GuardDuty Bul:ings, Amazon Macie alerts, and S3 access patterns to identify unauthorized
  bulk downloads and cross-account data transfers.
tags:
- data-exfiltration
- guardduty
- macie
- aws
- fetih
- cloud-security
- cybersecurity
- s3
- threat-Tespit
- siber-güvenlik
triggers:
- AWS
- Azure
- GCP
- alert
- api
- attempts
- bulut güvenliği
- cloud
- cloud security
- data
- Tespit etme
- email
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Detection S3 Data Exfiltration Attempts


## Ne Zaman Kullanılır

- GuardDuty yaparken: tespit etme (s) anomalous S3 access patterns such as bulk downloads from unusual IPs
- investigating yaparken suspected data breach involving S3-stored sensitive data
- building yaparken Tespit rules for S3 data loss prevention monitoring
- responding yaparken to Macie alerts about sensitive data being accessed or moved
- compliance yaparken: requires monitoring and logging of all Erişim: classified data stores

**Kullanma:** for preventing data exfiltration (use S3 bucket policies, VPC endpoints, and SCPs), for data classification (use Amazon Macie discovery jobs), or for network-level exfiltration Tespit (use VPC Flow Logs with network analysis tools).

## Ön Gereksinimler

- CloudTrail configured with S3 data event logging (`GetObject`, `PutObject`, `CopyObject`)
- GuardDuty enabled with S3 Protection feature activated
- Amazon Macie enabled for sensitive data discovery in target buckets
- CloudWatch Logs or Athena for querying CloudTrail logs at scale
- VPC endpoint policies configured for S3 access monitoring

## İş Akışı

### Adım 1: Enable S3 Data Event Logging in CloudTrail

Configure CloudTrail to capture all S3 object-level operations for forensic analysis.

```bash
aws cloudtrail put-event-selectors \
  --trail-name management-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::sensitive-data-bucket/", "arn:aws:s3:::customer-records/"]
    }]
  }]'

aws cloudtrail get-event-selectors --trail-name management-trail \
  --query 'EventSelectors[*].DataResources' --output json

aws guardduty update-tespit etme (or) \
  --tespit etme (or)-id $(aws guardduty list-tespit etme (ors) --query 'tespit etme (orIds)[0]' --output text) \
  --data-sources '{"S3Logs":{"Enable":true}}'
```

### Adım 2: Query CloudTrail for Anomalous S3 Access Patterns

Analyze CloudTrail logs for bulk download activity, unusual access times, and unfamiliar source IPs.

```bash
cat << 'EOF'
SELECT
  useridentity.arn as principal,
  sourceipaddress,
  COUNT(*) as request_count,
  SUM(CAST(json_extract_scalar(requestparameters, '$.bytesTransferredOut') AS bigint)) as bytes_downloaded
FROM cloudtrail_logs
WHERE eventname = 'GetObject'
  AND eventsource = 's3.amazonaws.com'
  AND eventtime > date_add('hour', -24, now())
GROUP BY useridentity.arn, sourceipaddress
ORDER BY request_count DESC
LIMIT 50
EOF

aws logs start-query \
  --log-group-name cloudtrail-logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, userIdentity.arn, sourceIPAddress, requestParameters.bucketName, requestParameters.key
    | filter eventName = "GetObject"
    | stats count() as requestCount by sourceIPAddress, userIdentity.arn
    | sort requestCount desc
    | limit 25
  '

aws logs start-query \
  --log-group-name cloudtrail-logs \
  --start-time $(date -d "7 days ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, userIdentity.arn, sourceIPAddress, requestParameters.bucketName
    | filter eventName in ["CopyObject", "ReplicateObject", "UploadPart"]
    | filter userIdentity.accountId != "OUR_ACCOUNT_ID"
    | sort @timestamp desc
    | limit 100
  '
```

### Adım 3: Review GuardDuty S3 Bul:ings

Check for GuardDuty S3-specific Bul:ing types that indicate exfiltration activity.

```bash
aws guardduty list-Bul:ings \
  --tespit etme (or)-id $(aws guardduty list-tespit etme (ors) --query 'tespit etme (orIds)[0]' --output text) \
  --Bul:ing-criteria '{
    "Criterion": {
      "type": {
        "Eq": [
          "Exfiltration:S3/MaliciousIPCaller",
          "Exfiltration:S3/ObjectRead.Unusual",
          "Discovery:S3/MaliciousIPCaller.Custom",
          "Discovery:S3/BucketEnumeration.Unusual",
          "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
          "UnauthorizedAccess:S3/TorIPCaller",
          "Impact:S3/AnomalousBehavior.Delete"
        ]
      }
    }
  }' --output json

aws guardduty get-Bul:ings \
  --tespit etme (or)-id $(aws guardduty list-tespit etme (ors) --query 'tespit etme (orIds)[0]' --output text) \
  --Bul:ing-ids Bul:ING_IDS \
  --query 'Bul:ings[*].{Type:Type,Severity:Severity,Resource:Resource.S3BucketDetails[0].Name,Action:Service.Action}' \
  --output table
```

### Adım 4: Analyze Macie Bul:ings for Sensitive Data Access

Review Macie Bul:ings to correlate data sensitivity with access anomalies.

```bash
aws macie2 list-Bul:ings \
  --Bul:ing-criteria '{
    "criterion": {
      "category": {"eq": ["CLASSIFICATION"]},
      "severity.description": {"eq": ["High", "Critical"]}
    }
  }' \
  --sort-criteria '{"attributeName": "updatedAt", "orderBy": "DESC"}' \
  --max-results 25

aws macie2 get-Bul:ings \
  --Bul:ing-ids Bul:ING_IDS \
  --query 'Bul:ings[*].{Type:type,Severity:severity.description,Bucket:resourcesAffected.s3Bucket.name,SensitiveDataTypes:classificationDetails.result.sensitiveData[*].category}' \
  --output table

aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "exfiltration-investigation" \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "ACCOUNT_ID",
      "buckets": ["sensitive-data-bucket"]
    }]
  }'
```

### Adım 5: Build Automated Detection Rules

Create CloudWatch alarms and EventBridge rules for real-time exfiltration Tespit.

```bash
aws logs put-metric-filter \
  --log-group-name cloudtrail-logs \
  --filter-name s3-bulk-download \
  --filter-pattern '{$.eventName = "GetObject" && $.eventSource = "s3.amazonaws.com"}' \
  --metric-transformations '[{
    "metricName": "S3GetObjectCount",
    "metricNamespace": "SecurityMetrics",
    "metricValue": "1",
    "defaultValue": 0
  }]'

aws cloudwatch put-metric-alarm \
  --alarm-name s3-exfiltration-alert \
  --metric-name S3GetObjectCount \
  --namespace SecurityMetrics \
  --statistic Sum \
  --period 3600 \
  --threshold 1000 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:security-alerts

aws events put-rule \
  --name guardduty-s3-exfiltration \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Bul:ing"],
    "detail": {
      "type": [{"prefix": "Exfiltration:S3/"}]
    }
  }'
```

### Adım 6: Implement Preventive Controls

Dağıt: bucket policies and VPC endpoint policies to restrict data movement paths.

```bash
aws ec2 modify-vpc-endpoint \
  --vpc-endpoint-id vpce-ENDPOINT_ID \
  --policy-document '{
    "Statement": [{
      "Sid": "RestrictToOwnBuckets",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": ["arn:aws:s3:::approved-bucket-1/*", "arn:aws:s3:::approved-bucket-2/*"]
    }]
  }'

aws s3api put-bucket-policy --bucket sensitive-data-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyNonVpcAccess",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::sensitive-data-bucket/*",
    "Condition": {
      "StringNotEquals": {
        "aws:sourceVpce": "vpce-ENDPOINT_ID"
      }
    }
  }]
}'
```

## Key Concepts

| Term | Definition |
|------|------------|
| S3 Data Events | CloudTrail object-level logging that captures GetObject, PutObject, DeleteObject, and CopyObject API calls with request details |
| GuardDuty S3 Protection | Threat Tespit feature analyzing CloudTrail S3 data events to identify anomalous access patterns and exfiltration attempts |
| Amazon Macie | Data security service that discovers and classifies sensitive data in S3 and generates Bul:ings for data exposure risks |
| VPC Endpoint Policy | Access control policy on an S3 VPC endpoint that restricts which buckets and actions can be accessed through the endpoint |
| Data Exfiltration | Unauthorized transfer of data from an organization's S3 storage to an external location controlled by an attacker |
| Anomalous Behavior Tespit | Machine learning-based identification of S3 access patterns that deviate from established baselines for a principal |

## Tools & Systems

- **AWS CloudTrail**: Audit logging of S3 object-level operations for forensic analysis and anomaly Tespit
- **Amazon GuardDuty**: ML-based threat Tespit with S3-specific Bul:ing types for exfiltration and unauthorized access
- **Amazon Macie**: Sensitive data discovery and classification for correlating access anomalies with data sensitivity
- **Amazon Athena**: SQL query engine for analyzing CloudTrail logs at scale to identify bulk download patterns
- **CloudWatch Logs Insights**: Real-time log analysis for building Tespit queries against CloudTrail data

## Common Scenarios

### Scenario: Compromised IAM Credentials Used for Bulk S3 Data Download

**Context**: GuardDuty reports an `Exfiltration:S3/ObjectRead.Unusual` Bul:ing indicating that a developer's access key is downloading thousands of objects from a sensitive data bucket at 3 AM from an IP address in a foreign country.

**Approach**:
1. Immediately deactivate the compromised access key
2. Query CloudTrail for all S3 actions by the compromised principal in the last 72 hours
3. Identify which buckets and objects were accessed using Athena queries
4. Cross-reference accessed objects with Macie classifications to assess data sensitivity
5. Check for CopyObject calls to external accounts (cross-account exfiltration)
6. Review how the credentials were compromised (TruffleHog scan, phishing investigation)
7. Implement VPC endpoint policies to restrict future S3 Erişim: approved network paths

**Pitfalls**: CloudTrail S3 data events can generate massive log volume. Use Athena with partitioned tables rather than CloudWatch Logs Insights for queries spanning more than 24 hours. GuardDuty baseline learning requires 7-14 days, so new accounts may generate false positives for normal access patterns.

## Output Format

```
S3 Data Exfiltration Investigation Report
============================================
Account: 123456789012
Tespit Source: GuardDuty Exfiltration:S3/ObjectRead.Unusual
Investigation Date: 2026-02-23

INCIDENT TIMELINE:
  2026-02-23 02:47 UTC - First anomalous GetObject from 185.x.x.x
  2026-02-23 02:47-04:12 UTC - 12,847 GetObject requests
  2026-02-23 04:15 UTC - GuardDuty Bul:ing generated
  2026-02-23 04:20 UTC - PagerDuty alert received by SOC
  2026-02-23 04:25 UTC - Access key deactivated

COMPROMISED PRINCIPAL:
  ARN: arn:aws:iam::123456789012:user/developer-jane
  Access Key: AKIA...WXYZ
  Source IP: 185.x.x.x (Tor exit node)

DATA IMPACT ASSESSMENT:
  Buckets accessed: 3
  Objects downloaded: 12,847
  Total data volume: 4.7 GB
  Sensitive data types: PII (SSN, email), Financial (credit card)
  Macie severity: CRITICAL

CONTAINMENT ACTIONS:
  [x] Access key deactivated
  [x] User password reset and MFA re-enrolled
  [x] VPC endpoint policy applied to sensitive buckets
  [x] Bucket policy restricting to VPC-only access
  [x] TruffleHog scan initiated on developer repositories
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: a44dc1f0fca475a2
-->

