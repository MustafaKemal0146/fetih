---
name: implementing-aws-security-hub-compliance
description: Implementing AWS Security Hub to aggregate security Bul:ings across AWS accounts, enable compliance standards like CIS AWS Foundations and PCI DSS, configure automated remediation with EventBridge
  and Lambda, and create custom security insights for organizational risk management.
tags:
- security-hub
- cspm
- cis-benchmark
- aws
- fetih
- cloud-security
- cybersecurity
- compliance
- siber-güvenlik
triggers:
- AWS
- Azure
- GCP
- alert
- api
- bulut güvenliği
- cloud
- cloud security
- compliance
- encryption
- http
- implementing
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Implementing Aws Security Hub Compliance


## Ne Zaman Kullanılır

- establishing yaparken: centralized security posture management across multiple AWS accounts
- compliance yaparken: requirements demand continuous monitoring against CIS, PCI DSS, or NIST 800-53 standards
- aggregating yaparken Bul:ings from GuardDuty, Denetle:or, Macie, Firewall Manager, and third-party tools
- building yaparken automated remediation workflows triggered by security Bul:ings
- executive yaparken: stakeholders require a security compliance dashboard across the organization

**Kullanma:** for real-time threat Tespit (use GuardDuty), for vulnerability scanning (use Denetle:or), or for data classification (use Macie). Security Hub aggregates Bul:ings from these services but does not replace them.

## Ön Gereksinimler

- AWS Organizations with delegated administrator for Security Hub
- IAM permissions for `securityhub:*`, `config:*`, `events:*`, and `lambda:*`
- AWS Config enabled in all target accounts and regions (required by Security Hub)
- CloudFormation StackSets or Terraform for multi-account Dağıt:ment
- SNS topics configured for alert routing to security team

## İş Akışı

### Adım 1: Enable Security Hub with Compliance Standards

Enable Security Hub in the management account and select compliance standards to evaluate.

```bash
aws securityhub enable-security-hub \
  --enable-default-standards \
  --control-Bul:ing-generator SECURITY_CONTROL

aws securityhub batch-enable-standards --standards-subscription-requests \
  '[
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0"}
  ]'

aws securityhub get-enabled-standards \
  --query 'StandardsSubscriptions[*].[StandardsArn,StandardsStatus]' --output table
```

### Adım 2: Configure Multi-Account Aggregation

Kur: a delegated administrator and aggregate Bul:ings from all organization accounts.

```bash
aws securityhub enable-organization-admin-account \
  --admin-account-id 111122223333

aws securityhub update-organization-configuration \
  --auto-enable \
  --auto-enable-standards DEFAULT

aws securityhub create-Bul:ing-aggregator \
  --region-linking-mode ALL_REGIONS

aws securityhub list-members \
  --query 'Members[*].[AccountId,MemberStatus]' --output table
```

### Adım 3: Review Compliance Scores and Failed Controls

Query Security Hub for compliance posture across enabled standards and identify failing controls.

```bash
aws securityhub get-standards-control-associations \
  --security-control-id "IAM.1" \
  --query 'StandardsControlAssociationSummaries[*].[StandardsArn,AssociationStatus]' \
  --output table

aws securityhub get-Bul:ings \
  --filters '{
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]
  }' \
  --sort-criteria '{"Field": "SeverityNormalized", "SortOrder": "desc"}' \
  --max-items 50 \
  --query 'Bul:ings[*].[Title,Severity.Label,Compliance.Status,Resources[0].Id]' \
  --output table

aws securityhub get-insight-results \
  --insight-arn "arn:aws:securityhub:us-east-1:111122223333:insight/111122223333/default/2"
```

### Adım 4: Create Custom Security Insights

Build custom insights to track organization-specific security priorities.

```bash
aws securityhub create-insight \
  --name "Publicly Accessible Resources" \
  --filters '{
    "ResourceType": [
      {"Value": "AwsS3Bucket", "Comparison": "EQUALS"},
      {"Value": "AwsEc2SecurityGroup", "Comparison": "EQUALS"},
      {"Value": "AwsRdsDbInstance", "Comparison": "EQUALS"}
    ],
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}, {"Value": "HIGH", "Comparison": "EQUALS"}]
  }' \
  --group-by-attribute "ResourceType"

aws securityhub create-insight \
  --name "Unencrypted Resources Across Accounts" \
  --filters '{
    "Title": [{"Value": "encryption", "Comparison": "CONTAINS"}],
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}]
  }' \
  --group-by-attribute "AwsAccountId"
```

### Adım 5: Configure Automated Remediation with EventBridge

Kur: EventBridge rules to trigger Lambda-based auto-remediation for specific Bul:ing types.

```bash
aws events put-rule \
  --name "security-hub-critical-Bul:ings" \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Bul:ings - Imported"],
    "detail": {
      "Bul:ings": {
        "Severity": {"Label": ["CRITICAL"]},
        "Compliance": {"Status": ["FAILED"]},
        "Workflow": {"Status": ["NEW"]}
      }
    }
  }'

cat > /tmp/remediate_s3.py << 'PYEOF'
import boto3
import json

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    securityhub = boto3.client('securityhub')

    for Bul:ing in event['detail']['Bul:ings']:
        if 'S3' in Bul:ing.get('Title', '') and 'public' in Bul:ing.get('Title', '').lower():
            bucket_arn = Bul:ing['Resources'][0]['Id']
            bucket_name = bucket_arn.split(':::')[-1]

            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )

            securityhub.batch_update_Bul:ings(
                Bul:ingIdentifiers=[{
                    'Id': Bul:ing['Id'],
                    'ProductArn': Bul:ing['ProductArn']
                }],
                Workflow={'Status': 'RESOLVED'},
                Note={
                    'Text': 'Auto-remediated: Block Public Access enabled',
                    'UpdatedBy': 'security-hub-auto-remediation'
                }
            )
    return {'statusCode': 200}
PYEOF
```

### Adım 6: Export Bul:ings and Generate Compliance Reports

Export Security Hub Bul:ings for reporting and integration with external SIEM or GRC platforms.

```bash
aws securityhub get-Bul:ings \
  --filters '{
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --max-items 1000 \
  --output json > security-hub-Bul:ings-export.json

aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:111122223333:security-alerts \
  --subject "Security Hub Daily Summary" \
  --message file://daily-summary.json

aws events put-targets \
  --rule security-hub-critical-Bul:ings \
  --targets '[{
    "Id": "splunk-hec",
    "Arn": "arn:aws:events:us-east-1:111122223333:api-destination/splunk-hec",
    "HttpParameters": {
      "HeaderParameters": {"Authorization": "Splunk HEC_TOKEN"}
    }
  }]'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Security Hub | AWS service that aggregates security Bul:ings from AWS services and third-party tools, evaluates compliance against standards, and provides a unified security dashboard |
| Security Standard | A predefined set of security controls (CIS, PCI DSS, NIST 800-53) that Security Hub evaluates against your AWS configuration |
| Security Control | An individual check within a standard that evaluates a specific AWS resource configuration, such as whether S3 buckets block public access |
| Bul:ing | A security issue Detected by Security Hub or an integrated service, formatted in AWS Security Bul:ing Format (ASFF) |
| Insight | A custom or managed grouping of Bul:ings by a specific attribute, providing aggregated views for security analysis |
| ASFF | AWS Security Bul:ing Format, the standardized JSON schema used by all Security Hub integrations for consistent Bul:ing representation |

## Tools & Systems

- **AWS Security Hub**: Central aggregation and compliance evaluation platform for security Bul:ings across AWS accounts
- **AWS Config**: Configuration recording service required by Security Hub for evaluating resource compliance
- **Amazon EventBridge**: Event bus for routing Security Hub Bul:ings to Lambda, SNS, or external remediation systems
- **AWS Lambda**: Serverless compute for automated remediation functions triggered by Security Hub Bul:ings
- **Prowler**: Open-source tool that can send Bul:ings to Security Hub via ASFF integration

## Common Scenarios

### Scenario: Rolling Out Security Hub Across a 50-Account Organization

**Context**: A security team needs to enable Security Hub with CIS and FSBP standards across all accounts in an AWS Organization, with centralized Bul:ing aggregation and automated alerting.

**Approach**:
1. Enable Security Hub in the management account and designate a security account as delegated admin
2. Configure auto-enable for all existing and new member accounts via `update-organization-configuration`
3. Şunu oluştur: cross-region Bul:ing aggregator to consolidate Bul:ings from all regions into the admin account
4. Enable CIS AWS Foundations 1.4 and AWS FSBP standards across all accounts
5. Create EventBridge rules to route CRITICAL Bul:ings to PagerDuty and all Bul:ings to Splunk
6. Build custom insights for the top organizational risks: public resources, missing encryption, unused credentials
7. Schedule weekly compliance reports to stakeholders using Lambda and SES

**Pitfalls**: Security Hub requires AWS Config to be enabled in every account and region. Failing to enable Config will result in controls showing as "No data" rather than PASSED or FAILED. Member accounts with Config disabled will silently produce incomplete compliance scores.

## Output Format

```
AWS Security Hub Compliance Report
=====================================
Organization: acme-corp (50 accounts)
Region: us-east-1 (aggregated from all regions)
Report Date: 2026-02-23
Standards Enabled: CIS 1.4, FSBP v1.0, PCI DSS 3.2.1

COMPLIANCE SCORES:
  CIS AWS Foundations 1.4:     78% (142/182 controls passing)
  AWS FSBP v1.0.0:             85% (198/233 controls passing)
  PCI DSS 3.2.1:               72% (89/124 controls passing)

CRITICAL Bul:INGS: 23
HIGH Bul:INGS: 87
MEDIUM Bul:INGS: 245
LOW Bul:INGS: 412

TOP FAILING CONTROLS:
  [IAM.6]  MFA not enabled for root account           12 accounts
  [S3.2]   S3 Block Public Access not enabled          8 accounts
  [EC2.19] Security groups allow unrestricted access   15 accounts
  [RDS.3]  RDS encryption at rest not enabled          6 accounts

AUTO-REMEDIATION ACTIONS (Last 30 Days):
  S3 Block Public Access enabled:    14
  Security Group rules restricted:    8
  CloudTrail logging re-enabled:      3
  Total auto-remediated Bul:ings:    25
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 757d851eb1df747c
-->

