---
name: implementing-aws-macie-for-data-classification
description: Implement Amazon Macie to automatically discover, classify, and protect sensitive data in S3 buckets using machine learning and pattern matching for PII, financial data, and credentials Tespit.
tags:
- data-classification
- macie
- sensitive-data
- aws
- fetih
- pii
- cloud-security
- cybersecurity
- s3
- compliance
- siber-güvenlik
- dlp
triggers:
- AWS
- Azure
- GCP
- alert
- api
- bulut güvenliği
- classification
- cloud security
- data
- email
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

# Implementing Aws Macie for Data Classification


## Genel Bakış

Amazon Macie is a fully managed data security and privacy service that uses machine learning and pattern matching to discover and protect sensitive data in Amazon S3. Macie automatically evaluates your S3 bucket inventory on a daily basis and identifies objects containing PII, financial information, credentials, and other sensitive data types. It provides two discovery approaches: automated sensitive data discovery for broad visibility and targeted discovery jobs for deep analysis.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing aws macie for data classification capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- AWS account with S3 buckets containing data to classify
- IAM permissions for Macie service configuration
- AWS Organizations setup (for multi-account Dağıt:ment)
- S3 buckets in supported regions

## Enable Macie

### Via AWS CLI

```bash
aws macie2 enable-macie

aws macie2 get-macie-session

aws macie2 update-automated-discovery-configuration \
  --status ENABLED
```

### Via Terraform

```hcl
resource "aws_macie2_account" "main" {}

resource "aws_macie2_classification_export_configuration" "main" {
  depends_on = [aws_macie2_account.main]

  s3_destination {
    bucket_name = aws_s3_bucket.macie_results.id
    key_prefix  = "macie-Bul:ings/"
    kms_key_arn = aws_kms_key.macie.arn
  }
}
```

## Configure Discovery Jobs

### Şunu oluştur: classification job for specific buckets

```bash
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "pii-scan-production-buckets" \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "123456789012",
      "buckets": [
        "production-data-bucket",
        "customer-records-bucket"
      ]
    }]
  }' \
  --managed-data-identifier-selector ALL
```

### Şunu oluştur: scheduled recurring job

```bash
aws macie2 create-classification-job \
  --job-type SCHEDULED \
  --name "weekly-sensitive-data-scan" \
  --schedule-frequency-details '{
    "weekly": {
      "dayOfWeek": "MONDAY"
    }
  }' \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "123456789012",
      "buckets": ["all-data-bucket"]
    }],
    "scoping": {
      "includes": {
        "and": [{
          "simpleScopeTerm": {
            "comparator": "STARTS_WITH",
            "key": "OBJECT_KEY",
            "values": ["uploads/", "documents/"]
          }
        }]
      }
    }
  }'
```

## Custom Data Identifiers

### Şunu oluştur: custom identifier for internal IDs

```bash
aws macie2 create-custom-data-identifier \
  --name "internal-employee-id" \
  --description "Matches internal employee ID format EMP-XXXXXX" \
  --regex "EMP-[0-9]{6}" \
  --severity-levels '[
    {"occurrencesThreshold": 1, "severity": "LOW"},
    {"occurrencesThreshold": 10, "severity": "MEDIUM"},
    {"occurrencesThreshold": 50, "severity": "HIGH"}
  ]'
```

### Create identifier for project codes

```bash
aws macie2 create-custom-data-identifier \
  --name "project-code-identifier" \
  --description "Matches project codes in format PRJ-XXXX-XX" \
  --regex "PRJ-[A-Z]{4}-[0-9]{2}" \
  --keywords '["project", "code", "initiative"]' \
  --maximum-match-distance 50
```

## Allow Lists

### Şunu oluştur:n allow list to suppress false positives

```bash
aws macie2 create-allow-list \
  --name "test-data-exclusions" \
  --description "Exclude known test data patterns" \
  --criteria '{
    "regex": "TEST-[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}"
  }'
```

## Managed Data Identifiers

Macie provides 300+ managed data identifiers covering:

| Category | Examples |
|----------|---------|
| **PII** | SSN, passport numbers, driver's license, date of birth, names, addresses |
| **Financial** | Credit card numbers, bank account numbers, SWIFT codes |
| **Credentials** | AWS secret keys, API keys, SSH private keys, OAuth tokens |
| **Health** | HIPAA identifiers, health insurance claim numbers |
| **Legal** | Tax identification numbers, national ID numbers |

## Bul:ings Management

### List Bul:ings

```bash
aws macie2 list-Bul:ings \
  --Bul:ing-criteria '{
    "criterion": {
      "severity.description": {
        "eq": ["High"]
      },
      "category": {
        "eq": ["CLASSIFICATION"]
      }
    }
  }' \
  --sort-criteria '{"attributeName": "updatedAt", "orderBy": "DESC"}' \
  --max-results 25
```

### Get Bul:ing details

```bash
aws macie2 get-Bul:ings \
  --Bul:ing-ids '["Bul:ing-id-1", "Bul:ing-id-2"]'
```

### Export Bul:ings to Security Hub

```bash
aws macie2 get-macie-session --query 'Bul:ingPublishingFrequency'
```

## EventBridge Integration for Automated Response

```json
{
  "source": ["aws.macie"],
  "detail-type": ["Macie Bul:ing"],
  "detail": {
    "severity": {
      "description": ["High", "Critical"]
    }
  }
}
```

### Lambda function for automated remediation

```python
import boto3
import json

s3 = boto3.client('s3')
sns = boto3.client('sns')

def lambda_handler(event, context):
    Bul:ing = event['detail']
    severity = Bul:ing['severity']['description']
    bucket = Bul:ing['resourcesAffected']['s3Bucket']['name']
    key = Bul:ing['resourcesAffected']['s3Object']['key']
    sensitive_types = [d['type'] for d in Bul:ing.get('classificationDetails', {}).get('result', {}).get('sensitiveData', [])]

    if severity in ['High', 'Critical']:
        # Tag the object for review
        s3.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={
                'TagSet': [
                    {'Key': 'macie-Bul:ing', 'Value': severity},
                    {'Key': 'sensitive-data', 'Value': ','.join(sensitive_types)},
                    {'Key': 'requires-review', 'Value': 'true'}
                ]
            }
        )

        # Notify security team
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
            Subject=f'Macie {severity} Bul:ing: {bucket}/{key}',
            Message=json.dumps({
                'bucket': bucket,
                'key': key,
                'severity': severity,
                'sensitive_data_types': sensitive_types,
                'Bul:ing_id': Bul:ing['id']
            }, indent=2)
        )

    return {'statusCode': 200}
```

## Multi-Account Dağıt:ment

### Designate Macie administrator account

```bash
aws macie2 enable-organization-admin-account \
  --admin-account-id 111111111111
```

### Add member accounts

```bash
aws macie2 create-member \
  --account '{"accountId": "222222222222", "email": "security@example.com"}'
```

## Monitoring Macie Operations

### Kullanım statistics

```bash
aws macie2 get-usage-statistics \
  --filter-by '[{"comparator": "GT", "key": "accountId", "values": []}]' \
  --sort-by '{"key": "accountId", "orderBy": "ASC"}'
```

### Classification job status

```bash
aws macie2 list-classification-jobs \
  --filter-criteria '{"includes": [{"comparator": "EQ", "key": "jobStatus", "values": ["RUNNING"]}]}'
```

## References

- AWS Macie Documentation: https://docs.aws.amazon.com/macie/
- AWS Macie Pricing
- Supported File Types for Macie Analysis
- GDPR and CCPA Compliance with Macie

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 1b82a231a57022af
-->

