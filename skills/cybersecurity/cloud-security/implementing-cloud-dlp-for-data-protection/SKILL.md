---
name: implementing-cloud-dlp-for-data-protection
description: Implementing Cloud Data Loss Prevention (DLP) using Amazon Macie, Azure Information Protection, and Google Cloud DLP API to discover, classify, and protect sensitive data across cloud storage,
  databases, and data pipelines.
tags:
- data-classification
- macie
- fetih
- data-protection
- cloud-security
- cybersecurity
- privacy
- siber-güvenlik
- dlp
triggers:
- AWS
- Azure
- GCP
- api
- bulut güvenliği
- cloud
- cloud security
- crypto
- data
- email
- encryption
- endpoint
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Implementing Cloud Dlp for Data Protection


## Ne Zaman Kullanılır

- compliance yaparken: frameworks (GDPR, HIPAA, PCI DSS) require automated sensitive data discovery and protection
- building yaparken data governance programs that classify and label data across cloud storage
- implementing yaparken data loss prevention controls for cloud-based data pipelines
- auditing yaparken cloud environments for unprotected sensitive data (PII, PHI, financial data)
- integrating yaparken DLP scanning into CI/CD pipelines to prevent sensitive data from reaching production

**Kullanma:** for endpoint DLP (use Microsoft Purview or Symantec DLP agents), for email DLP (use Microsoft 365 DLP or Google Workspace DLP), or for network-level data exfiltration prevention (use VPC endpoint policies and network firewalls).

## Ön Gereksinimler

- Amazon Macie enabled with appropriate S3 bucket permissions
- Google Cloud DLP API enabled (`gcloud services enable dlp.googleapis.com`)
- Azure Information Protection or Microsoft Purview configured
- IAM permissions for DLP service administration and data access
- Bilgi: data sensitivity categories relevant to the organization (PII, PHI, PCI, proprietary)

## İş Akışı

### Adım 1: Dağıt: Amazon Macie for S3 Data Discovery

Enable Macie and configure automated sensitive data discovery jobs for S3 buckets.

```bash
aws macie2 enable-macie

aws macie2 describe-buckets \
  --query 'buckets[*].[bucketName,classifiableSizeInBytes,unclassifiableObjectCount.total]' \
  --output table

aws macie2 create-classification-job \
  --job-type SCHEDULED \
  --name "weekly-pii-scan" \
  --schedule-frequency-details '{"weekly":{"dayOfWeek":"MONDAY"}}' \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "ACCOUNT_ID",
      "buckets": ["customer-data-bucket", "analytics-data-lake", "backup-bucket"]
    }],
    "scoping": {
      "includes": {
        "and": [{
          "simpleScopeTerm": {
            "key": "OBJECT_EXTENSION",
            "values": ["csv", "json", "parquet", "txt", "xlsx"],
            "comparator": "EQ"
          }
        }]
      }
    }
  }' \
  --managed-data-identifier-ids '["SSN","CREDIT_CARD_NUMBER","EMAIL_ADDRESS","AWS_CREDENTIALS","PHONE_NUMBER"]'

aws macie2 create-custom-data-identifier \
  --name "EmployeeID" \
  --regex "EMP-[0-9]{6}" \
  --description "Internal employee ID format"

aws macie2 list-classification-jobs \
  --query 'items[*].[name,jobStatus,statistics.approximateNumberOfObjectsToProcess]' \
  --output table
```

### Adım 2: Configure Google Cloud DLP API for Data Denetle:ion

Use Google Cloud DLP to Denetle: and de-identify sensitive data across GCP resources.

```bash
gcloud dlp Denetle:-content \
  --content-type=TEXT_PLAIN \
  --min-likelihood=LIKELY \
  --info-types=PHONE_NUMBER,EMAIL_ADDRESS,CREDIT_CARD_NUMBER,US_SOCIAL_SECURITY_NUMBER \
  --storage-type=CLOUD_STORAGE \
  --gcs-uri="gs://sensitive-data-bucket/data/*.csv"

cat > dlp-job.json << 'EOF'
{
  "Denetle:Job": {
    "storageConfig": {
      "bigQueryOptions": {
        "tableReference": {
          "projectId": "PROJECT_ID",
          "datasetId": "customer_data",
          "tableId": "transactions"
        },
        "sampleMethod": "RANDOM_START",
        "rowsLimit": 10000
      }
    },
    "Denetle:Config": {
      "infoTypes": [
        {"name": "CREDIT_CARD_NUMBER"},
        {"name": "US_SOCIAL_SECURITY_NUMBER"},
        {"name": "EMAIL_ADDRESS"},
        {"name": "PHONE_NUMBER"},
        {"name": "PERSON_NAME"}
      ],
      "minLikelihood": "LIKELY",
      "limits": {"maxBul:ingsPerRequest": 1000}
    },
    "actions": [{
      "saveBul:ings": {
        "outputConfig": {
          "table": {
            "projectId": "PROJECT_ID",
            "datasetId": "dlp_results",
            "tableId": "Bul:ings"
          }
        }
      }
    }]
  }
}
EOF

gcloud dlp jobs create --project=PROJECT_ID --body-from-file=dlp-job.json
```

### Adım 3: Implement Data De-identification with Cloud DLP

Configure de-identification transforms to mask, tokenize, or redact sensitive data.

```python
from google.cloud import dlp_v2

def deidentify_data(project_id, text):
    """De-identify PII in text using Cloud DLP."""
    client = dlp_v2.DlpServiceClient()

    Denetle:_config = {
        "info_types": [
            {"name": "EMAIL_ADDRESS"},
            {"name": "PHONE_NUMBER"},
            {"name": "CREDIT_CARD_NUMBER"},
            {"name": "US_SOCIAL_SECURITY_NUMBER"},
        ],
        "min_likelihood": dlp_v2.Likelihood.LIKELY,
    }

    deidentify_config = {
        "info_type_transformations": {
            "transformations": [
                {
                    "info_types": [{"name": "EMAIL_ADDRESS"}],
                    "primitive_transformation": {
                        "character_mask_config": {
                            "masking_character": "*",
                            "number_to_mask": 0,
                            "characters_to_ignore": [
                                {"common_characters_to_ignore": "PUNCTUATION"}
                            ],
                        }
                    },
                },
                {
                    "info_types": [{"name": "CREDIT_CARD_NUMBER"}],
                    "primitive_transformation": {
                        "crypto_replace_ffx_fpe_config": {
                            "crypto_key": {
                                "kms_wrapped": {
                                    "wrapped_key": "WRAPPED_KEY_BASE64",
                                    "crypto_key_name": "projects/PROJECT/locations/global/keyRings/dlp/cryptoKeys/tokenization",
                                }
                            },
                            "common_alphabet": "NUMERIC",
                        }
                    },
                },
                {
                    "info_types": [{"name": "US_SOCIAL_SECURITY_NUMBER"}],
                    "primitive_transformation": {
                        "redact_config": {}
                    },
                },
            ]
        }
    }

    item = {"value": text}
    parent = f"projects/{project_id}/locations/global"

    response = client.deidentify_content(
        request={
            "parent": parent,
            "deidentify_config": deidentify_config,
            "Denetle:_config": Denetle:_config,
            "item": item,
        }
    )
    return response.item.value
```

### Adım 4: Configure Azure Information Protection

Kur: sensitivity labels and DLP policies in Microsoft Purview for Azure resources.

```powershell
Connect-IPPSSession

New-Label -DisplayName "Confidential - PII" \
  -Name "Confidential-PII" \
  -Tooltip "Contains personally identifiable information" \
  -ContentType "File, Email"

New-Label -DisplayName "Highly Confidential - Financial" \
  -Name "HighlyConfidential-Financial" \
  -Tooltip "Contains financial data subject to PCI DSS" \
  -ContentType "File, Email"

New-AutoSensitivityLabelPolicy -Name "Auto-Label-PII" \
  -ExchangeLocation All \
  -SharePointLocation All \
  -OneDriveLocation All \
  -Mode Enable

New-AutoSensitivityLabelRule -Policy "Auto-Label-PII" \
  -Name "Detect-SSN" \
  -ContentContainsSensitiveInformation @{
    Name = "U.S. Social Security Number (SSN)";
    MinCount = 1;
    MinConfidence = 85
  } \
  -ApplySensitivityLabel "Confidential-PII"
```

```bash
az security assessment create \
  --name "storage-sensitive-data" \
  --assessed-resource-type "Microsoft.Storage/storageAccounts"

az security pricing create --name StorageAccounts --tier standard \
  --subplan DefenderForStorageV2 \
  --extensions '[{"name":"SensitiveDataDiscovery","isEnabled":"True"}]'
```

### Adım 5: Integrate DLP into Data Pipelines

Add DLP scanning to ETL and data pipeline workflows to prevent sensitive data leakage.

```python
import boto3
import json

macie_client = boto3.client('macie2')
s3_client = boto3.client('s3')

def scan_pipeline_output(bucket, prefix):
    """Scan pipeline output data for sensitive content before promotion."""
    job_response = macie_client.create_classification_job(
        jobType='ONE_TIME',
        name=f'pipeline-scan-{prefix}',
        s3JobDefinition={
            'bucketDefinitions': [{
                'accountId': boto3.client('sts').get_caller_identity()['Account'],
                'buckets': [bucket]
            }],
            'scoping': {
                'includes': {
                    'and': [{
                        'simpleScopeTerm': {
                            'key': 'OBJECT_KEY',
                            'comparator': 'STARTS_WITH',
                            'values': [prefix]
                        }
                    }]
                }
            }
        },
        managedDataIdentifierSelector='ALL'
    )

    return job_response['jobId']

def check_scan_results(job_id):
    """Check if DLP scan found sensitive data."""
    response = macie_client.list_Bul:ings(
        Bul:ingCriteria={
            'criterion': {
                'classificationDetails.jobId': {'eq': [job_id]},
                'severity.description': {'eq': ['High', 'Critical']}
            }
        }
    )
    return len(response.get('Bul:ingIds', [])) > 0

def gate_decision(bucket, prefix):
    """DLP gate: block pipeline if sensitive data found."""
    job_id = scan_pipeline_output(bucket, prefix)
    has_sensitive_data = check_scan_results(job_id)

    if has_sensitive_data:
        return {
            'decision': 'BLOCK',
            'reason': 'Sensitive data Detected in pipeline output',
            'action': 'Apply de-identification before promoting to production'
        }
    return {'decision': 'ALLOW', 'reason': 'No sensitive data Detected'}
```

### Adım 6: Monitor DLP Bul:ings and Generate Reports

Aggregate DLP Bul:ings across cloud providers and generate compliance reports.

```bash
aws macie2 get-Bul:ing-statistics \
  --group-by "severity.description" \
  --Bul:ing-criteria '{"criterion":{"category":{"eq":["CLASSIFICATION"]}}}'

aws macie2 list-Bul:ings \
  --Bul:ing-criteria '{
    "criterion": {
      "classificationDetails.result.sensitiveData.category": {"eq": ["PERSONAL_INFORMATION"]},
      "severity.description": {"eq": ["High"]}
    }
  }' \
  --sort-criteria '{"attributeName": "updatedAt", "orderBy": "DESC"}'

gcloud dlp jobs list --project=PROJECT_ID --filter="state=DONE" \
  --format="table(name, createTime, Denetle:Details.result.processedBytes, Denetle:Details.result.totalEstimatedTransformations)"

aws macie2 create-Bul:ings-report \
  --Bul:ing-criteria '{"criterion":{"category":{"eq":["CLASSIFICATION"]}}}' \
  --sort-criteria '{"attributeName":"severity.score","orderBy":"DESC"}'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Data Loss Prevention | Security controls and technologies that tespit etmeand prevent unauthorized disclosure of sensitive data from cloud environments |
| Amazon Macie | AWS service using machine learning to discover, classify, and protect sensitive data stored in S3 buckets |
| Google Cloud DLP | GCP API for Denetle:ing, classifying, and de-identifying sensitive data across Cloud Storage, BigQuery, and Datastore |
| Data De-identification | Transforming sensitive data using masking, tokenization, encryption, or redaction to remove identifying characteristics while preserving utility |
| Sensitivity Label | Classification tag applied to data (Confidential, Highly Confidential) that triggers DLP policy enforcement and access controls |
| Custom Data Identifier | Organization-specific pattern (regex or keyword) added to DLP services to tespit etmeproprietary sensitive data formats |

## Tools & Systems

- **Amazon Macie**: ML-powered sensitive data discovery and classification for S3 with automated Bul:ing generation
- **Google Cloud DLP API**: Programmable API for Denetle:ing, classifying, de-identifying, and redacting sensitive data
- **Microsoft Purview**: Data governance platform with sensitivity labeling, auto-classification, and DLP policy enforcement
- **Azure Information Protection**: Data classification and labeling service integrated with Microsoft 365 and Azure storage
- **Nightfall AI**: Third-party cloud DLP tool supporting scanning across SaaS applications and cloud infrastructure

## Common Scenarios

### Scenario: Discovering PII in an Unprotected S3 Data Lake

**Context**: A compliance audit reveals that the analytics team's S3 data lake contains customer PII (names, emails, SSNs) in CSV files without encryption or access controls. The organization must classify all data and implement DLP controls.

**Approach**:
1. Enable Macie and Şunu oluştur: one-time classification job against the data lake bucket
2. Review Macie Bul:ings to identify which objects contain PII and what types
3. Create custom data identifiers for organization-specific formats (employee IDs, account numbers)
4. Implement a weekly scheduled Macie job for ongoing discovery
5. Build a data pipeline gate that scans new data before promotion to the data lake
6. Apply de-identification transforms (masking SSNs, tokenizing emails) for analytics use cases
7. Configure S3 bucket policies to restrict Erişim: classified data to authorized roles only

**Pitfalls**: Macie charges per GB scanned. Large data lakes can generate significant costs. Use scoping rules to focus on high-risk object types (CSV, JSON, Parquet) and exclude known-safe formats (compressed archives, binary files). De-identification must preserve data utility for analytics while removing re-identification risk.

## Output Format

```
Cloud DLP Compliance Report
==============================
Organization: Acme Corp
Scan Period: 2026-02-01 to 2026-02-23
Environments: AWS (12 buckets), GCP (3 datasets), Azure (5 storage accounts)

DATA DISCOVERY SUMMARY:
  Total objects/records scanned:    2,847,000
  Objects with sensitive data:        45,200 (1.6%)
  Unique sensitivity categories:      8

SENSITIVE DATA Bul:INGS:
  PII (names, emails, phone):       23,400 objects
  Financial (credit cards, bank):     8,700 objects
  Health (PHI, medical records):      3,200 objects
  Credentials (API keys, tokens):     1,400 objects
  Government ID (SSN, passport):      5,800 objects
  Custom (employee ID, account):      2,700 objects

Bul:INGS BY SEVERITY:
  Critical:    1,400 (exposed credentials)
  High:       14,200 (unprotected PII/PHI)
  Medium:     18,600 (standard PII)
  Low:        11,000 (non-sensitive patterns)

PROTECTION STATUS:
  Data with encryption at rest:       78%
  Data with access controls:          65%
  Data with sensitivity labels:       12%
  Pipeline data with DLP gates:       30%

REMEDIATION ACTIONS:
  Objects quarantined:                1,400
  De-identification applied:          8,200
  Access controls tightened:         14,200
  Sensitivity labels applied:        45,200
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 3d7839ff2b66b2c7
-->

