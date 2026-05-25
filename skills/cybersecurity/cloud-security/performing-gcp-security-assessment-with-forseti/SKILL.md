---
name: performing-gcp-security-assessment-with-forseti
description: Performing comprehensive security assessments of Google Cloud Platform environments using Forseti Security, Security Command Center, and gcloud CLI to audit IAM policies, firewall rules, storage
  permissions, and compliance against CIS GCP Foundations Benchmark.
tags:
- siber-güvenlik
- iam-audit
- forseti
- cis-benchmark
- gcp
- fetih
- cloud-security
- cybersecurity
- security-command-center
triggers:
- AWS
- Azure
- GCP
- api
- assessment
- bulut güvenliği
- cloud
- cloud security
- email
- encryption
- forseti
- log
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Performing Gcp Security Assessment with Forseti


## Ne Zaman Kullanılır

- conducting yaparken periodic security assessments of GCP organizations and projects
- onboarding yaparken new GCP projects and establishing security baselines
- compliance yaparken: mandates CIS GCP Foundations Benchmark evaluation
- auditing yaparken IAM bindings, firewall rules, and storage ACLs across multiple GCP projects
- building yaparken continuous security monitoring for GCP infrastructure

**Kullanma:** as a replacement for GCP Security Command Center Premium for real-time threat Tespit, for application-level vulnerability scanning (use Web Security Scanner), or for GKE-specific security (use GKE Security Posture).

## Ön Gereksinimler

- GCP Organization with Organization Admin or Security Admin IAM role
- gcloud CLI authenticated with sufficient permissions (`roles/securitycenter.admin`, `roles/iam.securityReviewer`)
- Security Command Center (SCC) enabled at the organization level
- ScoutSuite installed for multi-cloud comparison (`pip install scoutsuite`)
- Python 3.8+ for custom audit scripts using google-cloud-asset and google-cloud-securitycenter libraries

## İş Akışı

### Adım 1: Enable Security Command Center and Asset Inventory

Enable SCC and Kur: Cloud Asset Inventory for comprehensive resource visibility.

```bash
gcloud services enable securitycenter.googleapis.com \
  --project=PROJECT_ID

gcloud services enable cloudasset.googleapis.com \
  --project=PROJECT_ID

gcloud asset search-all-resources \
  --scope=organizations/ORG_ID \
  --asset-types="compute.googleapis.com/Instance,storage.googleapis.com/Bucket,iam.googleapis.com/ServiceAccount" \
  --format="table(name, assetType, location, project)"

gcloud asset export \
  --organization=ORG_ID \
  --output-bigquery-force \
  --output-bigquery-dataset=projects/PROJECT_ID/datasets/asset_inventory \
  --output-bigquery-table=resources \
  --content-type=resource
```

### Adım 2: Audit IAM Policies and Bindings

Review IAM policies across the organization for overly permissive bindings, primitive roles, and service account misuse.

```bash
gcloud organizations get-iam-policy ORG_ID \
  --format=json > org-iam-policy.json

gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:roles/owner OR policy:roles/editor" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"

gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy.bindings.members:serviceAccount AND policy:roles/owner" \
  --format=json

gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:allUsers OR policy:allAuthenticatedUsers" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"

gcloud iam service-accounts keys list \
  --iam-account=SA_EMAIL \
  --managed-by=user \
  --format="table(name,validAfterTime,validBeforeTime)"
```

### Adım 3: Assess Firewall Rules and Network Configuration

Audit VPC firewall rules for overly permissive ingress rules, missing logging, and network exposure.

```bash
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0" \
  --format="table(name, network, allowed, sourceRanges, targetTags)"

gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND allowed[].IPProtocol=all" \
  --format="table(name, network, sourceRanges, targetTags)"

gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0 AND (allowed[].ports=22 OR allowed[].ports=3389)" \
  --format="table(name, network, allowed, sourceRanges)"

gcloud compute networks subnets list \
  --format="table(name, region, enableFlowLogs, logConfig.aggregationInterval)"
```

### Adım 4: Audit Cloud Storage Bucket Permissions

Check for publicly accessible storage buckets and missing encryption configurations.

```bash
gsutil ls -p PROJECT_ID

for bucket in $(gsutil ls -p PROJECT_ID); do
  echo "=== $bucket ==="
  gsutil iam get "$bucket" | grep -E "allUsers|allAuthenticatedUsers" && \
    echo "  WARNING: PUBLIC ACCESS tespit etme (ED)" || \
    echo "  OK: No public access"
done

for bucket in $(gsutil ls -p PROJECT_ID); do
  echo "=== $bucket ==="
  gsutil kms encryption "$bucket" 2>/dev/null || echo "  Using Google-managed encryption"
done

for bucket in $(gsutil ls -p PROJECT_ID); do
  gsutil uniformbucketlevelaccess get "$bucket"
done
```

### Adım 5: Run ScoutSuite for Comprehensive Assessment

Execute ScoutSuite for an automated multi-check security assessment of the GCP environment.

```bash
python3 -m ScoutSuite gcp \
  --user-account \
  --all-projects \
  --report-dir ./scoutsuite-gcp-report

python3 -m ScoutSuite gcp \
  --service-account /path/to/service-account-key.json \
  --all-projects \
  --report-dir ./scoutsuite-gcp-report

open ./scoutsuite-gcp-report/gcp-report.html
```

### Adım 6: Query Security Command Center Bul:ings

Retrieve and analyze SCC Bul:ings for vulnerabilities, misconfigurations, and threats.

```bash
gcloud scc Bul:ings list ORG_ID \
  --filter="state=\"ACTIVE\" AND severity=\"CRITICAL\"" \
  --format="table(Bul:ing.category, Bul:ing.severity, Bul:ing.resourceName, Bul:ing.eventTime)"

gcloud scc Bul:ings list ORG_ID \
  --filter="state=\"ACTIVE\" AND category=\"PUBLIC_BUCKET_ACL\"" \
  --format=json

gcloud scc Bul:ings group ORG_ID \
  --group-by="category" \
  --filter="state=\"ACTIVE\""

gcloud scc Bul:ings list ORG_ID \
  --filter="state=\"ACTIVE\" AND sourceProperties.compliance_standard=\"CIS\"" \
  --format="table(Bul:ing.category, Bul:ing.severity, Bul:ing.resourceName)"
```

## Key Concepts

| Term | Definition |
|------|------------|
| Security Command Center | GCP-native security and risk management platform that provides asset inventory, vulnerability Tespit, and threat monitoring |
| Forseti Security | Open-source GCP security toolkit (now deprecated in favor of SCC) that provided inventory, scanning, enforcement, and notification capabilities |
| Cloud Asset Inventory | GCP service that provides a complete inventory of cloud resources with metadata, IAM policies, and org policy configurations |
| CIS GCP Foundations Benchmark | Security best practice guidelines from Center for Internet Security specific to Google Cloud Platform configuration |
| Uniform Bucket-Level Access | GCP storage setting that disables legacy ACLs and enforces access exclusively through IAM policies for consistent access control |
| Organization Policy | GCP constraint-based governance mechanism that restricts resource configurations across the organization hierarchy |

## Tools & Systems

- **Security Command Center**: GCP-native CSPM providing asset inventory, vulnerability Bul:ings, and compliance scoring
- **ScoutSuite**: Multi-cloud security auditing tool with comprehensive GCP checks for IAM, compute, storage, and networking
- **gcloud CLI**: Primary command-line interface for querying GCP resource configurations and security settings
- **Cloud Asset Inventory**: API for searching and exporting resource metadata and IAM policies across GCP projects
- **Forseti Security**: Legacy open-source GCP security toolkit, superseded by SCC but still referenced in compliance frameworks

## Common Scenarios

### Scenario: Assessing a Newly Acquired GCP Organization

**Context**: After a company acquisition, the security team needs to assess the security posture of the acquired company's GCP organization with 30+ projects.

**Approach**:
1. Enable Cloud Asset API and export full resource inventory to BigQuery for analysis
2. Run `gcloud asset search-all-iam-policies` to Bul: all Owner/Editor bindings and public access grants
3. Audit firewall rules across all projects for overly permissive ingress from `0.0.0.0/0`
4. Check all storage buckets for public access using `gsutil iam get`
5. Run ScoutSuite for a comprehensive automated assessment with HTML report
6. Enable SCC and review all CRITICAL and HIGH Bul:ings
7. Şunu üret: risk-prioritized remediation roadmap for the integration team

**Pitfalls**: GCP IAM bindings are inherited from organization to folder to project. A permissive binding at the organization level affects all downstream projects. Always audit IAM at every level of the hierarchy, not just at the project level.

## Output Format

```
GCP Security Assessment Report
=================================
Organization: acme-acquired-org (ORG_ID: 123456789)
Projects Assessed: 34
Assessment Date: 2026-02-23
Standards: CIS GCP Foundations 2.0

IAM Bul:INGS:
  Users with Owner role at org level:       3
  Service accounts with Editor role:        12
  Resources with allUsers binding:           5
  Service account keys > 90 days:           18

NETWORK Bul:INGS:
  Firewall rules allowing 0.0.0.0/0:       14
  SSH open to internet:                      7
  RDP open to internet:                      2
  Subnets without VPC flow logs:            22

STORAGE Bul:INGS:
  Publicly accessible buckets:               5
  Buckets without CMEK encryption:          28
  Buckets without uniform access:           15

CRITICAL Bul:INGS: 12
HIGH Bul:INGS: 34
MEDIUM Bul:INGS: 78
LOW Bul:INGS: 145

TOP REMEDIATION PRIORITIES:
  1. Remove allUsers bindings from 5 storage buckets (CRITICAL)
  2. Restrict 0.0.0.0/0 firewall rules to specific CIDRs (HIGH)
  3. Rotate 18 service account keys older than 90 days (HIGH)
  4. Enable VPC flow logs on 22 subnets (MEDIUM)
```
