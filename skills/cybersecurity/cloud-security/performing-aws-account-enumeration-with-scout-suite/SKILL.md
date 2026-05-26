---
name: performing-aws-account-enumeration-with-scout-suite
description: Perform comprehensive security posture assessment of AWS accounts using ScoutSuite to enumerate resources, identify misconfigurations, and Şunu üret:ctionable security reports.
tags:
- cybersecurity
- cspm
- scoutsuite
- misconfiguration
- aws
- fetih
- security-audit
- cloud-security
- nccgroup
- enumeration
- siber-güvenlik
triggers:
- AWS
- Azure
- GCP
- account
- api
- authentication
- bulut güvenliği
- cloud
- cloud security
- encryption
- endpoint
- enumeration
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Performing Aws Account Enumeration with Scout Suite


## Genel Bakış

ScoutSuite is an open-source multi-cloud security auditing tool developed by NCC Group that enables comprehensive security posture assessment of AWS environments. It queries AWS APIs to gather configuration data across all services, stores results locally, and generates interactive HTML reports highlighting high-risk areas. ScoutSuite is agentless and works by analyzing how cloud resources are configured, accessed, and monitored.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing aws account enumeration with scout suite
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Python 3.6+ installed
- AWS CLI configured with appropriate IAM credentials
- Read-only IAM permissions across target AWS services (SecurityAudit managed policy recommended)
- pip package manager for ScoutSuite installation
- Network Erişim: AWS API endpoints

## Kurulum and Setup

### Install ScoutSuite

```bash
pip install scoutsuite
```

### Verify installation

```bash
scout --version
```

### Configure AWS credentials

```bash
aws configure
export AWS_ACCESS_KEY_ID=<your-key>
export AWS_SECRET_ACCESS_KEY=<your-secret>
export AWS_DEFAULT_REGION=us-east-1
```

### Required IAM Policy

Attach the AWS managed policy `SecurityAudit` and `ViewOnlyAccess` to the IAM user or role running ScoutSuite. For comprehensive scanning, a custom policy may be needed:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm:Describe*",
        "acm:List*",
        "cloudformation:Describe*",
        "cloudformation:Get*",
        "cloudformation:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "config:Describe*",
        "config:Get*",
        "config:List*",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "ec2:Describe*",
        "ec2:Get*",
        "elasticloadbalancing:Describe*",
        "iam:Generate*",
        "iam:Get*",
        "iam:List*",
        "iam:Simulate*",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "lambda:Get*",
        "lambda:List*",
        "logs:Describe*",
        "logs:Get*",
        "rds:Describe*",
        "rds:List*",
        "redshift:Describe*",
        "route53:Get*",
        "route53:List*",
        "s3:Get*",
        "s3:List*",
        "ses:Get*",
        "ses:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:Get*",
        "sqs:List*",
        "ssm:Describe*",
        "ssm:Get*",
        "ssm:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

## Running ScoutSuite

### Full AWS scan

```bash
scout aws
```

### Scan specific services only

```bash
scout aws --services s3 iam ec2 rds
```

### Scan specific regions

```bash
scout aws --regions us-east-1 us-west-2 eu-west-1
```

### Use an assumed role for cross-account scanning

```bash
scout aws --profile target-account-profile
```

### Exclude specific services from scan

```bash
scout aws --skip iam ec2
```

### Specify output directory

```bash
scout aws --report-dir /tmp/scoutsuite-reports/
```

## Report Analysis

ScoutSuite generates an interactive HTML report stored locally. The report includes:

1. **Dashboard**: Overview of Bul:ings by severity (danger, warning, good)
2. **Service-level Bul:ings**: Grouped by AWS service (IAM, S3, EC2, RDS, etc.)
3. **Rule-based checks**: Each Bul:ing maps to a security best practice rule
4. **Resource inventory**: Complete listing of enumerated resources

### Key areas to review in the report

| Service | Critical Checks |
|---------|----------------|
| IAM | Root account MFA, password policy, unused credentials, overprivileged policies |
| S3 | Public buckets, unencrypted buckets, versioning disabled, logging disabled |
| EC2 | Security groups with 0.0.0.0/0, unencrypted EBS volumes, public IPs |
| RDS | Public accessibility, unencrypted databases, backup retention |
| CloudTrail | Logging disabled, log file validation, multi-region disabled |
| Lambda | Public access, environment variable secrets, VPC configuration |

## Interpreting Bul:ings

### Severity Levels

- **Danger (Red)**: Critical security issues requiring immediate remediation (e.g., S3 buckets with public write access)
- **Warning (Orange)**: Moderate risk Bul:ings that should be addressed (e.g., unused IAM access keys)
- **Good (Green)**: Security best practices that are properly configured

### Common High-Risk Bul:ings

1. **IAM root account without MFA**: The AWS root account has no multi-factor authentication enabled
2. **S3 bucket policy allows public access**: Bucket policies with Principal set to "*"
3. **Security group allows unrestricted SSH**: Inbound rule allowing 0.0.0.0/0 on port 22
4. **CloudTrail not enabled in all regions**: Audit logging gaps allow unmonitored API activity
5. **RDS instance publicly accessible**: Database endpoints reachable from the internet

## İyileştirme Workflow

1. Run ScoutSuite scan to establish baseline
2. Export Bul:ings and prioritize by severity
3. Create remediation tickets for danger and warning Bul:ings
4. Implement fixes (update security groups, enable encryption, restrict access)
5. Re-run ScoutSuite to verify remediation
6. Schedule regular scans (weekly or after infrastructure changes)

## Integration with CI/CD

```bash
scout aws --services s3 iam ec2 --no-browser --report-dir ./scout-report/

python -c "
import json
with open('./scout-report/scoutsuite-results/scoutsuite_results.json') as f:
    results = json.load(f)
    for service in results.get('services', {}):
        Bul:ings = results['services'][service].get('Bul:ings', {})
        for Bul:ing_id, Bul:ing in Bul:ings.items():
            if Bul:ing.get('flagged_items', 0) > 0 and Bul:ing.get('level') == 'danger':
                print(f'CRITICAL: {Bul:ing_id} - {Bul:ing.get(\"description\", \"\")}')
"
```

## Multi-Cloud Capability

ScoutSuite supports multiple cloud providers using the same framework:

```bash
scout azure --cli

scout gcp --user-account

scout aws --profile production
```

## References

- ScoutSuite GitHub Repository: https://github.com/nccgroup/ScoutSuite
- AWS Security Audit Checklist
- CIS AWS Foundations Benchmark
- AWS Well-Architected Security Pillar

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 667759313aa74901
-->

