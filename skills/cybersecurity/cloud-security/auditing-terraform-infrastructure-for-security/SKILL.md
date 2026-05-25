---
name: auditing-terraform-infrastructure-for-security
description: Auditing Terraform infrastructure-as-code for security misconfigurations using Checkov, tfsec, Terrascan, and OPA/Rego policies to tespit etmeoverly permissive IAM policies, public resource exposure,
  missing encryption, and insecure defaults before cloud Dağıt:ment.
tags:
- checkov
- tfsec
- fetih
- terraform
- cloud-security
- cybersecurity
- policy-as-code
- siber-güvenlik
- infrastructure-as-code
triggers:
- AWS
- Azure
- GCP
- api
- auditing
- bulut güvenliği
- cloud
- cloud security
- encryption
- hash
- infrastructure
- log
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Auditing Terraform Infrastructure for Security


## Ne Zaman Kullanılır

- integrating yaparken security scanning into CI/CD pipelines for Terraform Dağıt:ments
- reviewing yaparken Terraform plans and modules for security best practices before applying
- building yaparken policy-as-code guardrails for cloud infrastructure provisioning
- auditing yaparken existing Terraform state files to identify Dağıtılmış misconfigurations
- enforcing yaparken organizational security standards across multiple Terraform projects

**Kullanma:** for runtime security monitoring (use CSPM tools), for application security testing (use SAST/DAST tools), or for cloud configuration drift Tespit (use AWS Config or Azure Policy after Dağıt:ment).

## Ön Gereksinimler

- Checkov kurulu (`pip install checkov`)
- tfsec kurulu (`brew install tfsec` or binary from GitHub)
- Terrascan kurulu (`brew install terrascan`)
- Terraform v1.0+ for plan generation
- OPA (Open Policy Agent) for custom policy enforcement
- Git repository with Terraform code to audit

## İş Akışı

### Adım 1: Scan Terraform Code with Checkov

Run Checkov for comprehensive IaC security scanning with built-in and custom policies.

```bash
checkov -d ./terraform/ --framework terraform

checkov -d ./terraform/ --check CKV_AWS_18,CKV_AWS_19,CKV_AWS_20,CKV_AWS_21

checkov -d ./terraform/ --output json > checkov-results.json

terraform init && terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
checkov -f tfplan.json --framework terraform_plan

checkov -d ./terraform/ --skip-check CKV_AWS_145 \
  --bc-api-key $BRIDGECREW_API_KEY

checkov -d ./modules/ --framework terraform --compact

checkov --list --framework terraform | grep CKV_AWS
```

### Adım 2: Scan with tfsec for Terraform-Specific Issues

Use tfsec for Terraform-native security analysis with detailed remediation guidance.

```bash
tfsec ./terraform/

tfsec ./terraform/ --minimum-severity HIGH

tfsec ./terraform/ --format json > tfsec-results.json

tfsec ./terraform/ --custom-check-dir ./custom-checks/

tfsec ./terraform/ --exclude-downloaded-modules \
  --exclude aws-s3-enable-bucket-logging

tfsec ./terraform/ --minimum-severity CRITICAL --soft-fail

tfsec ./terraform/ --format sarif > tfsec.sarif
```

### Adım 3: Run Terrascan for Multi-Framework Compliance

Execute Terrascan for compliance checking against CIS, NIST, and SOC 2 frameworks.

```bash
terrascan scan -t aws -i terraform -d ./terraform/ \
  --policy-type aws --verbose

terrascan scan -t aws -i terraform -d ./terraform/ \
  --policy-type aws \
  --categories "Compliance Validation"

terrascan scan -t aws -i terraform -d ./terraform/ \
  --output json > terrascan-results.json

terrascan scan -t aws -i terraform \
  --iac-file tfplan.json \
  --iac-type tfplan

terrascan scan --list-policies -t aws
```

### Adım 4: Create Custom OPA Policies for Organization Standards

Write Rego policies for organization-specific security requirements.

```rego
package terraform.aws.s3

deny[msg] {
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration
    msg := sprintf("S3 bucket '%s' must have server-side encryption enabled", [name])
}

package terraform.aws.iam

deny[msg] {
    resource := input.resource.aws_iam_policy[name]
    statement := resource.policy.Statement[_]
    statement.Action == "*"
    statement.Effect == "Allow"
    msg := sprintf("IAM policy '%s' must not use wildcard (*) actions", [name])
}

deny[msg] {
    resource := input.resource.aws_iam_policy[name]
    statement := resource.policy.Statement[_]
    statement.Resource == "*"
    statement.Effect == "Allow"
    contains(statement.Action[_], "*")
    msg := sprintf("IAM policy '%s' has overly permissive actions on wildcard resources", [name])
}

package terraform.aws.security_group

deny[msg] {
    resource := input.resource.aws_security_group_rule[name]
    resource.type == "ingress"
    resource.cidr_blocks[_] == "0.0.0.0/0"
    resource.from_port <= 22
    resource.to_port >= 22
    msg := sprintf("Security group rule '%s' allows SSH from 0.0.0.0/0", [name])
}
```

```bash
terraform show -json tfplan | opa eval \
  --data ./policy/ \
  --input /dev/stdin \
  "data.terraform.aws" \
  --format pretty

conftest test tfplan.json --policy ./policy/ --output json
```

### Adım 5: Integrate Security Scanning into CI/CD Pipeline

Add IaC security scanning as a mandatory CI/CD gate.

```yaml
name: Terraform Security Scan
on:
  pull_request:
    paths: ['terraform/**']

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init & Plan
        run: |
          cd terraform/
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > tfplan.json

      - name: Checkov Scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          output_format: sarif
          output_file_path: checkov.sarif
          soft_fail: false

      - name: tfsec Scan
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: terraform/
          soft_fail: false

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: checkov.sarif

      - name: OPA Policy Check
        run: |
          conftest test terraform/tfplan.json \
            --policy ./policy/ \
            --output json
```

### Adım 6: Scan Terraform State for Dağıtılmış Misconfigurations

Audit the current Terraform state to identify already-Dağıtılmış security issues.

```bash
terraform show -json > terraform-state.json

checkov -f terraform-state.json --framework terraform_plan

terraform state list | while read resource; do
  terraform state show "$resource" 2>/dev/null | grep -i "public\|0.0.0.0\|encrypt.*false\|password"
done

terraform state list | grep aws_instance | while read resource; do
  tags=$(terraform state show "$resource" | grep -A20 "tags")
  if ! echo "$tags" | grep -q "Environment"; then
    echo "MISSING TAG: $resource lacks 'Environment' tag"
  fi
done
```

## Key Concepts

| Term | Definition |
|------|------------|
| Infrastructure as Code | Practice of managing cloud infrastructure through declarative configuration files (Terraform, CloudFormation) rather than manual console operations |
| Policy as Code | Expressing security and compliance policies as executable code (Rego, Python) that can be automatically evaluated against infrastructure definitions |
| Shift Left Security | Moving security checks earlier in the development lifecycle by scanning IaC before Dağıt:ment rather than auditing after provisioning |
| Terraform Plan | Preview of changes Terraform will make, which can be exported as JSON for security scanning before applying changes |
| Checkov | Open-source static analysis tool for IaC supporting Terraform, CloudFormation, Kubernetes, and Docker with 1000+ built-in policies |
| OPA/Rego | Open Policy Agent and its policy language Rego for defining custom security rules that evaluate against structured data inputs |

## Tools & Systems

- **Checkov**: Comprehensive IaC scanner with 1000+ policies for Terraform, CloudFormation, Kubernetes, ARM, and Dockerfile
- **tfsec**: Terraform-specific static analysis tool with detailed remediation guidance and SARIF output
- **Terrascan**: Multi-IaC scanner supporting compliance frameworks (CIS, NIST, SOC 2) with policy-as-code
- **OPA/Conftest**: Custom policy engine for defining organization-specific security rules using Rego language
- **Bridgecrew**: Commercial platform built on Checkov providing drift Tespit and supply chain security

## Common Scenarios

### Scenario: Adding Security Gates to an Existing Terraform CI/CD Pipeline

**Context**: A DevOps team Dağıt:s infrastructure via Terraform in GitHub Actions but has no security scanning. Recent audit Bul:ings show multiple S3 buckets without encryption and security groups allowing SSH from the internet.

**Approach**:
1. Add Checkov as the first security gate in the GitHub Actions workflow
2. Run `checkov -d ./terraform/` to establish the current baseline of Bul:ings
3. Triage existing Bul:ings: fix CRITICAL issues, create tickets for HIGH, suppress accepted risks
4. Add tfsec as a secondary scanner for Terraform-specific checks
5. Write custom OPA policies for organization standards (required tags, naming conventions)
6. Şunu yapılandır: pipeline to block PRs with CRITICAL or HIGH Bul:ings
7. Generate SARIF reports for GitHub Security tab integration

**Pitfalls**: Adding security scanning to an existing project will initially produce hundreds of Bul:ings. Implement gradually by starting with CRITICAL-only blocking, then expanding to HIGH. Use inline suppression comments (`#checkov:skip=CKV_AWS_18:Public bucket for static website`) for intentional exceptions with documented justification.

## Output Format

```
Terraform Security Audit Report
==================================
Repository: acme-corp/infrastructure
Branch: main
Scan Date: 2026-02-23
Tools: Checkov 3.x, tfsec 1.x, OPA custom policies

SCAN RESULTS:
  Checkov checks passed:    187
  Checkov checks failed:     34
  tfsec checks passed:      156
  tfsec checks failed:       28
  OPA custom policies:       12 passed, 3 failed

CRITICAL Bul:INGS:
[TF-001] S3 Bucket Without Encryption
  File: modules/storage/main.tf:24
  Resource: aws_s3_bucket.data_lake
  Check: CKV_AWS_19
  Fix: Add server_side_encryption_configuration block

[TF-002] Security Group Allows SSH from 0.0.0.0/0
  File: modules/network/security.tf:45
  Resource: aws_security_group_rule.ssh_access
  Check: CKV_AWS_24
  Fix: Restrict cidr_blocks to bastion subnet

[TF-003] IAM Policy with Wildcard Actions
  File: modules/iam/policies.tf:12
  Resource: aws_iam_policy.developer_policy
  Check: CKV_AWS_1
  Fix: Scope actions to specific services required

SUMMARY BY SEVERITY:
  Critical:  6 Bul:ings
  High:     14 Bul:ings
  Medium:   28 Bul:ings
  Low:      18 Bul:ings
  Info:     12 Bul:ings
```
