---
name: Tespit etme-aws-iam-privilege-escalation
description: tespit etmeAWS IAM privilege escalation paths using boto3 and Cloudsplaining policy analysis to identify overly permissive policies, dangerous permission combinations, and least-privilege violations
tags:
- boto3
- least-privilege
- aws
- fetih
- privilege-escalation
- cloudsplaining
- cloud-security
- cybersecurity
- policy-analysis
- siber-güvenlik
- iam
triggers:
- AWS
- Azure
- GCP
- bulut güvenliği
- cloud
- cloud security
- Tespit etme
- escalation
- incident
- privilege
- threat
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Detection Aws Iam Privilege Escalation


## Genel Bakış

bu skill uses boto3 and Cloudsplaining-style analysis to identify IAM privilege escalation paths in AWS accounts. It downloads the account authorization details, analyzes each policy for dangerous permission combinations (iam:PassRole + lambda:CreateFunction, iam:CreatePolicyVersion, sts:AssumeRole), and flags policies that violate least-privilege principles.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme aws iam privilege escalation
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Python 3.8+ with boto3 library
- AWS credentials with IAM read-only access (iam:GetAccountAuthorizationDetails)
- Optional: cloudsplaining Python package for HTML report generation

## Adımlar

1. **Download IAM Authorization Details** — Call iam:GetAccountAuthorizationDetails to retrieve all users, groups, roles, and policies
2. **Analyze Policies for Privilege Escalation** — Check each policy for known escalation permission combinations
3. **Identify Wildcard Resource Policies** — Flag policies using Resource: "*" with dangerous actions
4. **Map Principal-to-Policy Relationships** — Build a graph of which principals can access which escalation paths
5. **Score and Prioritize Bul:ings** — Rank Bul:ings by severity based on escalation vector type
6. **Generate Report** — Produce structured JSON report with remediation guidance

## Expected Output

- JSON report of privilege escalation Bul:ings with severity scores
- List of dangerous permission combinations per principal
- Wildcard resource policy audit results
- Remediation recommendations for each Bul:ing

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 1aaa085f2a2fef48
-->

