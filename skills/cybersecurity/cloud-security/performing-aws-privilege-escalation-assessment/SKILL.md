---
name: performing-aws-privilege-escalation-assessment
description: Performing authorized privilege escalation assessments in AWS environments to identify IAM misconfigurations that allow users or roles to elevate their permissions using Pacu, CloudFox, Principal
  Mapper, and manual IAM policy analysis techniques.
tags:
- pacu
- aws
- offensive-security
- privilege-escalation
- fetih
- cloud-security
- cybersecurity
- siber-güvenlik
- iam
triggers:
- AWS
- Azure
- GCP
- api
- assessment
- bulut güvenliği
- cloud
- cloud security
- endpoint
- escalation
- exploit
- log
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Performing Aws Privilege Escalation Assessment


## Ne Zaman Kullanılır

- conducting yaparken authorized penetration testing of AWS IAM configurations
- validating yaparken that IAM policies follow the principle of least privilege
- assessing yaparken the blast radius of a compromised AWS credential
- building yaparken security reviews for IAM role and policy changes in CI/CD pipelines
- evaluating yaparken: cross-account trust relationships for privilege escalation risks

**Kullanma:** for unauthorized testing against AWS accounts, for assessing non-IAM attack vectors (SSRF, application vulnerabilities), or as a substitute for comprehensive cloud penetration testing. Always obtain written authorization before testing.

## Ön Gereksinimler

- Written authorization for privilege escalation testing in the target AWS account
- Test IAM user or role with limited permissions as the starting point
- Pacu kurulu (`pip install pacu`)
- CloudFox kurulu (`go install github.com/BishopFox/cloudfox@latest`)
- PMapper (Principal Mapper) kurulu (`pip install principalmapper`)
- AWS CLI configured with test credentials and CloudTrail logging enabled for audit trail

## İş Akışı

### Adım 1: Enumerate Starting Permissions

Establish the baseline permissions of the test principal before attempting escalation.

```bash
aws sts get-caller-identity

aws iam list-user-policies --user-name test-user
aws iam list-attached-user-policies --user-name test-user

aws iam list-groups-for-user --user-name test-user
for group in $(aws iam list-groups-for-user --user-name test-user --query 'Groups[*].GroupName' --output text); do
  echo "=== Group: $group ==="
  aws iam list-group-policies --group-name "$group"
  aws iam list-attached-group-policies --group-name "$group"
done

aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:user/test-user \
  --action-names iam:CreateUser iam:AttachUserPolicy iam:PassRole \
    lambda:CreateFunction ec2:RunInstances sts:AssumeRole \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' --output table
```

### Adım 2: Scan for Privilege Escalation Paths with Pacu

Use Pacu's privilege escalation scanner to identify known IAM escalation techniques.

```bash
pacu

Pacu (new:session) > set_keys --key-alias privesc-test

Pacu > run iam__enum_users_roles_policies_groups
Pacu > run iam__enum_permissions

Pacu > run iam__privesc_scan

```

### Adım 3: Map Privilege Escalation Graphs with PMapper

Use Principal Mapper to build a graph of all IAM principals and identify escalation edges.

```bash
pmapper graph create --account ACCOUNT_ID

pmapper query 'who can do iam:AttachUserPolicy with * on *'
pmapper query 'who can do sts:AssumeRole with arn:aws:iam::ACCOUNT:role/AdminRole'

pmapper analysis

pmapper visualize --filetype png

pmapper query 'can arn:aws:iam::ACCOUNT:user/test-user do iam:CreatePolicyVersion with *'
pmapper query 'can arn:aws:iam::ACCOUNT:user/test-user do sts:AssumeRole with arn:aws:iam::ACCOUNT:role/*'
```

### Adım 4: Test Cross-Account Role Assumption

Evaluate cross-account trust policies for misconfigured role assumptions that allow unauthorized escalation.

```bash
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output text | while read name arn; do
  trust=$(aws iam get-role --role-name "$name" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
  # Check for wildcards or broad trust
  echo "$trust" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
for stmt in doc.get('Statement', []):
    principal = stmt.get('Principal', {})
    condition = stmt.get('Condition', {})
    if isinstance(principal, dict):
        aws_princ = principal.get('AWS', '')
    else:
        aws_princ = principal
    if '*' in str(aws_princ) or 'root' in str(aws_princ):
        has_external_id = 'sts:ExternalId' in str(condition)
        has_mfa = 'aws:MultiFactorAuthPresent' in str(condition)
        print(f'ROLE: $name')
        print(f'  Principal: {aws_princ}')
        print(f'  ExternalId required: {has_external_id}')
        print(f'  MFA required: {has_mfa}')
        if not has_external_id and not has_mfa:
            print(f'  WARNING: No ExternalId or MFA condition - confused deputy risk')
" 2>/dev/null
done

aws sts assume-role \
  --role-arn arn:aws:iam::TARGET_ACCOUNT:role/CrossAccountRole \
  --role-session-name privesc-test \
  --duration-seconds 900
```

### Adım 5: Enumerate CloudFox Attack Paths

Use CloudFox to identify additional attack surfaces including resource-based policies and service-specific escalation paths.

```bash
cloudfox aws --profile target-account all-checks -o ./cloudfox-output/

cloudfox aws --profile target-account permissions
cloudfox aws --profile target-account role-trusts
cloudfox aws --profile target-account access-keys
cloudfox aws --profile target-account env-vars  # Lambda environment variables with secrets
cloudfox aws --profile target-account instances  # EC2 with instance profiles
cloudfox aws --profile target-account endpoints  # Exposed services
```

### Adım 6: Document Bul:ings and Remediation

Compile all discovered escalation paths with proof-of-concept steps and remediation recommendations.

```bash
cat > privesc-report.md << 'EOF'

## Tested Escalation Vectors

| Vector | Status | Starting Principal | Escalated To | Risk |
|--------|--------|--------------------|--------------|------|
| iam:CreatePolicyVersion | EXPLOITABLE | test-user | AdministratorAccess | Critical |
| iam:PassRole + lambda:CreateFunction | EXPLOITABLE | dev-role | LambdaAdminRole | Critical |
| sts:AssumeRole (cross-account) | EXPLOITABLE | test-user | ProdAdminRole | High |
| iam:AttachUserPolicy | BLOCKED | test-user | N/A | N/A |
| ec2:RunInstances + iam:PassRole | BLOCKED | test-user | N/A | N/A |

## İyileştirme
1. Apply permission boundaries to all IAM users and roles
2. Remove iam:CreatePolicyVersion from non-admin principals
3. Add sts:ExternalId condition to all cross-account role trust policies
4. Implement SCP guardrails preventing privilege escalation actions
EOF
```

## Key Concepts

| Term | Definition |
|------|------------|
| IAM Privilege Escalation | Exploiting overly permissive IAM policies to gain higher-level access than originally granted to a principal |
| Permission Boundary | IAM policy that sets the maximum permissions a principal can have, regardless of identity-based policies attached to it |
| iam:PassRole | IAM action allowing a principal to pass an IAM role to an AWS service, enabling the service to act with that role's permissions |
| Confused Deputy | Attack where an attacker tricks a trusted service into performing actions on their behalf using cross-account role assumption without external ID validation |
| Service Control Policy | AWS Organizations policy that sets maximum permissions for member accounts, providing guardrails against privilege escalation |
| Principal Mapper | Open-source tool that models IAM principals and their escalation paths as a directed graph for analysis |

## Tools & Systems

- **Pacu**: AWS exploitation framework with 21+ privilege escalation modules for automated Tespit and exploitation
- **Principal Mapper**: Graph-based IAM analysis tool that maps escalation paths between principals
- **CloudFox**: AWS enumeration tool focused on identifying attack paths from an attacker's perspective
- **IAM Policy Simulator**: AWS-native tool for testing effective permissions against specific API actions
- **AWS Access Analyzer**: Service that identifies resource policies granting external access and validates IAM policy changes

## Common Scenarios

### Scenario: Developer Role with iam:CreatePolicyVersion Leads to Admin Access

**Context**: During an authorized assessment, a tester discovers that a developer role has the `iam:CreatePolicyVersion` permission, which allows creating a new version of any customer-managed policy with arbitrary permissions.

**Approach**:
1. Enumerate policies attached to the developer role using `iam__enum_permissions` in Pacu
2. Identify that the role can call `iam:CreatePolicyVersion` on its own attached policy
3. Şunu oluştur: new policy version with `"Action": "*", "Resource": "*", "Effect": "Allow"`
4. Set the new version as the default policy version
5. Verify admin access by calling `iam:ListUsers`, `s3:ListBuckets`, etc.
6. Şunu belgele: escalation chain and recommend removing `iam:CreatePolicyVersion` and implementing permission boundaries

**Pitfalls**: AWS limits managed policies to 5 versions. If all 5 exist, you must delete a version before creating a new one. Always record the original default version to restore it during cleanup. Permission boundaries prevent this escalation if properly configured, so verify boundary policies before declaring a Bul:ing.

## Output Format

```
AWS Privilege Escalation Assessment Report
=============================================
Account: 123456789012 (Production)
Assessment Date: 2026-02-23
Starting Principal: arn:aws:iam::123456789012:user/test-user
Starting Permissions: S3 read-only, Lambda invoke, EC2 describe
Authorization: Signed by CISO, engagement #PT-2026-014

ESCALATION PATHS DISCOVERED: 4

[PRIVESC-001] iam:CreatePolicyVersion -> Admin
  Severity: CRITICAL
  Starting Permission: iam:CreatePolicyVersion on policy/dev-policy
  Escalation: Created policy version 6 with Action:* Resource:*
  Time to Exploit: < 2 minutes
  Remediation: Remove iam:CreatePolicyVersion, apply permission boundary

[PRIVESC-002] iam:PassRole + lambda:CreateFunction -> LambdaAdminRole
  Severity: CRITICAL
  Starting Permission: iam:PassRole, lambda:CreateFunction
  Escalation: Created Lambda function with AdminRole, invoked to get admin credentials
  Time to Exploit: < 5 minutes
  Remediation: Restrict iam:PassRole to specific role ARNs with condition key

[PRIVESC-003] sts:AssumeRole -> Cross-Account Admin
  Severity: HIGH
  Starting Permission: sts:AssumeRole on arn:aws:iam::987654321098:role/SharedRole
  Escalation: Role trust policy allows any principal in source account
  Remediation: Add sts:ExternalId condition and restrict Principal to specific roles

TOTAL ESCALATION PATHS: 4 (2 Critical, 1 High, 1 Medium)
PERMISSION BOUNDARIES IN PLACE: 0 / 47 IAM principals
SCP GUARDRAILS BLOCKING ESCALATION: 0 / 3 tested vectors
```
