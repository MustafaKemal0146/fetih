---
name: conducting-cloud-incident-response
description: Responds to security incidents in cloud environments (AWS, Azure, GCP) by performing identity-based containment, cloud-native log analysis, resource isolation, and forensic evidence acquisition
  adapted for ephemeral cloud infrastructure. Activates for requests involving cloud incident response, AWS security incident, Azure compromise, GCP breach, cloud forensics, or cloud identity compromise.
tags:
- cloud-IR
- identity-containment
- AWS-forensics
- incident-response
- GCP-security
- fetih
- cybersecurity
- siber-güvenlik
- Azure-incident-response
triggers:
- IR
- alert
- api
- breach
- cloud
- conducting
- container
- crypto
- forensic
- güvenlik olayı
- incident
- incident response
category: incident-response
source_subdomain: incident-response
mitre_attack:
- T1078
- T1537
- T1580
- T1525
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
adapted_for: fetih
---

# Conducting Cloud Incident Response


## Ne Zaman Kullanılır

- Cloud security posture management (CSPM) alerts on unauthorized resource changes
- CloudTrail, Azure Activity Logs, or GCP Audit Logs show suspicious API calls
- Cloud access keys or service principal credentials are suspected compromised
- Unauthorized compute instances, storage buckets, or IAM changes are Detected
- A cloud-hosted application is breached and attacker activity spans cloud services

**Kullanma:** for on-premises-only incidents with no cloud component; use standard enterprise IR procedures.

## Ön Gereksinimler

- Cloud-native logging enabled and centralized: AWS CloudTrail (all regions), Azure Activity/Sign-in Logs, GCP Cloud Audit Logs
- IR-specific cloud IAM roles pre-provisioned with read-only forensic access
- Isolated forensic account/subscription/project for evidence preservation
- Cloud incident response runbooks specific to each cloud provider
- Cloud-native security tools: AWS GuardDuty, Azure Defender for Cloud, GCP Security Command Center
- Network traffic logging: VPC Flow Logs (AWS/GCP), NSG Flow Logs (Azure)

## İş Akışı

### Adım 1: tespit etmeand Confirm the Cloud Incident

the tespit et: scope and nature of the compromise:

**AWS Indicators:**
```
CloudTrail suspicious events to Araştır::
- ConsoleLogin from unexpected geolocation or IP
- CreateAccessKey for existing IAM user (persistence)
- RunInstances for crypto-mining (large instance types)
- PutBucketPolicy making S3 bucket public
- AssumeRole to cross-account roles
- DeleteTrail or StopLogging (defense evasion)
- CreateUser or AttachUserPolicy (privilege escalation)
```

**Azure Indicators:**
```
Azure Activity Log events to Araştır::
- Sign-in from anonymous IP or TOR exit node
- Service principal credential added
- Role assignment changes (Owner, Contributor added)
- VM created in unusual region
- Storage account access key regenerated
- Conditional Access policy modified or deleted
- MFA disabled for user account
```

**GCP Indicators:**
```
GCP Audit Log events to Araştır::
- SetIamPolicy changes granting broad access
- CreateServiceAccountKey for existing SA
- InsertInstance in unexpected zone
- SetBucketIamPolicy with allUsers
- DeleteLog or UpdateSink (log tampering)
```

### Adım 2: Contain Cloud Identity Compromise

Cloud containment is primarily an identity operation:

**AWS Containment:**
```bash
aws iam update-access-key --user-name compromised-user \
  --access-key-id AKIA... --status Inactive

aws iam attach-user-policy --user-name compromised-user \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll

aws iam put-role-policy --role-name compromised-role \
  --policy-name RevokeOlderSessions --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":"*",
      "Resource":"*",
      "Condition":{"DateLessThan":
        {"aws:TokenIssueTime":"2025-11-15T15:00:00Z"}}
    }]
  }'

aws ec2 modify-instance-attribute --instance-id i-0abc123 \
  --groups sg-isolate-forensic
```

**Azure Containment:**
```powershell
Set-AzureADUser -ObjectId "user@tenant.onmicrosoft.com" -AccountEnabled $false

Revoke-AzureADUserAllRefreshToken -ObjectId "user-object-id"

Remove-AzRoleAssignment -ObjectId "sp-object-id" -RoleDefinitionName "Contributor"

$nsg = New-AzNetworkSecurityGroup -Name "isolate-nsg" -ResourceGroupName "rg" -Location "eastus"
$nsg | Add-AzNetworkSecurityRuleConfig -Name "DenyAll" -Priority 100 -Direction Inbound `
  -Access Deny -Protocol * -SourceAddressPrefix * -SourcePortRange * `
  -DestinationAddressPrefix * -DestinationPortRange *
```

### Adım 3: Preserve Cloud Evidence

Collect evidence before ephemeral resources are terminated or logs rotate:

**AWS Evidence Collection:**
- Export CloudTrail events to S3 in the forensic account
- Snapshot EBS volumes of compromised EC2 instances
- Copy S3 access logs and object versions
- Export VPC Flow Logs for the affected VPC
- Capture IAM credential reports and access advisor data

**Azure Evidence Collection:**
- Export Azure Activity Logs and Sign-in Logs (90-day retention by default)
- Snapshot managed disks of compromised VMs
- Export Azure AD audit logs
- Capture NSG flow logs
- Export Conditional Access sign-in details

**GCP Evidence Collection:**
- Export Cloud Audit Logs to a forensic storage bucket
- Snapshot persistent disks of compromised VMs
- Export VPC Flow Logs
- Capture IAM policy snapshots

### Adım 4: Araştır: Cloud-Specific Attack Patterns

Analyze logs for common cloud attack techniques:

```
Common Cloud Attack Patterns:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Credential Compromise → IAM Privilege Escalation → Resource Abuse
2. Public S3/Blob → Data Exfiltration
3. SSRF from Web App → IMDS Token Theft → Lateral Movement
4. Compromised CI/CD Pipeline → Malicious Dağıt:ment
5. Cross-Account Role Abuse → Multi-Account Pivot
6. Lambda/Function Abuse → Crypto-mining or Data Processing
```

**IMDS Token Theft Investigation (AWS):**
```bash
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventSource,AttributeValue=ec2.amazonaws.com \
  --start-time 2025-11-14 --end-time 2025-11-16 \
  | jq '.Events[] | select(.CloudTrailEvent | fromjson | .sourceIPAddress != "internal")'
```

### Adım 5: Eradicate and Recover

Remove adversary access and restore secure state:

- Rotate all compromised credentials (access keys, passwords, service principal secrets)
- Remove unauthorized IAM users, roles, policies, and access keys created by the attacker
- Terminate unauthorized compute instances (crypto-miners, C2 servers)
- Restore modified S3 bucket policies and storage access policies to pre-incident state
- Re-enable security controls that were disabled (CloudTrail, GuardDuty, Defender for Cloud)
- Review and restore Conditional Access policies and MFA configurations

### Adım 6: Post-Incident Cloud Hardening

Implement controls to prevent recurrence:

- Enable MFA for all IAM users and require MFA for sensitive API calls
- Implement SCPs (AWS) or Azure Policy to prevent logging disablement
- Enable GuardDuty / Defender for Cloud / Security Command Center with auto-remediation
- Implement least-privilege IAM policies using access analyzer data
- Enable IMDS v2 (token-required) on all EC2 instances to prevent SSRF-based token theft
- Configure budget alerts to tespit etmecrypto-mining cost spikes

## Key Concepts

| Term | Definition |
|------|------------|
| **IMDS (Instance Metadata Service)** | Cloud service providing instance credentials accessible from within a VM; SSRF attacks target IMDS to steal tokens |
| **CloudTrail** | AWS service logging all API calls across the AWS account; primary evidence source for AWS incident response |
| **Service Principal** | Non-human identity in Azure AD used by applications and services; compromise enables persistent API access |
| **SCP (Service Control Policy)** | AWS Organizations policy that limits the maximum permissions available to accounts; useful for guardrails |
| **Ephemeral Infrastructure** | Cloud resources (containers, functions, auto-scaled instances) that may be terminated before evidence can be collected |
| **Cross-Account Role Assumption** | AWS mechanism allowing one account to temporarily access resources in another; attackers pivot through assumed roles |

## Tools & Systems

- **AWS CloudTrail / Azure Activity Logs / GCP Audit Logs**: Cloud-native API logging services providing the primary audit trail
- **Cado Response**: Cloud-native forensics platform for automated evidence capture from AWS, Azure, and GCP
- **Prowler (AWS) / ScoutSuite (multi-cloud)**: Open-source cloud security assessment tools for post-incident posture review
- **Steampipe**: Open-source SQL-based tool for querying cloud APIs to Araştır: IAM configurations and resource states
- **Cartography (Lyft)**: Open-source tool for mapping cloud infrastructure relationships and identifying attack paths

## Common Scenarios

### Scenario: AWS Access Key Compromised via Public GitHub Repository

**Context**: AWS GuardDuty alerts on API calls from an unexpected IP address using an IAM user's access key. The key was accidentally committed to a public GitHub repository 4 hours ago.

**Approach**:
1. Immediately disable the compromised access key via AWS IAM
2. Attach AWSDenyAll policy to the affected IAM user
3. Query CloudTrail for all API calls made with the compromised key since exposure
4. Identify resources created or modified by the attacker (EC2 instances for crypto-mining, new IAM users for persistence)
5. Terminate unauthorized resources and remove backdoor IAM entities
6. Rotate all credentials the compromised user had access to
7. Enable GitHub secret scanning to prevent future credential leaks

**Pitfalls**:
- Only disabling the access key without checking for new access keys or IAM users created as persistence
- Not checking all AWS regions for attacker-created resources (crypto-miners Dağıtılmış in every region)
- Forgetting to revoke temporary credentials from assumed roles (STS tokens remain valid until expiry)
- Not calculating the financial impact of unauthorized resource usage for insurance claims

## Output Format

```
CLOUD INCIDENT RESPONSE REPORT
================================
Incident:          INC-2025-1705
Cloud Provider:    AWS (Account: 123456789012)
Date Detected:     2025-11-15T14:00:00Z
Tespit Source:  GuardDuty - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration

COMPROMISE SUMMARY
Initial Access:    IAM access key exposed in public GitHub repo
Affected Identity: iam-user: Dağıt:-bot (AKIA...)
Attacker IP:       203.0.113.42 (VPN exit node, Netherlands)
Duration:          4 hours (10:00 UTC - 14:00 UTC)

ATTACKER ACTIVITY (from CloudTrail)
10:15 UTC - DescribeInstances (reconnaissance)
10:18 UTC - RunInstances x 12 (c5.4xlarge, all regions - crypto-mining)
10:22 UTC - CreateUser "backup-admin" (persistence)
10:23 UTC - CreateAccessKey for "backup-admin"
10:25 UTC - AttachUserPolicy - AdministratorErişim: "backup-admin"
10:30 UTC - PutBucketPolicy - s3://data-bucket made public (exfiltration)

CONTAINMENT ACTIONS
[x] Original access key disabled
[x] User policy set to AWSDenyAll
[x] Backdoor IAM user "backup-admin" deleted
[x] 12 crypto-mining instances terminated (all regions)
[x] S3 bucket policy restored to private

FINANCIAL IMPACT
Unauthorized EC2: $2,847 (4 hours x 12 x c5.4xlarge)
Data Transfer:    $127 (S3 public access data egress)
Total:            $2,974

POST-INCIDENT HARDENING
1. GitHub secret scanning enabled
2. Access key rotation policy implemented
3. SCP preventing CloudTrail disablement Dağıtılmış
4. GuardDuty auto-remediation Lambda configured
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 2c10c1a236a313e5
-->

