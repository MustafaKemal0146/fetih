---
name: performing-cloud-incident-containment-procedures
description: Execute cloud-native incident containment across AWS, Azure, and GCP by isolating compromised resources, revoking credentials, preserving forensic evidence, and applying security group restrictions
  to prevent lateral movement.
tags:
- incident-response
- incident-containment
- azure
- cloud-forensics
- credential-revocation
- gcp
- aws
- fetih
- cloud-security
- cybersecurity
- network-isolation
- siber-güvenlik
triggers:
- IR
- api
- breach
- cloud
- containment
- email
- forensic
- güvenlik olayı
- hash
- http
- incident
- incident response
category: incident-response
source_subdomain: incident-response
mitre_attack:
- T1078
- T1537
- T1580
- T1525
- T1098
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
---

# Performing Cloud Incident Containment Procedures


## Genel Bakış

Cloud incident containment requires cloud-native approaches that differ significantly from traditional on-premises response. Containment procedures must leverage platform-specific controls including security groups, IAM policies, network ACLs, and service-level isolation to restrict compromised resources while preserving forensic evidence. According to the 2025 Unit 42 Global Incident Response Report, responding to cloud incidents requires understanding shared responsibility models, ephemeral infrastructure, and API-driven operations. Effective containment involves credential revocation, resource isolation, evidence snapshot creation, and automated response playbook execution.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing cloud incident containment procedures
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with incident response concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## AWS Containment Procedures

### 1. Credential Compromise Containment

```bash
aws iam update-access-key --user-name compromised-user \
  --access-key-id AKIA... --status Inactive

aws iam list-access-keys --user-name compromised-user
aws iam delete-access-key --user-name compromised-user --access-key-id AKIA...

aws iam put-user-policy --user-name compromised-user \
  --policy-name DenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

aws iam put-role-policy --role-name compromised-role \
  --policy-name RevokeOldSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
      }
    }]
  }'

aws iam update-assume-role-policy --role-name compromised-role \
  --policy-document '{"Version":"2012-10-17","Statement":[]}'
```

### 2. EC2 Instance Isolation

```bash
aws ec2 create-security-group --group-name quarantine-sg \
  --description "Quarantine - No traffic allowed" --vpc-id vpc-xxxxx

aws ec2 revoke-security-group-egress --group-id sg-quarantine \
  --ip-permissions '[{"IpProtocol":"-1","FromPort":-1,"ToPort":-1,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

aws ec2 create-snapshot --volume-id vol-xxxxx \
  --description "Forensic snapshot - IR Case 2025-001" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=IR-Case,Value=2025-001}]'

aws ec2 modify-instance-attribute --instance-id i-xxxxx \
  --groups sg-quarantine

aws ec2 create-tags --resources i-xxxxx \
  --tags Key=IR-Status,Value=Contained Key=IR-Case,Value=2025-001

aws ssm send-command --instance-ids i-xxxxx \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["dd if=/dev/mem of=/tmp/memory.dump bs=1M"]'
```

### 3. S3 Bucket Containment

```bash
aws s3api put-public-access-block --bucket compromised-bucket \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-bucket-policy --bucket compromised-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyAllExceptForensics",
      "Effect": "Deny",
      "NotPrincipal": {"AWS": "arn:aws:iam::ACCOUNT:role/IR-Forensics"},
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::compromised-bucket","arn:aws:s3:::compromised-bucket/*"]
    }]
  }'

aws s3api put-bucket-versioning --bucket compromised-bucket \
  --versioning-configuration Status=Enabled

aws s3api put-object-lock-configuration --bucket evidence-bucket \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 365}}
  }'
```

### 4. Lambda Function Containment

```bash
aws lambda put-function-concurrency --function-name compromised-function \
  --reserved-concurrent-executions 0

aws lambda list-event-source-mappings --function-name compromised-function
aws lambda delete-event-source-mapping --uuid mapping-uuid
```

## Azure Containment Procedures

### 1. Identity Containment

```powershell
Revoke-AzureADUserAllRefreshToken -ObjectId "user-object-id"

Set-AzureADUser -ObjectId "user-object-id" -AccountEnabled $false

Set-AzureADUserPassword -ObjectId "user-object-id" -Password (
  ConvertTo-SecureString "TempP@ss!" -AsPlainText -Force
) -ForceChangePasswordNextLogin $true


Remove-AzureADServiceAppRoleAssignment -ObjectId "sp-object-id" \
  -AppRoleAssignmentId "assignment-id"
```

### 2. VM Isolation

```powershell
$nsg = New-AzNetworkSecurityGroup -ResourceGroupName "rg" -Location "eastus" `
  -Name "quarantine-nsg" `
  -SecurityRules @(
    New-AzNetworkSecurityRuleConfig -Name "DenyAllInbound" -Protocol * `
      -Direction Inbound -Priority 100 -SourceAddressPrefix * `
      -SourcePortRange * -DestinationAddressPrefix * `
      -DestinationPortRange * -Access Deny,
    New-AzNetworkSecurityRuleConfig -Name "DenyAllOutbound" -Protocol * `
      -Direction Outbound -Priority 100 -SourceAddressPrefix * `
      -SourcePortRange * -DestinationAddressPrefix * `
      -DestinationPortRange * -Access Deny
  )

$vm = Get-AzVM -ResourceGroupName "rg" -Name "compromised-vm"
$snapshotConfig = New-AzSnapshotConfig -SourceUri $vm.StorageProfile.OsDisk.ManagedDisk.Id `
  -Location "eastus" -CreateOption Copy
New-AzSnapshot -ResourceGroupName "rg" -SnapshotName "forensic-snap" -Snapshot $snapshotConfig

$nic = Get-AzNetworkInterface -ResourceGroupName "rg" -Name "compromised-nic"
$nic.NetworkSecurityGroup = $nsg
Set-AzNetworkInterface -NetworkInterface $nic
```

### 3. Storage Account Containment

```powershell
Update-AzStorageAccountNetworkRuleSet -ResourceGroupName "rg" `
  -Name "storageaccount" -DefaultAction Deny

New-AzStorageAccountKey -ResourceGroupName "rg" -Name "storageaccount" -KeyName key1
New-AzStorageAccountKey -ResourceGroupName "rg" -Name "storageaccount" -KeyName key2

```

## GCP Containment Procedures

### 1. IAM Containment

```bash
gcloud projects get-iam-policy PROJECT_ID --format=json > policy.json
gcloud projects set-iam-policy PROJECT_ID policy.json

gcloud iam service-accounts disable SA_EMAIL

gcloud iam service-accounts keys list --iam-account SA_EMAIL
gcloud iam service-accounts keys delete KEY_ID --iam-account SA_EMAIL
```

### 2. Compute Instance Isolation

```bash
gcloud compute disks snapshot compromised-disk \
  --snapshot-names forensic-snap-$(date +%Y%m%d) \
  --zone us-central1-a

gcloud compute firewall-rules create quarantine-deny-all \
  --network default --action DENY --rules all \
  --target-tags quarantine --priority 0

gcloud compute instances add-tags compromised-instance \
  --tags quarantine --zone us-central1-a

gcloud compute instances delete-access-config compromised-instance \
  --access-config-name "External NAT" --zone us-central1-a
```

## Evidence Preservation Best Practices

1. **Always snapshot before containment** - Create disk/volume snapshots before network isolation
2. **Preserve CloudTrail/Activity Logs** - Copy logs to write-protected storage
3. **Document all actions** - Timestamp every containment step taken
4. **Use break-glass procedures** - Pre-establish emergency access for IR team
5. **Maintain forensic chain of custody** - Hash all evidence artifacts

## MITRE ATT&CK Cloud Techniques

| Technique | Containment Action |
|-----------|-------------------|
| T1078 - Valid Accounts | Disable accounts, revoke tokens |
| T1530 - Data from Cloud Storage | Lock down bucket/storage policies |
| T1537 - Transfer to Cloud Account | Block cross-account access |
| T1578 - Modify Cloud Compute | Isolate instances, snapshot disks |
| T1552 - Unsecured Credentials | Rotate all access keys and secrets |

## References

- [Sygnia: Cloud Incident Response Best Practices](https://www.sygnia.co/blog/incident-response-to-cloud-security-incidents-aws-azure-and-gcp-best-practices/)
- [Unit 42: Responding to Cloud Incidents](https://unit42.paloaltonetworks.com/responding-to-cloud-incidents/)
- [Wiz: Cloud Incident Response Checklist](https://www.wiz.io/academy/incident-response-checklist)
- [Microsoft Cloud Security Benchmark - IR](https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response)
