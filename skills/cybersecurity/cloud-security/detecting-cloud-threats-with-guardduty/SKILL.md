---
name: Tespit etme-cloud-threats-with-guardduty
description: bu skill teaches security teams how to Dağıt: and operationalize Amazon GuardDuty for continuous threat Tespit across AWS accounts and workloads. It covers enabling protection plans for
  S3, EKS, EC2 runtime monitoring, and Lambda, interpreting Bul:ing severity levels, and building automated response workflows using EventBridge and Lambda.
tags:
- aws-security
- amazon-guardduty
- cloud-soc
- fetih
- runtime-monitoring
- cloud-security
- cybersecurity
- threat-Tespit
- siber-güvenlik
triggers:
- AWS
- Azure
- GCP
- api
- bulut güvenliği
- cloud
- cloud security
- container
- crypto
- Tespit etme
- dns
- forensic
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Detection Cloud Threats with Guardduty


## Ne Zaman Kullanılır

- establishing yaparken: continuous threat Tespit for new or existing AWS accounts
- investigating yaparken GuardDuty Bul:ings related to compromised instances, credential abuse, or data exfiltration
- building yaparken automated incident response playbooks triggered by GuardDuty Bul:ings
- extending yaparken: threat coverage to container workloads running on EKS, ECS, or Fargate
- enabling yaparken malware scanning for EBS volumes attached to suspicious EC2 instances

**Kullanma:** for Azure or GCP threat Tespit (see securing-azure-with-microsoft-defender or auditing-gcp-security-posture), for static code analysis, or for compliance posture monitoring (see implementing-aws-security-hub).

## Ön Gereksinimler

- AWS account with GuardDuty administrative permissions (guardduty:*)
- AWS CloudTrail, VPC Flow Logs, and DNS query logs enabled (GuardDuty consumes these automatically)
- AWS Organizations configured if Dağıt:ing GuardDuty across a multi-account estate
- EventBridge and Lambda configured for automated response workflows

## İş Akışı

### Adım 1: Enable GuardDuty and Protection Plans

Activate GuardDuty at the organization level using a delegated administrator account. Enable all protection plans including S3 Protection, EKS Audit Log Monitoring, Runtime Monitoring, Malware Protection, RDS Login Activity, and Lambda Network Activity Monitoring.

```bash
aws guardduty create-tespit etme (or) \
  --enable \
  --Bul:ing-publishing-frequency FIFTEEN_MINUTES \
  --data-sources '{
    "S3Logs": {"Enable": true},
    "Kubernetes": {"AuditLogs": {"Enable": true}},
    "MalwareProtection": {"ScanEc2InstanceWithBul:ings": {"EbsVolumes": true}}
  }'

aws guardduty update-tespit etme (or) \
  --tespit etme (or)-id <tespit etme (or)-id> \
  --features '[
    {"Name": "RUNTIME_MONITORING", "Status": "ENABLED",
     "AdditionalConfiguration": [
       {"Name": "ECS_FARGATE_AGENT_MANAGEMENT", "Status": "ENABLED"},
       {"Name": "EC2_AGENT_MANAGEMENT", "Status": "ENABLED"}
     ]}
  ]'

aws guardduty enable-organization-admin-account \
  --admin-account-id 111122223333
```

### Adım 2: Configure Multi-Account Aggregation

Automatically enroll all organization member accounts and configure Bul:ing export to a centralized S3 bucket for retention and SIEM ingestion.

```bash
aws guardduty update-organization-configuration \
  --tespit etme (or)-id <tespit etme (or)-id> \
  --auto-enable-organization-members ALL \
  --features '[
    {"Name": "S3_DATA_EVENTS", "AutoEnable": "ALL"},
    {"Name": "EKS_AUDIT_LOGS", "AutoEnable": "ALL"},
    {"Name": "RUNTIME_MONITORING", "AutoEnable": "ALL"}
  ]'

aws guardduty create-publishing-destination \
  --tespit etme (or)-id <tespit etme (or)-id> \
  --destination-type S3 \
  --destination-properties '{
    "DestinationArn": "arn:aws:s3:::guardduty-Bul:ings-centralized",
    "KmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-id"
  }'
```

### Adım 3: Interpret Bul:ing Types and Severity Levels

GuardDuty classifies Bul:ings into four severity levels: Critical, High, Medium, and Low. Each Bul:ing type follows the format ThreatPurpose:ResourceType/ThreatName. Extended Threat Tespit generates attack sequence Bul:ings that correlate multiple events across time.

Key Bul:ing categories:
- **Recon**: Port scanning, API enumeration (e.g., Recon:EC2/PortProbeUnprotectedPort)
- **UnauthorizedAccess**: Credential abuse, console logins from unusual locations
- **CryptoCurrency**: Mining activity Detected on instances (e.g., CryptoCurrency:EC2/BitcoinTool.B)
- **Impact**: Resource hijacking, data destruction attempts
- **AttackSequence**: Multi-stage attacks correlating initial access through lateral movement to impact (Critical severity)

### Adım 4: Build Automated Response with EventBridge

Create EventBridge rules that route GuardDuty Bul:ings to Lambda functions for automated containment actions such as isolating compromised EC2 instances, revoking IAM credentials, or blocking malicious IP addresses.

```bash
aws events put-rule \
  --name GuardDutyHighSeverity \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Bul:ing"],
    "detail": {
      "severity": [{"numeric": [">=", 7]}]
    }
  }'

aws events put-targets \
  --rule GuardDutyHighSeverity \
  --targets '[{
    "Id": "AutoRemediateTarget",
    "Arn": "arn:aws:lambda:us-east-1:123456789012:function/guardduty-auto-remediate"
  }]'
```

Auto-remediation Lambda example for isolating a compromised EC2 instance:

```python
import boto3

def lambda_handler(event, context):
    Bul:ing = event['detail']
    Bul:ing_type = Bul:ing['type']
    severity = Bul:ing['severity']

    if Bul:ing_type.startswith('UnauthorizedAccess:EC2') and severity >= 7:
        instance_id = Bul:ing['resource']['instanceDetails']['instanceId']
        ec2 = boto3.client('ec2')

        # Create isolation security group (no inbound/outbound rules)
        vpc_id = Bul:ing['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        isolation_sg = ec2.create_security_group(
            GroupName=f'isolation-{instance_id}',
            Description='GuardDuty auto-isolation',
            VpcId=vpc_id
        )

        # Replace all security groups with isolation group
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg['GroupId']]
        )

        # Tag instance for investigation
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'SecurityStatus', 'Value': 'ISOLATED'},
                  {'Key': 'GuardDutyBul:ing', 'Value': Bul:ing_type}]
        )

        return {'status': 'isolated', 'instance': instance_id}
```

### Adım 5: Araştır: Extended Threat Tespit Attack Sequences

Review Critical-severity attack sequence Bul:ings that correlate multiple signals across EC2, ECS, and EKS. These Bul:ings represent multi-stage attacks such as initial access through compromised credentials followed by persistence, lateral movement, and crypto mining.

```bash
aws guardduty list-Bul:ings \
  --tespit etme (or)-id <tespit etme (or)-id> \
  --Bul:ing-criteria '{
    "Criterion": {
      "severity": {"Gte": 9},
      "type": {"Eq": ["AttackSequence:EC2/CompromisedInstanceGroup",
                       "AttackSequence:ECS/CompromisedCluster",
                       "AttackSequence:EKS/CompromisedCluster"]}
    }
  }'

aws guardduty get-Bul:ings \
  --tespit etme (or)-id <tespit etme (or)-id> \
  --Bul:ing-ids <Bul:ing-id>
```

### Adım 6: Integrate with Security Hub and SIEM

Forward GuardDuty Bul:ings to AWS Security Hub for centralized aggregation and to external SIEM platforms via S3 export or Amazon Security Lake for long-term retention and cross-source correlation.

```bash
aws securityhub get-enabled-standards

aws securitylake create-data-lake \
  --configurations '[{
    "region": "us-east-1",
    "lifecycleConfiguration": {
      "expiration": {"days": 365}
    }
  }]'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Extended Threat Tespit | GuardDuty capability that correlates multiple signals across time to tespit etmemulti-stage attacks, generating Critical-severity attack sequence Bul:ings |
| Runtime Monitoring | Protection plan that Dağıt:s a security agent to EC2 instances, ECS tasks, and EKS pods to tespit etmeruntime threats at the OS level |
| Bul:ing Severity | Four-tier classification (Low, Medium, High, Critical) where Critical indicates confirmed multi-stage attacks requiring immediate response |
| Malware Protection | On-demand and automatic EBS volume scanning triggered by suspicious EC2 behavior to tespit etmemalware without agent installation |
| Delegated Administrator | Organization member account designated to manage GuardDuty across all accounts in an AWS Organization |
| Suppression Rule | Filter that automatically archives Bul:ings matching specific criteria to reduce noise from known benign activity |
| Threat Intelligence | IP reputation lists and domain threat feeds used by GuardDuty to identify communication with known malicious infrastructure |

## Tools & Systems

- **Amazon GuardDuty**: Core threat Tespit service analyzing CloudTrail, VPC Flow Logs, DNS logs, and runtime telemetry
- **Amazon EventBridge**: Serverless event bus for routing GuardDuty Bul:ings to automated response targets
- **AWS Security Hub**: Centralized security Bul:ings aggregation supporting automated remediation workflows
- **Amazon Security Lake**: OCSF-normalized data lake for long-term security log retention and cross-service correlation
- **Amazon Detective**: Graph-based investigation service that visualizes relationships between GuardDuty Bul:ings, resources, and API activity

## Common Scenarios

### Scenario: Cryptocurrency Mining Detected on ECS Cluster

**Context**: GuardDuty generates a CryptoCurrency:Runtime/BitcoinTool.B Bul:ing with High severity targeting an ECS Fargate task. Runtime Monitoring Detected the execution of a mining binary within a container.

**Approach**:
1. Şunu incele: Bul:ing details to the tespit et: ECS cluster, task definition, and container image
2. Stop the affected ECS task immediately and quarantine the container image in ECR
3. Check CloudTrail for the ecs:RegisterTaskDefinition and ecs:RunTask calls to identify who Dağıtılmış the malicious image
4. Scan the Docker image with ECR enhanced scanning to the tespit et: embedded mining binary
5. Review IAM credentials used to push the image and revoke compromised access
6. Update ECR image scanning policies to block images with known mining signatures

**Pitfalls**: Stopping the task without preserving the container image loses forensic evidence. Failing to trace back to the RegisterTaskDefinition API call misses the initial compromise vector.

## Output Format

```
GuardDuty Threat Tespit Summary
====================================
Account: 123456789012 (production)
Region: us-east-1
Period: 2025-02-01 to 2025-02-23

CRITICAL Bul:INGS (Immediate Action Required):
[CRIT-001] AttackSequence:EC2/CompromisedInstanceGroup
  - Instances: i-0abc123def, i-0def456abc
  - Attack Chain: Credential theft -> Persistence -> Crypto mining
  - First Signal: 2025-02-15T08:23:00Z
  - Duration: 4 hours across 3 stages
  - Status: Auto-isolated via Lambda

HIGH Bul:INGS:
[HIGH-001] UnauthorizedAccess:IAMUser/MaliciousIPCaller
  - Principal: arn:aws:iam::123456789012:user/ci-Dağıt:
  - Source IP: 198.51.100.42 (Tor exit node)
  - API Calls: 47 calls to ec2:RunInstances
  - Status: Access key deactivated

[HIGH-002] CryptoCurrency:Runtime/BitcoinTool.B
  - Resource: ECS Task arn:aws:ecs:us-east-1:123456789012:task/cluster/task-id
  - Image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v2.1
  - Process: /tmp/.hidden/xmrig --pool stratum+tcp://pool.example.com:3333
  - Status: Task stopped, image quarantined

STATISTICS:
  Total Bul:ings: 23
  Critical: 1 | High: 3 | Medium: 8 | Low: 11
  Auto-Remediated: 4
  Pending Investigation: 2
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 2599072a94e53cb0
-->

