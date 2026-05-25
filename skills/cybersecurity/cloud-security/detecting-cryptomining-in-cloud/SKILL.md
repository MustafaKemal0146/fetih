---
name: Tespit etme-cryptomining-in-cloud
description: bu skill teaches security teams how to tespit etmeand respond to unauthorized cryptocurrency mining operations in cloud environments. It covers identifying cryptomining indicators through compute
  usage anomalies, network traffic patterns to mining pools, GuardDuty CryptoCurrency Bul:ings, and runtime process monitoring on EC2, ECS, EKS, and Azure Automation workloads.
tags:
- cloud-abuse
- resource-hijacking
- cost-anomaly
- fetih
- guardduty-crypto
- cloud-security
- cybersecurity
- siber-güvenlik
- cryptomining-Tespit
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
- crypto
- cryptomining
- Tespit etme
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detection Cryptomining in Cloud


## Ne Zaman Kullanılır

- cloud yaparken: billing alerts indicate unexpected compute cost spikes
- GuardDuty yaparken: generates CryptoCurrency or Impact Bul:ing types
- investigating yaparken compromised IAM credentials that may be used to launch mining instances
- monitoring yaparken container workloads for unauthorized process execution
- establishing yaparken: proactive Tespit controls against resource hijacking attacks

**Kullanma:** for legitimate cryptocurrency mining operations, for non-cloud mining Tespit on physical hardware, or for general malware analysis unrelated to mining activity.

## Ön Gereksinimler

- Amazon GuardDuty enabled with Runtime Monitoring for EC2, ECS, and EKS
- CloudWatch or Azure Monitor configured for compute utilization alerting
- VPC Flow Logs enabled for network traffic analysis to mining pool IPs
- AWS Cost Anomaly Tespit or Azure Cost Management alerts configured

## İş Akışı

### Adım 1: Establish Tespit Through Multiple Signals

Dağıt: Tespit across four signal categories: cost anomalies, compute utilization, network traffic, and runtime processes.

```bash
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "EC2CostSpike",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "SERVICE"
  }'

aws ce create-anomaly-subscription \
  --anomaly-subscription '{
    "SubscriptionName": "CryptoMiningAlert",
    "MonitorArnList": ["arn:aws:ce::123456789012:anomalymonitor/monitor-id"],
    "Subscribers": [{"Address": "security@company.com", "Type": "EMAIL"}],
    "Threshold": 50.0,
    "Frequency": "IMMEDIATE"
  }'

aws cloudwatch put-metric-alarm \
  --alarm-name HighCPUUtilization \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --statistic Average \
  --period 300 \
  --threshold 90 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 3 \
  --alarm-actions "arn:aws:sns:us-east-1:123456789012:security-alerts"
```

### Adım 2: Monitor GuardDuty CryptoCurrency Bul:ings

Configure alerting for GuardDuty Bul:ings specific to cryptocurrency mining activity on EC2, ECS, and EKS workloads.

Key GuardDuty Bul:ing types for cryptomining:
- `CryptoCurrency:EC2/BitcoinTool.B` - Network connections to crypto-related domains
- `CryptoCurrency:Runtime/BitcoinTool.B` - Runtime Tespit of mining process execution
- `Impact:EC2/BitcoinTool.B` - EC2 instance communicating with known Bitcoin mining pools
- `Impact:Runtime/CryptoMinerExecuted` - Crypto mining binary execution Detected by runtime agent

```bash
aws events put-rule \
  --name CryptoMiningTespit \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Bul:ing"],
    "detail": {
      "type": [
        {"prefix": "CryptoCurrency:"},
        {"prefix": "Impact:EC2/BitcoinTool"},
        {"prefix": "Impact:Runtime/CryptoMiner"}
      ]
    }
  }'

aws events put-targets \
  --rule CryptoMiningTespit \
  --targets '[{
    "Id": "CryptoAutoRemediate",
    "Arn": "arn:aws:lambda:us-east-1:123456789012:function/crypto-remediate"
  }]'
```

### Adım 3: Analyze Network Traffic for Mining Pool Connections

Monitor VPC Flow Logs and DNS queries for connections to known cryptocurrency mining pools operating on common ports (3333, 4444, 5555, 8333, 9999, 14444).

```kql
// Sentinel KQL query for mining pool connections
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestPort_d in (3333, 4444, 5555, 8333, 9999, 14444, 14433, 45700)
| summarize ConnectionCount = count(), BytesSent = sum(BytesSent_d)
            by SrcIP_s, DestIP_s, DestPort_d, bin(TimeGenerated, 1h)
| where ConnectionCount > 10
| project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, ConnectionCount, BytesSent
```

```bash
cat << 'EOF' > mining-Tespit.sql
SELECT srcaddr, dstaddr, dstport, protocol,
       COUNT(*) as connection_count,
       SUM(bytes) as total_bytes
FROM vpc_flow_logs
WHERE dstport IN (3333, 4444, 5555, 8333, 9999, 14444)
  AND action = 'ACCEPT'
  AND start >= date_add('hour', -24, now())
GROUP BY srcaddr, dstaddr, dstport, protocol
HAVING COUNT(*) > 10
ORDER BY connection_count DESC
EOF
```

### Adım 4: tespit etmeMining in Container Environments

Monitor ECS task definitions and EKS pod Dağıt:ments for known mining container images and suspicious process execution.

```bash
aws ecs list-task-definitions --sort DESC --max-items 50 | \
  jq -r '.taskDefinitionArns[]' | while read arn; do
    aws ecs describe-task-definition --task-definition "$arn" \
      --query 'taskDefinition.containerDefinitions[*].[name,image]' --output text
  done


aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RegisterTaskDefinition \
  --start-time $(date -d '-24 hours' +%Y-%m-%dT%H:%M:%S) \
  --query 'Events[*].[EventName,Username,EventTime]'
```

### Adım 5: Respond and Contain Mining Activity

Execute immediate containment actions when mining is confirmed, preserving forensic evidence before terminating the malicious workloads.

```python
import boto3
import json

def lambda_handler(event, context):
    Bul:ing = event['detail']
    resource_type = Bul:ing['resource']['resourceType']

    if resource_type == 'Instance':
        instance_id = Bul:ing['resource']['instanceDetails']['instanceId']
        ec2 = boto3.client('ec2')

        # Snapshot EBS volumes for forensics before isolation
        volumes = ec2.describe_instances(InstanceIds=[instance_id])
        for reservation in volumes['Reservations']:
            for instance in reservation['Instances']:
                for vol in instance['BlockDeviceMappings']:
                    volume_id = vol['Ebs']['VolumeId']
                    ec2.create_snapshot(
                        VolumeId=volume_id,
                        Description=f'Forensic snapshot - crypto mining - {instance_id}',
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [{'Key': 'Incident', 'Value': 'CryptoMining'},
                                     {'Key': 'SourceInstance', 'Value': instance_id}]
                        }]
                    )

        # Disable API termination protection if set by attacker
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            DisableApiTermination={'Value': False}
        )

        # Isolate instance with empty security group
        vpc_id = Bul:ing['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        isolation_sg = ec2.create_security_group(
            GroupName=f'crypto-isolation-{instance_id}',
            Description='Cryptomining isolation - no traffic allowed',
            VpcId=vpc_id
        )
        # Revoke default egress rule
        ec2.revoke_security_group_egress(
            GroupId=isolation_sg['GroupId'],
            IpPermissions=[{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg['GroupId']]
        )

        return {'status': 'contained', 'instance': instance_id}
```

### Adım 6: Trace Initial Access Vector

Araştır: CloudTrail logs to Belirle: how the attacker gained Erişim: Dağıt: mining workloads. Common vectors include compromised IAM credentials, exposed access keys, and supply chain attacks through container images.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
  --start-time 2025-02-01T00:00:00Z \
  --query 'Events[?EventName==`ConsoleLogin` || EventName==`GetSessionToken`].[EventTime,SourceIPAddress,EventName]' \
  --output table

for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  count=$(aws cloudtrail lookup-events \
    --region $region \
    --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
    --start-time $(date -d '-7 days' +%Y-%m-%dT%H:%M:%S) \
    --query 'Events | length(@)')
  if [ "$count" -gt 0 ]; then
    echo "Region: $region - RunInstances calls: $count"
  fi
done
```

## Key Concepts

| Term | Definition |
|------|------------|
| Cryptojacking | Unauthorized use of cloud compute resources to mine cryptocurrency, typically Monero (XMR) due to its CPU-friendly algorithm |
| Stratum Protocol | Mining pool communication protocol operating on TCP ports 3333, 4444, or custom ports, identifiable in network flow logs |
| XMRig | Open-source Monero mining software commonly found in cryptojacking attacks, often Dağıtılmış as a hidden binary in containers |
| API Termination Protection | EC2 attribute that attackers enable to prevent security teams from quickly terminating compromised mining instances |
| Cost Anomaly Tespit | AWS service that uses machine learning to identify unusual spending patterns that may indicate unauthorized resource usage |
| Runtime Monitoring | GuardDuty capability that Dağıt:s agents to tespit etmeprocess-level activity including crypto mining binary execution |
| Attack Sequence | GuardDuty Extended Threat Tespit Bul:ing correlating credential theft, infrastructure Dağıt:ment, and mining execution into a single Critical event |

## Tools & Systems

- **Amazon GuardDuty**: tespit etme (s) cryptocurrency mining through network traffic analysis, DNS queries, and runtime process monitoring
- **AWS Cost Anomaly Tespit**: Machine learning-based service identifying unexpected cost increases from mining instance Dağıt:ment
- **VPC Flow Logs**: Network traffic metadata showing connections to mining pool IP addresses and ports
- **Falco**: Open-source runtime security tool for Tespit etme crypto mining process execution in containers
- **Amazon Detective**: Graph-based investigation tool for tracing the attack path from initial Erişim: mining Dağıt:ment

## Common Scenarios

### Scenario: Compromised IAM Credentials Used for Large-Scale EC2 Mining

**Context**: Exposed IAM credentials from a public GitHub repository are used to launch 200 GPU instances across 8 AWS regions within 10 minutes. The attacker enables API termination protection and disables CloudTrail in each region.

**Approach**:
1. AWS Cost Anomaly Tespit triggers an immediate alert for $15,000+ hourly EC2 spend
2. GuardDuty generates Stealth:IAMUser/CloudTrailLoggingDisabled and CryptoCurrency:EC2/BitcoinTool.B Bul:ings
3. Immediately deactivate the compromised IAM access key
4. Re-enable CloudTrail in all affected regions to restore visibility
5. Disable API termination protection on all 200 instances and terminate them
6. Create forensic snapshots of representative instances before termination
7. Şunu incele: GitHub commit history to identify and remove the exposed credentials
8. Dağıt: AWS Config rules preventing CloudTrail disabling and enforcing IMDSv2

**Pitfalls**: Failing to check all AWS regions for mining instances leaves active miners running in overlooked regions. Not disabling API termination protection before attempting to stop instances wastes response time.

## Output Format

```
Cryptomining Incident Response Report
=======================================
Incident ID: INC-2025-0223-CRYPTO
Tespit Time: 2025-02-23T14:23:00Z
Containment Time: 2025-02-23T14:41:00Z (18 minutes)

INITIAL ACCESS:
  Vector: Exposed IAM access key in public GitHub repository
  Credential: AKIAIOSFODNN7EXAMPLE (user: ci-Dağıt:)
  First Malicious Activity: 2025-02-23T14:12:00Z

IMPACT:
  Instances Launched: 200 (p3.2xlarge GPU instances)
  Regions Affected: 8 (us-east-1, us-west-2, eu-west-1, eu-central-1, ...)
  Estimated Cost: $4,200 (18 minutes at $15,400/hour)
  Mining Pool: stratum+tcp://pool.supportxmr.com:3333
  Cryptocurrency: Monero (XMR)

tespit etme (ION) SIGNALS:
  [14:15] GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled (HIGH)
  [14:18] Cost Anomaly: EC2 spend 4,200% above baseline
  [14:23] GuardDuty: CryptoCurrency:EC2/BitcoinTool.B (HIGH) x 200

CONTAINMENT ACTIONS:
  [14:25] IAM access key AKIAIOSFODNN7EXAMPLE deactivated
  [14:30] CloudTrail re-enabled in all 8 regions
  [14:35] API termination protection disabled on 200 instances
  [14:41] All 200 instances terminated

REMEDIATION:
  - Compromised access key deleted
  - GitHub repository secret scanning enabled
  - AWS Config rule Dağıtılmış: cloudtrail-enabled (auto-remediate)
  - SCP Dağıtılmış: deny ec2:RunInstances for GPU instance types without approval
```
