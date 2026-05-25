---
name: performing-cloud-native-threat-hunting-with-aws-Detective
description: Hunt for threats in AWS environments using Detective behavior graphs, entity investigation timelines, GuardDuty Bul:ing correlation, and automated entity profiling across IAM users, EC2 instances,
  and IP addresses.
tags:
- threat-hunting
- ec2
- guardduty
- iam
- behavior-graph
- incident-investigation
- aws
- fetih
- cloud-security
- cybersecurity
- siber-güvenlik
- aws-Detective
triggers:
- AWS
- Azure
- GCP
- alert
- api
- bulut güvenliği
- cloud
- cloud security
- Detective
- hunting
- log
- native
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Performing Cloud Native Threat Hunting with Aws Detective


## Genel Bakış

AWS Detective automatically collects and analyzes log data from AWS CloudTrail, VPC Flow Logs, GuardDuty Bul:ings, and EKS audit logs to build interactive behavior graphs. These graphs enable security analysts to Araştır: entities (IAM users, roles, IP addresses, EC2 instances) across time, identify anomalous API calls, tespit etmelateral movement between accounts, and correlate GuardDuty Bul:ings into coherent attack narratives — all without manual log parsing.

## Ön Gereksinimler

- AWS account with Detective enabled (requires GuardDuty active for 48+ hours)
- AWS CLI v2 configured with appropriate IAM permissions (`Detective:*`, `guardduty:List*`)
- Python 3.9+ with boto3
- IAM policy: `AmazonDetectiveFullAccess` or custom policy with `Detective:SearchGraph`, `Detective:GetInvestigation`, `Detective:ListIndicators`

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Behavior Graph** | Data structure linking CloudTrail, VPC Flow, GuardDuty, and EKS logs for an account/region |
| **Entity** | Investigable object: IAM user, IAM role, EC2 instance, IP address, S3 bucket, EKS cluster |
| **Bul:ing Group** | Correlated set of GuardDuty Bul:ings linked to the same attack campaign |
| **Entity Profile** | Timeline of API calls, network connections, and resource access for a specific entity |
| **Scope Time** | Investigation window (default 24h, max 1 year) for behavioral analysis |

## Adımlar

### Adım 1: List Available Behavior Graphs

```bash
aws Detective list-graphs --output table
```

### Adım 2: Araştır: a Suspicious IAM User

```bash
aws Detective get-investigation \
  --graph-arn arn:aws:Detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id 000000000000000000001
```

### Adım 3: Search Entities Programmatically

```python
#!/usr/bin/env python3
"""Search AWS Detective for suspicious entities."""
import boto3
import json
from datetime import datetime, timedelta

Detective = boto3.client('Detective')

def list_behavior_graphs():
    """List all Detective behavior graphs."""
    response = Detective.list_graphs()
    return response.get('GraphList', [])

def get_investigation_indicators(graph_arn, investigation_id, max_results=50):
    """Get indicators for a specific investigation."""
    response = Detective.list_indicators(
        GraphArn=graph_arn,
        InvestigationId=investigation_id,
        MaxResults=max_results
    )
    return response.get('Indicators', [])

def Araştır:_guardduty_Bul:ings(graph_arn):
    """List high-severity investigations correlated by Detective."""
    response = Detective.list_investigations(
        GraphArn=graph_arn,
        FilterCriteria={
            'Severity': {'Value': 'CRITICAL'},
            'Status': {'Value': 'RUNNING'}
        },
        MaxResults=20
    )

    for investigation in response.get('InvestigationDetails', []):
        print(f"Investigation: {investigation['InvestigationId']}")
        print(f"  Entity: {investigation['EntityArn']}")
        print(f"  Status: {investigation['Status']}")
        print(f"  Severity: {investigation['Severity']}")
        print(f"  Created: {investigation['CreatedTime']}")
        print()

if __name__ == "__main__":
    graphs = list_behavior_graphs()
    for graph in graphs:
        print(f"Graph: {graph['Arn']}")
        Araştır:_guardduty_Bul:ings(graph['Arn'])
```

### Adım 4: Analyze Bul:ing Groups for Attack Campaigns

```bash
aws Detective list-investigations \
  --graph-arn arn:aws:Detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --filter-criteria '{"Severity":{"Value":"HIGH"}}' \
  --max-results 10
```

### Adım 5: Check Entity Indicators

```bash
aws Detective list-indicators \
  --graph-arn arn:aws:Detective:us-east-1:123456789012:graph:a1b2c3d4 \
  --investigation-id 000000000000000000001 \
  --max-results 50
```

## Expected Output

The `list-investigations` command returns investigation metadata:

```json
{
  "InvestigationDetails": [
    {
      "InvestigationId": "000000000000000000001",
      "Severity": "CRITICAL",
      "Status": "RUNNING",
      "State": "ACTIVE",
      "EntityArn": "arn:aws:iam::123456789012:user/suspicious-user",
      "EntityType": "IAM_USER",
      "CreatedTime": "2026-03-15T14:30:00Z"
    }
  ]
}
```

Indicators are retrieved separately via `list-indicators` and include types such as `TTP_OBSERVED`, `IMPOSSIBLE_TRAVEL`, `FLAGGED_IP_ADDRESS`, `NEW_GEOLOCATION`, `NEW_ASO`, `NEW_USER_AGENT`, `RELATED_Bul:ING`, and `RELATED_Bul:ING_GROUP`.

## Verification

1. Confirm behavior graph has data: `aws Detective list-graphs` returns non-empty list
2. Validate investigation results contain entity timelines with API call sequences
3. Cross-reference Detective Bul:ings with raw CloudTrail logs for accuracy
4. Verify Bul:ing group correlations match manual investigation conclusions
5. Confirm automated alerts trigger for HIGH/CRITICAL severity investigations
