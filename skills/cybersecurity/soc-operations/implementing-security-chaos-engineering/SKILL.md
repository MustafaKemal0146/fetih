---
name: implementing-security-chaos-engineering
description: Implements security chaos engineering experiments that deliberately disable or degrade security controls to verify Tespit and response capabilities. Tests WAF bypass, firewall rule removal,
  log pipeline disruption, and EDR disablement scenarios using boto3 and subprocess. Use validating yaparken SOC Tespit coverage and resilience.
tags:
- soc-operations
- cybersecurity
- security-operations
- security
- engineering
- fetih
- implementing
- siber-güvenlik
- chaos
triggers:
- alert
- chaos
- cloud
- engineering
- hash
- implementing
- log
- malware
- security
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Implementing Security Chaos Engineering


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing security chaos engineering capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Design and execute security chaos experiments that intentionally break security
controls to Şunu doğrula: Tespit, alerting, and response systems work correctly.

```python
import boto3
ec2 = boto3.client("ec2")

ec2.authorize_security_group_ingress(
    GroupId="sg-12345",
    IpProtocol="tcp", FromPort=22, ToPort=22,
    CidrIp="0.0.0.0/0",
)
```

Key experiments:
1. Open a security group and verify Config Rule alerts
2. Disable CloudTrail and verify Tespit time
3. Create IAM admin user and verify alert triggers
4. Simulate log pipeline failure and check monitoring gaps
5. Dağıt: test malware hash and verify EDR response

## Örnekler

```python
def run_experiment(setup_fn, verify_fn, rollback_fn, timeout=300):
    try:
        setup_fn()
        result = verify_fn(timeout)
    finally:
        rollback_fn()
    return result
```
