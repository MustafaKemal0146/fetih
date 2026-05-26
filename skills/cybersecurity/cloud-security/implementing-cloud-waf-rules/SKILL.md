---
name: implementing-cloud-waf-rules
description: bu skill covers Dağıt:ing and tuning Web Application Firewall rules on AWS WAF, Azure WAF, and Cloudflare to protect cloud-hosted applications against OWASP Top 10 attacks. It details configuring
  managed rule sets, creating custom rules for business logic protection, implementing rate limiting, Dağıt:ing bot management, and reducing false positives through rule tuning and logging analysis.
tags:
- azure-waf
- cybersecurity
- owasp-protection
- cloud-waf
- cloudflare-waf
- aws-waf
- fetih
- rate-limiting
- cloud-security
- siber-güvenlik
triggers:
- AWS
- Azure
- GCP
- api
- authentication
- bulut güvenliği
- cloud
- cloud security
- endpoint
- http
- implementing
- log
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Implementing Cloud Waf Rules


## Ne Zaman Kullanılır

- Dağıt:ing yaparken new web applications or APIs behind cloud load balancers requiring OWASP protection
- application yaparken: penetration testing reveals SQL injection, XSS, or other injection vulnerabilities
- experiencing yaparken: brute force, credential stuffing, or bot attacks against authentication endpoints
- compliance yaparken: requirements mandate a WAF for PCI-DSS or similar standards
- tuning yaparken: WAF rules to reduce false positives blocking legitimate application traffic

**Kullanma:** for network-level DDoS protection (use AWS Shield or Azure DDoS Protection), for API authentication design (see managing-cloud-identity-with-okta), or for application code-level security fixes (WAF is a compensating control, not a replacement for secure code).

## Ön Gereksinimler

- AWS ALB/CloudFront, Azure Application Gateway, or Cloudflare configured as the application entry point
- Application traffic logs for baseline analysis before WAF Dağıt:ment
- Test environment for validating WAF rules before production enforcement
- Understanding of application request patterns to minimize false positives

## İş Akışı

### Adım 1: Dağıt: Managed Rule Sets

Enable cloud provider managed rule sets that cover OWASP Top 10 vulnerabilities. Start in Count (Tespit) mode before switching to Block (prevention) mode.

```bash
aws wafv2 create-web-acl \
  --name production-waf \
  --scope REGIONAL \
  --default-action '{"Allow": {}}' \
  --visibility-config '{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "production-waf"
  }' \
  --rules '[
    {
      "Name": "AWSManagedRulesCommonRuleSet",
      "Priority": 1,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesCommonRuleSet"
        }
      },
      "OverrideAction": {"Count": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "CommonRuleSet"
      }
    },
    {
      "Name": "AWSManagedRulesSQLiRuleSet",
      "Priority": 2,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesSQLiRuleSet"
        }
      },
      "OverrideAction": {"Count": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "SQLiRuleSet"
      }
    },
    {
      "Name": "AWSManagedRulesKnownBadInputsRuleSet",
      "Priority": 3,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesKnownBadInputsRuleSet"
        }
      },
      "OverrideAction": {"Count": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "KnownBadInputs"
      }
    }
  ]'
```

### Adım 2: Create Custom Rate Limiting Rules

Dağıt: rate-based rules to protect login endpoints against brute force and credential stuffing attacks.

```bash
aws wafv2 update-web-acl \
  --name production-waf \
  --scope REGIONAL \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --default-action '{"Allow": {}}' \
  --rules '[
    {
      "Name": "RateLimitLogin",
      "Priority": 0,
      "Statement": {
        "RateBasedStatement": {
          "Limit": 100,
          "AggregateKeyType": "IP",
          "ScopeDownStatement": {
            "ByteMatchStatement": {
              "FieldToMatch": {"UriPath": {}},
              "PositionalConstraint": "STARTS_WITH",
              "SearchString": "/api/auth/login",
              "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}]
            }
          }
        }
      },
      "Action": {"Block": {"CustomResponse": {"ResponseCode": 429}}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "RateLimitLogin"
      }
    }
  ]'
```

### Adım 3: Configure Geo-Blocking and IP Reputation

Block traffic from countries where the application has no legitimate users and leverage IP reputation lists to block known malicious sources.

```bash
aws wafv2 create-ip-set \
  --name blocked-ips \
  --scope REGIONAL \
  --ip-address-version IPV4 \
  --addresses "198.51.100.0/24" "203.0.113.0/24"

```

### Adım 4: Tune Rules to Reduce False Positives

Analyze WAF logs in Count mode to identify legitimate requests being flagged. Create rule exceptions for specific URI paths or request patterns.

```bash
aws wafv2 put-logging-configuration \
  --logging-configuration '{
    "ResourceArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/production-waf/id",
    "LogDestinationConfigs": ["arn:aws:s3:::waf-logs-bucket"],
    "RedactedFields": [{"SingleHeader": {"Name": "authorization"}}]
  }'

cat << 'EOF' > waf-analysis.sql
SELECT
  terminatingRuleId,
  httpRequest.uri,
  httpRequest.httpMethod,
  COUNT(*) as block_count
FROM waf_logs
WHERE action = 'BLOCK'
  AND timestamp > date_add('day', -7, now())
GROUP BY terminatingRuleId, httpRequest.uri, httpRequest.httpMethod
ORDER BY block_count DESC
LIMIT 20
EOF
```

```bash
aws wafv2 update-web-acl \
  --name production-waf \
  --scope REGIONAL \
  --id <web-acl-id> \
  --lock-token <lock-token> \
  --rules '[{
    "Name": "AWSManagedRulesCommonRuleSet",
    "Priority": 1,
    "Statement": {
      "ManagedRuleGroupStatement": {
        "VendorName": "AWS",
        "Name": "AWSManagedRulesCommonRuleSet",
        "ExcludedRules": [{"Name": "SizeRestrictions_BODY"}]
      }
    },
    "OverrideAction": {"None": {}},
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "CommonRuleSet"
    }
  }]'
```

### Adım 5: Switch to Block Mode After Validation

After 7-14 days of Count mode with acceptable false positive rates, switch managed rules to Block mode for active protection.

```bash
```

## Key Concepts

| Term | Definition |
|------|------------|
| Web ACL | Web Access Control List defining the set of rules evaluated against every HTTP request to a protected resource |
| Managed Rule Group | Pre-configured rule set maintained by the cloud provider or third-party vendor covering common attack patterns |
| Rate-Based Rule | WAF rule that tracks request rates per IP address and blocks IPs exceeding the threshold within a time window |
| Count Mode | WAF action that logs matching requests without blocking them, used for rule validation before enforcement |
| Rule Priority | Numerical ordering determining which rules are evaluated first; lower numbers have higher priority |
| Custom Response | WAF capability to return specific HTTP status codes and headers blocking yaparken requests |
| Scope-Down Statement | Condition that narrows a rate-based rule to specific URI paths, methods, or headers |
| False Positive | Legitimate request incorrectly blocked by a WAF rule, requiring rule tuning or exclusion |

## Tools & Systems

- **AWS WAF**: Cloud-native WAF integrated with ALB, CloudFront, API Gateway, and AppSync
- **Azure WAF**: Web application firewall on Application Gateway or Front Door with OWASP CRS rule sets
- **AWS Firewall Manager**: Centralized WAF policy management across multiple AWS accounts in an Organization
- **WAF Security Automations**: AWS solution that Dağıt:s Lambda-based automated WAF rule updates based on log analysis
- **CloudWatch Metrics**: Monitoring dashboard for tracking WAF rule match rates, block counts, and allowed requests

## Common Scenarios

### Scenario: Credential Stuffing Attack Against Authentication API

**Context**: An e-commerce application experiences 50,000 login attempts per hour from a botnet using stolen credential lists. The attacker rotates source IPs every few minutes to evade simple IP-based blocking.

**Approach**:
1. Dağıt: rate-based rules limiting login endpoint requests to 10 per 5 minutes per IP
2. Enable AWS WAF Bot Control managed rule group to tespit etmeautomated request patterns beyond IP rotation
3. Add a custom rule requiring valid CAPTCHA tokens for login requests exceeding 5 failures
4. Implement IP reputation blocking using AWSManagedRulesAmazonIpReputationList
5. Şunu oluştur: custom rule matching on User-Agent patterns common to credential stuffing tools
6. Monitor blocked request metrics and adjust thresholds based on legitimate traffic patterns

**Pitfalls**: Setting rate limits too aggressively blocks legitimate users behind shared NAT IPs. Blocking by User-Agent alone is easily bypassed by rotating agent strings.

## Output Format

```text
Cloud WAF Configuration Report
================================
Web ACL: production-waf
Scope: Regional (us-east-1)
Protected Resources: ALB (arn:aws:elasticloadbalancing:...)
Report Date: 2025-02-23

RULE CONFIGURATION:
  [P0] RateLimitLogin          - BLOCK (100 req/5min/IP)
  [P1] AWSManagedRulesCommon   - BLOCK (1 exclusion: SizeRestrictions_BODY)
  [P2] AWSManagedRulesSQLi     - BLOCK
  [P3] AWSManagedRulesKnownBad - BLOCK
  [P4] AWSManagedRulesBotControl - COUNT (evaluation phase)
  [P5] GeoBlockRule            - BLOCK (12 countries blocked)

TRAFFIC ANALYSIS (Last 7 Days):
  Total Requests:    2,847,293
  Allowed:           2,791,456 (98.0%)
  Blocked:              51,234 (1.8%)
  Counted:               4,603 (0.2%)

TOP BLOCKED RULES:
  RateLimitLogin:              23,456 blocks (45.8%)
  SQLiDetect               8,234 blocks (16.1%)
  CommonRuleSet (XSS):          7,891 blocks (15.4%)
  GeoBlockRule:                 6,543 blocks (12.8%)
  KnownBadInputs:              5,110 blocks (10.0%)

FALSE POSITIVE ANALYSIS:
  Reported False Positives: 3
  Confirmed False Positives: 1 (SizeRestrictions_BODY for /api/upload)
  Action Taken: Rule exclusion applied
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 38fb7c0f4a118960
-->

