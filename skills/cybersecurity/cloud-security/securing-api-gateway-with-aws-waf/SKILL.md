---
name: securing-api-gateway-with-aws-waf
description: Securing API Gateway endpoints with AWS WAF by configuring managed rule groups for OWASP Top 10 protection, creating custom rate limiting rules, implementing bot control, setting up IP reputation
  filtering, and monitoring WAF metrics for security effectiveness.
tags:
- cybersecurity
- bot-protection
- owasp
- aws
- fetih
- api-gateway
- rate-limiting
- cloud-security
- siber-güvenlik
- waf
triggers:
- AWS
- Azure
- GCP
- alert
- api
- authentication
- bulut güvenliği
- cloud
- cloud security
- endpoint
- gateway
- http
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Securing Api Gateway with Aws Waf


## Ne Zaman Kullanılır

- Dağıt:ing yaparken API Gateway endpoints that require protection against common web attacks
- implementing yaparken rate limiting and throttling to prevent API abuse and DDoS attacks
- building yaparken bot Tespit and mitigation for API endpoints exposed to the internet
- compliance yaparken: requires WAF protection for all public-facing API endpoints
- customizing yaparken: access controls based on IP reputation, geolocation, or request patterns

**Kullanma:** for network-level DDoS protection (use AWS Shield), for application logic vulnerabilities (use SAST/DAST tools), or for internal API security between microservices (use service mesh authentication and authorization).

## Ön Gereksinimler

- AWS API Gateway (REST or HTTP API) Dağıtılmış with public endpoints
- IAM permissions for `wafv2:*` and `apigateway:*` operations
- CloudWatch and S3 or Kinesis Firehose configured for WAF logging
- Understanding of the API's expected traffic patterns for rate limiting configuration
- IP reputation lists or threat intelligence feeds for custom IP blocking

## İş Akışı

### Adım 1: Şunu oluştur: WAF Web ACL with Managed Rule Groups

Şunu oluştur: Web ACL with AWS Managed Rules for baseline protection against OWASP Top 10 attacks.

```bash
aws wafv2 create-web-acl \
  --name api-gateway-waf \
  --scope REGIONAL \
  --default-action '{"Allow":{}}' \
  --visibility-config '{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "api-gateway-waf"
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
      "OverrideAction": {"None": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "CommonRuleSet"
      }
    },
    {
      "Name": "AWSManagedRulesKnownBadInputsRuleSet",
      "Priority": 2,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesKnownBadInputsRuleSet"
        }
      },
      "OverrideAction": {"None": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "KnownBadInputs"
      }
    },
    {
      "Name": "AWSManagedRulesSQLiRuleSet",
      "Priority": 3,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesSQLiRuleSet"
        }
      },
      "OverrideAction": {"None": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "SQLiRuleSet"
      }
    },
    {
      "Name": "AWSManagedRulesAmazonIpReputationList",
      "Priority": 4,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesAmazonIpReputationList"
        }
      },
      "OverrideAction": {"None": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "IPReputationList"
      }
    }
  ]'
```

### Adım 2: Add Rate Limiting Rules

Configure rate-based rules to throttle excessive API requests per IP address.

```bash
WEB_ACL_ARN=$(aws wafv2 list-web-acls --scope REGIONAL \
  --query "WebACLs[?Name=='api-gateway-waf'].ARN" --output text)

aws wafv2 update-web-acl \
  --name api-gateway-waf \
  --scope REGIONAL \
  --id $(aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[?Name=='api-gateway-waf'].Id" --output text) \
  --lock-token $(aws wafv2 get-web-acl --name api-gateway-waf --scope REGIONAL --id WEB_ACL_ID --query 'LockToken' --output text) \
  --default-action '{"Allow":{}}' \
  --visibility-config '{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "api-gateway-waf"
  }' \
  --rules '[
    {
      "Name": "RateLimitPerIP",
      "Priority": 0,
      "Statement": {
        "RateBasedStatement": {
          "Limit": 2000,
          "AggregateKeyType": "IP"
        }
      },
      "Action": {"Block": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "RateLimitPerIP"
      }
    },
    {
      "Name": "RateLimitLoginEndpoint",
      "Priority": 5,
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
      "Action": {"Block": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "RateLimitLogin"
      }
    }
  ]'
```

### Adım 3: Implement Bot Control

Add AWS WAF Bot Control to tespit etmeand manage automated traffic.

```bash
{
  "Name": "AWSManagedRulesBotControlRuleSet",
  "Priority": 6,
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesBotControlRuleSet",
      "ManagedRuleGroupConfigs": [{
        "AWSManagedRulesBotControlRuleSet": {
          "Denetle:ionLevel": "COMMON"
        }
      }],
      "ExcludedRules": [
        {"Name": "CategoryHttpLibrary"},
        {"Name": "SignalNonBrowserUserAgent"}
      ]
    }
  },
  "OverrideAction": {"None": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BotControl"
  }
}
```

### Adım 4: Create Custom Rules for API-Specific Protection

Build custom WAF rules for API-specific security requirements.

```bash
{
  "Name": "RequireAPIKey",
  "Priority": 7,
  "Statement": {
    "NotStatement": {
      "Statement": {
        "ByteMatchStatement": {
          "FieldToMatch": {
            "SingleHeader": {"Name": "x-api-key"}
          },
          "PositionalConstraint": "EXACTLY",
          "SearchString": "",
          "TextTransformations": [{"Priority": 0, "Type": "NONE"}]
        }
      }
    }
  },
  "Action": {"Block": {"CustomResponse": {"ResponseCode": 403}}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "RequireAPIKey"
  }
}

{
  "Name": "GeoRestriction",
  "Priority": 8,
  "Statement": {
    "NotStatement": {
      "Statement": {
        "GeoMatchStatement": {
          "CountryCodes": ["US", "CA", "GB", "DE", "FR", "AU"]
        }
      }
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "GeoRestriction"
  }
}

{
  "Name": "MaxBodySize",
  "Priority": 9,
  "Statement": {
    "SizeConstraintStatement": {
      "FieldToMatch": {"Body": {"OversizeHandling": "MATCH"}},
      "ComparisonOperator": "GT",
      "Size": 10240,
      "TextTransformations": [{"Priority": 0, "Type": "NONE"}]
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "MaxBodySize"
  }
}
```

### Adım 5: Associate WAF with API Gateway and Enable Logging

Attach the Web ACL to the API Gateway stage and configure comprehensive logging.

```bash
aws wafv2 associate-web-acl \
  --web-acl-arn $WEB_ACL_ARN \
  --resource-arn arn:aws:apigateway:us-east-1::/restapis/API_ID/stages/prod

aws wafv2 put-logging-configuration \
  --logging-configuration '{
    "ResourceArn": "'$WEB_ACL_ARN'",
    "LogDestinationConfigs": [
      "arn:aws:firehose:us-east-1:ACCOUNT:deliverystream/aws-waf-logs-api-gateway"
    ],
    "RedactedFields": [
      {"SingleHeader": {"Name": "authorization"}},
      {"SingleHeader": {"Name": "cookie"}}
    ]
  }'

aws wafv2 get-web-acl-for-resource \
  --resource-arn arn:aws:apigateway:us-east-1::/restapis/API_ID/stages/prod
```

### Adım 6: Monitor WAF Metrics and Tune Rules

Monitor WAF effectiveness and tune rules to reduce false positives.

```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/WAFV2 \
  --metric-name BlockedRequests \
  --dimensions Name=WebACL,Value=api-gateway-waf Name=Rule,Value=ALL \
  --start-time 2026-02-22T00:00:00Z \
  --end-time 2026-02-23T00:00:00Z \
  --period 3600 \
  --statistics Sum

aws wafv2 get-sampled-requests \
  --web-acl-arn $WEB_ACL_ARN \
  --rule-metric-name RateLimitPerIP \
  --scope REGIONAL \
  --time-window '{"StartTime":"2026-02-22T00:00:00Z","EndTime":"2026-02-23T00:00:00Z"}' \
  --max-items 50

aws wafv2 get-rate-based-statement-managed-keys \
  --web-acl-name api-gateway-waf \
  --scope REGIONAL \
  --web-acl-id WEB_ACL_ID \
  --rule-name RateLimitPerIP

aws cloudwatch put-metric-alarm \
  --alarm-name waf-high-block-rate \
  --namespace AWS/WAFV2 \
  --metric-name BlockedRequests \
  --dimensions Name=WebACL,Value=api-gateway-waf Name=Rule,Value=ALL \
  --statistic Sum --period 300 --threshold 1000 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:security-alerts
```

## Key Concepts

| Term | Definition |
|------|------------|
| Web ACL | AWS WAF access control list that defines the collection of rules and their actions (allow, block, count) applied to associated resources |
| Managed Rule Group | Pre-configured set of WAF rules maintained by AWS or third-party vendors for common attack patterns like OWASP Top 10 |
| Rate-Based Rule | WAF rule that tracks request rates per IP address and blocks traffic exceeding a defined threshold within a 5-minute window |
| Bot Control | AWS WAF managed rule group that identifies and manages automated traffic including scrapers, crawlers, and attack bots |
| IP Reputation List | AWS-maintained list of IP addresses associated with malicious activity including botnets, scanners, and known attackers |
| Custom Response | WAF capability to return specific HTTP status codes and custom response bodies blocking yaparken requests |

## Tools & Systems

- **AWS WAF**: Web application firewall service for protecting API Gateway, ALB, CloudFront, and AppSync endpoints
- **AWS Managed Rules**: Pre-built rule groups for common attack patterns maintained by AWS security team
- **AWS Firewall Manager**: Central management of WAF policies across multiple accounts in AWS Organizations
- **Kinesis Firehose**: Streaming delivery service for WAF logs to S3, Elasticsearch, or third-party analytics
- **CloudWatch**: Monitoring service for WAF metrics including allowed, blocked, and counted requests

## Common Scenarios

### Scenario: Protecting a Public API from Credential Stuffing and Bot Attacks

**Context**: A public REST API experiences thousands of authentication attempts per hour from automated bots attempting credential stuffing against the `/api/auth/login` endpoint.

**Approach**:
1. Şunu oluştur: Web ACL with AWS Managed Rules Common Rule Set for baseline protection
2. Add a rate-based rule limiting the login endpoint to 100 requests per IP per 5 minutes
3. Enable Bot Control managed rules to tespit etmeand block automated traffic
4. Add IP Reputation List to block known malicious IPs proactively
5. Şunu oluştur: custom rule blocking requests without proper User-Agent headers
6. Enable WAF logging and create CloudWatch alarms for high block rates
7. Review sampled blocked requests weekly to tune rules and reduce false positives

**Pitfalls**: Rate limiting by IP can block legitimate users behind shared NAT gateways or corporate proxies. Consider using API key or authenticated session-based rate limiting for more granular control. Bot Control rules in COMMON Denetle:ion level may block legitimate API clients; start in Count mode and review before switching to Block.

## Output Format

```
AWS WAF API Gateway Security Report
======================================
Web ACL: api-gateway-waf
Associated Resource: API Gateway - production-api (prod stage)
Report Period: 2026-02-16 to 2026-02-23

TRAFFIC SUMMARY:
  Total requests:              2,450,000
  Allowed requests:            2,380,000 (97.1%)
  Blocked requests:               70,000 (2.9%)

BLOCKS BY RULE:
  RateLimitPerIP:              28,000 (40%)
  AWSManagedRulesCommonRuleSet: 18,000 (25.7%)
  BotControl:                  12,000 (17.1%)
  SQLiRuleSet:                  5,000 (7.1%)
  IPReputationList:             4,000 (5.7%)
  RateLimitLogin:               2,000 (2.9%)
  GeoRestriction:               1,000 (1.4%)

TOP BLOCKED IPs:
  185.x.x.x:     8,400 requests (rate limited)
  45.x.x.x:      5,200 requests (bot Detected)
  198.x.x.x:     3,100 requests (SQLi attempts)

ATTACK TYPES BLOCKED:
  Credential stuffing (login endpoint):  2,000
  SQL injection attempts:                5,000
  Cross-site scripting:                  3,200
  Known bad bot traffic:                12,000
  Rate limit violations:               28,000

WAF RULE HEALTH:
  Rules in Block mode:    8 / 10
  Rules in Count mode:    2 / 10 (under evaluation)
  False positive rate:    < 0.1%
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 765ed2a1a3f46288
-->

