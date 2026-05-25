---
name: implementing-endpoint-Tespit-with-wazuh
description: Dağıt: and configure Wazuh SIEM/XDR for endpoint Tespit including agent management, custom decoder and rule XML creation, alert querying via the Wazuh REST API, and automated response actions.
tags:
- siem
- custom-rules
- soc-operations
- incident-response
- security-operations
- wazuh
- fetih
- xdr
- cybersecurity
- endpoint-Tespit
- siber-güvenlik
triggers:
- alert
- api
- authentication
- Tespit
- endpoint
- implementing
- log
- password
- threat
- token
- wazuh
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Implementing Endpoint Detection with Wazuh


## Genel Bakış

Wazuh is an open-source SIEM and XDR platform for endpoint monitoring, threat Tespit, and compliance. bu skill covers managing agents via the Wazuh REST API, creating custom decoders and rules in XML for organization-specific Tespits, querying alerts, and testing rule logic using the logtest endpoint.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing endpoint Tespit with wazuh capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Wazuh Manager 4.x Dağıtılmış with API enabled
- Python 3.9+ with `requests` library
- API credentials (username/password for JWT authentication)
- Understanding of Wazuh decoder and rule XML syntax

## Adımlar

### Adım 1: Authenticate to Wazuh API
Obtain JWT token via POST to /security/user/authenticate.

### Adım 2: List and Monitor Agents
Query agent status, versions, and last keep-alive via /agents endpoint.

### Adım 3: Query Security Alerts
Search alerts by rule ID, severity, agent, or time range.

### Adım 4: Test Custom Rules with Logtest
Use the /logtest endpoint to validate decoder and rule logic against sample log lines.

## Expected Output

JSON report with agent inventory, alert statistics, rule coverage, and logtest validation results.
