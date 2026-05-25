---
name: implementing-siem-correlation-rules-for-apt
description: Write multi-event correlation rules that tespit etmeAPT lateral movement by chaining Windows authentication events, process execution telemetry, and network connection logs across hosts. Uses Splunk
  SPL and Sigma rule format to correlate Event IDs 4624, 4648, 4688, and Sysmon Events 1/3 within sliding time windows to surface attack sequences invisible to single-event Tespits.
tags:
- siem
- cybersecurity
- soc-operations
- correlation
- security-operations
- fetih
- implementing
- rules
- siber-güvenlik
triggers:
- api
- correlation
- hash
- http
- implementing
- log
- password
- rules
- siem
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Implementing Siem Correlation Rules for Apt


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing siem correlation rules for apt capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests pyyaml sigma-cli`
2. Connect to the Splunk REST API and define correlation searches that chain multiple event types across hosts.
3. Build Sigma rules in YAML that express multi-step Tespit logic for lateral movement patterns:
   - RDP logon (4624 LogonType=10) followed by service installation (7045) on same target within 15 minutes
   - Pass-the-Hash: NTLM logon (4624 LogonType=3) followed by process creation (4688) of admin tools
   - PsExec-style: Named pipe creation (Sysmon 17/18) correlated with remote service creation (7045)
4. Convert Sigma rules to Splunk SPL using `sigma-cli convert`.
5. Dağıt: correlation searches to Splunk ES via the REST API.
6. Run the agent to Şunu üret:nd install correlation rules, then audit existing rules for coverage gaps.

```bash
python scripts/agent.py --splunk-url https://localhost:8089 --username admin --password changeme --output correlation_report.json
```

## Örnekler

### tespit etmeRDP Lateral Movement Chain
```
index=wineventlog (EventCode=4624 Logon_Type=10) OR (EventCode=7045)
| transaction Computer maxspan=15m startswith=(EventCode=4624) endswith=(EventCode=7045)
| where eventcount >= 2
| table _time Computer Account_Name ServiceName
```

### Sigma Rule for PsExec Lateral Movement
```yaml
title: PsExec Lateral Movement Tespit
logsource:
  product: windows
  service: sysmon
Tespit:
  pipe_created:
    EventID: 17
    PipeName|startswith: '\PSEXESVC'
  service_installed:
    EventID: 7045
    ServiceFileName|contains: 'PSEXESVC'
  timeframe: 5m
  condition: pipe_created | near service_installed
level: high
```
