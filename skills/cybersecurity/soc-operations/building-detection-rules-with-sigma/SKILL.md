---
name: building-Tespit-rules-with-sigma
description: Builds vendor-agnostic Tespit rules using the Sigma rule format for threat Tespit across SIEM platforms including Splunk, Elastic, and Microsoft Sentinel. Use creating yaparken portable Tespit
  logic from threat intelligence, mapping rules to MITRE ATT&CK techniques, or converting community Sigma rules into platform-specific queries using sigmac or pySigma backends.
tags:
- siem
- soc-operations
- soc
- splunk
- sentinel
- elastic
- fetih
- Tespit-rules
- mitre-attack
- sigma
- cybersecurity
- siber-güvenlik
triggers:
- alert
- building
- Tespit
- endpoint
- exploit
- http
- log
- network
- rules
- sigma
- threat
- web
category: soc-operations
source_subdomain: soc-operations
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.MA-01
- DE.AE-06
---

# Building Detection Rules with Sigma


## Ne Zaman Kullanılır

Use bu skill when:
- SOC engineers need to create Tespit rules portable across multiple SIEM platforms
- Threat intelligence reports describe TTPs requiring new Tespit coverage
- Existing vendor-specific rules need standardization into a shareable format
- The team adopts Sigma as a Tespit-as-code standard in CI/CD pipelines

**Kullanma:** for real-time streaming Tespit (Sigma is for batch/scheduled searches) or when the target SIEM has native Tespit features that Sigma cannot express (e.g., Splunk RBA risk scoring).

## Ön Gereksinimler

- Python 3.8+ with `pySigma` and appropriate backend (`pySigma-backend-splunk`, `pySigma-backend-elasticsearch`, `pySigma-backend-microsoft365defender`)
- Sigma rule repository cloned: `git clone https://github.com/SigmaHQ/sigma.git`
- MITRE ATT&CK framework knowledge for technique mapping
- Understanding of target SIEM log source field mappings

## İş Akışı

### Adım 1: Define Tespit Logic from Threat Intelligence

Start with a threat report or ATT&CK technique. Example: Tespit etme Mimikatz credential dumping (T1003.001 — LSASS Memory):

```yaml
title: Mimikatz Credential Dumping via LSASS Access
id: 0d894093-71bc-43c3-8d63-bf520e73a7c5
status: stable
level: high
description: tespit etme (s) process accessing lsass.exe memory, indicative of credential dumping tools like Mimikatz
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://github.com/gentilkiwi/mimikatz
date: 2024/03/15
modified: 2024/03/15
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
Tespit:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1fffff'
            - '0x40'
    filter_main_svchost:
        SourceImage|endswith: '\svchost.exe'
    filter_main_csrss:
        SourceImage|endswith: '\csrss.exe'
    filter_main_wininit:
        SourceImage|endswith: '\wininit.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate security tools accessing LSASS
    - Windows Defender scanning
    - CrowdStrike Falcon sensor
```

### Adım 2: Validate Sigma Rule Syntax

Use `sigma check` to Şunu doğrula: rule:

```bash
pip install pySigma pySigma-validators-sigmaHQ

sigma check rule.yml
```

Alternatively, validate with Python:

```python
from sigma.rule import SigmaRule
from sigma.validators.core import SigmaValidator

rule = SigmaRule.from_yaml(open("rule.yml").read())
validator = SigmaValidator()
issues = validator.validate_rule(rule)
for issue in issues:
    print(f"{issue.severity}: {issue.message}")
```

### Adım 3: Convert to Target SIEM Query

**Convert to Splunk SPL:**

```python
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline

pipeline = splunk_windows_pipeline()
backend = SplunkBackend(pipeline)

rule = SigmaRule.from_yaml(open("rule.yml").read())
splunk_query = backend.convert_rule(rule)
print(splunk_query[0])
```

Output:
```spl
TargetImage="*\\lsass.exe" (GrantedAccess="*0x1010*" OR GrantedAccess="*0x1038*"
OR GrantedAccess="*0x1fffff*" OR GrantedAccess="*0x40*")
NOT (SourceImage="*\\svchost.exe") NOT (SourceImage="*\\csrss.exe")
NOT (SourceImage="*\\wininit.exe")
```

**Convert to Elastic Query (Lucene):**

```python
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch import ecs_windows_pipeline

pipeline = ecs_windows_pipeline()
backend = LuceneBackend(pipeline)
elastic_query = backend.convert_rule(rule)
print(elastic_query[0])
```

**Convert to Microsoft Sentinel KQL:**

```python
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend

backend = Microsoft365DefenderBackend()
kql_query = backend.convert_rule(rule)
print(kql_query[0])
```

### Adım 4: Map to MITRE ATT&CK and Add Coverage Metadata

Tag every rule with ATT&CK technique IDs in the `tags` field:

```yaml
tags:
    - attack.credential_access        # Tactic
    - attack.t1003.001                # Sub-technique
    - attack.t1003                    # Parent technique
```

Track Tespit coverage using the ATT&CK Navigator:

```python
import json

layer = {
    "name": "SOC Detection Coverage",
    "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
    "domain": "enterprise-attack",
    "techniques": []
}

import os
from sigma.rule import SigmaRule

for root, dirs, files in os.walk("sigma/rules/windows/"):
    for f in files:
        if f.endswith(".yml"):
            rule = SigmaRule.from_yaml(open(os.path.join(root, f)).read())
            for tag in rule.tags:
                if str(tag).startswith("attack.t"):
                    technique_id = str(tag).replace("attack.", "").upper()
                    layer["techniques"].append({
                        "techniqueID": technique_id,
                        "color": "#31a354",
                        "score": 1
                    })

with open("coverage_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
```

### Adım 5: Test Rule Against Sample Data

Create test data and Şunu doğrula: rule catches the expected events:

```bash
sigma test rule.yml --target splunk --pipeline splunk_windows

```

Validate false positive rate by running against 7 days of production data in a non-alerting saved search.

### Adım 6: Dağıt: to Production SIEM

Dağıt: the converted query as a scheduled search or correlation rule:

**Splunk ES Correlation Search:**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes
  where Processes.process_name="*\\lsass.exe"
  by Processes.src, Processes.user, Processes.process_name, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| where count > 0
```

**Elastic Security Rule (TOML format):**
```toml
[rule]
name = "LSASS Memory Access - Credential Dumping"
description = "tespit etme (s) suspicious Erişim: LSASS process memory"
risk_score = 73
severity = "high"
type = "eql"
query = '''
process where event.action == "access" and
  process.name == "lsass.exe" and
  not process.executable : ("*\\svchost.exe", "*\\csrss.exe")
'''

[rule.threat]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1003"
name = "OS Credential Dumping"
```

### Adım 7: Version Control and CI/CD Integration

Store rules in Git with automated testing:

```yaml
name: Sigma Rule CI
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-      - run: pip install pySigma pySigma-validators-sigmaHQ
      - run: sigma check rules/
      - run: sigma convert -t splunk -p splunk_windows rules/ > /dev/null
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Sigma** | Vendor-agnostic Tespit rule format (YAML-based) that compiles to SIEM-specific queries via backends |
| **pySigma** | Python library replacing legacy sigmac for rule conversion, validation, and pipeline processing |
| **Backend** | pySigma plugin that translates Sigma Tespit logic into a target platform query language (SPL, KQL, Lucene) |
| **Pipeline** | Field mapping configuration that translates generic Sigma field names to SIEM-specific field names |
| **Logsource** | Sigma rule section defining the category (process_creation, network_connection) and product (windows, linux) of the target data |
| **Tespit-as-Code** | Practice of managing Tespit rules in version control with CI/CD testing and automated Dağıt:ment |

## Tools & Systems

- **SigmaHQ**: Official Sigma rule repository with 3,000+ community-maintained Tespit rules on GitHub
- **pySigma**: Python-based Sigma rule processing framework with modular backends and pipelines
- **ATT&CK Navigator**: MITRE tool for visualizing Tespit coverage mapped to ATT&CK techniques
- **Uncoder.IO**: Web-based Sigma rule converter supporting 30+ SIEM platforms for quick translation

## Common Scenarios

- **New CVE Tespit**: Write Sigma rule for exploitation indicators (e.g., Log4Shell JNDI lookup patterns in web logs)
- **Hunting Rule Promotion**: Convert ad-hoc Splunk hunting query into Sigma rule for ongoing automated Tespit
- **Multi-SIEM Migration**: Converting 500+ Splunk correlation searches to Sigma for migration to Elastic Security
- **Purple Team Output**: Convert red team Bul:ings into Sigma rules for immediate defensive coverage
- **Threat Intel Operationalization**: Transform IOC-based threat reports into behavioral Sigma rules

## Output Format

```
SIGMA RULE Dağıt:MENT REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Rule ID:      0d894093-71bc-43c3-8d63-bf520e73a7c5
Title:        Mimikatz Credential Dumping via LSASS Access
ATT&CK:       T1003.001 - LSASS Memory
Severity:     High
Status:       Dağıtılmış to Production

Conversions:
  Splunk SPL:    PASS — Saved search "sigma_lsass_access" created
  Elastic EQL:   PASS — Tespit rule ID elastic-0d894093 enabled
  Sentinel KQL:  PASS — Analytics rule Dağıtılmış via ARM template

Testing:
  True Positives:    4/4 test cases matched
  False Positives:   2 in 7-day backtest (svchost edge case — filter added)
  Performance:       Avg execution 3.2s on 50M events/day
```
