---
name: Tespit etme-supply-chain-attacks-in-ci-cd
description: Scans GitHub Actions workflows and CI/CD pipeline configurations for supply chain attack vectors including unpinned actions, script injection via expressions, dependency confusion, and secrets
  exposure. Uses PyGithub and YAML parsing for automated audit. Use hardening yaparken CI/CD pipelines or investigating compromised build systems.
tags:
- soc-operations
- chain
- security-operations
- fetih
- Tespit etme
- supply
- attacks
- cybersecurity
- siber-güvenlik
triggers:
- attacks
- chain
- Tespit etme
- incident
- supply
- threat
- token
category: soc-operations
source_subdomain: security-operations
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---

# Detection Supply Chain Attacks in Ci Cd


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme supply chain attacks in ci cd
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with security operations concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Scan CI/CD workflow files for supply chain risks by parsing GitHub Actions YAML,
checking for unpinned dependencies, script injection vectors, and secrets exposure.

```python
import yaml
from pathlib import Path

for wf in Path(".github/workflows").glob("*.yml"):
    with open(wf) as f:
        workflow = yaml.safe_load(f)
    for job_name, job in workflow.get("jobs", {}).items():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if uses and "@" in uses and not uses.split("@")[1].startswith("sha"):
                print(f"Unpinned action: {uses} in {wf.name}")
```

Key supply chain risks:
1. Unpinned GitHub Actions (using @main instead of SHA)
2. Script injection via ${{ github.event }} expressions
3. Overly permissive GITHUB_TOKEN permissions
4. Third-party actions with write Erişim: repo
5. Dependency confusion via public/private package name collision

## Örnekler

```python
for step in job.get("steps", []):
    run_cmd = step.get("run", "")
    if "${{" in run_cmd and "github.event" in run_cmd:
        print(f"Script injection risk: {run_cmd[:80]}")
```
