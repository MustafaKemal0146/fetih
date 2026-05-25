---
name: analyzing-kubernetes-audit-logs
description: Parses Kubernetes API server audit logs (JSON lines) to tespit etmeexec-into-pod, secret access, RBAC modifications, privileged pod creation, and anonymous API access. Builds threat Tespit rules
  from audit event patterns. Use investigating yaparken Kubernetes cluster compromise or building k8s-specific SIEM Tespit rules.
tags:
- analyzing
- container-security
- logs
- fetih
- audit
- cybersecurity
- kubernetes
- siber-güvenlik
triggers:
- analyzing
- audit
- container
- incident
- kubernetes
- log
- logs
- threat
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
---

# Analyzing Kubernetes Audit Logs


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing kubernetes audit logs
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Familiarity with container security concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Parse Kubernetes audit log files (JSON lines format) to tespit etmesecurity-relevant
events including unauthorized access, privilege escalation, and data exfiltration.

```python
import json

with open("/var/log/kubernetes/audit.log") as f:
    for line in f:
        event = json.loads(line)
        verb = event.get("verb")
        resource = event.get("objectRef", {}).get("resource")
        user = event.get("user", {}).get("username")
        if verb == "create" and resource == "pods/exec":
            print(f"Pod exec by {user}")
```

Key events to Detect:
1. pods/exec and pods/attach (shell into containers)
2. secrets access (get/list/watch)
3. clusterrolebindings creation (RBAC escalation)
4. Privileged pod creation
5. Anonymous or system:unauthenticated access

## Örnekler

```python
if verb in ("get", "list") and resource == "secrets":
    print(f"Secret access: {user} -> {event['objectRef'].get('name')}")
```
