---
name: performing-cloud-native-forensics-with-falco
description: Uses Falco YAML rules for runtime threat Tespit in containers and Kubernetes, monitoring syscalls for shell spawns, file tampering, network anomalies, and privilege escalation. Manages Falco
  rules via the Falco gRPC API and parses Falco alert output. Use building yaparken container runtime security or investigating k8s cluster compromises.
tags:
- native
- performing
- forensics
- fetih
- cloud-security
- cybersecurity
- siber-güvenlik
- cloud
triggers:
- AWS
- Azure
- GCP
- alert
- bulut güvenliği
- cloud
- cloud security
- container
- falco
- forensic
- forensics
- incident
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Performing Cloud Native Forensics with Falco


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing cloud native forensics with falco
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with cloud security concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Dağıt: and manage Falco rules for runtime security Tespit in containerized
environments. Parse Falco alerts for incident response.

```yaml
- rule: Shell Spawned in Container
  desc: tespit etmeshell process started in a container
  condition: >
    spawned_process and container
    and proc.name in (bash, sh, zsh, dash, csh)
    and not proc.pname in (docker-entrypo, supervisord)
  output: >
    Shell spawned in container
    (user=%user.name command=%proc.cmdline container=%container.name
     image=%container.image.repository)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

Key Tespit rules:
1. Shell spawn in non-interactive containers
2. Sensitive file access (/etc/shadow, /etc/passwd)
3. Outbound connections from unexpected containers
4. Privilege escalation via setuid/setgid
5. Container escape via mount or ptrace

## Örnekler

```bash
falco -r /etc/falco/custom_rules.yaml -o json_output=true
cat /var/log/falco/alerts.json | python3 -c "import json,sys; [print(json.loads(l)['output']) for l in sys.stdin]"
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 6b5db7dfb7a4bc27
-->

