---
name: performing-container-escape-Tespit
description: tespit etme (s) container escape attempts by analyzing namespace configurations, privileged container checks, dangerous capability assignments, and host path mounts using the kubernetes Python client.
  Identifies CVE-2022-0492 style escapes via cgroup abuse. Use auditing yaparken container security posture or investigating escape attempts.
tags:
- escape
- container
- performing
- container-security
- fetih
- cybersecurity
- siber-güvenlik
- Tespit
triggers:
- api
- container
- Tespit
- escape
- incident
- network
- performing
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Performing Container Escape Detection


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing container escape Tespit
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with container security concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Audit Kubernetes pods for container escape vectors including privileged mode,
dangerous capabilities, host namespace sharing, and writable hostPath mounts.

```python
from kubernetes import client, config
config.load_kube_config()
v1 = client.CoreV1Api()

pods = v1.list_pod_for_all_namespaces()
for pod in pods.items:
    for container in pod.spec.containers:
        sc = container.security_context
        if sc and sc.privileged:
            print(f"PRIVILEGED: {pod.metadata.namespace}/{pod.metadata.name}")
```

Key escape vectors:
1. Privileged containers (full host access)
2. CAP_SYS_ADMIN capability
3. Host PID/Network/IPC namespace sharing
4. Writable hostPath mounts to / or /etc
5. Docker socket mount (/var/run/docker.sock)

## Örnekler

```python
for vol in pod.spec.volumes or []:
    if vol.host_path and "docker.sock" in (vol.host_path.path or ""):
        print(f"Docker socket exposed: {pod.metadata.name}")
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: a9ad82752f5d6922
-->

