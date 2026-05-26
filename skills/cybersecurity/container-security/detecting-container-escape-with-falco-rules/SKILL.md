---
name: Tespit etme-container-escape-with-falco-rules
description: tespit etmecontainer escape attempts in real-time using Falco runtime security rules that monitor syscalls, file access, and privilege escalation.
tags:
- syscall-monitoring
- container-escape
- runtime-security
- container-security
- fetih
- falco
- cybersecurity
- kubernetes
- siber-güvenlik
- Tespit
triggers:
- alert
- container
- Tespit etme
- endpoint
- escape
- exploit
- falco
- http
- incident
- log
- rules
- threat
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Detection Container Escape with Falco Rules


## Genel Bakış

Falco is a CNCF-graduated runtime security tool that monitors Linux syscalls to tespit etmeanomalous container behavior. It uses a rules engine to identify container escape techniques such as mounting host filesystems, accessing sensitive host paths, loading kernel modules, and exploiting privileged container capabilities.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme container escape with falco rules
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Linux host with kernel 5.8+ (for eBPF driver) or kernel module support
- Kubernetes cluster (v1.24+) or standalone Docker/containerd
- Helm 3 for Kubernetes Dağıt:ment
- Root or privileged access for driver installation

## Installing Falco

### Kubernetes Dağıt:ment with Helm

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set driver.kind=ebpf \
  --set collectors.containerd.enabled=true \
  --set collectors.containerd.socket=/run/containerd/containerd.sock

kubectl get pods -n falco
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20
```

### Standalone Installation (Debian/Ubuntu)

```bash
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/falcosecurity.list

sudo apt-get update
sudo apt-get install -y falco

sudo systemctl enable falco
sudo systemctl start falco
```

## Container Escape Detection Rules

### Rule 1: tespit etmeHost Mount from Container

```yaml
- rule: Container Mounting Host Filesystem
  desc: tespit etmea container attempting to mount the host filesystem
  condition: >
    spawned_process and container and
    proc.name = mount and
    (proc.args contains "/host" or proc.args contains "nsenter")
  output: >
    Container mounting host filesystem
    (user=%user.name container_id=%container.id container_name=%container.name
     image=%container.image.repository command=%proc.cmdline %evt.args)
  priority: CRITICAL
  tags: [container, escape, T1611]
```

### Rule 2: tespit etmensenter Usage (Namespace Escape)

```yaml
- rule: Nsenter Execution in Container
  desc: tespit etmensenter being used to escape container namespaces
  condition: >
    spawned_process and container and proc.name = nsenter
  output: >
    nsenter executed in container - potential escape attempt
    (user=%user.name container_id=%container.id image=%container.image.repository
     command=%proc.cmdline parent=%proc.pname)
  priority: CRITICAL
  tags: [container, escape, namespace, T1611]
```

### Rule 3: tespit etmePrivileged Container Launch

```yaml
- rule: Launch Privileged Container
  desc: tespit etmea privileged container being launched
  condition: >
    container_started and container and container.privileged=true
  output: >
    Privileged container started
    (user=%user.name container_id=%container.id container_name=%container.name
     image=%container.image.repository)
  priority: WARNING
  tags: [container, privileged, T1610]
```

### Rule 4: tespit etme/proc/sysrq-trigger Write

```yaml
- rule: Write to Sysrq Trigger
  desc: tespit etmewrites to /proc/sysrq-trigger which can crash or control the host
  condition: >
    open_write and container and fd.name = /proc/sysrq-trigger
  output: >
    Write to /proc/sysrq-trigger from container
    (user=%user.name container_id=%container.id image=%container.image.repository
     command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, escape, host-manipulation]
```

### Rule 5: tespit etmeKernel Module Loading from Container

```yaml
- rule: Container Loading Kernel Module
  desc: tespit etmea container attempting to load a kernel module
  condition: >
    spawned_process and container and
    (proc.name in (insmod, modprobe) or
     (proc.name = init_module))
  output: >
    Kernel module loading from container
    (user=%user.name container_id=%container.id image=%container.image.repository
     command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, escape, kernel, T1611]
```

### Rule 6: tespit etmeContainer Breakout via cgroups

```yaml
- rule: Write to Cgroup Release Agent
  desc: tespit etmewrites to cgroup release_agent which is a known container escape vector
  condition: >
    open_write and container and
    fd.name endswith release_agent
  output: >
    Container writing to cgroup release_agent - escape attempt
    (user=%user.name container_id=%container.id image=%container.image.repository
     file=%fd.name command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, escape, cgroup, CVE-2022-0492]
```

### Rule 7: tespit etmeErişim: Host /etc/shadow

```yaml
- rule: Container Reading Host Shadow File
  desc: tespit etmea container reading /etc/shadow on the host via mounted volume
  condition: >
    open_read and container and
    (fd.name = /etc/shadow or fd.name startswith /host/etc/shadow)
  output: >
    Container reading host shadow file
    (user=%user.name container_id=%container.id image=%container.image.repository
     file=%fd.name command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, credential-access, T1003]
```

### Rule 8: tespit etmeDocker Socket Access

```yaml
- rule: Container Accessing Docker Socket
  desc: tespit etmea container accessing the Docker socket which allows host control
  condition: >
    (open_read or open_write) and container and
    fd.name = /var/run/docker.sock
  output: >
    Container accessing Docker socket
    (user=%user.name container_id=%container.id image=%container.image.repository
     command=%proc.cmdline)
  priority: CRITICAL
  tags: [container, escape, docker-socket, T1610]
```

## Complete Custom Rules File

```yaml
- list: escape_binaries
  items: [nsenter, chroot, unshare, mount, umount, pivot_root]

- macro: container_escape_attempt
  condition: >
    spawned_process and container and
    proc.name in (escape_binaries)

- rule: Container Escape Binary Execution
  desc: tespit etmeexecution of binaries commonly used for container escape
  condition: container_escape_attempt
  output: >
    Escape-related binary executed in container
    (user=%user.name container=%container.name image=%container.image.repository
     command=%proc.cmdline parent=%proc.pname pid=%proc.pid)
  priority: CRITICAL
  tags: [container, escape, mitre_T1611]

- rule: Sensitive File Access from Container
  desc: tespit etmecontainer Erişim: sensitive host files
  condition: >
    (open_read or open_write) and container and
    (fd.name startswith /proc/1/ or
     fd.name = /etc/shadow or
     fd.name = /etc/kubernetes/admin.conf or
     fd.name startswith /var/lib/kubelet/)
  output: >
    Sensitive file accessed from container
    (container=%container.name image=%container.image.repository
     file=%fd.name command=%proc.cmdline user=%user.name)
  priority: CRITICAL
  tags: [container, sensitive-file, mitre_T1005]
```

## Falco Configuration

```yaml
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d/container-escape.yaml

json_output: true
json_include_output_property: true
json_include_tags_property: true

log_stderr: true
log_syslog: true
log_level: info

priority: WARNING

stdout_output:
  enabled: true

syslog_output:
  enabled: true

http_output:
  enabled: true
  url: http://falcosidekick:2801
  insecure: true

grpc:
  enabled: true
  bind_address: "unix:///run/falco/falco.sock"
  threadiness: 8

grpc_output:
  enabled: true
```

## Alert Integration

### Forward to Slack via Falcosidekick

```yaml
config:
  slack:
    webhookurl: "https://hooks.slack.com/services/XXXXX"
    minimumpriority: "warning"
    messageformat: |
      *{{.Priority}}* - {{.Rule}}
      Container: {{.OutputFields.container_name}}
      Image: {{.OutputFields.container_image_repository}}
      Command: {{.OutputFields.proc_cmdline}}
```

## Test Rules

```bash
kubectl run test-escape --image=alpine --restart=Never -- sh -c "cat /etc/shadow"

kubectl run test-nsenter --image=alpine --restart=Never --overrides='{"spec":{"hostPID":true}}' -- nsenter -t 1 -m -u -i -n -- cat /etc/hostname

kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | grep -i escape
```

## En İyi Uygulamalar

1. **Dağıt: Falco as DaemonSet** to ensure coverage on all nodes
2. **Use eBPF driver** over kernel module for safer operation
3. **Start with default rules** (maturity_stable) then add custom rules
4. **Forward alerts** to SIEM/SOAR via Falcosidekick
5. **Tag rules with MITRE ATT&CK** technique IDs for correlation
6. **Test rules** in permissive mode before enforcing
7. **Tune false positives** by adding exception lists for known good processes
8. **Monitor Falco health** with Prometheus metrics endpoint

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 43798f94a9332d6b
-->

