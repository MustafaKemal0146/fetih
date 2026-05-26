---
name: implementing-kubernetes-pod-security-standards
description: Pod Security Standards (PSS) define three levels of security policies -- Privileged, Baseline, and Restricted -- enforced by the Pod Security Admission (PSA) controller built into Kubernetes
  1.25+. PS
tags:
- security
- container-security
- fetih
- PSA
- cybersecurity
- pod-security
- kubernetes
- siber-güvenlik
- containers
triggers:
- api
- container
- http
- implementing
- kubernetes
- log
- network
- security
- standards
- token
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Implementing Kubernetes Pod Security Standards


## Genel Bakış

Pod Security Standards (PSS) define three levels of security policies -- Privileged, Baseline, and Restricted -- enforced by the Pod Security Admission (PSA) controller built into Kubernetes 1.25+. PSA replaces the deprecated PodSecurityPolicy and provides namespace-level enforcement with three modes: enforce, audit, and warn.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing kubernetes pod security standards capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Kubernetes cluster 1.25+ (PSA GA)
- kubectl configured with cluster-admin access
- Understanding of Linux capabilities and security contexts

## Core Concepts

### Three Security Profiles

| Profile | Purpose | Restrictions |
|---------|---------|-------------|
| **Privileged** | Unrestricted, system workloads | None |
| **Baseline** | Prevents known escalations | No hostNetwork, hostPID, hostIPC, privileged containers, dangerous capabilities |
| **Restricted** | Hardened best practices | Non-root, drop ALL caps, seccomp required, read-only rootfs recommended |

### Three Enforcement Modes

| Mode | Behavior |
|------|----------|
| **enforce** | Rejects pods that violate the policy |
| **audit** | Logs violations in audit log but allows pod |
| **warn** | Returns warning to user but allows pod |

## İş Akışı

### Adım 1: Label Namespaces for PSA

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-```

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-```

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/enforce-```

### Adım 2: Apply Labels to Existing Namespaces

```bash
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

kubectl label namespace staging \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

kubectl get namespaces -L pod-security.kubernetes.io/enforce
```

### Adım 3: Create Compliant Pod Specs

```yaml
apiVersion: apps/v1
kind: Dağıt:ment
metadata:
  name: secure-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: myregistry.com/myapp:v1.0.0@sha256:abc123
          ports:
            - containerPort: 8080
              protocol: TCP
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
            runAsNonRoot: true
            runAsUser: 65534
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "256Mi"
              cpu: "500m"
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /var/cache
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
        - name: cache
          emptyDir:
            sizeLimit: 50Mi
```

### Adım 4: Gradual Migration Strategy

```bash
kubectl label namespace my-namespace \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

kubectl logs -n kube-system -l component=kube-apiserver | grep "pod-security"

kubectl label namespace my-namespace \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

kubectl label namespace my-namespace \
  pod-security.kubernetes.io/enforce=restricted \
  --overwrite
```

### Adım 5: Dry-Run Enforcement Testing

```bash
kubectl label --dry-run=server --overwrite namespace my-namespace \
  pod-security.kubernetes.io/enforce=restricted

```

## Baseline Profile Restrictions

| Control | Restricted | Requirement |
|---------|-----------|-------------|
| HostProcess | Must not set | Pods cannot use Windows HostProcess |
| Host Namespaces | Must not set | No hostNetwork, hostPID, hostIPC |
| Privileged | Must not set | No privileged: true |
| Capabilities | Baseline list only | Only NET_BIND_SERVICE, drop ALL for restricted |
| HostPath Volumes | Must not use | No hostPath volume mounts |
| Host Ports | Must not use | No hostPort in container spec |
| AppArmor | Default/runtime | Cannot set to unconfined |
| SELinux | Limited types | Only container_t, container_init_t, container_kvm_t |
| /proc Mount Type | Default only | Must use Default proc mount |
| Seccomp | RuntimeDefault or Localhost | Must specify seccomp profile (restricted) |
| Sysctls | Safe set only | Limited to safe sysctls |

## Doğrulama Commands

```bash
kubectl get ns --show-labels | grep pod-security

kubectl run test-pod --image=nginx --namespace=production --dry-run=server

kubectl get events --field-selector reason=FailedCreate -A

kubescape scan framework nsa --namespace production
```

## References

- [Pod Security Standards - Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Pod Security Admission - Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Migrate from PodSecurityPolicy](https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/)
- [Kubescape PSS Scanner](https://github.com/kubescape/kubescape)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: ee7d4b70edf462f4
-->

