---
name: scanning-kubernetes-manifests-with-kubesec
description: Perform security risk analysis on Kubernetes resource manifests using Kubesec to identify misconfigurations, privilege escalation risks, and deviations from security best practices.
tags:
- kubesec
- cybersecurity
- ci-cd
- misconfiguration
- security-scanning
- container-security
- fetih
- devsecops
- manifest-scanning
- kubernetes
- siber-güvenlik
- static-analysis
triggers:
- api
- container
- endpoint
- exploit
- http
- incident
- kubernetes
- kubesec
- manifests
- network
- scanning
- web
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Scanning Kubernetes Manifests with Kubesec


## Genel Bakış

Kubesec is an open-source security risk analysis tool developed by ControlPlane that Denetle:s Kubernetes resource manifests for common exploitable risks such as privilege escalation, writable host mounts, and excessive capabilities. It assigns a numerical security score to each resource and provides actionable recommendations for hardening. Kubesec can be used as a CLI binary, Docker container, kubectl plugin, admission webhook, or REST API endpoint.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve scanning kubernetes manifests with kubesec
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Kubernetes manifest files (YAML/JSON) for Dağıt:ments, Pods, DaemonSets, StatefulSets
- Docker or Go runtime for local installation
- kubectl access for scanning live cluster resources
- CI/CD pipeline access for automated scanning integration

## Core Concepts

### Security Scoring System

Kubesec assigns a score to each Kubernetes resource based on security checks:

- **Positive scores**: Awarded for security-enhancing configurations (readOnlyRootFilesystem, runAsNonRoot)
- **Zero or negative scores**: Indicate missing security controls or dangerous configurations
- **Critical advisories**: Flagged configurations that represent immediate security risks

### Check Categories

1. **Privilege Controls**: Checks for privileged containers, host PID/network access, root execution
2. **Capabilities**: Identifies excessive Linux capabilities (SYS_ADMIN, NET_RAW)
3. **Volume Mounts**: tespit etme (s) dangerous host path mounts and writable sensitive paths
4. **Resource Limits**: Validates presence of CPU/memory resource constraints
5. **Security Context**: Verifies seccomp profiles, AppArmor annotations, SELinux contexts

## Kurulum

### Binary Installation

```bash
curl -sSL https://github.com/controlplaneio/kubesec/releases/latest/download/kubesec_linux_amd64.tar.gz | \
  tar xz -C /usr/local/bin/ kubesec

kubesec version
```

### Docker Installation

```bash
docker pull kubesec/kubesec:v2

docker run -i kubesec/kubesec:v2 scan /dev/stdin < Dağıt:ment.yaml
```

### kubectl Plugin

```bash
kubectl krew install kubesec-scan
kubectl kubesec-scan pod mypod -n default
```

## Practical Scanning

### Scanning a Single Manifest

```bash
kubesec scan Dağıt:ment.yaml

kubesec scan -o json Dağıt:ment.yaml

cat pod.yaml | kubesec scan -
```

### Sample Output

```json
[
  {
    "object": "Pod/web-app.default",
    "valid": true,
    "fileName": "pod.yaml",
    "message": "Passed with a score of 3 points",
    "score": 3,
    "scoring": {
      "passed": [
        {
          "id": "ReadOnlyRootFilesystem",
          "selector": "containers[] .securityContext .readOnlyRootFilesystem == true",
          "reason": "An immutable root filesystem prevents applications from writing to their local disk",
          "points": 1
        },
        {
          "id": "RunAsNonRoot",
          "selector": "containers[] .securityContext .runAsNonRoot == true",
          "reason": "Force the running image to run as a non-root user",
          "points": 1
        },
        {
          "id": "LimitsCPU",
          "selector": "containers[] .resources .limits .cpu",
          "reason": "Enforcing CPU limits prevents DOS via resource exhaustion",
          "points": 1
        }
      ],
      "advise": [
        {
          "id": "ApparmorAny",
          "selector": "metadata .annotations .\"container.apparmor.security.beta.kubernetes.io/nginx\"",
          "reason": "Well defined AppArmor policies reduce the attack surface of the container",
          "points": 3
        },
        {
          "id": "ServiceAccountName",
          "selector": ".spec .serviceAccountName",
          "reason": "Service accounts restrict Kubernetes API access and should be configured",
          "points": 3
        }
      ]
    }
  }
]
```

### Scanning Multiple Resources

```bash
for file in manifests/*.yaml; do
  echo "=== Scanning $file ==="
  kubesec scan "$file"
done

kubesec scan multi-resource.yaml
```

### Using the HTTP API

```bash
curl -sSX POST --data-binary @Dağıt:ment.yaml \
  https://v2.kubesec.io/scan

kubesec http --port 8080 &

curl -sSX POST --data-binary @Dağıt:ment.yaml \
  http://localhost:8080/scan
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Kubesec Scan
on: [pull_request]
jobs:
  kubesec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Kubesec
        run: |
          curl -sSL https://github.com/controlplaneio/kubesec/releases/latest/download/kubesec_linux_amd64.tar.gz | \
            tar xz -C /usr/local/bin/ kubesec
      - name: Scan Manifests
        run: |
          FAIL=0
          for file in k8s/*.yaml; do
            SCORE=$(kubesec scan "$file" | jq '.[0].score')
            echo "$file: score=$SCORE"
            if [ "$SCORE" -lt 0 ]; then
              echo "FAIL: $file has critical issues (score: $SCORE)"
              FAIL=1
            fi
          done
          exit $FAIL
```

### GitLab CI

```yaml
kubesec-scan:
  stage: security
  image: kubesec/kubesec:v2
  script:
    - |
      for file in k8s/*.yaml; do
        kubesec scan "$file" > /tmp/result.json
        SCORE=$(cat /tmp/result.json | jq '.[0].score')
        if [ "$SCORE" -lt 0 ]; then
          echo "CRITICAL: $file scored $SCORE"
          cat /tmp/result.json | jq '.[0].scoring.critical'
          exit 1
        fi
      done
  artifacts:
    paths:
      - kubesec-results/
```

### Admission Webhook

Dağıt: Kubesec as a ValidatingWebhookConfiguration to reject insecure manifests at Dağıt: time:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: kubesec-webhook
webhooks:
  - name: kubesec.controlplane.io
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["Dağıt:ments", "daemonsets", "statefulsets"]
    clientConfig:
      service:
        name: kubesec-webhook
        namespace: kube-system
        path: /scan
    failurePolicy: Fail
    sideEffects: None
    admissionReviewVersions: ["v1"]
```

## Security Checks Reference

### Critical Checks (Negative Score)

| Check | Selector | Risk |
|-------|----------|------|
| Privileged | `securityContext.privileged == true` | Full host access |
| HostPID | `spec.hostPID == true` | Process namespace escape |
| HostNetwork | `spec.hostNetwork == true` | Network namespace escape |
| SYS_ADMIN | `capabilities.add contains SYS_ADMIN` | Near-root capability |

### Best Practice Checks (Positive Score)

| Check | Points | Description |
|-------|--------|-------------|
| ReadOnlyRootFilesystem | +1 | Prevents filesystem writes |
| RunAsNonRoot | +1 | Non-root process execution |
| RunAsUser > 10000 | +1 | High UID reduces collision risk |
| LimitsCPU | +1 | Prevents CPU resource exhaustion |
| LimitsMemory | +1 | Prevents memory resource exhaustion |
| RequestsCPU | +1 | Ensures scheduler resource awareness |
| ServiceAccountName | +3 | Explicit service account |
| AppArmor annotation | +3 | Kernel-level MAC enforcement |
| Seccomp profile | +4 | Syscall filtering |

## References

- [Kubesec GitHub Repository](https://github.com/controlplaneio/kubesec)
- [Kubesec Online Scanner](https://kubesec.io/)
- [ControlPlane Security Tools](https://controlplane.io/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: a4aeb2b1aa667874
-->

