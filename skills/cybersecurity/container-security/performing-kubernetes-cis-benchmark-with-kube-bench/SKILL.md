---
name: performing-kubernetes-cis-benchmark-with-kube-bench
description: Audit Kubernetes cluster security posture against CIS benchmarks using kube-bench with automated checks for control plane, worker nodes, and RBAC.
tags:
- cybersecurity
- aquasecurity
- cis-benchmark
- container-security
- fetih
- kube-bench
- compliance
- kubernetes
- hardening
- siber-güvenlik
triggers:
- api
- authentication
- bench
- benchmark
- container
- encryption
- http
- incident
- kube
- kubernetes
- log
- network
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Performing Kubernetes Cis Benchmark with Kube Bench


## Genel Bakış

kube-bench is an open-source Go tool by Aqua Security that runs the CIS Kubernetes Benchmark checks. It verifies control plane, etcd, worker node, and policy configurations against security best practices, producing actionable pass/fail/warn reports.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing kubernetes cis benchmark with kube bench
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Kubernetes cluster (v1.24+)
- kubectl with cluster-admin access
- Node access for direct runs or privileged pod access

## Kurulum

```bash
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.7.3/kube-bench_0.7.3_linux_amd64.tar.gz | tar xz
sudo mv kube-bench /usr/local/bin/

kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-master.yaml
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-node.yaml
```

## Running Benchmarks

### Full Benchmark

```bash
kube-bench run

kube-bench run --json > kube-bench-results.json

kube-bench run --junit > kube-bench-results.xml
```

### Component-Specific Checks

```bash
kube-bench run --targets master

kube-bench run --targets node

kube-bench run --targets etcd

kube-bench run --targets policies

kube-bench run --targets master,etcd
```

### Managed Kubernetes

```bash
kube-bench run --benchmark eks-1.2.0

kube-bench run --benchmark gke-1.4.0

kube-bench run --benchmark aks-1.0

kube-bench run --benchmark rh-1.0
```

### Filtering Results

```bash
kube-bench run --targets master | grep "\[FAIL\]"

kube-bench run --check 1.2.1

kube-bench run --group 1.2
```

## CIS Benchmark Sections

| Section | Component | Key Checks |
|---------|-----------|------------|
| 1.1 | Control Plane - API Server | Anonymous auth, RBAC, audit logging |
| 1.2 | Control Plane - API Server | Admission controllers, encryption |
| 1.3 | Control Plane - Controller Manager | Service account tokens, bind address |
| 1.4 | Control Plane - Scheduler | Profiling, bind address |
| 2.1 | etcd | Client cert auth, peer encryption |
| 3.1 | Control Plane - Authentication | OIDC, client certs |
| 4.1 | Worker - kubelet | Anonymous auth, authorization |
| 4.2 | Worker - kubelet | TLS, read-only port |
| 5.1 | Policies - RBAC | Cluster-admin usage, service accounts |
| 5.2 | Policies - Pod Security | Privileged, host namespaces |
| 5.3 | Policies - Network | Network policies per namespace |
| 5.7 | Policies - General | Secrets, security context |

## Output Example

```
[INFO] 1 Control Plane Security Configuration
[INFO] 1.1 Control Plane Node Configuration Files
[PASS] 1.1.1 Şundan emin ol: the API server pod specification file permissions are set to 600
[PASS] 1.1.2 Şundan emin ol: the API server pod specification file ownership is set to root:root
[FAIL] 1.1.3 Şundan emin ol: the controller manager pod specification file permissions are set to 600
[WARN] 1.1.4 Şundan emin ol: the scheduler pod specification file permissions are set to 600

== Summary ==
45 checks PASS
12 checks FAIL
8 checks WARN
0 checks INFO
```

## CI/CD Integration

### GitHub Actions

```yaml
name: CIS Benchmark
on:
  schedule:
    - cron: '0 6 * * 1'

jobs:
  kube-bench:
    runs-on: ubuntu-latest
    steps:
      - name: Configure kubectl
        uses: azure/setup-kubectl@v3

      - name: Run kube-bench
        run: |
          kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
          kubectl wait --for=condition=complete job/kube-bench --timeout=120s
          kubectl logs job/kube-bench > kube-bench-report.txt

      - name: Check for failures
        run: |
          FAILS=$(grep -c "\[FAIL\]" kube-bench-report.txt || true)
          echo "Failed checks: $FAILS"
          if [ "$FAILS" -gt 0 ]; then
            echo "::warning::$FAILS CIS benchmark checks failed"
          fi

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: kube-bench-report
          path: kube-bench-report.txt
```

## İyileştirme Examples

### 1.2.1 - Ensure --anonymous-auth is set to false
```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --anonymous-auth=false
```

### 4.2.1 - Ensure --anonymous-auth is set to false on kubelet
```yaml
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
```

### 5.2.1 - Minimize wildcard RBAC
```bash
kubectl get clusterroles -o json | jq '.items[] | select(.rules[].resources[] == "*") | .metadata.name'
```

## En İyi Uygulamalar

1. **Run kube-bench before and after** cluster provisioning
2. **Schedule weekly scans** via CronJob for drift Tespit
3. **Export JSON** for SIEM/compliance reporting
4. **Fix FAIL items first**, then address WARN items
5. **Use benchmark profiles** matching your Kubernetes distribution
6. **Track score over time** to measure security posture improvement
7. **Combine with admission controllers** to prevent drift

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 99c9190ed31ccd91
-->

