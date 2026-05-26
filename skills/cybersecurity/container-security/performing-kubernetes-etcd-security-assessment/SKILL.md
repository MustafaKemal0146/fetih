---
name: performing-kubernetes-etcd-security-assessment
description: Assess the security posture of Kubernetes etcd clusters by evaluating encryption at rest, TLS configuration, access controls, backup encryption, and network isolation.
tags:
- secrets
- control-plane
- etcd
- backup
- security-assessment
- container-security
- encryption
- fetih
- cybersecurity
- kubernetes
- siber-güvenlik
- tls
triggers:
- api
- assessment
- authentication
- certificate
- crypto
- encryption
- endpoint
- etcd
- http
- incident
- kubernetes
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

# Performing Kubernetes Etcd Security Assessment


## Genel Bakış

etcd is the distributed key-value store that serves as Kubernetes' backing store for all cluster data, including Secrets, RBAC policies, ConfigMaps, and workload configurations. Without proper hardening, etcd exposes all cluster secrets in plaintext, making it the highest-value target for attackers who gain control plane access. A comprehensive security assessment covers encryption at rest, TLS for transport, access control, backup security, and network isolation.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing kubernetes etcd security assessment
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Erişim: Kubernetes control plane nodes
- SSH Erişim: etcd cluster nodes (or etcdctl configured)
- CIS Kubernetes Benchmark reference document
- Understanding of TLS certificate management and EncryptionConfiguration

## Assessment Areas

### 1. Encryption at Rest

Şunu doğrula: Kubernetes encrypts Secret data stored in etcd:

```bash
ps aux | grep kube-apiserver | grep encryption-provider-config

cat /etc/kubernetes/enc/encryption-config.yaml
```

Expected secure configuration:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}  # Fallback for reading unencrypted data
```

Verify secrets are actually encrypted in etcd:

```bash
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/my-secret | hexdump -C | head -20

```

### 2. TLS Transport Security

```bash
ETCDCTL_API=3 etcdctl endpoint health \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

ps aux | grep etcd | tr ' ' '\n' | grep -E "peer-cert|peer-key|peer-trusted-ca"

openssl x509 -in /etc/kubernetes/pki/etcd/server.crt -noout -enddate
openssl x509 -in /etc/kubernetes/pki/etcd/peer.crt -noout -enddate
```

Expected flags:

| Flag | Required Value | Purpose |
|------|---------------|---------|
| `--cert-file` | Path to server cert | Client-to-server TLS |
| `--key-file` | Path to server key | Client-to-server TLS |
| `--trusted-ca-file` | Path to CA cert | Client certificate validation |
| `--peer-cert-file` | Path to peer cert | Peer-to-peer TLS |
| `--peer-key-file` | Path to peer key | Peer-to-peer TLS |
| `--peer-trusted-ca-file` | Path to peer CA | Peer certificate validation |
| `--client-cert-auth` | true | Require client certificates |
| `--peer-client-cert-auth` | true | Require peer certificates |

### 3. Access Control

```bash
ps aux | grep etcd | tr ' ' '\n' | grep listen-client-urls

ls -la /etc/kubernetes/pki/etcd/

ss -tlnp | grep 2379
```

### 4. Backup Security

```bash
ETCDCTL_API=3 etcdctl snapshot save /backup/etcd-snapshot.db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

gpg --symmetric --cipher-algo AES256 /backup/etcd-snapshot.db

ETCDCTL_API=3 etcdctl snapshot status /backup/etcd-snapshot.db --write-out=table
```

### 5. Network Isolation

```bash
iptables -L -n | grep -E "2379|2380"

curl -k https://<control-plane-ip>:2379/health
```

## CIS Benchmark Checks

| CIS Control | Check | Expected Result |
|-------------|-------|----------------|
| 2.1 | etcd cert-file set | TLS certificate configured |
| 2.2 | etcd client-cert-auth | Client certificate authentication enabled |
| 2.3 | etcd auto-tls disabled | auto-tls=false |
| 2.4 | etcd peer cert-file set | Peer TLS configured |
| 2.5 | etcd peer client-cert-auth | Peer authentication enabled |
| 2.6 | etcd peer auto-tls disabled | peer-auto-tls=false |
| 2.7 | etcd unique CA | Separate CA for etcd (not shared with cluster) |

## Key Rotation Procedure

```bash
NEW_KEY=$(head -c 32 /dev/urandom | base64)

cat > /etc/kubernetes/enc/encryption-config.yaml <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key2
              secret: ${NEW_KEY}
            - name: key1
              secret: <old-key>
      - identity: {}
EOF

kubectl get secrets --all-namespaces -o json | \
  kubectl replace -f -

```

## References

- [Kubernetes etcd Encryption Documentation](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [CIS Kubernetes Benchmark - etcd Controls](https://www.cisecurity.org/benchmark/kubernetes)
- [Securing etcd - K8s Security Guide](https://k8s-security.geek-kb.com/docs/best_practices/cluster_setup_and_hardening/control_plane_security/etcd_security_mitigation/)
- [Infosec: Encryption and etcd](https://www.infosecinstitute.com/resources/cryptography/encryption-and-etcd-the-key-to-securing-kubernetes/)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 29445bd6d28714f8
-->

