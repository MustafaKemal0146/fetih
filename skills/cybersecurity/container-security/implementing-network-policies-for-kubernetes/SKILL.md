---
name: implementing-network-policies-for-kubernetes
description: Kubernetes NetworkPolicies provide pod-level network segmentation by defining ingress and egress rules that control traffic flow between pods, namespaces, and external endpoints. Combined with
  CNI plu
tags:
- microsegmentation
- security
- network-policies
- container-security
- fetih
- cybersecurity
- kubernetes
- siber-güvenlik
- containers
triggers:
- api
- cloud
- dns
- endpoint
- http
- implementing
- kubernetes
- network
- policies
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
---

# Implementing Network Policies for Kubernetes


## Genel Bakış

Kubernetes NetworkPolicies provide pod-level network segmentation by defining ingress and egress rules that control traffic flow between pods, namespaces, and external endpoints. Combined with CNI plugins like Calico or Cilium, network policies enforce zero-trust microsegmentation to prevent lateral movement within the cluster.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing network policies for kubernetes capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Kubernetes cluster with NetworkPolicy-supporting CNI (Calico, Cilium, Antrea)
- kubectl configured with admin access
- Understanding of pod labels and selectors

## İş Akışı

### Adım 1: Default Deny All Traffic

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # Applies to all pods
  policyTypes:
    - Ingress
    - Egress
```

### Adım 2: Allow DNS Egress (Required for Service Discovery)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Adım 3: Application-Specific Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-allow-frontend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-allow-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: backend
      ports:
        - protocol: TCP
          port: 5432
```

### Adım 4: Cross-Namespace Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring-scrape
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              purpose: monitoring
      ports:
        - protocol: TCP
          port: 9090  # Prometheus metrics port
```

### Adım 5: Egress Restrictions

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
    - to:  # Allow external API
        - ipBlock:
            cidr: 203.0.113.0/24
      ports:
        - protocol: TCP
          port: 443
    - to:  # DNS
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
```

### Adım 6: Block Cloud Metadata Access

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32  # AWS/GCP metadata
              - 100.100.100.200/32  # Azure metadata
```

## Doğrulama Commands

```bash
kubectl get networkpolicies -n production

kubectl run test-pod --image=busybox --restart=Never -n production -- wget -qO- --timeout=2 http://database-service:5432

kubectl run frontend-test --image=busybox --labels=app=frontend --restart=Never -n production -- wget -qO- --timeout=2 http://backend-service:8080
```

## References

- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Calico Network Policies](https://docs.tigera.io/calico/latest/network-policy/)
- [Cilium Network Policies](https://docs.cilium.io/en/stable/security/policy/)
- [Network Policy Editor](https://editor.networkpolicy.io/)
