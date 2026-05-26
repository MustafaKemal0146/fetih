---
name: implementing-kubernetes-network-policy-with-calico
description: Implement Kubernetes network segmentation using Calico NetworkPolicy and GlobalNetworkPolicy for zero-trust pod-to-pod communication.
tags:
- network-policy
- calico
- network-segmentation
- cni
- container-security
- fetih
- cybersecurity
- zero-trust
- kubernetes
- siber-güvenlik
triggers:
- api
- calico
- dns
- endpoint
- http
- implementing
- kubernetes
- log
- network
- policy
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Implementing Kubernetes Network Policy with Calico


## Genel Bakış

Calico is an open-source CNI plugin that provides fine-grained network policy enforcement for Kubernetes clusters. It implements the full Kubernetes NetworkPolicy API and extends it with Calico-specific GlobalNetworkPolicy, supporting policy ordering, deny rules, and service-account-based selectors.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing kubernetes network policy with calico capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Kubernetes cluster (v1.24+)
- Calico CNI kurulu (v3.26+)
- `kubectl` and `calicoctl` CLI tools
- Cluster admin RBAC permissions

## Installing Calico

### Operator-based Installation (Recommended)

```bash
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/tigera-operator.yaml

kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/custom-resources.yaml

kubectl get pods -n calico-system
watch kubectl get pods -n calico-system

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calicoctl.yaml
```

### Verify Calico is Running

```bash
kubectl get pods -n calico-system

kubectl exec -n calico-system calicoctl -- calicoctl node status

kubectl exec -n calico-system calicoctl -- calicoctl get ippool -o wide
```

## Kubernetes NetworkPolicy

### Default Deny All Traffic

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
```

### Allow Specific Pod-to-Pod Communication

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
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
```

### Allow DNS Egress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Namespace Isolation

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector: {}
```

## Calico-Specific Policies

### GlobalNetworkPolicy (Cluster-Wide)

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-external-ingress
spec:
  order: 100
  selector: "projectcalico.org/namespace != 'ingress-nginx'"
  types:
    - Ingress
  ingress:
    - action: Deny
      source:
        nets:
          - 0.0.0.0/0
      destination: {}
```

### Calico NetworkPolicy with Deny Rules

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: deny-database-from-frontend
  namespace: production
spec:
  order: 10
  selector: app == 'database'
  types:
    - Ingress
  ingress:
    - action: Deny
      source:
        selector: app == 'frontend'
    - action: Allow
      source:
        selector: app == 'backend'
      destination:
        ports:
          - 5432
```

### Service Account Based Policy

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-by-service-account
  namespace: production
spec:
  selector: app == 'api'
  ingress:
    - action: Allow
      source:
        serviceAccounts:
          names:
            - frontend-sa
            - monitoring-sa
  egress:
    - action: Allow
      destination:
        serviceAccounts:
          names:
            - database-sa
```

### Host Endpoint Protection

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: restrict-host-ssh
spec:
  order: 10
  selector: "has(kubernetes.io/hostname)"
  applyOnForward: false
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        nets:
          - 10.0.0.0/8
      destination:
        ports:
          - 22
    - action: Deny
      protocol: TCP
      destination:
        ports:
          - 22
```

## Calico Policy Tiers

```yaml
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: security
spec:
  order: 100

---
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: platform
spec:
  order: 200
```

## Monitoring and Troubleshooting

```bash
kubectl get networkpolicy --all-namespaces

kubectl exec -n calico-system calicoctl -- calicoctl get networkpolicy --all-namespaces -o wide
kubectl exec -n calico-system calicoctl -- calicoctl get globalnetworkpolicy -o wide

kubectl exec -n calico-system calicoctl -- calicoctl get workloadendpoint -n production -o yaml

kubectl logs -n calico-system -l k8s-app=calico-node --tail=100

kubectl exec -n production frontend-pod -- wget -qO- --timeout=2 http://backend-svc:8080/health
```

## En İyi Uygulamalar

1. **Start with default deny** - Apply deny-all policies to every namespace, then allow specific traffic
2. **Use labels consistently** - Define a labeling standard for app, tier, environment
3. **Order policies** - Use Calico policy ordering (`order` field) to control evaluation precedence
4. **Allow DNS first** - Always create DNS egress rules before applying egress deny policies
5. **Use GlobalNetworkPolicy** for cluster-wide security baselines
6. **Test policies in staging** - Validate network connectivity after applying policies
7. **Monitor denied traffic** - Enable Calico flow logs for visibility into blocked connections
8. **Use tiers** - Organize policies into security, platform, and application tiers

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 6f728d84fa7ff1e4
-->

