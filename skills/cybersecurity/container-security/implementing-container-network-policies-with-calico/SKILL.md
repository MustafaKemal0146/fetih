---
name: implementing-container-network-policies-with-calico
description: Enforce Kubernetes network segmentation using Calico CNI network policies and global network policies to control pod-to-pod traffic, restrict egress, and implement zero-trust microsegmentation.
tags:
- microsegmentation
- network-policy
- calico
- cni
- container-security
- fetih
- cybersecurity
- kubernetes
- siber-güvenlik
triggers:
- api
- calico
- container
- dns
- implementing
- network
- policies
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Implementing Container Network Policies with Calico


## Genel Bakış

Calico provides Kubernetes-native and extended network policy enforcement through its CNI plugin. bu skill covers creating and auditing Calico NetworkPolicy and GlobalNetworkPolicy resources to implement pod-to-pod traffic control, namespace isolation, egress restrictions, and DNS-based policy rules using calicoctl and the Kubernetes API.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing container network policies with calico capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Kubernetes cluster with Calico CNI installed
- Python 3.9+ with `kubernetes` client library
- calicoctl CLI tool installed and configured
- kubectl access with RBAC permissions for network policy management

## Adımlar

### Adım 1: Audit Existing Network Policies
Use calicoctl and kubectl to inventory current network policies and identify unprotected namespaces.

### Adım 2: Implement Default-Deny Policies
Create default-deny ingress and egress policies per namespace as a zero-trust baseline.

### Adım 3: Create Workload-Specific Allow Rules
Define granular allow rules for legitimate pod-to-pod and pod-to-service communication.

### Adım 4: Validate Policy Enforcement
Test connectivity between pods to verify policies are correctly enforced.

## Expected Output

JSON audit report listing all network policies, unprotected namespaces, policy rule counts, and connectivity test results.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 60292091daa88320
-->

