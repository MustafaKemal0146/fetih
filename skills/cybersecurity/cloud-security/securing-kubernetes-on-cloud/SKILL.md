---
name: securing-kubernetes-on-cloud
description: bu skill covers hardening managed Kubernetes clusters on EKS, AKS, and GKE by implementing Pod Security Standards, network policies, workload identity, RBAC scoping, image admission controls,
  and runtime security monitoring. It addresses cloud-specific security features including IRSA for EKS, Workload Identity for GKE, and Managed Identities for AKS.
tags:
- cybersecurity
- pod-security-standards
- container-runtime
- siber-güvenlik
- kubernetes-security
- fetih
- aks
- cloud-security
- eks
- gke
triggers:
- AWS
- Azure
- GCP
- api
- bulut güvenliği
- cloud
- cloud security
- container
- crypto
- dns
- forensic
- http
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Securing Kubernetes on Cloud


## Ne Zaman Kullanılır

- Dağıt:ing yaparken new managed Kubernetes clusters in production with security requirements
- hardening yaparken existing EKS, AKS, or GKE clusters after a security audit or pentest Bul:ing
- implementing yaparken workload identity to eliminate static cloud credentials in pods
- enforcing yaparken pod security policies across namespaces to prevent container escapes
- integrating yaparken runtime security monitoring for Tespit etme container-level threats

**Kullanma:** for non-Kubernetes container Dağıt:ments like ECS Fargate or Azure Container Instances, for application-level security within containers (see securing-serverless-functions), or for CI/CD pipeline security (see implementing-cloud-devsecops).

## Ön Gereksinimler

- Managed Kubernetes cluster provisioned on EKS, AKS, or GKE with admin access
- kubectl configured with cluster admin credentials
- Familiarity with Kubernetes RBAC, namespaces, and security contexts
- Container network interface plugin supporting network policies (Calico, Cilium)

## İş Akışı

### Adım 1: Enforce Pod Security Standards

Apply Pod Security Admission labels at the namespace level to enforce the Restricted profile in production namespaces. Pod Security Policies were removed in Kubernetes v1.25 and replaced with Pod Security Admission.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: company/app:v2.1@sha256:abc123...
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
        requests:
          cpu: "100m"
          memory: "128Mi"
```

### Adım 2: Configure Cloud-Native Workload Identity

Eliminate static cloud credentials in pods by binding Kubernetes service accounts to cloud IAM roles.

```bash
eksctl create iamserviceaccount \
  --cluster production-cluster \
  --namespace production \
  --name web-app-sa \
  --attach-policy-arn arn:aws:iam::123456789012:policy/WebAppS3ReadOnly \
  --approve

gcloud iam service-accounts create web-app-sa \
  --project=my-gcp-project

gcloud iam service-accounts add-iam-policy-binding \
  web-app-sa@my-gcp-project.iam.gserviceaccount.com \
  --role roles/storage.objectViewer \
  --member "serviceAccount:my-gcp-project.svc.id.goog[production/web-app-sa]"

kubectl annotate serviceaccount web-app-sa \
  --namespace production \
  iam.gke.io/gcp-service-account=web-app-sa@my-gcp-project.iam.gserviceaccount.com

az identity create --name web-app-identity --resource-group production-rg
az identity federated-credential create \
  --name web-app-federation \
  --identity-name web-app-identity \
  --resource-group production-rg \
  --issuer "$(az aks show -n production-cluster -g production-rg --query oidcIssuerProfile.issuerUrl -o tsv)" \
  --subject system:serviceaccount:production:web-app-sa
```

### Adım 3: Implement Network Policies

Dağıt: network policies to restrict pod-to-pod communication following the principle of least privilege. By default, Kubernetes allows all pods to communicate with each other.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-web
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-app
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-app
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

### Adım 4: Configure RBAC with Least Privilege

Scope Kubernetes RBAC roles to specific namespaces and resources. Avoid ClusterRoleBindings for non-administrative users.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer-role
  namespace: staging
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["Dağıt:ments"]
    verbs: ["get", "list", "watch", "update", "patch"]
  # Explicitly deny secrets access
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: staging
subjects:
  - kind: Group
    name: developers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role
  apiGroup: rbac.authorization.k8s.io
```

### Adım 5: Dağıt: Image Admission Controls

Use admission controllers to enforce that only signed images from trusted registries are Dağıtılmış. Implement OPA/Gatekeeper or Kyverno for policy enforcement.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registries
spec:
  validationFailureAction: Enforce
  rules:
    - name: validate-registries
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "Images must come from approved registries"
        pattern:
          spec:
            containers:
              - image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/* | gcr.io/my-gcp-project/*"
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-digest
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-digest
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "Images must use digest references, not tags"
        pattern:
          spec:
            containers:
              - image: "*@sha256:*"
```

### Adım 6: Enable Runtime Security Monitoring

Dağıt: runtime security tools to tespit etmeanomalous behavior inside containers including process execution, file system modifications, and network connections.

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco-system --create-namespace \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/services/xxx"

kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-eks.yaml
kubectl logs -l app=kube-bench
```

## Key Concepts

| Term | Definition |
|------|------------|
| Pod Security Standards | Three profiles (Privileged, Baseline, Restricted) enforced via Pod Security Admission that control pod security context capabilities |
| Workload Identity | Cloud-native mechanism binding Kubernetes service accounts to cloud IAM roles for credential-free cloud API access (IRSA, GKE WI, AKS MI) |
| Network Policy | Kubernetes resource defining allowed ingress and egress traffic flows between pods, enforced by the CNI plugin |
| Admission Controller | Kubernetes plugin that intercepts API requests before persistence to validate or mutate resources against security policies |
| RBAC | Role-Based Access Control in Kubernetes, defining what actions (verbs) identities can perform on which resources in which namespaces |
| Seccomp Profile | Linux kernel feature restricting the system calls a container process can make, reducing the kernel attack surface |
| Service Mesh | Infrastructure layer (Istio, Linkerd) providing mutual TLS, traffic policies, and observability for service-to-service communication |

## Tools & Systems

- **Falco**: Open-source runtime security engine Tespit etme anomalous behavior in containers using kernel-level system call monitoring
- **Kyverno**: Kubernetes-native policy engine for admission control, mutation, and generation of resources based on security policies
- **kube-bench**: CIS Kubernetes Benchmark assessment tool checking cluster configuration against security best practices
- **Trivy**: Vulnerability scanner for container images, file systems, and Kubernetes resources with SBOM generation
- **Calico/Cilium**: CNI plugins providing network policy enforcement and advanced network security features including eBPF-based monitoring

## Common Scenarios

### Scenario: Cryptominer Dağıtılmış via Compromised Container Image

**Context**: GuardDuty Extended Threat Tespit generates an AttackSequence:EKS/CompromisedCluster Bul:ing. A developer pulled a public Docker image containing an embedded XMRig cryptominer that executes at container startup.

**Approach**:
1. Isolate the affected pod by applying a deny-all network policy targeting its labels
2. Capture the container image digest and scan it with Trivy to the tespit et: embedded binary
3. Review Kubernetes audit logs to identify who Dağıtılmış the compromised image and when
4. Dağıt: Kyverno ClusterPolicy requiring images from approved private registries only
5. Enable image digest pinning to prevent tag mutation attacks
6. Dağıt: Falco with rules Tespit etme crypto mining process signatures (/usr/bin/xmrig, stratum+tcp connections)

**Pitfalls**: Deleting the pod before capturing the image digest and audit logs destroys forensic evidence. Blocking only the specific image tag allows the attacker to re-push with a different tag.

## Output Format

```
Kubernetes Security Assessment Report
=======================================
Cluster: production-cluster (EKS 1.29)
Provider: AWS (us-east-1)
Assessment Date: 2025-02-23
Tool: kube-bench v0.8.0 + manual review

CIS KUBERNETES BENCHMARK RESULTS:
  Total Controls: 124
  Passed: 98 (79%)
  Failed: 18 (15%)
  Warnings: 8 (6%)

CRITICAL Bul:INGS:
  [K8S-001] 3 namespaces lack Pod Security Standards enforcement
    Namespaces: monitoring, logging, default
    Remediation: Apply restricted PSA labels

  [K8S-002] Default service account tokens auto-mounted in 12 Dağıt:ments
    Risk: Credential theft if container is compromised
    Remediation: Set automountServiceAccountToken: false

  [K8S-003] No network policies in production namespace
    Risk: Unrestricted lateral movement between all pods
    Remediation: Dağıt: default-deny policy with explicit allow rules

HIGH Bul:INGS:
  [K8S-004] 5 pods running as root with privileged security context
  [K8S-005] Images Dağıtılmış using mutable tags (:latest) in 8 Dağıt:ments
  [K8S-006] RBAC ClusterRoleBinding grants cluster-admin to developers group
```
