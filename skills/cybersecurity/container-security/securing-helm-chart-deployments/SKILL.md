---
name: securing-helm-chart-Dağıt:ments
description: Secure Helm chart Dağıt:ments by validating chart integrity, scanning templates for misconfigurations, and enforcing security contexts in Kubernetes releases.
tags:
- helm
- chart-security
- supply-chain
- Dağıt:ment
- container-security
- fetih
- cybersecurity
- kubernetes
- configuration-security
- siber-güvenlik
triggers:
- api
- chart
- container
- Dağıt:ments
- helm
- http
- log
- network
- password
- securing
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

# Securing Helm Chart Dağıt:ments


## Genel Bakış

Helm is the Kubernetes package manager. Securing Helm Dağıt:ments requires validating chart provenance, scanning templates for security misconfigurations, enforcing pod security contexts, managing secrets securely, and controlling RBAC for Helm operations.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring securing helm chart Dağıt:ments capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Helm 3.12+ installed
- kubectl with cluster access
- GnuPG for chart signing/verification
- kubesec or checkov for template scanning

## Chart Provenance and Integrity

### Sign a Helm Chart

```bash
gpg --full-generate-key

helm package ./mychart --sign --key "helm-signing@example.com" --keyring ~/.gnupg/pubring.gpg

helm verify mychart-0.1.0.tgz --keyring ~/.gnupg/pubring.gpg
```

### Verify Chart Before Install

```bash
helm pull myrepo/mychart --verify --keyring /path/to/keyring.gpg

cat mychart-0.1.0.tgz.prov
```

## Template Security Scanning

### Render and Scan Templates

```bash
helm template myrelease ./mychart --values values-prod.yaml > rendered.yaml

kubesec scan rendered.yaml

checkov -f rendered.yaml --framework kubernetes

trivy config rendered.yaml

kube-linter lint rendered.yaml
```

### Helm Lint for Misconfigurations

```bash
helm lint ./mychart --values values-prod.yaml --strict

helm lint ./mychart --debug
```

## Security Context Enforcement in values.yaml

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 3000
  fsGroup: 2000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL

podSecurityContext:
  seccompProfile:
    type: RuntimeDefault

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

networkPolicy:
  enabled: true

serviceAccount:
  create: true
  automountServiceAccountToken: false

image:
  pullPolicy: Always
  # Use digest instead of tag for immutability
  # tag: "1.0.0"
  # digest: "sha256:abc123..."
```

### Template with Security Contexts

```yaml
apiVersion: apps/v1
kind: Dağıt:ment
metadata:
  name: {{ include "mychart.fullname" . }}
spec:
  template:
    spec:
      automountServiceAccountToken: {{ .Values.serviceAccount.automountServiceAccountToken }}
      securityContext:
        {{- toYaml .Values.podSecurityContext | nindent 8 }}
      containers:
        - name: {{ .Chart.Name }}
          securityContext:
            {{- toYaml .Values.securityContext | nindent 12 }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
```

## Secrets Management

### Use External Secrets (Not Helm Values)

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: {{ include "mychart.fullname" . }}-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: ClusterSecretStore
  target:
    name: {{ include "mychart.fullname" . }}-secrets
  data:
    - secretKey: db-password
      remoteRef:
        key: production/database
        property: password
```

### helm-secrets Plugin

```bash
helm plugin install https://github.com/jkroepke/helm-secrets

helm secrets encrypt values-secrets.yaml

helm secrets install myrelease ./mychart -f values.yaml -f values-secrets.yaml

helm secrets edit values-secrets.yaml
```

## RBAC for Helm Operations

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: helm-Dağıt:er
  namespace: production
rules:
  - apiGroups: ["", "apps", "batch", "networking.k8s.io"]
    resources: ["Dağıt:ments", "services", "configmaps", "secrets", "ingresses", "jobs"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: helm-Dağıt:er-binding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: helm-Dağıt:er
    namespace: production
roleRef:
  kind: Role
  name: helm-Dağıt:er
  apiGroup: rbac.authorization.k8s.io
```

## CI/CD Helm Security Pipeline

```yaml
name: Helm Chart Security
on:
  pull_request:
    paths: ['charts/**']

jobs:
  lint-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Helm lint
        run: helm lint ./charts/mychart --strict

      - name: Render templates
        run: helm template test ./charts/mychart -f charts/mychart/values.yaml > rendered.yaml

      - name: Scan with kube-linter
        uses: stackrox/kube-linter-action@v1
        with:
          directory: rendered.yaml

      - name: Scan with trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          scan-ref: rendered.yaml

      - name: Scan with checkov
        uses: bridgecrewio/checkov-action@master
        with:
          file: rendered.yaml
          framework: kubernetes
```

## En İyi Uygulamalar

1. **Sign charts** with GPG and verify before installation
2. **Render and scan** templates before Dağıt:ing to catch misconfigurations
3. **Enforce security contexts** in values.yaml defaults
4. **Never store secrets** in Helm values - use external secrets or helm-secrets plugin
5. **Use image digests** instead of tags for immutable references
6. **Restrict Helm RBAC** to least privilege per namespace
7. **Pin chart versions** in requirements - never use `latest`
8. **Lint strictly** in CI with `--strict` flag
9. **Review third-party charts** before Dağıt:ing to production
10. **Use Helm test hooks** to validate Dağıt:ments post-install

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 75d73540ab7c758e
-->

