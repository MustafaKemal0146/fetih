---
name: securing-container-registry-with-harbor
description: Harbor is an open-source container registry that provides security features including vulnerability scanning (integrated Trivy), image signing (Notary/Cosign), RBAC, content trust policies,
  replicatio
tags:
- cybersecurity
- registry
- security
- docker
- container-security
- fetih
- harbor
- kubernetes
- siber-güvenlik
- containers
triggers:
- api
- authentication
- certificate
- container
- email
- endpoint
- harbor
- http
- log
- password
- registry
- securing
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Securing Container Registry with Harbor


## Genel Bakış

Harbor is an open-source container registry that provides security features including vulnerability scanning (integrated Trivy), image signing (Notary/Cosign), RBAC, content trust policies, replication, and audit logging. Securing Harbor involves configuring these features to enforce image provenance, prevent vulnerable image Dağıt:ment, and maintain registry access control.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring securing container registry with harbor capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Harbor 2.10+ kurulu (Helm or Docker Compose)
- TLS certificates for HTTPS
- Trivy scanner integration
- OIDC/LDAP for authentication
- Kubernetes cluster (for Dağıt:ment target)

## İş Akışı

### Adım 1: Install Harbor with Security Configuration

```yaml
expose:
  type: ingress
  tls:
    enabled: true
    certSource: secret
    secret:
      secretName: harbor-tls
      notarySecretName: harbor-tls
  ingress:
    hosts:
      core: harbor.example.com
      notary: notary.example.com

externalURL: https://harbor.example.com

persistence:
  enabled: true
  resourcePolicy: "keep"

harborAdminPassword: "<strong-password>"

trivy:
  enabled: true
  gitHubToken: "<github-token>"
  severity: "CRITICAL,HIGH,MEDIUM"
  autoScan: true

notary:
  enabled: true

core:
  secretKey: "<32-char-secret>"

database:
  type: external
  external:
    host: postgres.example.com
    port: "5432"
    username: harbor
    password: "<db-password>"
    sslmode: require
```

```bash
helm repo add harbor https://helm.getharbor.io
helm install harbor harbor/harbor -f harbor-values.yaml -n harbor --create-namespace
```

### Adım 2: Configure Vulnerability Scanning Policies

```bash
curl -k -X PUT "https://harbor.example.com/api/v2.0/projects/myproject" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {
      "auto_scan": "true",
      "severity": "critical",
      "prevent_vul": "true",
      "reuse_sys_cve_allowlist": "true"
    }
  }'
```

### Adım 3: Configure Content Trust

```bash
curl -k -X PUT "https://harbor.example.com/api/v2.0/projects/myproject" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {
      "enable_content_trust": "true",
      "enable_content_trust_cosign": "true"
    }
  }'

cosign sign --key cosign.key harbor.example.com/myproject/myapp:v1.0.0

cosign verify --key cosign.pub harbor.example.com/myproject/myapp:v1.0.0
```

### Adım 4: Configure RBAC and Project Isolation

```bash
curl -k -X POST "https://harbor.example.com/api/v2.0/projects" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "project_name": "production",
    "metadata": {
      "public": "false",
      "auto_scan": "true",
      "prevent_vul": "true",
      "severity": "high"
    }
  }'

curl -k -X POST "https://harbor.example.com/api/v2.0/projects/production/members" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": 3,
    "member_user": {"username": "developer1"}
  }'
```

### Adım 5: Configure Immutable Tags and Retention

```bash
curl -k -X POST "https://harbor.example.com/api/v2.0/projects/production/immutabletagrules" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "tag_filter": "v*",
    "scope_selectors": {
      "repository": [{"kind": "doublestar", "decoration": "repoMatches", "pattern": "**"}]
    }
  }'

curl -k -X POST "https://harbor.example.com/api/v2.0/retentions" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "or",
    "rules": [
      {
        "action": "retain",
        "template": "latestPushedK",
        "params": {"latestPushedK": 10},
        "tag_selectors": [{"kind": "doublestar", "decoration": "matches", "pattern": "**"}],
        "scope_selectors": {"repository": [{"kind": "doublestar", "decoration": "repoMatches", "pattern": "**"}]}
      }
    ],
    "trigger": {"kind": "Schedule", "settings": {"cron": "0 0 * * *"}}
  }'
```

### Adım 6: OIDC Authentication Integration

```yaml
auth_mode: oidc_auth
oidc_name: "Okta"
oidc_endpoint: "https://company.okta.com/oauth2/default"
oidc_client_id: "harbor-client-id"
oidc_client_secret: "harbor-client-secret"
oidc_groups_claim: "groups"
oidc_admin_group: "harbor-admins"
oidc_scope: "openid,profile,email,groups"
oidc_verify_cert: true
oidc_auto_onboard: true
```

## Doğrulama Commands

```bash
docker pull harbor.example.com/production/vulnerable-app:latest

DOCKER_CONTENT_TRUST=0 docker push harbor.example.com/production/unsigned:latest

curl -k "https://harbor.example.com/api/v2.0/projects/production/repositories/myapp/artifacts/v1.0.0/additions/vulnerabilities" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)"

curl -k "https://harbor.example.com/api/v2.0/audit-logs?page=1&page_size=10" \
  -H "Authorization: Basic $(echo -n admin:Harbor12345 | base64)"
```

## References

- [Harbor Documentation](https://goharbor.io/docs/)
- [Harbor Security Best Practices](https://goharbor.io/docs/2.10.0/administration/vulnerability-scanning/)
- [Harbor GitHub Repository](https://github.com/goharbor/harbor)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: d52fd9402a088573
-->

