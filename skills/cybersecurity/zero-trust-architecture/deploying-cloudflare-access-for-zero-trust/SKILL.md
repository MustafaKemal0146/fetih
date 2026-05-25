---
name: Dağıt:ing-cloudflare-access-for-zero-trust
description: Dağıt:ing Cloudflare Access with Cloudflare Tunnel to provide zero trust Erişim: self-hosted and private applications, configuring identity-aware access policies, device posture checks, and
  WARP client enrollment for VPN replacement.
tags:
- warp
- zero-trust-architecture
- ztna
- cloudflare
- cloudflare-access
- fetih
- cloudflare-tunnel
- cybersecurity
- cloudflare-one
- zero-trust
- siber-güvenlik
triggers:
- access
- api
- authentication
- certificate
- cloud
- cloudflare
- Dağıt:ing
- dns
- email
- encryption
- endpoint
- http
category: zero-trust-architecture
source_subdomain: zero-trust-architecture
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
---

# Dağıt:ing Cloudflare Access for Zero Trust


## Ne Zaman Kullanılır

- replacing yaparken: VPN infrastructure with identity-aware application access using Cloudflare One
- exposing yaparken: self-hosted internal applications through Cloudflare Tunnel without opening inbound ports
- implementing yaparken ZTNA for a distributed workforce accessing web applications, SSH, and RDP services
- needing yaparken: a cost-effective zero trust solution with integrated DLP, CASB, and SWG capabilities
- securing yaparken contractor and third-party Erişim: specific applications without full network access

**Kullanma:** for applications requiring persistent UDP connections not supported by Cloudflare Tunnel, for environments requiring air-gapped or fully on-premises access control, or when regulatory requirements prohibit routing traffic through third-party cloud infrastructure.

## Ön Gereksinimler

- Cloudflare account with Zero Trust subscription (Free for up to 50 users, paid plans for larger teams)
- Domain name managed by Cloudflare DNS (or ability to add CNAME records)
- Linux, Windows, or macOS server to run `cloudflared` tunnel daemon
- Identity provider: Okta, Microsoft Entra ID, Google Workspace, GitHub, or any SAML/OIDC provider
- Cloudflare WARP client for device-level enrollment (optional but recommended)

## İş Akışı

### Adım 1: Şunu oluştur: Cloudflare Tunnel to Internal Applications

Install `cloudflared` and Şunu oluştur: persistent tunnel to expose internal services.

```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb \
  -o cloudflared.deb
sudo dpkg -i cloudflared.deb

cloudflared tunnel login

cloudflared tunnel create internal-apps

cat > ~/.cloudflared/config.yml << 'EOF'
tunnel: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
credentials-file: /home/admin/.cloudflared/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.json

ingress:
  - hostname: wiki.company.com
    service: http://localhost:8080
  - hostname: git.company.com
    service: http://10.1.1.50:3000
  - hostname: grafana.company.com
    service: http://10.1.1.60:3000
  - hostname: ssh.company.com
    service: ssh://localhost:22
  - hostname: rdp.company.com
    service: rdp://10.1.1.100:3389
  # Catch-all rule (required)
  - service: http_status:404
EOF

cloudflared tunnel route dns internal-apps wiki.company.com
cloudflared tunnel route dns internal-apps git.company.com
cloudflared tunnel route dns internal-apps grafana.company.com

sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared

cloudflared tunnel info internal-apps
```

### Adım 2: Configure Identity Provider Integration

Kur: authentication with your organization's identity provider.

```bash
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/identity_providers" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Corporate Okta",
    "type": "okta",
    "config": {
      "client_id": "OKTA_CLIENT_ID",
      "client_secret": "OKTA_CLIENT_SECRET",
      "okta_account": "company.okta.com",
      "api_token": "OKTA_API_TOKEN",
      "claims": ["email", "groups", "name"],
      "email_claim_name": "email"
    }
  }'

curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/identity_providers" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Microsoft Entra ID",
    "type": "azureAD",
    "config": {
      "client_id": "AZURE_APP_CLIENT_ID",
      "client_secret": "AZURE_APP_CLIENT_SECRET",
      "directory_id": "AZURE_TENANT_ID",
      "support_groups": true,
      "claims": ["email", "groups", "name"]
    }
  }'
```

### Adım 3: Şunu oluştur:ccess Applications and Policies

Define Access applications with identity-aware policies for each internal service.

```bash
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/apps" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Internal Wiki",
    "domain": "wiki.company.com",
    "type": "self_hosted",
    "session_duration": "8h",
    "auto_redirect_to_identity": true,
    "http_only_cookie_attribute": true,
    "same_site_cookie_attribute": "lax",
    "logo_url": "https://company.com/wiki-logo.png",
    "allowed_idps": ["OKTA_IDP_ID", "AZURE_IDP_ID"]
  }'

curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/apps/{app_id}/policies" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Allow Engineering Team",
    "decision": "allow",
    "precedence": 1,
    "include": [
      {"group": {"id": "ENGINEERING_GROUP_ID"}},
      {"okta": {"name": "Engineering", "identity_provider_id": "OKTA_IDP_ID"}}
    ],
    "require": [
      {"device_posture": {"integration_uid": "CROWDSTRIKE_INTEGRATION_ID"}}
    ]
  }'

curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/apps" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "SSH Access",
    "domain": "ssh.company.com",
    "type": "ssh",
    "session_duration": "4h",
    "auto_redirect_to_identity": true
  }'
```

### Adım 4: Dağıt: WARP Client for Device Enrollment

Enroll corporate devices using Cloudflare WARP for private network access and device posture.

```bash
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/policy" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Corporate Device Enrollment",
    "match": "identity.email matches \".*@company\\.com$\"",
    "precedence": 100,
    "enabled": true,
    "gateway_unique_id": "GATEWAY_ID",
    "support_url": "https://helpdesk.company.com/warp-help"
  }'

cat > warp_mdm_config.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>organization</key>
    <string>company</string>
    <key>auto_connect</key>
    <integer>1</integer>
    <key>switch_locked</key>
    <true/>
    <key>onboarding</key>
    <false/>
</dict>
</plist>
EOF

sudo cp cloudflare-root-ca.pem /usr/local/share/ca-certificates/cloudflare-root-ca.crt
sudo update-ca-certificates

curl -X PUT "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/policy/{policy_id}/fallback_domains" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '[
    {"suffix": "internal.corp", "description": "Internal corporate domain"},
    {"suffix": "10.0.0.0/8", "description": "Private network range"}
  ]'
```

### Adım 5: Configure Device Posture Checks

Integrate endpoint security signals into Access policies.

```bash
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/posture/integration" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "CrowdStrike Falcon",
    "type": "crowdstrike_s2s",
    "config": {
      "api_url": "https://api.crowdstrike.com",
      "client_id": "CS_API_CLIENT_ID",
      "client_secret": "CS_API_CLIENT_SECRET",
      "customer_id": "CS_CUSTOMER_ID"
    },
    "interval": "10m"
  }'

curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/posture" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Disk Encryption Required",
    "type": "disk_encryption",
    "match": [{"platform": "windows"}, {"platform": "mac"}],
    "input": {"requireAll": true}
  }'

curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/posture" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Minimum OS Version",
    "type": "os_version",
    "match": [{"platform": "windows"}],
    "input": {"version": "10.0.19045", "operator": ">="}
  }'
```

### Adım 6: Kur: Audit Logging and Analytics

Configure logging for access decisions and tunnel health monitoring.

```bash
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/logpush/jobs" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "access-audit-logs",
    "output_options": {
      "field_names": ["RayID","Action","Allowed","AppDomain","AppUUID","Connection","Country","CreatedAt","Email","IPAddress","PurposeJustificationPrompt","PurposeJustificationResponse","TemporaryAccessDuration","UserUID"],
      "timestamp_format": "rfc3339"
    },
    "destination_conf": "s3://security-logs-bucket/cloudflare-access/?region=us-east-1&access-key-id=AKID&secret-access-key=SECRET",
    "dataset": "access_requests",
    "enabled": true
  }'

curl -X POST "https://api.cloudflare.com/client/v4/graphql" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "query": "{ viewer { accounts(filter: {accountTag: \"ACCOUNT_ID\"}) { accessLoginRequestsAdaptiveGroups(filter: {datetime_gt: \"2026-02-22T00:00:00Z\"}, limit: 100, orderBy: [count_DESC]) { dimensions { action appName userEmail country } count } } } }"
  }'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Cloudflare Tunnel | Encrypted outbound-only connection from your infrastructure to Cloudflare's network, exposing internal services without opening inbound firewall ports |
| Cloudflare Access | Identity-aware reverse proxy evaluating every request against access policies before granting Erişim: protected applications |
| WARP Client | Cloudflare's endpoint agent that routes device traffic through Cloudflare's network for policy enforcement and private network access |
| Access Application | Configuration object defining a protected resource (self-hosted, SaaS, or infrastructure) with associated access policies |
| Device Posture | Endpoint health signals (OS version, disk encryption, EDR status) evaluated as conditions in Access policies |
| Cloudflare One | Unified SASE platform combining ZTNA (Access), SWG (Gateway), CASB, DLP, and RBI |

## Tools & Systems

- **Cloudflare Access**: Identity-aware application proxy providing per-request authorization
- **Cloudflare Tunnel (cloudflared)**: Daemon creating encrypted tunnels from internal networks to Cloudflare edge
- **WARP Client**: Cross-platform endpoint agent for device enrollment, DNS filtering, and private network routing
- **Cloudflare Gateway**: Secure Web Gateway providing DNS/HTTP filtering and DLP Denetle:ion
- **Cloudflare Logpush**: Real-time log streaming to external SIEM and storage destinations
- **Access for Infrastructure**: SSH and RDP access with short-lived certificates and session recording

## Common Scenarios

### Scenario: Startup with 200 Employees Dağıt:ing Zero Trust from Scratch

**Context**: A SaaS startup with 200 employees and no existing VPN wants to provide secure Erişim: internal tools (Grafana, internal APIs, staging environments) running on AWS. Budget is limited, and the team has no dedicated security staff.

**Approach**:
1. Start with Cloudflare Zero Trust free tier (up to 50 users) for proof of concept
2. Dağıt: one `cloudflared` tunnel on an EC2 instance in the production VPC
3. Expose Grafana, internal wiki, and staging apps through tunnel with DNS routing
4. Configure Google Workspace as IdP for SSO authentication
5. Şunu oluştur:ccess policies requiring @company.com email domain for all applications
6. Add device posture checks for disk encryption and OS version
7. Upgrade to paid plan and Dağıt: WARP client to all employee laptops via MDM
8. Enable Gateway DNS filtering and HTTP Denetle:ion for malware protection
9. Configure Logpush to send access logs to Datadog for monitoring

**Pitfalls**: Cloudflare root certificate must be kurulu: all devices for TLS Denetle:ion to work; some applications may break with TLS interception. Tunnel failover requires running multiple `cloudflared` instances or using Cloudflare's replicas feature. Access policies should always include a default deny rule. WebSocket applications may require specific tunnel configuration.

## Output Format

```
Cloudflare Zero Trust Dağıt:ment Report
==================================================
Organization: StartupCorp
Team Name: startupcorp
Dağıt:ment Date: 2026-02-23

TUNNEL INFRASTRUCTURE:
  Active Tunnels: 2 (primary + failover)
  Tunnel Status: Healthy
  Connected Edge: Washington DC, Ashburn
  Ingress Routes: 8

ACCESS APPLICATIONS:
  Self-Hosted Apps: 6
  SaaS Apps: 3
  SSH/Infrastructure: 2
  Total Policies: 15

DEVICE ENROLLMENT:
  Enrolled Devices: 187 / 200
  WARP Connected: 182 / 187 (97.3%)
  Posture Compliant: 175 / 187 (93.6%)

ACCESS METRICS (last 30 days):
  Total Requests: 89,432
  Allowed: 88,756 (99.2%)
  Blocked: 676 (0.8%)
  Unique Users: 195
  Countries: 12
  Avg Session Duration: 6.2 hours
```
