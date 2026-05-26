---
name: implementing-zero-trust-network-access
description: Implementing Zero Trust Network Access (ZTNA) in cloud environments by configuring identity-aware proxies, micro-segmentation, continuous verification with conditional access policies, and
  replacing traditional VPN-based access with BeyondCorp-style architectures across AWS, Azure, and GCP.
tags:
- zero-trust
- siber-güvenlik
- ztna
- fetih
- cloud-security
- cybersecurity
- beyondcorp
- micro-segmentation
- identity-aware-proxy
triggers:
- AWS
- Azure
- GCP
- access
- api
- authentication
- bulut güvenliği
- certificate
- cloud
- cloud security
- dns
- email
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Implementing Zero Trust Network Access


## Ne Zaman Kullanılır

- replacing yaparken: traditional VPN-based remote access with identity-based access controls
- implementing yaparken micro-segmentation to limit lateral movement within cloud networks
- compliance yaparken: or security strategy requires zero trust architecture adoption
- providing yaparken: secure Erişim: cloud workloads without exposing them to the public internet
- building yaparken context-aware access policies based on user identity, device health, and location

**Kullanma:** as a complete replacement for network security controls (ZTNA complements but does not replace firewalls and network ACLs), for protecting internet-facing public applications (use WAF), or for IoT device access where identity-based authentication is not feasible.

## Ön Gereksinimler

- Identity provider (Entra ID, Okta, Google Workspace) with MFA enforcement
- Cloud-native networking capabilities (AWS PrivateLink, Azure Private Link, GCP IAP)
- Device management solution (Intune, Jamf, CrowdStrike) for device posture assessment
- Service mesh or zero trust proxy (Cloudflare Access, Zscaler ZPA, or cloud-native IAP)
- Centralized logging for access decisions and policy enforcement

## İş Akışı

### Adım 1: Dağıt: GCP Identity-Aware Proxy (IAP) for Application Access

Configure IAP to provide authenticated Erişim: web applications without VPN.

```bash
gcloud services enable iap.googleapis.com

gcloud iap oauth-brands create \
  --application_title="Corporate Apps" \
  --support_email=security@company.com

gcloud iap web enable \
  --resource-type=app-engine \
  --oauth2-client-id=CLIENT_ID \
  --oauth2-client-secret=CLIENT_SECRET

gcloud compute backend-services update BACKEND_SERVICE \
  --iap=enabled,oauth2-client-id=CLIENT_ID,oauth2-client-secret=CLIENT_SECRET \
  --global

gcloud iap web add-iam-policy-binding \
  --resource-type=app-engine \
  --member="group:engineering@company.com" \
  --role="roles/iap.httpsResourceAccessor"

gcloud access-context-manager levels create corporate-device \
  --title="Corporate Managed Device" \
  --basic-level-spec=level-spec.yaml \
  --policy=POLICY_ID
```

### Adım 2: Implement AWS Verified Access for Zero Trust

Dağıt: AWS Verified Erişim: provide identity-based Erişim: internal applications.

```bash
aws ec2 create-verified-access-trust-provider \
  --trust-provider-type user \
  --user-trust-provider-type oidc \
  --oidc-options '{
    "Issuer": "https://login.microsoftonline.com/TENANT_ID/v2.0",
    "AuthorizationEndpoint": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize",
    "TokenEndpoint": "https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token",
    "UserInfoEndpoint": "https://graph.microsoft.com/oidc/userinfo",
    "ClientId": "CLIENT_ID",
    "ClientSecret": "CLIENT_SECRET",
    "Scope": "openid profile email"
  }'

aws ec2 create-verified-access-instance \
  --description "Zero Trust Access Instance"

aws ec2 attach-verified-access-trust-provider \
  --verified-access-instance-id vai-INSTANCE_ID \
  --verified-access-trust-provider-id vatp-PROVIDER_ID

aws ec2 create-verified-access-group \
  --verified-access-instance-id vai-INSTANCE_ID \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": "*",
      "Action": "verified-access:AllowAccess",
      "Condition": {
        "StringEquals": {
          "verified-access:user/groups": "engineering"
        }
      }
    }]
  }'

aws ec2 create-verified-access-endpoint \
  --verified-access-group-id vag-GROUP_ID \
  --endpoint-type load-balancer \
  --attachment-type vpc \
  --domain-certificate-arn arn:aws:acm:REGION:ACCOUNT:certificate/CERT_ID \
  --application-domain app.internal.company.com \
  --endpoint-domain-prefix app \
  --load-balancer-options '{
    "LoadBalancerArn": "arn:aws:elasticloadbalancing:REGION:ACCOUNT:loadbalancer/app/internal-app/xxx",
    "Port": 443,
    "Protocol": "https",
    "SubnetIds": ["subnet-xxx"]
  }'
```

### Adım 3: Configure Azure Private Link and Conditional Access

Kur: Azure Private Link for network isolation and conditional access for identity-based controls.

```bash
az network private-endpoint create \
  --name app-private-endpoint \
  --resource-group production-rg \
  --vnet-name production-vnet \
  --subnet private-endpoint-subnet \
  --private-connection-resource-id /subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.Web/sites/internal-app \
  --group-ids sites \
  --connection-name app-connection

az network private-dns zone create \
  --resource-group production-rg \
  --name privatelink.azurewebsites.net

az network private-dns link vnet create \
  --resource-group production-rg \
  --zone-name privatelink.azurewebsites.net \
  --name production-link \
  --virtual-network production-vnet \
  --registration-enabled false
```

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$params = @{
    DisplayName = "Zero Trust - Require MFA and Compliant Device"
    State = "enabled"
    Conditions = @{
        Applications = @{
            IncludeApplications = @("All")
        }
        Users = @{
            IncludeUsers = @("All")
            ExcludeGroups = @("BreakGlass-Group-ID")
        }
        Locations = @{
            IncludeLocations = @("All")
            ExcludeLocations = @("AllTrusted")
        }
    }
    GrantControls = @{
        Operator = "AND"
        BuiltInControls = @("mfa", "compliantDevice")
    }
    SessionControls = @{
        SignInFrequency = @{
            Value = 4
            Type = "hours"
            IsEnabled = $true
        }
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

### Adım 4: Implement Micro-Segmentation with Network Policies

Dağıt: network-level micro-segmentation to complement identity-based access controls.

```bash
aws ec2 create-security-group \
  --group-name web-tier-sg \
  --description "Web tier - only HTTPS from ALB" \
  --vpc-id vpc-PROD

aws ec2 authorize-security-group-ingress \
  --group-id sg-WEB \
  --protocol tcp --port 443 \
  --source-group sg-ALB

aws ec2 create-security-group \
  --group-name app-tier-sg \
  --description "App tier - only from web tier"

aws ec2 authorize-security-group-ingress \
  --group-id sg-APP \
  --protocol tcp --port 8080 \
  --source-group sg-WEB

cat << 'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow-web-only
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web-frontend
      ports:
        - protocol: TCP
          port: 8080
EOF
```

### Adım 5: Enable Continuous Verification and Logging

Implement continuous trust verification rather than one-time authentication.

```bash
aws logs create-log-group --log-group-name /verified-access/access-logs

aws ec2 modify-verified-access-instance-logging-configuration \
  --verified-access-instance-id vai-INSTANCE_ID \
  --access-logs '{
    "CloudWatchLogs": {
      "Enabled": true,
      "LogGroup": "/verified-access/access-logs"
    }
  }'

aws logs start-query \
  --log-group-name /verified-access/access-logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, identity.user, http_request.url, decision
    | filter decision = "deny"
    | sort @timestamp desc
    | limit 50
  '
```

## Key Concepts

| Term | Definition |
|------|------------|
| Zero Trust | Security model that requires strict identity verification for every person and device accessing resources, regardless of network location |
| ZTNA | Zero Trust Network Access, the technology that implements zero trust principles by providing identity-aware, context-based Erişim: applications |
| Identity-Aware Proxy | Proxy service that verifies user identity and device context before allowing Erişim: backend applications, replacing VPN-based access |
| Micro-Segmentation | Network security technique that creates fine-grained security zones around individual workloads or applications to limit lateral movement |
| BeyondCorp | Google's implementation of zero trust architecture that shifts access controls from the network perimeter to individual users and devices |
| Continuous Verification | Ongoing assessment of user identity, device health, and access context throughout a session rather than only at authentication time |

## Tools & Systems

- **GCP Identity-Aware Proxy**: Google's BeyondCorp implementation providing context-aware Erişim: web applications and VMs
- **AWS Verified Access**: AWS service for zero trust Erişim: applications based on identity and device posture verification
- **Azure Conditional Access**: Microsoft's policy engine for enforcing context-based access controls based on user, device, location, and risk
- **Cloudflare Access**: Cloud-delivered ZTNA solution providing identity-aware Erişim: internal applications
- **Zscaler ZPA**: Enterprise ZTNA platform replacing VPN with application-level access based on identity and context

## Common Scenarios

### Scenario: Replacing Corporate VPN with Zero Trust Access for Cloud Applications

**Context**: An organization with 2,000 employees accesses 30+ internal cloud applications through a traditional VPN concentrator. VPN performance issues and security concerns drive the decision to implement ZTNA.

**Approach**:
1. Inventory all applications currently accessed through VPN and classify by sensitivity
2. Dağıt: GCP IAP or AWS Verified Access for web-based internal applications
3. Configure conditional access policies requiring MFA and device compliance for all applications
4. Implement micro-segmentation using security groups to limit lateral movement between application tiers
5. Kur: continuous verification with re-authentication every 4 hours for sensitive applications
6. Migrate users in phases, starting with low-risk applications, monitoring access logs for issues
7. Decommission VPN after all applications are accessible through ZTNA with full logging

**Pitfalls**: Not all applications support identity-aware proxy integration. Legacy thick-client applications may require agent-based ZTNA solutions instead of proxy-based approaches. Device posture assessment requires an endpoint management solution Dağıtılmış to all corporate devices. Break-glass access procedures must be documented for scenarios where the identity provider is unavailable.

## Output Format

```
Zero Trust Network Access Implementation Report
==================================================
Organization: Acme Corp
Implementation Date: 2026-02-23
Applications Migrated: 24 / 30

ZTNA ARCHITECTURE:
  Identity Provider: Microsoft Entra ID
  Access Proxy: AWS Verified Access + GCP IAP
  Device Management: Microsoft Intune
  MFA: FIDO2 + Authenticator App

ACCESS POLICY COVERAGE:
  Applications requiring MFA:          30 / 30 (100%)
  Applications requiring compliant device: 24 / 30 (80%)
  Applications with continuous verification: 18 / 30 (60%)
  Applications with location restrictions:  12 / 30 (40%)

SECURITY IMPROVEMENTS:
  VPN-related incidents (before):      12/month
  ZTNA-related incidents (after):       2/month
  Mean time to tespit etmeunauthorized access: 4 min (was 2 hours)
  Lateral movement paths eliminated:   85%

MIGRATION STATUS:
  Phase 1 (low-risk apps):     12/12 complete
  Phase 2 (medium-risk apps):  12/12 complete
  Phase 3 (high-risk apps):     0/6  in progress
  VPN decommission:            Scheduled after Phase 3
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 62ba8de3c8bf8643
-->

