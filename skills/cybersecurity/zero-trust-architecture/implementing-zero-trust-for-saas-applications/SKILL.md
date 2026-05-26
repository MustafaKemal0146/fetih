---
name: implementing-zero-trust-for-saas-applications
description: Implementing zero trust access controls for SaaS applications using CASB, SSPM, conditional access policies, OAuth app governance, and session controls to enforce identity verification, device
  compliance, and data protection for cloud-hosted services.
tags:
- saas-security
- session-controls
- casb
- zero-trust-architecture
- sspm
- fetih
- conditional-access
- cybersecurity
- oauth-governance
- zero-trust
- siber-güvenlik
triggers:
- api
- applications
- authentication
- cloud
- email
- http
- implementing
- log
- mobile
- saas
- token
- trust
category: zero-trust-architecture
source_subdomain: zero-trust-architecture
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
adapted_for: fetih
---

# Implementing Zero Trust for Saas Applications


## Ne Zaman Kullanılır

- securing yaparken Erişim: SaaS applications (Microsoft 365, Google Workspace, Salesforce, Slack)
- implementing yaparken conditional access policies requiring MFA and device compliance for SaaS
- Dağıt:ing yaparken CASB for shadow IT discovery and unsanctioned app blocking
- enforcing yaparken session-level controls (DLP, download restrictions) for sensitive SaaS data
- governing yaparken: OAuth application permissions and Tespit etme excessive consent grants

**Kullanma:** as a replacement for SaaS-native security controls (configure those first), for applications with no SAML/OIDC support, or when SaaS vendor does not support API integration for CASB/SSPM.

## Ön Gereksinimler

- Identity provider with conditional access: Microsoft Entra ID P1/P2, Okta
- CASB solution: Microsoft Defender for Cloud Apps, Netskope, or Zscaler CASB
- SaaS applications configured with SSO via SAML 2.0 or OIDC
- MDM enrollment for device compliance signals (Intune, Jamf)
- DLP policies defined for sensitive data categories

## İş Akışı

### Adım 1: Federate SaaS Authentication Through Identity Provider

Centralize authentication for all SaaS applications through a single IdP.

```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"

$app = New-MgServicePrincipal -AppId "SALESFORCE_APP_ID" -DisplayName "Salesforce"

$samlSettings = @{
    preferredSingleSignOnMode = "saml"
    samlSingleSignOnSettings = @{
        relayState = ""
    }
}
Update-MgServicePrincipal -ServicePrincipalId $app.Id -BodyParameter $samlSettings

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $app.Id -BodyParameter @{
    principalId = "SALES_GROUP_ID"
    resourceId = $app.Id
    appRoleId = "DEFAULT_ROLE_ID"
}
```

### Adım 2: Create Conditional Access Policies for SaaS Applications

Enforce identity and device requirements before granting SaaS access.

```powershell
$policy = @{
    displayName = "ZT - Require Compliant Device for SaaS"
    state = "enabled"
    conditions = @{
        applications = @{
            includeApplications = @("SALESFORCE_APP_ID", "M365_APP_ID", "SLACK_APP_ID")
        }
        users = @{
            includeUsers = @("All")
            excludeGroups = @("BREAK_GLASS_GROUP")
        }
        clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
    }
    grantControls = @{
        operator = "AND"
        builtInControls = @("mfa", "compliantDevice")
    }
    sessionControls = @{
        cloudAppSecurity = @{
            isEnabled = $true
            cloudAppSecurityType = "mcasConfigured"
        }
        signInFrequency = @{
            value = 8
            type = "hours"
            isEnabled = $true
        }
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $policy

$downloadPolicy = @{
    displayName = "ZT - Block Downloads on Unmanaged Devices"
    state = "enabled"
    conditions = @{
        applications = @{ includeApplications = @("SHAREPOINT_APP_ID") }
        users = @{ includeUsers = @("All") }
        devices = @{
            deviceFilter = @{
                mode = "include"
                rule = "device.isCompliant -ne True -or device.trustType -ne 'ServerAD'"
            }
        }
    }
    sessionControls = @{
        cloudAppSecurity = @{
            isEnabled = $true
            cloudAppSecurityType = "mcasConfigured"
        }
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $downloadPolicy
```

### Adım 3: Dağıt: CASB for Shadow IT Discovery and App Governance

Configure Microsoft Defender for Cloud Apps to discover and control SaaS usage.

```bash
curl -X GET "https://api.cloudappsecurity.com/api/v1/discovery/" \
  -H "Authorization: Token ${MDCA_API_TOKEN}" \
  -H "Content-Type: application/json"

curl -X GET "https://api.cloudappsecurity.com/api/v1/discovery/discovered_apps/" \
  -H "Authorization: Token ${MDCA_API_TOKEN}" \
  -d '{
    "filters": {
      "appTag": {"eq": "unsanctioned"},
      "traffic": {"gte": 1000}
    },
    "sortField": "traffic",
    "sortDirection": "desc"
  }'

curl -X POST "https://api.cloudappsecurity.com/api/v1/policies/" \
  -H "Authorization: Token ${MDCA_API_TOKEN}" \
  -d '{
    "name": "Block PII Upload to SaaS",
    "policyType": "SESSION",
    "severity": "HIGH",
    "enabled": true,
    "sessionPolicyType": "CONTROL_UPLOAD",
    "filters": {
      "fileType": {"eq": ["DOCUMENT", "SPREADSHEET"]},
      "contentDenetle:ion": {
        "dataType": ["CREDIT_CARD", "SSN", "PASSPORT"]
      }
    },
    "actions": {
      "block": true,
      "notify": {
        "emailRecipients": ["security-team@company.com"]
      }
    }
  }'
```

### Adım 4: Configure OAuth App Governance

Review and restrict OAuth application permissions to prevent excessive consent.

```powershell
$oauthApps = Invoke-MgGraphRequest -Method GET `
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&\$select=displayName,appId,oauth2PermissionScopes"

$grants = Get-MgOauth2PermissionGrant -All
$highRisk = $grants | Where-Object {
    $_.Scope -match "Mail.ReadWrite|Files.ReadWrite.All|Directory.ReadWrite.All"
}

Write-Host "High-risk OAuth grants: $($highRisk.Count)"
$highRisk | ForEach-Object {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId
    Write-Host "  App: $($sp.DisplayName) | Scope: $($_.Scope) | Type: $($_.ConsentType)"
}

$consentPolicy = @{
    displayName = "Require Admin Approval for High-Risk Permissions"
    conditions = @{
        clientApplications = @{ includeAllClientApplications = $true }
        permissions = @{
            permissionClassification = "high"
            permissions = @(
                @{ permissionValue = "Mail.ReadWrite"; permissionType = "delegated" }
                @{ permissionValue = "Files.ReadWrite.All"; permissionType = "delegated" }
            )
        }
    }
}
```

### Adım 5: Implement SaaS Security Posture Management (SSPM)

Audit and remediate SaaS security configuration drift.

```bash
curl -X GET "https://api.cloudappsecurity.com/api/v1/security_config/" \
  -H "Authorization: Token ${MDCA_API_TOKEN}" \
  -d '{"app": "Microsoft 365"}'

```

## Key Concepts

| Term | Definition |
|------|------------|
| CASB | Cloud Access Security Broker - intermediary enforcing security policies between users and SaaS applications |
| SSPM | SaaS Security Posture Management - continuous monitoring of SaaS application security configurations |
| OAuth Governance | Review and control of third-party application permissions granted through OAuth consent flows |
| Session Controls | Real-time access restrictions (block downloads, DLP Denetle:ion, watermarking) applied during active SaaS sessions |
| Shadow IT | Unauthorized SaaS applications used by employees without IT approval or security review |
| Conditional Access | Policy engine evaluating identity, device, location, and risk signals before granting SaaS access |

## Tools & Systems

- **Microsoft Defender for Cloud Apps**: CASB providing shadow IT discovery, session controls, DLP, and SSPM
- **Microsoft Entra ID Conditional Access**: Policy engine for identity-based access control to SaaS applications
- **Netskope CASB**: Cloud-native CASB with inline and API-based SaaS security controls
- **Okta Identity Governance**: OAuth app governance and access certification for SaaS applications
- **SSPM Tools**: AppOmni, Adaptive Shield, Valence Security for SaaS configuration monitoring

## Common Scenarios

### Scenario: Securing Microsoft 365 and Salesforce for 1,000-User Organization

**Context**: A professional services firm with 1,000 users uses Microsoft 365, Salesforce, Slack, and 20+ other SaaS apps. Several data breaches in the industry drive a zero trust initiative for all SaaS access.

**Approach**:
1. Federate all SaaS authentication through Entra ID with SAML SSO
2. Create conditional access policies requiring MFA + compliant device for all SaaS apps
3. Dağıt: Defender for Cloud Apps for shadow IT discovery (identify 150+ unauthorized apps)
4. Mark unauthorized apps as unsanctioned and block via SWG/proxy
5. Configure session controls: block downloads on unmanaged devices, DLP for file uploads
6. Review OAuth app permissions: revoke 45 high-risk consent grants, enable admin approval workflow
7. Enable SSPM monitoring for Microsoft 365 and Salesforce configurations
8. Kur: weekly automated posture reports for security leadership

**Pitfalls**: Conditional access policies need break-glass exclusions. Some legacy SaaS apps may not support modern authentication. Session controls require proxy-based CASB which can impact performance. OAuth app revocation may break integrations; coordinate with app owners first.

## Output Format

```
Zero Trust SaaS Security Report
==================================================
Organization: ProServices Corp
Report Date: 2026-02-23

SAAS INVENTORY:
  Sanctioned Apps: 25
  Unsanctioned (blocked): 127
  Shadow IT Users: 342 (discovered in last 30 days)

CONDITIONAL ACCESS:
  Policies active: 8
  Sign-ins evaluated: 456,789
  Blocked by policy: 2,345 (0.5%)
  MFA enforced: 100% of sign-ins

DEVICE COMPLIANCE:
  Compliant device required: All 25 sanctioned apps
  Sign-ins from compliant: 448,123 (98.1%)
  Sign-ins blocked (non-compliant): 8,666

CASB / DLP:
  DLP violations Detected: 89
  Files blocked from upload: 34
  Downloads blocked (unmanaged): 1,234

OAUTH GOVERNANCE:
  Total OAuth apps: 312
  High-risk permissions: 12 (reviewed)
  Revoked consents: 45
  Pending admin approval: 8

SSPM Bul:INGS:
  Critical misconfigurations: 3
  High: 7
  Medium: 15
  Remediated this month: 18
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 197850c471b24b8b
-->

