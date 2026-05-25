---
name: Tespit etme-suspicious-oauth-application-consent
description: tespit etmerisky OAuth application consent grants in Azure AD / Microsoft Entra ID using Microsoft Graph API, audit logs, and permission analysis to identify illicit consent grant attacks.
tags:
- cybersecurity
- Entra-ID
- application-permissions
- Microsoft-Graph
- fetih
- illicit-consent
- Azure-AD
- cloud-security
- siber-güvenlik
- OAuth
triggers:
- AWS
- Azure
- GCP
- api
- application
- authentication
- bulut güvenliği
- certificate
- cloud security
- consent
- Tespit etme
- incident
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detection Suspicious Oauth Application Consent


## Genel Bakış

Illicit consent grant attacks trick users into granting excessive permissions to malicious OAuth applications in Azure AD / Microsoft Entra ID. bu skill uses the Microsoft Graph API to enumerate OAuth2 permission grants, analyze application permissions for overly broad scopes, review directory audit logs for consent events, and flag high-risk applications based on publisher verification status and permission scope.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme suspicious oauth application consent
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Azure AD / Entra ID tenant with Global Reader or Security Reader role
- Microsoft Graph API access with `Application.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`
- Python 3.9+ with `msal`, `requests`
- App registration with client secret or certificate for authentication

## Adımlar

1. Authenticate to Microsoft Graph using MSAL client credentials flow
2. Enumerate all OAuth2 permission grants via `/oauth2PermissionGrants`
3. List service principals and their assigned application permissions
4. Query directory audit logs for `Consent to application` events
5. Flag applications with high-risk scopes (Mail.Read, Files.ReadWrite.All, etc.)
6. Check publisher verification status for each application
7. Generate risk report with remediation recommendations

## Expected Output

- JSON report listing all OAuth apps with granted permissions, risk scores, unverified publishers, and suspicious consent patterns
- Audit trail of consent grant events with user and IP details
