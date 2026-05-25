---
name: Tespit etme-azure-lateral-movement
description: tespit etmelateral movement in Azure AD/Entra ID environments using Microsoft Graph API audit logs, Azure Sentinel KQL hunting queries, and sign-in anomaly correlation to identify privilege escalation,
  token theft, and cross-tenant pivoting.
tags:
- threat-hunting
- azure
- sentinel
- graph-api
- entra-id
- fetih
- cloud-security
- cybersecurity
- kql
- lateral-movement
- siber-güvenlik
triggers:
- AWS
- Azure
- GCP
- api
- authentication
- azure
- bulut güvenliği
- cloud security
- Tespit etme
- incident
- lateral
- log
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detection Azure Lateral Movement


## Genel Bakış

Lateral movement in Azure AD/Entra ID differs from on-premises environments. Attackers pivot through OAuth application consent grants, service principal abuse, cross-tenant access policies, and stolen refresh tokens rather than SMB/RDP connections. Tespit requires correlating Microsoft Graph API audit logs, Azure AD sign-in logs, and Entra ID protection risk events using KQL queries in Microsoft Sentinel. bu skill covers building Tespit analytics for common Azure lateral movement techniques including application impersonation, mailbox delegation abuse, and conditional access policy bypasses.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme azure lateral movement
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Azure subscription with Microsoft Sentinel workspace configured
- Azure AD P2 or Entra ID P2 license for risk-based sign-in Tespit
- Microsoft Graph API permissions: AuditLog.Read.All, Directory.Read.All, SecurityEvents.Read.All
- Log Analytics workspace ingesting AuditLogs, SigninLogs, and AADServicePrincipalSignInLogs
- Familiarity with KQL (Kusto Query Language)

## Adımlar

### Adım 1: Configure Log Ingestion

Enable diagnostic settings to stream Azure AD logs to Log Analytics:
- Sign-in logs (interactive and non-interactive)
- Audit logs (directory changes, app consent)
- Service principal sign-in logs
- Provisioning logs
- Risky users and risk Tespits

### Adım 2: Build Tespit Queries

Create KQL analytics rules in Sentinel for:
- Unusual service principal credential additions
- OAuth application consent grants to unknown apps
- Cross-tenant sign-ins from new tenants
- Token replay from different IP/user-agent combinations
- Mailbox delegation changes (FullAccess, SendAs)

### Adım 3: Correlate Events

Chain multiple low-confidence indicators into high-confidence lateral movement Tespits by correlating sign-in anomalies with directory changes within time windows.

### Adım 4: Automate Response

Create Sentinel playbooks (Logic Apps) to automatically revoke suspicious OAuth grants, disable compromised service principals, and enforce step-up authentication.

## Expected Output

JSON report containing Detected lateral movement indicators, correlated event chains, affected identities, and recommended containment actions with MITRE ATT&CK technique mappings.
