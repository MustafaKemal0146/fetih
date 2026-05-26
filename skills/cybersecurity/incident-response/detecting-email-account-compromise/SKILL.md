---
name: Tespit etme-email-account-compromise
description: tespit etmecompromised O365 and Google Workspace email accounts by analyzing inbox rule creation, suspicious sign-in locations, mail forwarding rules, and unusual API access patterns via Microsoft
  Graph and audit logs.
tags:
- sign-in-analysis
- bec
- office365
- account-takeover
- email-compromise
- incident-response
- siber-güvenlik
- inbox-rules
- fetih
- cybersecurity
- microsoft-graph
triggers:
- IR
- account
- api
- authentication
- breach
- compromise
- Tespit etme
- email
- güvenlik olayı
- incident
- incident response
- log
category: incident-response
source_subdomain: incident-response
mitre_attack:
- T1114
- T1566
- T1078
- T1534
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
adapted_for: fetih
---

# Detection Email Account Compromise


## Genel Bakış

Email account compromise (EAC) is a prevalent attack vector where adversaries gain unauthorized Erişim: mailboxes to exfiltrate sensitive data, conduct business email compromise (BEC), or establish persistence through inbox rule manipulation. Attackers commonly create forwarding rules to siphon emails, delete rules to hide evidence, or use OAuth tokens for persistent access. Tespit relies on analyzing Microsoft 365 Unified Audit Logs, Azure AD sign-in logs for impossible travel or suspicious locations, inbox rule creation events (Set-InboxRule, New-InboxRule), and Microsoft Graph API access patterns. Key indicators include forwarding rules to external addresses, rules that delete or move messages matching keywords like "invoice" or "payment", and sign-ins from unusual user agents such as python-requests.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme email account compromise
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Microsoft 365 with Unified Audit Logging enabled
- Azure AD P1/P2 for risk Tespit APIs
- Python 3.9+ with `requests`, `msal` libraries
- Microsoft Graph API application registration with Mail.Read, AuditLog.Read.All permissions
- Understanding of OAuth2 client credential flows

## Adımlar

1. Export audit logs or connect to Microsoft Graph API using MSAL authentication
2. Query inbox rules for all monitored mailboxes via `/users/{id}/mailFolders/inbox/messageRules`
3. Analyze rules for external forwarding (ForwardTo, RedirectTo external addresses)
4. tespit etmesuspicious rule patterns: deletion rules, keyword-matching rules targeting financial terms
5. Query sign-in logs via `/auditLogs/signIns` for unusual locations and impossible travel
6. Check for suspicious user agent strings (python-requests, PowerShell, curl)
7. Identify OAuth application consent grants for suspicious third-party apps
8. Correlate Bul:ings across users to tespit etmecampaign-level compromise
9. Generate compromise indicators report with severity scores

## Expected Output

A JSON report listing compromised or suspicious accounts, malicious inbox rules Detected, impossible travel events, suspicious OAuth grants, and recommended containment actions with severity ratings.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: a22f9842d4720b4b
-->

