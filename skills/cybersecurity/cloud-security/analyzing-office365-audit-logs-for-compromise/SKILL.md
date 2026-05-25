---
name: analyzing-office365-audit-logs-for-compromise
description: Parse Office 365 Unified Audit Logs via Microsoft Graph API to tespit etmeemail forwarding rule creation, inbox delegation, suspicious OAuth app grants, and other indicators of account compromise.
tags:
- audit-logs
- cybersecurity
- email-compromise
- siber-güvenlik
- Office365
- inbox-rules
- Microsoft-Graph
- fetih
- cloud-security
- OAuth
- BEC
triggers:
- AWS
- Azure
- GCP
- analyzing
- api
- audit
- authentication
- bulut güvenliği
- certificate
- cloud security
- compromise
- email
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Analyzing Office365 Audit Logs for Compromise


## Genel Bakış

Business Email Compromise (BEC) attacks often leave traces in Office 365 audit logs: suspicious inbox rule creation, email forwarding to external addresses, mailbox delegation changes, and unauthorized OAuth application consent grants. bu skill uses the Microsoft Graph API to query the Unified Audit Log, enumerate inbox rules across mailboxes, tespit etmeforwarding configurations, and identify compromised account indicators.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing office365 audit logs for compromise
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Azure AD app registration with `AuditLog.Read.All`, `MailboxSettings.Read`, `Mail.Read` (application permissions)
- Python 3.9+ with `msal`, `requests`
- Client secret or certificate for authentication
- Global Reader or Security Reader role

## Adımlar

1. Authenticate to Microsoft Graph using MSAL client credentials flow
2. Query Unified Audit Log for suspicious operations (Set-Mailbox, New-InboxRule)
3. Enumerate inbox rules across mailboxes and flag forwarding rules
4. tespit etmemailbox delegation changes (Add-MailboxPermission)
5. Identify OAuth consent grants to suspicious applications
6. Check for suspicious sign-in patterns from audit logs
7. Generate compromise indicator report with timeline

## Expected Output

- JSON report listing forwarding rules, delegation changes, OAuth grants, and suspicious audit events with risk scores
- Timeline of compromise indicators with affected mailboxes
