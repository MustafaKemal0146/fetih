---
name: implementing-google-workspace-phishing-protection
description: Configure Google Workspace advanced phishing and malware protection settings including pre-delivery scanning, attachment protection, spoofing Tespit, and Enhanced Safe Browsing.
tags:
- gmail
- admin-console
- phishing-defense
- phishing
- fetih
- safe-browsing
- cybersecurity
- anti-spoofing
- google-workspace
- email-security
- siber-güvenlik
triggers:
- authentication
- dns
- email
- google
- implementing
- malware
- phishing
- protection
- threat
- workspace
category: phishing-defense
source_subdomain: phishing-defense
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
adapted_for: fetih
---

# Implementing Google Workspace Phishing Protection


## Genel Bakış
Google Workspace provides advanced phishing and malware protection through the Admin Console under Apps > Google Workspace > Gmail > Safety. Key features include Enhanced Pre-Delivery Scanning that İncele:s messages more thoroughly before they reach inboxes, attachment and link protection that scans for malware and checks against known malicious sites, and spoofing Tespit for domain and employee name impersonation. Google's Advanced Protection Program (APP) provides the strongest account security for high-privilege users.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing google workspace phishing protection capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler
- Google Workspace Business Standard or higher license
- Gmail Settings administrator privilege
- Understanding of organizational email flow and third-party integrations
- Erişim: Google Admin Console (admin.google.com)
- DNS management access for SPF, DKIM, DMARC configuration

## İş Akışı

### Adım 1: Configure Advanced Phishing Protection
- Şuraya git: Admin Console > Apps > Google Workspace > Gmail > Safety
- Enable "Protect against domain spoofing based on similar domain names"
- Enable "Protect against spoofing of employee names"
- Enable "Protect against inbound emails spoofing your domain"
- Set action for Detected spoofing: quarantine or move to spam with warning banner
- Apply settings to all organizational units or specific high-risk groups

### Adım 2: Enable Enhanced Pre-Delivery Scanning
- In Safety settings, enable "Enhanced pre-delivery message scanning"
- This adds additional delay (seconds) to scan messages more thoroughly
- Configure to tespit etmephishing attempts that evade initial filters
- Enable "Identify links behind shortened URLs"
- Enable "Scan linked images" for image-based phishing Tespit

### Adım 3: Configure Attachment Protection
- Enable "Protect against encrypted attachments from untrusted senders"
- Enable "Protect against attachments with scripts from untrusted senders"
- Enable "Protect against anomalous attachment types in emails"
- Configure action: warn users, move to spam, or quarantine
- Create exceptions for known legitimate encrypted file senders

### Adım 4: Enable Enhanced Safe Browsing
- Şuraya git: Admin Console > Security > Gmail Enhanced Safe Browsing
- Enable Enhanced Safe Browsing for the organization (off by default)
- This provides real-time protection against phishing URLs in emails
- Configure at organizational unit level for phased rollout
- Monitor user feedback for false positive impact

### Adım 5: Enroll High-Risk Users in Advanced Protection Program
- Identify high-privilege accounts: super admins, executives, finance leadership
- Enroll users in Google's Advanced Protection Program (APP)
- APP requires FIDO2 security keys for authentication
- APP blocks third-party app access unless explicitly approved
- APP provides enhanced scanning for Gmail and Drive downloads

### Adım 6: Configure Email Authentication
- Publish SPF record: `v=spf1 include:_spf.google.com ~all`
- Enable DKIM signing in Admin Console > Apps > Google Workspace > Gmail > Authenticate email
- Configure DMARC with monitoring: `v=DMARC1; p=none; rua=mailto:dmarc@company.com`
- Progress DMARC to enforcement per organizational readiness

## Tools & Resources
- **Google Admin Console**: Central management for all security settings
- **Google Workspace Security Investigation Tool**: Threat analysis and response
- **Google Security Center**: Security health recommendations and dashboard
- **Gmail Security Sandbox**: Attachment detonation for enterprise licenses
- **Google Advanced Protection Program**: Strongest account security

## Doğrulama
- Spoofing protection blocks test email with lookalike domain
- Pre-delivery scanning catches test phishing with delayed weaponization
- Attachment protection warns on test encrypted attachment
- Enhanced Safe Browsing blocks known phishing URL clicked in email
- APP-enrolled accounts reject non-FIDO2 authentication attempts
- SPF, DKIM, DMARC all pass for outbound messages

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 9bd70aa495a76004
-->

