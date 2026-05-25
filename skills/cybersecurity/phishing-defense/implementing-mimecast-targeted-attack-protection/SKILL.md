---
name: implementing-mimecast-targeted-attack-protection
description: Dağıt: Mimecast Targeted Threat Protection including URL Protect, Attachment Protect, Impersonation Protect, and Internal Email Protect to defend against advanced phishing and spearphishing
  attacks.
tags:
- mimecast
- impersonation
- attachment-sandboxing
- targeted-threat-protection
- phishing-defense
- url-protect
- phishing
- fetih
- cybersecurity
- email-security
- siber-güvenlik
triggers:
- alert
- api
- attack
- authentication
- email
- implementing
- log
- malware
- mimecast
- phishing
- protection
- targeted
category: phishing-defense
source_subdomain: phishing-defense
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---

# Implementing Mimecast Targeted Attack Protection


## Genel Bakış
Mimecast Targeted Threat Protection (TTP) is a suite of advanced email security services designed to protect against sophisticated phishing, spearphishing, and targeted attacks. TTP consists of four core modules: URL Protect (real-time URL rewriting and click-time analysis), Attachment Protect (sandbox detonation of suspicious attachments), Impersonation Protect (BEC and whaling Tespit), and Internal Email Protect (scanning internal/outbound email for threats). As of November 2025, Mimecast enabled URL Pre-Delivery Action with Hold setting for all customers by default.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing mimecast targeted attack protection capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler
- Mimecast Email Security license with TTP add-on
- Administrative Erişim: Mimecast Administration Console
- Microsoft 365 or Google Workspace environment
- MX records configured to route through Mimecast
- Understanding of email authentication (SPF, DKIM, DMARC)

## Key Concepts

### TTP Module Overview
| Module | Function | Key Capability |
|---|---|---|
| URL Protect | Rewrites and scans URLs at click time | Real-time sandbox, pre-delivery hold |
| Attachment Protect | Sandboxes suspicious attachments | Static + dynamic analysis |
| Impersonation Protect | tespit etme (s) BEC/whaling attacks | VIP name matching, header analysis |
| Internal Email Protect | Scans internal/outbound email | Lateral phishing Tespit |

### Impersonation Protection Scenarios
- **Hit 3 (Default)**: Flags emails matching 3+ impersonation indicators
- **Hit 1 (VIP)**: Flags emails matching 1+ indicator for designated VIP users
- Key identifiers: display name similarity, domain similarity, reply-to mismatch, newly registered domains

### URL Protect Modes
- **Rewrite**: URLs rewritten to route through Mimecast proxy at click time
- **Pre-Delivery Action (Hold)**: URLs checked before message delivery; held if suspicious
- **Pre-Delivery Action (None)**: URLs checked pre-delivery but not held

## İş Akışı

### Adım 1: Configure URL Protect Policy
- Şuraya git: Administration > Gateway > Policies > Targeted Threat Protection - URL Protect
- Create URL Protect definition with rewriting enabled for inbound messages
- Enable URL Pre-Delivery Action set to "Hold" for maximum protection
- Configure scan mode: aggressive for high-risk users, moderate for general population
- Set action for malicious URLs: block page with user notification
- Enable URL logging for all click events

### Adım 2: Configure Attachment Protect Policy
- Şuraya git: Administration > Gateway > Policies > Targeted Threat Protection - Attachment Protect
- Şunu oluştur:ttachment Protect definition for inbound email
- Select sandbox mode: "Safe File" (converts to safe format) or "Dynamic Configuration" (full sandbox)
- Configure attachment types to scan: executables, Office documents, PDFs, archives
- Set timeout for sandbox analysis (default: up to 7 minutes for complex files)
- Enable pre-emptive sandboxing for attachments from unknown senders

### Adım 3: Configure Impersonation Protect
- Create Default Impersonation Protect Definition (Hit 3) for all inbound email
- Create VIP Impersonation Protect Definition (Hit 1) for executive protection
- Build VIP list: CEO, CFO, CTO, board members, finance leadership
- Configure Tespit identifiers: display name, domain similarity, newly observed sender
- Set actions: quarantine high-confidence impersonation, tag moderate confidence
- Enable end-user warning banners for flagged messages

### Adım 4: Enable Internal Email Protect
- Configure journaling from Microsoft 365/Google Workspace to Mimecast
- Enable URL scanning for internal emails
- Enable attachment scanning for internal emails
- Configure alerts for internal account compromise indicators
- Kur: Tespit for internal phishing (compromised account sending malware)

### Adım 5: Create Test Group and Validate
- Create pilot group of 50-100 users across departments
- Apply TTP policies to pilot group first
- Send test emails with known-safe test URLs and EICAR test files
- Verify URL rewriting, attachment sandboxing, and impersonation Tespit
- Monitor false positive rate for 1-2 weeks before organization-wide Dağıt:ment

### Adım 6: Dağıt: Organization-Wide and Tune
- Extend TTP policies to all users
- Monitor Mimecast Threat Dashboard for Tespit metrics
- Review and whitelist legitimate applications triggering false positives
- Tune impersonation sensitivity based on false positive feedback
- Configure exception policies for automated systems and mailing lists

## Tools & Resources
- **Mimecast Administration Console**: Policy configuration and management
- **Mimecast Threat Dashboard**: Real-time threat visibility and analytics
- **Mimecast Awareness Training**: Integrated security awareness platform
- **Mimecast API**: Programmatic Erişim: logs and threat data
- **Message Center**: Quarantine management for admins and users

## Doğrulama
- URL Protect rewrites URLs in test messages and blocks known-malicious at click
- Attachment Protect sandboxes test file and returns verdict within SLA
- Impersonation Protect flags test BEC email impersonating VIP
- Internal Email Protect tespit etme (s) test lateral phishing scenario
- Pre-delivery hold catches weaponized URL before reaching inbox
- False positive rate below organizational threshold after tuning
