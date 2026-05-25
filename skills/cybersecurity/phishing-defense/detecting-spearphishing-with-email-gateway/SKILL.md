---
name: Tespit etme-spearphishing-with-email-gateway
description: Spearphishing targets specific individuals using personalized, researched content that bypasses generic spam filters. Email security gateways (SEGs) like Microsoft Defender for Office 365,
  Proofpoint,
tags:
- cybersecurity
- spearphishing
- dmarc
- phishing-defense
- email-gateway
- phishing
- fetih
- awareness
- social-engineering
- email-security
- siber-güvenlik
triggers:
- alert
- authentication
- Tespit etme
- email
- gateway
- http
- incident
- log
- phishing
- spearphishing
- threat
category: phishing-defense
source_subdomain: phishing-defense
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---

# Detection Spearphishing with Email Gateway


## Genel Bakış
Spearphishing targets specific individuals using personalized, researched content that bypasses generic spam filters. Email security gateways (SEGs) like Microsoft Defender for Office 365, Proofpoint, Mimecast, and Barracuda provide advanced Tespit capabilities including behavioral analysis, URL detonation, attachment sandboxing, and impersonation Tespit. bu skill covers configuring these gateways to tespit etmeand block targeted phishing attacks.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme spearphishing with email gateway
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler
- Erişim: email security gateway admin console
- Understanding of email flow architecture (MX records, transport rules)
- Familiarity with SPF/DKIM/DMARC authentication
- Bilgi: common spearphishing techniques and pretexts

## Key Concepts

### Spearphishing Characteristics
- **Targeted recipients**: Specific individuals, often executives or finance staff
- **Researched pretexts**: References to real projects, colleagues, or events
- **Impersonation**: Spoofs trusted senders (CEO, vendor, partner)
- **Low volume**: Few emails to avoid pattern-based Tespit
- **Urgent tone**: Creates pressure to act quickly

### Gateway Tespit Layers
1. **Reputation filtering**: IP/domain/URL reputation scoring
2. **Authentication checks**: SPF, DKIM, DMARC validation
3. **Content analysis**: NLP-based analysis of email body
4. **Impersonation Tespit**: Display name and domain similarity matching
5. **URL analysis**: Real-time URL detonation and redirect following
6. **Attachment sandboxing**: Behavioral analysis of attachments in isolated environments
7. **Behavioral analytics**: Anomaly Tespit in communication patterns

## İş Akışı

### Adım 1: Configure Impersonation Protection
```
Microsoft Defender for Office 365:
  Security > Anti-phishing policies > Impersonation settings
  - Enable user impersonation protection for VIPs
  - Enable domain impersonation protection
  - Add protected users (CEO, CFO, HR Director)
  - Set action: Quarantine message

Proofpoint:
  Email Protection > Impostor Classifier
  - Enable display name spoofing Tespit
  - Configure lookalike domain Tespit
  - Set Impostor threshold sensitivity
```

### Adım 2: Configure URL Protection
- Enable Safe Links / URL rewriting
- Enable time-of-click URL detonation
- Block newly registered domains (< 30 days)
- Enable URL redirect chain following

### Adım 3: Configure Attachment Sandboxing
- Enable Safe Attachments / attachment sandboxing
- Configure dynamic delivery (deliver body, hold attachments)
- Set sandbox detonation timeout to 60+ seconds
- Block macro-enabled Office documents from external senders

### Adım 4: Create Custom Detection Rules
Use the `scripts/process.py` to analyze email gateway logs, identify spearphishing patterns, and generate custom Tespit rules.

### Adım 5: Configure Alert and Response Actions
- Real-time alerts for impersonation attempts
- Automatic quarantine for high-confidence Tespits
- User notification with safety tips
- Integration with SIEM for correlation

## Tools & Resources
- **Microsoft Defender for Office 365**: https://security.microsoft.com
- **Proofpoint Email Protection**: https://www.proofpoint.com/us/products/email-security
- **Mimecast Email Security**: https://www.mimecast.com/products/email-security/
- **Barracuda Email Protection**: https://www.barracuda.com/products/email-protection

## Doğrulama
- Impersonation protection correctly identifies spoofed VIP display names
- URL detonation catches malicious links in test phishing emails
- Attachment sandboxing tespit etme (s) weaponized documents
- Custom rules trigger on known spearphishing patterns
- SIEM integration receives gateway alerts
