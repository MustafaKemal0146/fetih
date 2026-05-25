---
name: Tespit etme-business-email-compromise
description: Business Email Compromise (BEC) is a sophisticated fraud scheme where attackers impersonate executives, vendors, or trusted partners to trick employees into transferring funds, sharing sensitive
  data,
tags:
- cybersecurity
- bec
- dmarc
- phishing-defense
- fraud
- phishing
- fetih
- awareness
- social-engineering
- email-security
- siber-güvenlik
triggers:
- alert
- business
- compromise
- crypto
- Tespit etme
- email
- http
- incident
- log
- phishing
- threat
category: phishing-defense
source_subdomain: phishing-defense
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---

# Detection Business Email Compromise


## Genel Bakış
Business Email Compromise (BEC) is a sophisticated fraud scheme where attackers impersonate executives, vendors, or trusted partners to trick employees into transferring funds, sharing sensitive data, or changing payment details. Unlike traditional phishing, BEC often contains no malicious links or attachments, relying purely on social engineering. bu skill covers Tespit techniques using email gateway rules, behavioral analytics, and financial process controls.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require Tespit etme business email compromise
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler
- Email security gateway with BEC Tespit capabilities
- Understanding of organizational financial processes and approval chains
- Erişim: email logs and SIEM platform
- Bilgi: social engineering tactics

## Key Concepts

### BEC Attack Types (FBI IC3 Classification)
1. **CEO Fraud**: Attacker impersonates CEO, requests urgent wire transfer
2. **Account Compromise**: Employee email compromised, used to request payments from vendors
3. **False Invoice Scheme**: Fake invoices from "vendor" with changed bank details
4. **Attorney Impersonation**: Impersonates legal counsel for urgent confidential transfers
5. **Data Theft**: Requests W-2, tax forms, or PII from HR

### Tespit Indicators
- Urgency and secrecy language ("confidential", "do not discuss with others")
- New or changed payment instructions
- Executive communication outside normal patterns
- Display name matches executive but email domain differs
- Reply-to address differs from From address
- First-time communication pattern between sender and recipient
- Request for gift cards or cryptocurrency

## İş Akışı

### Adım 1: Configure BEC-Specific Email Rules
- Flag emails with VIP display names from external domains
- tespit etmefinancial keywords combined with urgency language
- Alert on first-time sender to finance/accounting staff
- Check for Reply-To domain mismatch

### Adım 2: Dağıt: Behavioral Analytics
- Baseline normal communication patterns per user
- tespit etmeanomalous requests (unusual recipient, unusual time, unusual request type)
- Monitor for email forwarding rule changes (T1114.003)

### Adım 3: Implement Financial Controls
- Dual-authorization for wire transfers above threshold
- Out-of-band verification for payment detail changes (phone callback)
- Vendor payment change verification process
- Finance team training on BEC red flags

### Adım 4: Monitor for Account Compromise
- tespit etmeimpossible travel in email login locations
- Alert on email forwarding rule creation
- Monitor for mailbox delegation changes
- Check for inbox rules hiding BEC-related emails

## Tools & Resources
- **Microsoft Defender for O365 Anti-BEC**: Built-in BEC Tespit
- **Proofpoint Email Fraud Defense**: BEC-specific solution
- **Abnormal Security**: AI-driven BEC Tespit
- **FBI IC3 BEC Advisory**: https://www.ic3.gov/
- **FinCEN BEC Advisory**: Financial institution guidance

## Doğrulama
- BEC Tespit rules trigger on test scenarios
- Financial controls prevent unauthorized transfers in drills
- Account compromise Tespit catches simulated attacks
- Reduced BEC susceptibility in awareness assessments
