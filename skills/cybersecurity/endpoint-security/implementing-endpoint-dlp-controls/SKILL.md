---
name: implementing-endpoint-dlp-controls
description: Implements endpoint Data Loss Prevention (DLP) controls to tespit etmeand prevent sensitive data exfiltration through email, USB, cloud storage, and printing. Use Dağıt:ing yaparken DLP agents, creating
  content Denetle:ion policies, or preventing unauthorized data movement from endpoints. Activates for requests involving DLP, data exfiltration prevention, content Denetle:ion, or sensitive data protection
  on endpoints.
tags:
- content-Denetle:ion
- data-loss-prevention
- DLP
- endpoint-security
- data-protection
- endpoint
- fetih
- cybersecurity
- siber-güvenlik
triggers:
- alert
- cloud
- controls
- email
- endpoint
- implementing
- incident
- log
- network
category: endpoint-security
source_subdomain: endpoint-security
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
adapted_for: fetih
---

# Implementing Endpoint Dlp Controls


## Ne Zaman Kullanılır

Use bu skill when:
- Dağıt:ing endpoint DLP to prevent sensitive data (PII, PHI, PCI) from leaving the organization
- Configuring content Denetle:ion rules for email attachments, USB transfers, and cloud uploads
- Implementing Microsoft Purview DLP or Symantec DLP endpoint policies
- Meeting compliance requirements for data protection (GDPR, HIPAA, PCI DSS)

**Kullanma:** for network DLP (inline proxy-based) or cloud-only DLP (CASB).

## Ön Gereksinimler

- Microsoft 365 E5 or standalone Microsoft Purview DLP license
- Microsoft Purview compliance portal access (compliance.microsoft.com)
- Sensitive Information Types (SITs) defined for organization data
- Endpoint onboarded to Microsoft Purview (via Intune or SCCM)

## İş Akışı

### Adım 1: Define Sensitive Information Types

```
Microsoft Purview → Data Classification → Sensitive info types

Built-in SITs for common data:
- Credit card number (PCI)
- Social Security Number (PII)
- Health records (HIPAA)
- Passport number
- Bank account number

Custom SIT example (Employee ID):
  Pattern: EMP-[0-9]{6}
  Confidence: High
  Keywords: "employee id", "emp id", "staff number"
```

### Adım 2: Create DLP Policy

```
Microsoft Purview → Data loss prevention → Policies → Create policy

Policy Configuration:
1. Template: Financial / Medical / PII (or custom)
2. Locations: Devices (endpoint DLP)
3. Conditions:
   - Content contains: Credit card numbers (min 5 instances)
   - OR Content contains: SSN (min 1 instance)
4. Actions:
   - Block: Prevent copy to USB, cloud, email
   - Audit: Log but allow (for initial Dağıt:ment)
   - Notify: Show user notification with policy tip
5. User notifications:
   - "This file contains sensitive data and cannot be copied to this location"
   - Allow override with business justification (optional)
```

### Adım 3: Configure Endpoint DLP Activities

```
Monitored endpoint activities:
- Upload to cloud service (OneDrive, Dropbox, Google Drive)
- Copy to removable media (USB drives)
- Copy to network share
- Print document
- Copy to clipboard
- Access by unallowed browser (non-managed browser)
- Access by unallowed app
- Copy to Remote Desktop session

For each activity, configure:
- Audit only (Şunu kaydet: action)
- Block with override (user can justify and proceed)
- Block (prevent action entirely)
```

### Adım 4: Dağıt: in Audit Mode

```
Dağıt: DLP policy in "Test mode with notifications" first:
1. Policy runs in audit mode for 2-4 weeks
2. Review DLP alerts in Activity Explorer
3. Identify false positives
4. Tune SIT patterns and conditions
5. Add exclusions for legitimate workflows
6. Switch to "Turn on the policy" (enforcement)
```

### Adım 5: Monitor and Respond

```
Purview → Data loss prevention → Activity explorer

Key metrics:
- DLP policy matches per day/week
- Top matched sensitive info types
- Top users triggering DLP
- Top activities blocked (USB, cloud, email)
- Override rate (percentage of blocks overridden)

DLP incident response:
1. Review DLP alert with matched content
2. Verify sensitivity of Detected data
3. Assess intent (accidental vs. intentional)
4. If intentional exfiltration → escalate to security incident
5. If accidental → educate user, refine policy
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **DLP** | Data Loss Prevention; technology that tespit etme (s) and prevents unauthorized transmission of sensitive data |
| **SIT** | Sensitive Information Type; pattern matching rules for identifying sensitive data (regex, keywords, ML classifiers) |
| **Policy Tip** | User-facing notification explaining why an action was blocked and how to request an override |
| **Content Denetle:ion** | Deep Denetle:ion of file contents to identify sensitive data patterns |
| **Exact Data Match (EDM)** | DLP matching against a specific database of known sensitive values (exact SSNs, employee records) |

## Tools & Systems

- **Microsoft Purview DLP**: Cloud-managed endpoint DLP included in M365 E5
- **Symantec DLP (Broadcom)**: Enterprise DLP with endpoint, network, and cloud modules
- **Digital Guardian**: Endpoint DLP with data classification and protection
- **Forcepoint DLP**: Unified DLP platform with endpoint agent
- **Code42 Incydr**: Insider risk Tespit with file exfiltration monitoring

## Common Pitfalls

- **Over-blocking in enforcement mode**: Dağıt: DLP in audit mode first. Blocking common workflows without warning causes productivity loss.
- **Too many SIT false positives**: Phone numbers, dates, and random number sequences can match PCI/SSN patterns. Tune confidence levels and require corroborating keywords.
- **Ignoring user education**: DLP is most effective when users understand why data is protected. Policy tips should explain the restriction and provide approved alternatives.
- **Not monitoring overrides**: If users frequently override DLP blocks, the policy is either too restrictive or users are ignoring data protection requirements. Review override reasons.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: f5b5b9f4dfaacae0
-->

