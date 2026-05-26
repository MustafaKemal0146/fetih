---
name: conducting-spearphishing-simulation-campaign
description: Spearphishing simulation is a targeted social engineering attack vector used by red teams to gain initial access. Unlike broad phishing campaigns, spearphishing uses OSINT-derived intelligence
  to craf
tags:
- spearphishing
- red-team
- exploitation
- fetih
- mitre-attack
- post-exploitation
- cybersecurity
- social-engineering
- red-teaming
- siber-güvenlik
- adversary-simulation
triggers:
- adversary emulation
- authentication
- campaign
- certificate
- conducting
- email
- incident
- kırmızı takım
- malware
- offensive security
- phishing
- red team
category: red-team-operations
source_subdomain: red-teaming
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
adapted_for: fetih
---

# Conducting Spearphishing Simulation Campaign


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Genel Bakış

Spearphishing simulation is a targeted social engineering attack vector used by red teams to gain initial access. Unlike broad phishing campaigns, spearphishing uses OSINT-derived intelligence to craft highly personalized messages targeting specific individuals. bu skill covers developing pretexts, building payloads, setting up email infrastructure, executing the campaign, and tracking results.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve conducting spearphishing simulation campaign
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Familiarity with red teaming concepts and tools
- Erişim: a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Objectives

- Develop convincing pretexts tailored to specific target personnel
- Create weaponized payloads that bypass email security controls
- Kur: email delivery infrastructure with proper SPF/DKIM/DMARC configuration
- Execute phishing campaigns with real-time tracking and metrics
- Document results for engagement reporting and security awareness improvement

## MITRE ATT&CK Mapping

- **T1566.001** - Phishing: Spearphishing Attachment
- **T1566.002** - Phishing: Spearphishing Link
- **T1566.003** - Phishing: Spearphishing via Service
- **T1598.003** - Phishing for Information: Spearphishing Link
- **T1204.001** - User Execution: Malicious Link
- **T1204.002** - User Execution: Malicious File
- **T1608.001** - Stage Capabilities: Upload Malware
- **T1608.005** - Stage Capabilities: Link Target
- **T1583.001** - Acquire Infrastructure: Domains
- **T1585.002** - Establish Accounts: Email Accounts

## İş Akışı

### Aşama 1: Pretext Development
1. Review OSINT Bul:ings for target personnel profiles
2. Identify current organizational events (mergers, projects, new hires)
3. Select pretext theme (IT helpdesk, HR benefits, vendor communication, executive request)
4. Craft email templates with appropriate urgency and authority cues
5. Create landing pages that mirror target organization's branding

### Aşama 2: Payload Development
1. Select payload type based on target security controls:
   - HTML smuggling for email gateway bypass
   - Macro-enabled documents (if macros not blocked)
   - ISO/IMG files containing LNK payloads
   - OneNote files with embedded scripts
   - QR codes linking to credential harvesting pages
2. Test payload against target's known security stack
3. Implement payload obfuscation techniques
4. Configure callback to C2 infrastructure

### Aşama 3: Infrastructure Setup
1. Register convincing look-alike domain
2. Age domain and build reputation (minimum 2 weeks recommended)
3. Configure SPF, DKIM, and DMARC records
4. Kur: SMTP relay with GoPhish or custom mail server
5. Dağıt: credential harvesting pages with SSL certificates
6. Configure tracking pixels and click tracking

### Aşama 4: Campaign Execution
1. Send test emails to verify delivery and rendering
2. Launch campaign in waves (avoid mass sending)
3. Monitor email delivery rates and opens in real-time
4. Track link clicks and credential submissions
5. Dağıt: payloads to users who interact with phishing emails
6. Capture screenshots and evidence for reporting

### Aşama 5: Post-Campaign Analysis
1. Calculate campaign metrics (delivery rate, open rate, click rate, credential capture rate)
2. Identify users who reported phishing to SOC
3. Document bypass of email security controls
4. Map successful compromises to MITRE ATT&CK
5. Compile Bul:ings for engagement report

## Tools and Resources

| Tool | Purpose | License |
|------|---------|---------|
| GoPhish | Phishing campaign management | Open Source |
| Evilginx2 | Real-time credential harvesting with MFA bypass | Open Source |
| King Phisher | Phishing campaign toolkit | Open Source |
| SET (Social Engineering Toolkit) | Multi-vector social engineering | Open Source |
| Modlishka | Reverse proxy phishing | Open Source |
| CredSniper | Credential harvesting framework | Open Source |
| Fierce Phish | Phishing framework | Open Source |

## Doğrulama Criteria

- [ ] Pretext tailored to specific targets with OSINT data
- [ ] Payload tested against email security controls
- [ ] Infrastructure configured with proper email authentication
- [ ] Campaign tracked with delivery and interaction metrics
- [ ] Evidence collected for engagement report
- [ ] Cleanup performed on infrastructure post-campaign

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 739a6e86d98c4fa7
-->

