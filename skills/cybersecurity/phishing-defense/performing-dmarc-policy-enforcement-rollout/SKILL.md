---
name: performing-dmarc-policy-enforcement-rollout
description: Execute a phased DMARC rollout from p=none monitoring through p=quarantine to p=reject enforcement, ensuring all legitimate email sources are authenticated before blocking unauthorized senders.
tags:
- email-authentication
- dmarc
- dkim
- dns
- phishing-defense
- phishing
- fetih
- cybersecurity
- anti-spoofing
- spf
- email-security
- siber-güvenlik
triggers:
- authentication
- dmarc
- dns
- email
- enforcement
- forensic
- incident
- performing
- policy
- rollout
category: phishing-defense
source_subdomain: phishing-defense
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---

# Performing Dmarc Policy Enforcement Rollout


## Genel Bakış
Domain-based Message Authentication, Reporting and Conformance (DMARC) is the cornerstone of email anti-spoofing protection. A DMARC rollout progresses through three phases: monitoring (p=none), quarantine (p=quarantine), and full enforcement (p=reject). When configured at p=reject, any email that fails both SPF and DKIM checks is outright rejected. Google and Yahoo now require DMARC for bulk senders (5,000+ emails), driving a 65% reduction in unauthenticated messages. The rollout typically takes 3-6 months for safe Dağıt:ment.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing dmarc policy enforcement rollout
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler
- Administrative Erişim: DNS management for the domain
- Understanding of SPF, DKIM, and DMARC protocols (RFC 7208, 6376, 7489)
- Complete inventory of all legitimate email sending sources
- DMARC reporting analysis tool (EasyDMARC, DMARCLY, Valimail, or dmarcian)
- Email gateway with DMARC enforcement capability

## Key Concepts

### DMARC Policy Levels
| Policy | Behavior | Use Case |
|---|---|---|
| p=none | Monitor only, no action on failures | Discovery phase |
| p=quarantine | Send failing messages to spam/junk | Transition phase |
| p=reject | Block failing messages entirely | Full enforcement |

### DMARC Record Anatomy
```
v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-agg@company.com; ruf=mailto:dmarc-forensic@company.com; adkim=r; aspf=r; fo=1
```
- **p**: Policy for organizational domain
- **sp**: Policy for subdomains
- **pct**: Percentage of messages subject to policy (for gradual rollout)
- **rua**: Aggregate report destination (daily XML reports)
- **ruf**: Forensic report destination (per-failure reports)
- **adkim**: DKIM alignment mode (r=relaxed, s=strict)
- **aspf**: SPF alignment mode (r=relaxed, s=strict)
- **fo**: Failure reporting options (0=both fail, 1=either fails)

### SPF and DKIM Alignment
- **SPF Alignment**: The domain in the Return-Path (envelope sender) must match the From header domain
- **DKIM Alignment**: The d= domain in the DKIM signature must match the From header domain
- **Relaxed**: Organizational domain match (sub.example.com matches example.com)
- **Strict**: Exact domain match required

## İş Akışı

### Adım 1: Inventory All Sending Sources (Week 1-2)
- Audit all systems sending email as your domain (marketing, CRM, ticketing, transactional)
- Document third-party services: Salesforce, Mailchimp, SendGrid, Zendesk, etc.
- Identify internal mail servers, applications, and relay hosts
- Check for shadow IT email sending (departments using unauthorized services)

### Adım 2: Configure SPF and DKIM (Week 2-4)
- Consolidate SPF record with all legitimate sending IPs and includes
- Ensure SPF record stays under 10 DNS lookup limit
- Şunu üret:nd publish DKIM keys for each sending source
- Verify DKIM signing works for all outbound mail paths
- Test with MX Toolbox or dmarcian SPF/DKIM validators

### Adım 3: Dağıt: DMARC in Monitoring Mode (Week 4-6)
- Publish initial DMARC record: `v=DMARC1; p=none; rua=mailto:dmarc@company.com; fo=1`
- Wait 1-2 weeks to collect representative aggregate reports
- Analyze reports to identify unauthorized senders and alignment failures
- Fix SPF/DKIM for all legitimate sources showing failures
- Iterate until all legitimate mail passes DMARC

### Adım 4: Move to Quarantine with pct Tag (Week 6-12)
- Update to quarantine at 10%: `v=DMARC1; p=quarantine; pct=10; rua=...`
- Monitor for false positives (legitimate mail being quarantined)
- Increase pct gradually: 10% -> 25% -> 50% -> 75% -> 100%
- Each increase: wait 1-2 weeks and review reports before advancing
- Fix any remaining alignment issues discovered at each stage

### Adım 5: Advance to Reject Policy (Week 12-20)
- After stable quarantine at 100%, move to reject at 10%: `v=DMARC1; p=reject; pct=10; rua=...`
- Gradually increase pct: 10% -> 25% -> 50% -> 100%
- Monitor closely for legitimate mail being rejected
- Establish emergency rollback procedure (revert to quarantine)
- Apply subdomain policy: `sp=reject` for subdomains

### Adım 6: Ongoing Monitoring and Maintenance
- Continuously monitor DMARC aggregate reports
- Add new sending sources before they start sending
- Review forensic reports for spoofing attempts
- Maintain SPF record as sending infrastructure changes
- Rotate DKIM keys annually

## Tools & Resources
- **EasyDMARC**: DMARC monitoring dashboard with aggregate/forensic report analysis
- **DMARCLY**: SPF, DKIM, DMARC monitoring with auto-DNS updates
- **dmarcian**: DMARC Dağıt:ment and management platform
- **Valimail**: Automated DMARC enforcement with hosted authentication
- **MX Toolbox**: DNS record lookup and DMARC validator
- **Google Admin Toolbox**: DMARC check and diagnostic tools

## Doğrulama
- DMARC record published and resolving correctly at _dmarc.domain.com
- All legitimate sending sources pass SPF and/or DKIM alignment
- Aggregate reports show >99% legitimate mail passing DMARC
- Spoofed messages from unauthorized senders are rejected
- No legitimate mail blocked after full p=reject enforcement
- Subdomain policy (sp=) also set to reject
