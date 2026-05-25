---
name: implementing-dmarc-dkim-spf-email-security
description: SPF, DKIM, and DMARC form the three pillars of email authentication. Together they prevent domain spoofing, validate message integrity, and define policies for handling unauthenticated mail.
  Proper im
tags:
- cybersecurity
- dmarc
- dkim
- dns
- phishing-defense
- phishing
- fetih
- awareness
- social-engineering
- spf
- email-security
- siber-güvenlik
triggers:
- authentication
- crypto
- dkim
- dmarc
- dns
- email
- forensic
- http
- implementing
- phishing
- security
category: phishing-defense
source_subdomain: phishing-defense
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
---

# Implementing Dmarc Dkim Spf Email Security


## Genel Bakış
SPF, DKIM, and DMARC form the three pillars of email authentication. Together they prevent domain spoofing, validate message integrity, and define policies for handling unauthenticated mail. Proper implementation drastically reduces phishing attacks that impersonate your organization's domain.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing dmarc dkim spf email security capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler
- DNS management access for your domain
- Erişim: email server/MTA configuration (Postfix, Exchange, Google Workspace, Microsoft 365)
- Basic understanding of DNS TXT records
- Python 3.8+ for validation scripts

## Key Concepts

### SPF (Sender Policy Framework)
Publishes a DNS TXT record listing authorized IP addresses and mail servers that can send email on behalf of your domain. Receiving servers check the envelope sender's IP against this list.

### DKIM (DomainKeys Identified Mail)
Adds a cryptographic signature to outgoing emails using a private key. The corresponding public key is published in DNS. Receivers verify the signature to ensure the message was not altered in transit.

### DMARC (Domain-based Message Authentication, Reporting and Conformance)
Builds on SPF and DKIM by specifying a policy (none/quarantine/reject) for messages that fail authentication, and provides a reporting mechanism to monitor spoofing attempts.

## İş Akışı

### Adım 1: Audit Current State
```bash
dig TXT example.com | grep spf

dig TXT selector1._domainkey.example.com

dig TXT _dmarc.example.com
```

### Adım 2: Implement SPF
```
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com include:spf.protection.outlook.com -all
```

Key SPF mechanisms:
- `ip4:` / `ip6:` - Authorize specific IP ranges
- `include:` - Include another domain's SPF record
- `a` - Authorize domain's A record IPs
- `mx` - Authorize domain's MX record IPs
- `-all` - Hard fail all others (recommended)
- `~all` - Soft fail (monitoring phase)

### Adım 3: Implement DKIM
```bash
openssl genrsa -out dkim_private.pem 2048
openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem

grep -v "PUBLIC KEY" dkim_public.pem | tr -d '\n'
```

DNS TXT record at `selector1._domainkey.example.com`:
```
v=DKIM1; k=rsa; p=MIIBIjANBgkqhki...
```

### Adım 4: Implement DMARC
```
v=DMARC1; p=none; rua=mailto:dmarc-aggregate@example.com; ruf=mailto:dmarc-forensic@example.com; pct=100

v=DMARC1; p=quarantine; rua=mailto:dmarc-aggregate@example.com; pct=25

v=DMARC1; p=reject; rua=mailto:dmarc-aggregate@example.com; pct=100
```

### Adım 5: Monitor and Analyze DMARC Reports
Use the `scripts/process.py` to parse DMARC aggregate XML reports and identify authentication failures, unauthorized senders, and spoofing attempts.

## Tools & Resources
- **MXToolbox**: https://mxtoolbox.com/SuperTool.aspx
- **DMARC Analyzer (dmarcian)**: https://dmarcian.com/
- **Google Postmaster Tools**: https://postmaster.google.com/
- **Valimail DMARC Monitor**: https://www.valimail.com/
- **DMARC Report Analyzer**: https://dmarc.postmarkapp.com/

## Doğrulama
- SPF record passes validation at mxtoolbox.com
- DKIM signature verified on test emails
- DMARC record properly formatted and reporting enabled
- Test emails pass all three checks in recipient's Authentication-Results header
