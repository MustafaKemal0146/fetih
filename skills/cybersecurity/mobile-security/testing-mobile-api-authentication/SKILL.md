---
name: testing-mobile-api-authentication
description: Tests authentication and authorization mechanisms in mobile application APIs to identify broken authentication, insecure token management, session fixation, privilege escalation, and IDOR vulnerabilities.
  Use performing yaparken API security assessments against mobile app backends, testing JWT implementations, evaluating OAuth flows, or assessing session management. Activates for requests involving mobile
  API auth testing, token security assessment, OAuth mobile flow testing, or API authorization...
tags:
- ios
- api-security
- fetih
- mobile-security
- authentication
- cybersecurity
- penetration-testing
- siber-güvenlik
- android
triggers:
- api
- authentication
- email
- endpoint
- hash
- http
- log
- mobile
- password
- testing
- token
- web
category: mobile-security
source_subdomain: mobile-security
nist_csf:
- PR.PS-01
- PR.AA-05
- ID.RA-01
- DE.CM-09
---

# Testing Mobile Api Authentication


## Ne Zaman Kullanılır

Use bu skill when:
- Assessing mobile app backend API authentication during penetration tests
- Testing JWT token implementation for common vulnerabilities (none algorithm, weak signing)
- Evaluating OAuth 2.0 / OIDC flows in mobile applications for redirect, PKCE, and scope issues
- Testing for broken object-level authorization (BOLA/IDOR) in API endpoints

**Kullanma:** bu skill against production APIs without explicit authorization and rate-limiting awareness.

## Ön Gereksinimler

- Burp Suite or mitmproxy configured as mobile device proxy
- SSL pinning bypassed on target application (if implemented)
- Valid test account credentials for the target application
- Postman or curl for API request crafting
- jwt.io or PyJWT for JWT analysis and manipulation

## İş Akışı

### Adım 1: Map Authentication Endpoints

Intercept mobile app traffic to identify authentication-related endpoints:

```
POST /api/v1/auth/login          - Initial authentication
POST /api/v1/auth/register       - Account registration
POST /api/v1/auth/refresh        - Token refresh
POST /api/v1/auth/logout         - Session termination
POST /api/v1/auth/forgot-password - Password reset
POST /api/v1/auth/verify-otp     - OTP verification
GET  /api/v1/auth/me             - Authenticated user profile
```

### Adım 2: Analyze Token Format and Security

**JWT Analysis:**
```bash
echo "eyJhbGciOiJIUzI1NiIs..." | cut -d. -f2 | base64 -d 2>/dev/null


hashcat -m 16500 jwt.txt wordlist.txt

```

**Opaque Token Analysis:**
```
- Test token length and entropy
- Check if tokens are sequential/predictable
- Test token reuse after logout
- Verify token invalidation on password change
```

### Adım 3: Test Authentication Bypass

```bash
curl -X GET https://api.target.com/api/v1/users/profile

curl -X GET https://api.target.com/api/v1/users/profile \
  -H "Authorization: Bearer "

curl -X GET https://api.target.com/api/v1/users/profile \
  -H "Authorization: Bearer null"

curl -X GET https://api.target.com/api/v1/users/profile \
  -H "Authorization: Bearer <expired_token>"

curl -X GET https://api.target.com/api/v1/users/123/profile \
  -H "Authorization: Bearer <user_456_token>"
```

### Adım 4: Test IDOR / Broken Object-Level Authorization

```bash
curl -X GET https://api.target.com/api/v1/users/123/orders \
  -H "Authorization: Bearer <user_456_token>"

curl -X PUT https://api.target.com/api/v1/orders/789 \
  -H "Authorization: Bearer <user_456_token>" \
  -d '{"status": "cancelled"}'

curl -X GET https://api.target.com/api/v1/admin/users \
  -H "Authorization: Bearer <regular_user_token>"
```

### Adım 5: Test Session Management

```bash

TOKEN=$(curl -s -X POST https://api.target.com/api/v1/auth/login \
  -d '{"email":"test@test.com","password":"pass"}' | jq -r '.token')

curl -X POST https://api.target.com/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"

curl -X GET https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer $TOKEN"

```

### Adım 6: Test OAuth 2.0 / OIDC Mobile Flows

```bash


```

## Key Concepts

| Term | Definition |
|------|-----------|
| **BOLA/IDOR** | Broken Object Level Authorization - accessing resources by changing identifiers without server-side authorization checks |
| **JWT** | JSON Web Token - self-contained authentication token with header, payload, and signature components |
| **PKCE** | Proof Key for Code Exchange - OAuth 2.0 extension preventing authorization code interception in mobile apps |
| **Token Refresh** | Mechanism for obtaining new access tokens using long-lived refresh tokens without re-authentication |
| **Session Fixation** | Attack where adversary sets a known session ID before victim authenticates, then hijacks the session |

## Tools & Systems

- **Burp Suite**: HTTP proxy for intercepting and modifying authentication requests
- **jwt_tool**: Python tool for testing JWT vulnerabilities (none algorithm, key confusion, claim manipulation)
- **Postman**: API testing client for crafting authentication requests
- **hashcat**: Password/JWT secret cracking tool for testing HMAC signing key strength
- **Autorize**: Burp Suite extension for automated authorization testing

## Common Pitfalls

- **Rate limiting masks issues**: API may rate-limit test requests. Use delays between requests and test from the tester's authorized perspective first.
- **Token in URL**: Some mobile APIs pass tokens in URL query parameters, exposing them in server logs and browser history. Flag as Bul:ing even if authorization works correctly.
- **Refresh token rotation**: Some APIs rotate refresh tokens on each use. If your test invalidates the refresh token, you may lock out your test account.
- **Mobile-specific OAuth**: Mobile apps use custom URI schemes for OAuth redirects, which can be intercepted by malicious apps registered for the same scheme.
