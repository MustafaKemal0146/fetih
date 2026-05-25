---
name: testing-for-sensitive-data-exposure
description: Identifying sensitive data exposure vulnerabilities including API key leakage, PII in responses, insecure storage, and unprotected data transmission during security assessments.
tags:
- secrets
- api-keys
- web-security
- data-exposure
- owasp
- fetih
- web-application-security
- pii
- cybersecurity
- penetration-testing
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- api
- authentication
- cloud
- crypto
- data
- email
- encryption
- endpoint
- exposure
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Testing for Sensitive Data Exposure


## Ne Zaman Kullanılır

- During authorized penetration tests assessing yaparken data protection controls
- evaluating yaparken: applications for GDPR, PCI DSS, HIPAA, or other data protection compliance
- For identifying leaked API keys, credentials, tokens, and secrets in application responses
- testing yaparken whether sensitive data is properly encrypted in transit and at rest
- During security assessments of APIs that handle PII, financial data, or health records

## Ön Gereksinimler

- **Authorization**: Written penetration testing agreement with data handling scope
- **Burp Suite Professional**: For intercepting and analyzing responses for sensitive data
- **trufflehog**: Secret scanning tool (`pip install trufflehog`)
- **gitleaks**: Git repository secret scanner (`go install github.com/gitleaks/gitleaks/v8@latest`)
- **curl/httpie**: For manual endpoint testing
- **Browser DevTools**: For examining local storage, session storage, and cached data
- **testssl.sh**: TLS configuration testing tool

## İş Akışı

### Adım 1: Scan for Secrets in Client-Side Code

Search JavaScript files, HTML source, and other client-side resources for exposed secrets.

```bash
curl -s "https://target.example.com/" | \
  grep -oP 'src="[^"]*\.js[^"]*"' | \
  grep -oP '"[^"]*"' | tr -d '"' | while read js; do
    echo "=== Scanning: $js ==="
    # Handle relative URLs
    if [[ "$js" == /* ]]; then
      curl -s "https://target.example.com$js"
    else
      curl -s "$js"
    fi | grep -inE \
      "(api[_-]?key|apikey|api[_-]?secret|aws[_-]?access|aws[_-]?secret|private[_-]?key|password|secret|token|auth|credential|AKIA[0-9A-Z]{16})" \
      | head -20
done

curl -s "https://target.example.com/static/app.js" | grep -nP \
  "(AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{48}|ghp_[a-zA-Z0-9]{36}|xox[bpsa]-[0-9a-zA-Z-]{10,})"

curl -s "https://target.example.com/static/app.js.map" | head -c 500

curl -s "https://target.example.com/" | grep -inE \
  "(api_key|secret|password|token|private_key|database_url|smtp_password)" | head -20

for file in .env .env.local .env.production config.json settings.json \
  .aws/credentials .docker/config.json; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.example.com/$file")
  if [ "$status" == "200" ]; then
    echo "FOUND: $file ($status)"
  fi
done
```

### Adım 2: Analyze API Responses for Data Over-Exposure

Check if API endpoints return more data than necessary.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users/me" | jq .


curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users" | jq '.[0] | keys'

echo "=== Public ==="
curl -s "https://target.example.com/api/users/1" | jq 'keys'
echo "=== Authenticated ==="
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users/1" | jq 'keys'

curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}' \
  "https://target.example.com/api/users" | jq .

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/search?q=john" | jq .
```

### Adım 3: Test Data Transmission Security

Şunu doğrula: sensitive data is encrypted during transmission.

```bash
./testssl.sh "https://target.example.com"

curl -s -v "https://target.example.com/" 2>&1 | grep -E "(SSL|TLS|cipher|subject)"

curl -s -I "http://target.example.com/" | head -5

curl -s "https://target.example.com/" | grep -oP "http://[^\"'> ]+" | head -20

curl -s "https://target.example.com/login" | grep -oP 'action="[^"]*"'


curl -s "https://target.example.com/" | grep -oP "(ws|wss)://[^\"'> ]+"
```

### Adım 4: İncele: Browser Storage for Sensitive Data

Check local storage, session storage, cookies, and cached responses.

```bash
curl -s -I "https://target.example.com/login" | grep -i "set-cookie"


curl -s "https://target.example.com/login" | \
  grep -oP '<input[^>]*(password|credit|ssn|card)[^>]*>' | \
  grep -v 'autocomplete="off"'

for page in /account/profile /api/users/me /transactions /billing; do
  echo -n "$page: "
  curl -s -I "https://target.example.com$page" \
    -H "Authorization: Bearer $TOKEN" | \
    grep -i "cache-control" | tr -d '\r'
  echo
done
```

### Adım 5: Scan Git Repositories and Source Code for Secrets

Ara: accidentally committed secrets in version control.

```bash
curl -s "https://target.example.com/.git/config"
curl -s "https://target.example.com/.git/HEAD"

git-dumper https://target.example.com/.git /tmp/target-repo

trufflehog filesystem /tmp/target-repo

gitleaks tespit etme--source /tmp/target-repo -v

trufflehog github --org target-organization --token $GITHUB_TOKEN
gitleaks tespit etme--source https://github.com/org/repo -v


```

### Adım 6: Test Data Masking and Redaction

Şunu doğrula: sensitive data is properly masked in the application.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/payment-methods" | jq .

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users/me" | jq '.ssn'

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users" | jq '.[].password // empty'

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/users/export?format=csv" | head -5

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://target.example.com/api/admin/logs" | \
  grep -iE "(password|token|secret|credit_card|ssn)" | head -10

curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"duplicate@test.com"}' \
  "https://target.example.com/api/register"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Sensitive Data Exposure** | Unintended disclosure of PII, credentials, financial data, or health records |
| **Data Over-Exposure** | API returning more data fields than the client needs |
| **Secret Leakage** | API keys, tokens, or credentials exposed in client-side code or logs |
| **Data at Rest** | Sensitive data stored in databases, files, or backups without encryption |
| **Data in Transit** | Sensitive data transmitted over network without TLS encryption |
| **Data Masking** | Replacing sensitive data with redacted values (e.g., showing last 4 digits of credit card) |
| **PII** | Personally Identifiable Information - data that can identify an individual |
| **Information Leakage** | Excessive error messages, stack traces, or debug information in responses |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Response analysis and regex-based sensitive data scanning |
| **trufflehog** | Secret Tespit across git repos, filesystems, and cloud storage |
| **gitleaks** | Git repository scanning for hardcoded secrets |
| **testssl.sh** | TLS/SSL configuration assessment |
| **git-dumper** | Downloading exposed .git directories from web servers |
| **SecretBul:er** | JavaScript file analysis for exposed API keys and tokens |
| **Retire.js** | Tespit etme JavaScript libraries with known vulnerabilities |

## Common Scenarios

### Scenario 1: API Key in JavaScript Bundle
The application's JavaScript bundle contains a hardcoded Google Maps API key and a Stripe publishable key. The Stripe key has overly broad permissions, allowing the attacker to create charges.

### Scenario 2: User API Returns Password Hashes
The `/api/users` endpoint returns complete user objects including bcrypt password hashes. Attackers can extract hashes and attempt offline cracking.

### Scenario 3: PII in Cached API Responses
The user profile API endpoint returns full SSN and credit card numbers without masking. The endpoint does not set `Cache-Control: no-store`, so responses are cached in the browser and proxy caches.

### Scenario 4: Git Repository with Database Credentials
The `.git` directory is accessible on the production server. Using git-dumper, the attacker downloads the repository history, Bul:ing database credentials committed in an early commit that were later "removed" but remain in git history.

## Output Format

```
## Sensitive Data Exposure Assessment Report

**Target**: target.example.com
**Assessment Date**: 2024-01-15
**OWASP Category**: A02:2021 - Cryptographic Failures

### Bul:ings Summary
| Bul:ing | Severity | Data Type |
|---------|----------|-----------|
| API keys in JavaScript source | High | Credentials |
| Password hashes in API response | Critical | Authentication |
| Unmasked SSN in user profile | Critical | PII |
| Credit card number in export | High | Financial |
| .git directory exposed | Critical | Source code + secrets |
| Missing TLS on API endpoint | High | All data in transit |
| Sensitive data in error messages | Medium | Technical info |

### Critical: Exposed Secrets
| Secret Type | Location | Risk |
|-------------|----------|------|
| AWS Access Key (AKIA...) | /static/app.js line 342 | AWS resource access |
| Stripe Secret Key (sk_live_...) | .env (via .git exposure) | Payment processing |
| Database URL with credentials | .git history commit abc123 | Database access |
| JWT Signing Secret | config.json (via .git) | Token forgery |

### Data Over-Exposure in APIs
| Endpoint | Unnecessary Fields Returned |
|----------|-----------------------------|
| GET /api/users | password_hash, internal_id, created_ip |
| GET /api/users/{id} | ssn, credit_card_full, date_of_birth |
| GET /api/orders | customer_phone, customer_address |

### Recommendation
1. Remove all hardcoded secrets from client-side code; use backend proxies
2. Rotate all exposed credentials immediately
3. Remove .git directory from production web root
4. Implement response field filtering; return only required fields
5. Mask sensitive data (SSN, credit card) in all API responses
6. Add Cache-Control: no-store to all sensitive endpoints
7. Enable TLS 1.2+ on all endpoints; redirect HTTP to HTTPS
8. Implement secret scanning in CI/CD pipeline (trufflehog/gitleaks)
```
