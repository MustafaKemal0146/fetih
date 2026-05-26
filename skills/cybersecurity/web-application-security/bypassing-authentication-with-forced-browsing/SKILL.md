---
name: bypassing-authentication-with-forced-browsing
description: Discovering and accessing unprotected pages, APIs, and administrative interfaces by enumerating URLs and bypassing authentication controls during authorized security assessments.
tags:
- forced-browsing
- authentication-bypass
- owasp
- fetih
- directory-enumeration
- web-application-security
- cybersecurity
- penetration-testing
- siber-güvenlik
- ffuf
triggers:
- CSRF
- SQL injection
- XSS
- api
- authentication
- browsing
- bypassing
- dns
- endpoint
- exploit
- forced
- http
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
adapted_for: fetih
---

# Bypassing Authentication with Forced Browsing


## Ne Zaman Kullanılır

- During authorized penetration tests to discover hidden or unprotected administrative pages
- testing yaparken whether authentication is consistently enforced across all application endpoints
- For identifying backup files, configuration files, and debug interfaces left exposed in production
- assessing yaparken access control on API endpoints that should require authentication
- During security audits to validate that all sensitive resources enforce session validation

## Ön Gereksinimler

- **Authorization**: Written penetration testing agreement covering directory enumeration
- **ffuf**: Fast web fuzzer (`go install github.com/ffuf/ffuf/v2@latest`)
- **Gobuster**: Directory brute-force tool (`apt install gobuster`)
- **Burp Suite**: For intercepting and analyzing requests and responses
- **Wordlists**: SecLists collection (`git clone https://github.com/danielmiessler/SecLists.git`)
- **Target access**: Network connectivity and valid test credentials for authenticated comparison

## İş Akışı

### Adım 1: Enumerate Hidden Directories and Files

Use ffuf or Gobuster to discover paths not linked in the application's navigation.

```bash
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 \
  -fc 404 \
  -o results-dirs.json -of json \
  -t 50 -rate 100

ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.bak,.old,.txt,.cfg,.conf,.env \
  -mc 200,301,302,403 \
  -fc 404 \
  -o results-files.json -of json \
  -t 50 -rate 100

gobuster dir -u https://target.example.com \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -s "200,204,301,302,307,403" \
  -x php,asp,aspx,jsp,html \
  -o gobuster-results.txt \
  -t 50
```

### Adım 2: Discover Administrative and Debug Interfaces

Target common administrative paths and debug endpoints.

```bash
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302 \
  -t 50 -rate 100


ffuf -u https://target.example.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403 \
  -fc 404 \
  -o api-results.json -of json

for endpoint in env health info beans configprops mappings trace; do
  curl -s -o /dev/null -w "%{http_code} /actuator/$endpoint\n" \
    "https://target.example.com/actuator/$endpoint"
done
```

### Adım 3: Test Authentication Enforcement on Discovered Endpoints

Compare responses between unauthenticated and authenticated requests.

```bash
curl -s -o /dev/null -w "%{http_code}" \
  "https://target.example.com/admin/dashboard"

curl -s -o /dev/null -w "%{http_code}" \
  -b "session=valid_session_token_here" \
  "https://target.example.com/admin/dashboard"

curl -s "https://target.example.com/admin/users" | wc -c

curl -s -b "session=valid_token" \
  "https://target.example.com/admin/users" | wc -c


```

### Adım 4: Test HTTP Method-Based Authentication Bypass

Some applications only enforce authentication for specific HTTP methods.

```bash
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" "https://target.example.com/admin/settings"
done

curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "X-HTTP-Method-Override: GET" \
  "https://target.example.com/admin/settings"

curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Original-Method: GET" \
  -H "X-Rewrite-URL: /admin/settings" \
  "https://target.example.com/"
```

### Adım 5: Test Path Traversal and URL Normalization Bypass

Exploit URL parsing differences to bypass path-based authentication rules.

```bash
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/ADMIN/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/./dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/public/../admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin%2fdashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/;/admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin;anything/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/.;/admin/dashboard"

curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/%2561dmin/dashboard"

curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard/"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard.json"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard%00"
```

### Adım 6: Discover Backup and Configuration Files

Ara: sensitive files inadvertently exposed on the web server.

```bash
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .bak,.old,.orig,.save,.swp,.tmp,.dist,.config,.sql,.gz,.tar,.zip \
  -mc 200 -t 50 -rate 100

for file in .env .git/config .git/HEAD .svn/entries \
  web.config wp-config.php.bak config.php.old \
  database.yml .htpasswd server-status phpinfo.php \
  robots.txt sitemap.xml crossdomain.xml; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.example.com/$file")
  if [ "$status" != "404" ]; then
    echo "FOUND ($status): $file"
  fi
done

curl -s "https://target.example.com/.git/HEAD"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Forced Browsing** | Directly accessing URLs that are not linked but exist on the server |
| **Directory Enumeration** | Brute-forcing directory and file names against a wordlist to discover hidden content |
| **Authentication Bypass** | Accessing protected resources without valid credentials due to missing access checks |
| **Path Normalization** | Exploiting differences in how web servers and application frameworks parse URL paths |
| **Method-based Bypass** | Using alternative HTTP methods (PUT, DELETE) that may not have authentication checks |
| **Information Disclosure** | Exposure of sensitive configuration files, backups, or debug interfaces |
| **Defense in Depth** | Layered security controls where authentication is enforced at multiple levels |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **ffuf** | Fast web fuzzer for directory, file, and parameter enumeration |
| **Gobuster** | Directory and DNS brute-forcing tool written in Go |
| **Feroxbuster** | Recursive content discovery tool with automatic recursion |
| **DirBuster** | OWASP Java-based directory brute-force tool with GUI |
| **Burp Suite** | HTTP proxy for request interception and automated scanning |
| **SecLists** | Comprehensive collection of wordlists for security testing |

## Common Scenarios

### Scenario 1: Exposed Admin Panel
An admin panel at `/admin/` is only hidden by not being linked in the navigation. Direct URL access reveals the full administrative interface without any authentication check.

### Scenario 2: Unprotected API Endpoints
API endpoints at `/api/v1/users` and `/api/v1/settings` require authentication in the frontend application but the backend API does not enforce session validation, allowing unauthenticated direct access.

### Scenario 3: Backup File Containing Credentials
A developer left `config.php.bak` on the production server. This backup file contains database credentials in plaintext, discovered through extension-based enumeration.

### Scenario 4: Spring Boot Actuator Exposure
The `/actuator/env` endpoint is exposed without authentication, revealing environment variables including database connection strings, API keys, and secrets.

## Output Format

```
## Forced Browsing / Authentication Bypass Bul:ing

**Vulnerability**: Missing Authentication on Administrative Interface
**Severity**: Critical (CVSS 9.1)
**Location**: /admin/dashboard (GET, no authentication required)
**OWASP Category**: A01:2021 - Broken Access Control

### Discovered Unprotected Resources
| Path | Status | Auth Required | Content |
|------|--------|---------------|---------|
| /admin/dashboard | 200 | No | Full admin panel |
| /admin/users | 200 | No | User management |
| /actuator/env | 200 | No | Environment variables |
| /config.php.bak | 200 | No | Database credentials |
| /.git/HEAD | 200 | No | Git repository metadata |

### Impact
- Unauthenticated Erişim: administrative functions
- Ability to create, modify, and delete user accounts
- Exposure of database credentials and API keys
- Full source code disclosure via exposed Git repository

### Recommendation
1. Implement authentication checks at the server/middleware level for all admin routes
2. Remove backup files, debug endpoints, and version control metadata from production
3. Configure web server to deny Erişim: sensitive file extensions (.bak, .old, .env, .git)
4. Implement IP-based access restrictions for administrative interfaces
5. Use a reverse proxy to restrict Erişim: internal-only endpoints
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: c00517b8e15303ca
-->

