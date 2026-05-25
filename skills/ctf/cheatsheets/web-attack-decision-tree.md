# Web CTF Saldırı Karar Ağacı

Modern web challenge gördüğünde hangi saldırı vektörünü deneyeceğini hızla seçmek için.

---

## İlk Triage (URL aldın, ne yapıyorsun?)

```
1. curl -sIv URL                    # Headers oku
2. curl -s URL/robots.txt           # Hidden endpoints
3. curl -s URL/sitemap.xml          # Map
4. View source (HTML comments)
5. Network tab (browser DevTools)   # API endpointleri
6. Cookie analizi (JWT? session?)
7. Tech stack tespit (X-Powered-By, server)
```

---

## Tech Stack → Saldırı Eşleme

| Stack İpucu | Olası Saldırılar | İlk Deneme |
|---|---|---|
| `X-Powered-By: Express` | NoSQL injection, prototype pollution, JWT bypass | `{"$gt":""}` injection |
| `X-Powered-By: PHP` | LFI, RFI, SQLi, deserialization | `?file=../../etc/passwd` |
| `Server: nginx + uwsgi` | Path traversal, SSRF, Python framework | `..%2f` bypass |
| `cookie: PHPSESSID` | Session prediction, PHP deserialization | `O:` payload |
| `cookie: connect.sid` | Express session | Prototype pollution |
| `cookie: JSESSIONID` | Java app — deserialization | ysoserial chains |
| `Set-Cookie: laravel_session` | Laravel — APP_KEY decrypt | Padding oracle |
| HS256 JWT | Secret brute (hashcat -m 16500) | `jwt.io` |
| RS256 JWT | alg confusion (RS256→HS256) | jwt_tool |
| GraphQL endpoint | Introspection, batching, IDOR | Introspection query |
| WebSocket | Origin check bypass, msg fuzzing | wsrepl |

---

## Sayfa Tipine Göre Karar

### Login formu
```
1. Default creds? (admin/admin, test/test)
2. SQL injection? (' OR 1=1--)
3. NoSQL injection? ({"$gt":""})
4. Username enumeration? (yanıt farkı)
5. Rate limit? Brute force?
6. Password reset → tokenpredictable?
7. 2FA bypass? (response manipulation)
```

### File upload
```
1. Extension bypass (.php.jpg, .phtml, .phar)
2. Content-Type bypass
3. Magic byte spoofing (GIF89a + PHP)
4. SSRF via SVG/XML
5. XXE via Office docs (.docx, .xlsx)
6. ZIP slip (../../../etc/passwd in ZIP)
7. RFI via uploaded file
```

### Search/filter
```
1. SQL injection (UNION based)
2. NoSQL injection ({"$regex":".*"})
3. XPath injection
4. SSTI ({{7*7}})
5. LDAP injection (*)
6. Command injection (; ls)
```

### API endpoint (REST/GraphQL)
```
1. IDOR (id değiştir, başkalarınki?)
2. Mass assignment (extra fields → admin: true)
3. JWT bypass
4. Race condition (parallel requests)
5. HTTP method tampering (PUT, PATCH, DELETE)
6. Verb tunneling (X-HTTP-Method-Override)
7. CORS misconfiguration (Origin: evil)
```

### Cookie / Session
```
1. JWT? (eyJ ile başlıyor mu?)
2. Predictable session (sequential?)
3. Session fixation (sabitleme)
4. Cookie integrity (encrypted? signed?)
5. PHP/Java/Python deserialization
```

### Admin panel
```
1. 403 bypass (path traversal, header)
2. SSRF → internal services
3. Default credentials
4. Authentication bypass (?admin=1)
5. Privilege escalation
```

---

## Modern Saldırı Tespit Patterns

### HTTP Request Smuggling
**İpuçları:**
- Frontend (HAProxy, nginx, CDN) + Backend (Java, Python)
- 200ms+ response time anomalies
- Some headers reflected, some not
- "CRLF" / `\r\n` filtering bypass

**Test:** `smuggler.py -u https://target.tld`

### Race Condition
**İpuçları:**
- Coupon kullan (sayı sınırlı)
- Para transferi
- Like/vote (1 kere)
- Rate limit (last-second exploit)
- File operation (check-then-act)

**Test:** Turbo Intruder veya `aiohttp` ile 50+ paralel request

### Prototype Pollution
**İpuçları:**
- JavaScript backend (Express)
- `Object.assign(target, userInput)`
- `_.merge`, `_.set` (lodash)
- Query string array (`?a[b]=c`)
- JSON body deep merge

**Test:** `?__proto__[polluted]=1`, sonra `Object.prototype.polluted` kontrolü

### SSTI (Server-Side Template Injection)
**İpuçları:**
- `{{7*7}}` → 49 görüyorsan SSTI var
- `${7*7}` → Java/Thymeleaf
- `<%= 7*7 %>` → ERB/EJS
- User input bir email/PDF/template'e basılıyor

### SSRF
**İpuçları:**
- URL parametre fetch ediliyor (`?url=...`)
- Webhook URL
- Open Redirect
- PDF generation
- Image proxy

**Test:** `http://169.254.169.254/` (AWS metadata), `http://localhost:8080/`

---

## SQLi Hızlı Karar

```
SQLi tespit ettin → Tipini belirle:
├── Error mesajı dönüyor → Error-based
├── Boolean ayrımı (true/false yanıt farklı) → Boolean blind
├── Time-based (SLEEP(5)) → Time blind
├── UNION mümkün → UNION-based
└── İçerik reflected → In-band

Veritabanı tespit:
├── @@version, version() → MySQL
├── pg_version → PostgreSQL
├── @@servername → MSSQL
├── banner → Oracle
└── sqlite_version() → SQLite
```

---

## JWT Hızlı Karar

```
JWT gördün → Header'ı decode et:
├── alg: none → forge direkt
├── alg: HS256 → secret brute (hashcat -m 16500)
├── alg: RS256 → public key bul → alg confusion → HS256 forge
├── alg: ES256 → ECDSA, nonce reuse mümkün mü?
├── kid header → SQL injection, LFI
├── jku/x5u → SSRF, controlled key
└── Custom alg → uygulama özgü saldırı
```

---

## Brute Force / Recon Araçları

```bash
# Subdomain
subfinder -d target.tld
amass enum -d target.tld
ffuf -w subs.txt -u https://FUZZ.target.tld

# Directory/file
ffuf -w common.txt -u https://target.tld/FUZZ
gobuster dir -u https://target.tld -w common.txt -x php,html,txt
feroxbuster -u https://target.tld

# Parameter discovery
arjun -u https://target.tld/api/endpoint
paramspider -d target.tld

# Vulnerabilities
nuclei -u https://target.tld -t cves/
nikto -h https://target.tld
```

---

## Karar Ağacı Akış Şeması

```
Web challenge geldi
│
├── Statik mi, dinamik mi? (curl + fark)
│   ├── Statik → HTML/JS/CSS analiz, hidden content
│   └── Dinamik → backend ile etkileşim
│
├── Auth var mı?
│   ├── Yok → direkt API/endpoint test
│   └── Var → bypass / register / brute
│
├── Tech stack tespit
│   └── Stack-specific saldırılar (yukarıdaki tablo)
│
├── Input vektörleri çıkar
│   ├── URL params → SSRF, LFI, IDOR
│   ├── POST body → SQLi, NoSQL, deserialization
│   ├── Headers → SSRF, smuggling
│   ├── Cookies → session, JWT
│   └── File upload → RCE, XXE
│
└── 3 saldırı dene; başarısızsa kategori değiştir
```

---

## İlgili Skill'ler

- `skills/ctf/web/sqli-exploitation/SKILL.md`
- `skills/ctf/web/jwt-web-bypass/SKILL.md`
- `skills/ctf/web/ssrf-ssti-chain/SKILL.md`
- `skills/ctf/web/graphql-attacks/SKILL.md`
- `skills/ctf/web/deserialization/SKILL.md`
- `skills/ctf/web/http-request-smuggling/SKILL.md`
- `skills/ctf/web/race-conditions/SKILL.md`
- `skills/ctf/web/prototype-pollution/SKILL.md`
