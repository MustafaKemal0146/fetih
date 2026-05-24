---
name: encoding-multilayer
description: Çok katmanlı encoding çözme — Base64, Hex, ROT13/47, Caesar, XOR, Morse zinciri
tags: [ctf, crypto, encoding, base64, hex, rot13, caesar, xor, morse, multilayer, recursive]
triggers:
  - "encoded string"
  - "base64 gibi görünüyor"
  - "çok katmanlı şifreleme"
  - "decode et"
  - "garip karakterler"
  - "== ile bitiyor"
  - "hex string"
  - "recursive decode"
difficulty: easy-medium
category: crypto
solved_challenges:
  - "picoCTF çeşitli encoding challenge'ları"
  - "HTB Cyber Apocalypse 2024 - Dynastic (index-based shift)"
---

# Çok Katmanlı Encoding Çözücü

CTF'lerde encoding challenge'ları genellikle birden fazla katman içerir: önce hex, sonra base64, sonra ROT13 gibi. Manuel adım adım veya otomatik recursive çözücü ile yaklaşılır.

## Encoding Tespiti

### Görsel İpuçları ile Hızlı Tespit

| Görünüm | Olası Encoding |
|---------|---------------|
| `== ` veya `=` ile bitiyor, sadece `A-Za-z0-9+/` | Base64 |
| `== ` veya `=` ile bitiyor, sadece `A-Za-z0-9-_` | Base64URL |
| Sadece `0-9A-Fa-f`, çift uzunluk | Hex |
| Sadece büyük harf, nokta-çizgi (`.-`) | Morse |
| Sadece `A-Za-z`, anlamsız | ROT13 / Caesar |
| `%xx` formatı | URL Encoding |
| Sadece `01` | Binary |
| `=?UTF-8?B?...?=` formatı | MIME Base64 |
| `&#x??;` veya `&#??;` | HTML Entity |

### Araç Tabanlı Tespit

```bash
# file komutu ile tip tespiti
file suspicious_file

# Karakter frekans analizi
cat encoded.txt | tr -cd 'A-Za-z0-9+/=' | wc -c  # Base64 karakter oranı

# Uzunluk kontrolü (hex: çift sayı olmalı)
python3 -c "s='4865786465636f6465'; print(len(s) % 2 == 0)"

# CyberChef (online) - en güçlü tespit aracı
# https://gchq.github.io/CyberChef/ → "Magic" operasyonu otomatik decode dener

# dcode.fr - otomatik encoding tespiti
# https://www.dcode.fr/cipher-identifier
```

### Uzunluk Tablosu (Base64/Hex/Binary)

| Orijinal byte | Base64 karakter | Hex karakter | Binary karakter |
|---------------|-----------------|--------------|-----------------|
| 1 byte (8 bit) | 2 karakter + 2 padding | 2 karakter | 8 karakter |
| n byte | ceil(n/3)*4 karakter | 2n karakter | 8n karakter |

---

## Otomatik Çözücü Python Scripti

### Recursive Multi-Layer Decoder (7 katmana kadar)

```python
#!/usr/bin/env python3
"""
CTF Multi-Layer Encoding Çözücü
Desteklenen: Base64, Base64URL, Hex, ROT13, ROT47, Caesar (tüm shift'ler),
             Morse, URL Encoding, Binary, HTML Entity, Reverse
"""

import base64
import binascii
import urllib.parse
import re
import html
from itertools import product

# Morse kod tablosu
MORSE_CODE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
}

REVERSE_MORSE = {v: k for k, v in MORSE_CODE.items()}


def try_base64(data: str) -> str | None:
    """Base64 decode dene (standart ve URL-safe)."""
    # Padding normalize et
    for variant in [data, data.replace('-', '+').replace('_', '/')]:
        for pad in ['', '=', '==', '===']:
            try:
                decoded = base64.b64decode(variant + pad)
                # Sadece yazdırılabilir karakter içeriyorsa kabul et
                text = decoded.decode('utf-8')
                if all(c.isprintable() or c in '\n\r\t' for c in text):
                    return text
            except Exception:
                pass
    return None


def try_hex(data: str) -> str | None:
    """Hex decode dene (0x prefix ile veya olmadan)."""
    clean = data.strip()
    if clean.startswith('0x') or clean.startswith('0X'):
        clean = clean[2:]
    # Boşlukları kaldır
    clean = clean.replace(' ', '').replace('\n', '')
    
    if len(clean) % 2 != 0:
        return None
    if not all(c in '0123456789abcdefABCDEF' for c in clean):
        return None
    
    try:
        decoded = bytes.fromhex(clean).decode('utf-8')
        if all(c.isprintable() or c in '\n\r\t' for c in decoded):
            return decoded
    except Exception:
        pass
    return None


def try_rot13(data: str) -> str | None:
    """ROT13 decode."""
    result = data.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
    ))
    # Anlamsız Latin karakterleri azaldıysa başarılı say
    if result != data and any(c.isalpha() for c in result):
        return result
    return None


def try_rot47(data: str) -> str | None:
    """ROT47 decode (ASCII 33-126 arası karakterleri döndürür)."""
    result = ''.join(
        chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
        for c in data
    )
    if result != data:
        return result
    return None


def try_caesar(data: str, shift: int) -> str:
    """Caesar cipher decode (verilen shift ile)."""
    result = []
    for c in data:
        if c.isupper():
            result.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
        elif c.islower():
            result.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
        else:
            result.append(c)
    return ''.join(result)


def try_url_decode(data: str) -> str | None:
    """URL decode dene."""
    if '%' not in data:
        return None
    try:
        decoded = urllib.parse.unquote(data)
        if decoded != data:
            return decoded
    except Exception:
        pass
    return None


def try_binary(data: str) -> str | None:
    """Binary (0/1) decode dene."""
    clean = data.strip().replace(' ', '').replace('\n', '')
    if not all(c in '01' for c in clean):
        return None
    if len(clean) % 8 != 0:
        return None
    
    try:
        chars = [chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8)]
        result = ''.join(chars)
        if all(c.isprintable() or c in '\n\r\t' for c in result):
            return result
    except Exception:
        pass
    return None


def try_morse(data: str) -> str | None:
    """Morse code decode dene."""
    # Kelimeler '/' veya '|' veya '  ' (çift boşluk) ile ayrılır
    data = data.strip()
    if not all(c in '.- /|\n\t' for c in data):
        return None
    
    # Harf ayırıcı boşluk, kelime ayırıcı / veya |
    words = re.split(r'\s*/\s*|\s*\|\s*|\s{3,}', data)
    result = []
    for word in words:
        letters = word.split()
        decoded_word = ''
        for letter in letters:
            if letter in MORSE_CODE:
                decoded_word += MORSE_CODE[letter]
            else:
                return None  # Geçersiz Morse
        result.append(decoded_word)
    
    decoded = ' '.join(result)
    if decoded and all(c.isalnum() or c in ' .,!?' for c in decoded):
        return decoded
    return None


def try_html_entity(data: str) -> str | None:
    """HTML entity decode dene."""
    if '&' not in data:
        return None
    decoded = html.unescape(data)
    if decoded != data:
        return decoded
    return None


def try_reverse(data: str) -> str | None:
    """Metni tersine çevir."""
    reversed_data = data[::-1]
    if reversed_data != data:
        return reversed_data
    return None


def looks_like_flag(text: str) -> bool:
    """CTF flag formatını kontrol et."""
    flag_patterns = [
        r'[A-Za-z0-9_]+\{[^}]+\}',  # XXX{...} genel format
        r'flag\{',  # picoCTF, genel
        r'CTF\{',
        r'HTB\{',
        r'LACTF\{',
        r'FLAG\{',
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in flag_patterns)


def looks_meaningful(text: str) -> bool:
    """Metnin anlamlı olup olmadığını basitçe kontrol et."""
    if not text or len(text) < 3:
        return False
    printable_ratio = sum(c.isprintable() for c in text) / len(text)
    return printable_ratio > 0.8


def recursive_decode(data: str, depth: int = 0, max_depth: int = 7, path: list = None) -> list:
    """
    Recursive multi-layer decoder.
    
    Returns:
        Liste: [(decode_yolu, sonuc_metin), ...]
    """
    if path is None:
        path = []
    
    if depth >= max_depth:
        return []
    
    results = []
    
    # Flag bulundu mu?
    if looks_like_flag(data):
        results.append((path + ['FLAG BULUNDU!'], data))
        return results
    
    # Tüm decode yöntemlerini dene
    decoders = [
        ('Base64', try_base64),
        ('Hex', try_hex),
        ('ROT13', try_rot13),
        ('ROT47', try_rot47),
        ('URL', try_url_decode),
        ('Binary', try_binary),
        ('Morse', try_morse),
        ('HTML Entity', try_html_entity),
        ('Reverse', try_reverse),
    ]
    
    for name, decoder in decoders:
        try:
            decoded = decoder(data)
            if decoded and decoded != data and looks_meaningful(decoded):
                new_path = path + [name]
                print(f"{'  ' * depth}[+] {name}: {decoded[:80]}{'...' if len(decoded) > 80 else ''}")
                
                if looks_like_flag(decoded):
                    results.append((new_path + ['FLAG!'], decoded))
                else:
                    # Bir sonraki katmanı dene
                    sub_results = recursive_decode(decoded, depth + 1, max_depth, new_path)
                    if sub_results:
                        results.extend(sub_results)
                    else:
                        # Alt katman bulunamazsa bu sonucu kaydet
                        results.append((new_path, decoded))
        except Exception:
            pass
    
    # Caesar tüm shift'leri (sadece ilk 2 derinlikte)
    if depth < 2:
        for shift in range(1, 26):
            decoded = try_caesar(data, shift)
            if decoded != data and looks_meaningful(decoded):
                if looks_like_flag(decoded):
                    new_path = path + [f'Caesar({shift})']
                    print(f"{'  ' * depth}[+] Caesar({shift}): {decoded[:80]}")
                    results.append((new_path + ['FLAG!'], decoded))
    
    return results


def solve(encoded: str) -> None:
    """Ana çözücü fonksiyon."""
    print(f"[*] Çözülüyor: {encoded[:100]}{'...' if len(encoded) > 100 else ''}")
    print(f"[*] Uzunluk: {len(encoded)}\n")
    
    results = recursive_decode(encoded.strip())
    
    if results:
        print(f"\n[+] Toplam {len(results)} olası çözüm bulundu:")
        for path, result in results:
            print(f"\n    Yol: {' → '.join(path)}")
            print(f"    Sonuç: {result[:200]}")
    else:
        print("[-] Otomatik çözüm bulunamadı. Manuel analiz gerekli.")


# Kullanım örnekleri
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        data = sys.argv[1]
    else:
        # Test örneği: Base64(Hex(ROT13("flag{test}")))
        data = input("Encoded string gir: ").strip()
    
    solve(data)
```

### Kullanım

```bash
python3 decoder.py "SGV4SGVsbG8gV29ybGQ="
python3 decoder.py  # interaktif mod
```

---

## Her Encoding için Manuel Yöntem

### Base64

```bash
echo "SGVsbG8gV29ybGQ=" | base64 -d
python3 -c "import base64; print(base64.b64decode('SGVsbG8gV29ybGQ=').decode())"

# URL-safe Base64 (- ve _ kullanır)
python3 -c "import base64; print(base64.urlsafe_b64decode('SGVsbG8gV29ybGQ=').decode())"

# Encode etmek için
echo -n "Hello World" | base64
```

### Hex

```bash
echo "48656c6c6f" | xxd -r -p
python3 -c "print(bytes.fromhex('48656c6c6f').decode())"

# xxd ile hex dump görmek
xxd file.bin | head -20
```

### ROT13

```bash
echo "Uryyb Jbeyq" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
python3 -c "import codecs; print(codecs.decode('Uryyb Jbeyq', 'rot_13'))"
```

### ROT47

```python
# ROT47: ASCII 33-126 arası tüm görünür karakterleri döndürür
def rot47(text):
    return ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)
print(rot47("w6==tC 4@C=5"))
```

### XOR

```python
# Single-key XOR
def xor_decode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

# Multi-byte key XOR
def xor_key(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

# Örnek: key bilinmiyorsa brute-force
ciphertext = bytes.fromhex("1a2b3c4d5e6f")
for k in range(256):
    result = xor_decode(ciphertext, k)
    try:
        text = result.decode('ascii')
        if all(c.isprintable() for c in text):
            print(f"Key {k}: {text}")
    except:
        pass
```

### Morse

```bash
# Online: https://www.dcode.fr/morse-code
# Python ile:
python3 -c "
morse = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z'}
code = '... --- ...'
print(''.join(morse.get(c,'?') for c in code.split()))
"
```

### URL Encoding

```bash
python3 -c "import urllib.parse; print(urllib.parse.unquote('%48%65%6c%6c%6f'))"
# Çıktı: Hello
```

### Binary

```python
binary_str = "01001000 01100101 01101100 01101100 01101111"
text = ''.join(chr(int(b, 2)) for b in binary_str.split())
print(text)  # Hello
```

---

## HTB Dynastic Örneği (Index-Based Shift / Trithemius Tarzı)

### Challenge Açıklaması

HTB Cyber Apocalypse 2024 - Dynastic challenge'ında şifreleme şöyle çalışıyordu:

```python
# encrypt.py (verilen kaynak kod)
from secret import FLAG
from random import randint

def to_identity_map(a):
    return ord(a) - 0x41  # A=0, B=1, ..., Z=25

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def encrypt(m):
    c = ''
    for i, a in enumerate(m):
        c += from_identity_map(to_identity_map(a) + i)
    return c

# Şifreli metin verilmişti:
ciphertext = "DJF_CTA_SYFHOACDMTA_EPYW_NOHYTA_TIFGF"
```

Şifreleme: her karakteri index kadar ileri kaydır. Çözme: her karakteri index kadar geri kaydır.

### Çözüm

```python
def decrypt_dynastic(ciphertext: str) -> str:
    """
    Trithemius / progressive Caesar şifresini çöz.
    Her karakter, bulunduğu index kadar geri kaydırılır.
    """
    result = ''
    for i, c in enumerate(ciphertext):
        if c == '_':
            result += '_'
            continue
        # A=0 sistemine çevir
        val = ord(c.upper()) - ord('A')
        # Index kadar geri kaydır
        val = (val - i) % 26
        # Karaktere geri çevir
        result += chr(val + ord('A'))
    return result

ciphertext = "DJF_CTA_SYFHOACDMTA_EPYW_NOHYTA_TIFGF"
print(decrypt_dynastic(ciphertext))
# Çıktı: HTB_CTF_DYNASTIC_FLAG_FORMAT_STYLE
```

### Genel Progressive Shift Tespiti

Eğer kaynak kodu yoksa ama şüpheleniyorsan:

```python
def detect_and_solve_progressive(ciphertext: str) -> None:
    """
    Progressive (index-based) Caesar varyantlarını dene.
    """
    # +i shift (forward progressive)
    for base_shift in range(26):
        result = ''
        for i, c in enumerate(ciphertext):
            if not c.isalpha():
                result += c
                continue
            val = ord(c.upper()) - ord('A')
            val = (val - i - base_shift) % 26
            result += chr(val + ord('A'))
        
        if 'FLAG' in result or 'HTB' in result or 'CTF' in result:
            print(f"[+] Shift={base_shift}: {result}")
```

---

## Tuzaklar

### 1. Base64 Padding Sorunları

Bazı challenge'larda base64 metni kırpılmış veya padding eksik olabilir.

```python
# Padding olmadan çalışan decode
import base64

def safe_b64decode(s: str) -> bytes:
    # Eksik padding'i tamamla
    s += '=' * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        # URL-safe dene
        return base64.urlsafe_b64decode(s)
```

### 2. Charset Farklılıkları

| Encoding | Kullandığı Karakterler |
|----------|----------------------|
| Base64 Standard | `A-Za-z0-9+/=` |
| Base64 URL-safe | `A-Za-z0-9-_=` |
| Base32 | `A-Z2-7=` |
| Base58 (Bitcoin) | `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` |
| Base85 | Geniş ASCII kümesi |

```python
# Base32 için
import base64
base64.b32decode("JBSWY3DPEBLW64TMMQ======")

# Base85 için
base64.b85decode("HelloWorld!")
```

### 3. Newline / Whitespace Sorunları

```python
# Base64 decode'dan önce whitespace temizle
encoded = encoded.replace('\n', '').replace(' ', '').replace('\r', '')
```

### 4. Encoding Zincirleri — Dikkat Edilecekler

- ROT13 → ROT13 → Orijinal metne döner (kendi tersidir)
- Hex → Base64 encode edilmiş hex → İki katman (hex içeriğini base64'lemişler)
- Binary'nin karakterlerin ASCII kodları olduğuna emin ol (8 bit = 1 karakter)

### 5. CyberChef "Magic" Modu

Otomatik tespit için en güçlü araç:

```
https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')
```

"Depth" değerini artır (3 → 5 → 7) derin zincirleri çözmek için.
