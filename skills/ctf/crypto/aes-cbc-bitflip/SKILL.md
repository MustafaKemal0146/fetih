---
name: aes-cbc-bitflip
description: AES CBC/ECB modlarına karşı kriptografik bütünlük saldırıları — bit flipping, IV manipulation, ECB cut-and-paste, CBC-MAC length extension, IV reuse
tags: [ctf, crypto, aes, cbc, ecb, bit-flipping, iv-manipulation, oracle, cut-and-paste, cbc-mac, length-extension]
triggers:
  - "AES CBC"
  - "AES ECB"
  - "bit flipping"
  - "IV manipülasyon"
  - "cookie içeriği değiştirme"
  - "admin=true"
  - "ECB pattern"
  - "aynı blok aynı ciphertext"
  - "CBC-MAC"
  - "length extension"
  - "IV reuse"
  - "encrypted cookie"
  - "cipher integrity"
  - "MAC olmadan şifreleme"
  - "cut and paste"
  - "padding error mesajı yok"
difficulty: medium
category: crypto
solved_challenges:
  - "CryptoHack - Triple DES (CBC IV reuse)"
  - "PicoCTF 2022 - basic-mod1 (CBC bit flipping)"
  - "HTB Crypto - Mind in the Clouds (ECB cut-and-paste)"
  - "ASIS CTF - cbc-flipping"
  - "RaRCTF 2021 - babycrypt (CBC-MAC length extension)"
related_skills:
  - rsa-padding-oracle
  - aes-gcm-nonce-reuse
  - jwt-attacks
adapted_for: fetih
---

# AES CBC/ECB Bütünlük Saldırıları — Padding Oracle Olmadan

Çoğu AES challenge'da `oracle` yoktur — sadece şifrelenmiş veri ve encrypt/decrypt servisi vardır. Bu skill **bütünlük (integrity) eksikliğini sömüren** saldırıları kapsar. Padding oracle saldırısı için ayrı: `rsa-padding-oracle/SKILL.md`.

---

## Ne Zaman Kullan

| Senaryo | Saldırı |
|---|---|
| Cookie/token = `AES_CBC(user_data + role)`, plaintext biliyorsun | CBC bit flipping |
| Sunucu IV'i sana gösteriyor/seçtiriyor | IV manipulation |
| `user_data` ECB ile şifreleniyor, kontrolün var | ECB cut-and-paste |
| Aynı blok aynı ciphertext (ECB tespit) | ECB Penguin / pattern leak |
| MAC = `CBC-MAC(msg)` ve mesaj uzunluğu fixed değil | CBC-MAC length extension |
| Aynı IV iki farklı mesaj şifrelenmiş | IV reuse → XOR leak |

---

## Saldırı 1 — CBC Bit Flipping

### Mantık
CBC decryption: `P_i = D_k(C_i) XOR C_{i-1}`. Yani `C_{i-1}`'in bir bitini flip etmek, `P_i`'nin aynı bitini flip eder (ama `P_{i-1}`'i tahrip eder — kabul edilebilir veya bypass edilir).

### Klasik Senaryo
Cookie: `IV + AES_CBC("user=guest;admin=false;sess=abc")`.
Saldırı: `admin=false` bloğunu `admin=true ` yapmak.

```python
# exploit_cbc_bitflip.py
import base64
from typing import Tuple

BLOCK = 16

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def bit_flip(ciphertext: bytes, block_idx: int, known_plain: bytes, target_plain: bytes) -> bytes:
    """
    block_idx: hedef plaintext bloğunun indeksi (0-tabanlı, IV dahil değil)
    known_plain: o bloğun mevcut plaintext'i
    target_plain: istediğin plaintext
    NOT: block_idx-1. ciphertext bloğunu modifiye eder.
    """
    iv_and_ct = ciphertext  # IV ilk 16 byte
    blocks = [iv_and_ct[i:i+BLOCK] for i in range(0, len(iv_and_ct), BLOCK)]

    # block_idx. plaintext'i flip etmek için, block_idx-1. ciphertext'i değiştir
    # Eğer block_idx = 0 ise IV'i değiştir
    target_block_idx = block_idx  # ct'de IV var, dolayısıyla aynı

    # known XOR target = flip mask
    flip_mask = xor(known_plain, target_plain)
    blocks[target_block_idx] = xor(blocks[target_block_idx], flip_mask)

    return b''.join(blocks)

# Kullanım
cookie_b64 = '...'  # sunucudan al
ct = base64.b64decode(cookie_b64)

# Plaintext: "comment1=cooking%20MCs;userdata=AAAAAAAAAAAAAAAA;admin=false;"
# Bizim eklediğimiz bloğu (4. blok) flip ederek 5. bloğu ("admin=false;...") değiştir
# Önemli: 4. blok tahrip olur, ama sunucu o bloğu önemsemiyorsa OK

known   = b'admin=false;sess'
target  = b'admin=true ;sess'   # aynı uzunluk!
modified = bit_flip(ct, block_idx=4, known_plain=known, target_plain=target)

print(base64.b64encode(modified).decode())
```

### Tipik Tuzak
- Modifiye edilen bloğun **tamamen tahrip olur**. Sunucu o bloğu parse ediyorsa bozulur.
- Çözüm: kullanıcı kontrolündeki "garbage" bloğu seç (`userdata=AAAA...`).

---

## Saldırı 2 — IV Manipulation (ilk blok için)

### Mantık
`P_0 = D_k(C_0) XOR IV`. IV'i kontrol edebilirsen `P_0`'ı kontrol edersin (ama D_k(C_0) sabit).

```python
# Sunucu IV'i gönderiyor + ciphertext + flag eklenmiş
# Cookie = IV || AES_CBC("status=user||...")
# Saldırı: IV'i flip et, status="admin" yap

iv = ct[:BLOCK]
flip = xor(b'status=user', b'status=admin')
iv_new = xor(iv, flip)
ct_new = iv_new + ct[BLOCK:]
```

---

## Saldırı 3 — ECB Cut-and-Paste

### Mantık
ECB'de her blok bağımsız. `encrypt(prefix + user_data)` formatında veri varsa, kullanıcı bloklarını yeniden düzenleyerek farklı plaintext üret.

### Klasik Senaryo
Sunucu: `email=ATTACKER&uid=10&role=user` formatını ECB şifreliyor. Saldırgan `email` ile `admin` blokunu enjekte eder, son bloğu `admin` ile değiştirir.

```python
# exploit_ecb_cut_paste.py
import requests
import base64

URL = 'https://target.tld/profile_for'

def get_ct(email: str) -> bytes:
    r = requests.get(URL, params={'email': email})
    return base64.b64decode(r.json()['token'])

# Önce, "admin" + padding(11 byte 0x0b) içeren bir blok üret
# Email = "AAAAAAAAAA" + "admin" + bytes([11]*11) + "@x.com"
# Bu sayede 2. blok ("admin\x0b...") şifreli halini alırız.
prefix_padding = b'A' * (BLOCK - len(b'email='))   # email= 6 byte, 10 byte A
admin_block = b'admin' + b'\x0b' * 11
email1 = (prefix_padding + admin_block + b'@x.com').decode()
ct1 = get_ct(email1)
admin_ct_block = ct1[BLOCK:2*BLOCK]

# Şimdi normal bir email ile token al, son bloğu admin_ct_block ile değiştir
email2 = 'a' * (13 - len(b'@x.com')) + '@x.com'   # öyle ki son blok "user\x0c\x0c..."
ct2 = get_ct(email2)
forged = ct2[:-BLOCK] + admin_ct_block

print(base64.b64encode(forged).decode())
```

---

## Saldırı 4 — ECB Pattern Leak (Penguin Attack)

### Mantık
ECB'de aynı plaintext blok = aynı ciphertext blok. Bir görüntü ECB ile şifrelendiyse desen sızar.

```python
# Detect ECB
def is_ecb(ciphertext: bytes, block_size: int = 16) -> bool:
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))

# ECB Byte-at-a-time decrypt (chosen plaintext)
def ecb_decrypt_byte_at_a_time(oracle, prefix_known=b''):
    """
    oracle(input) → encrypt(input + SECRET)
    """
    BS = 16
    secret = b''

    # Secret uzunluğunu bul
    base_len = len(oracle(b''))
    for i in range(1, BS + 1):
        if len(oracle(b'A' * i)) > base_len:
            secret_len = base_len - i
            break

    for offset in range(secret_len):
        block_idx = offset // BS
        # Hedef blok: kalıbı doldur
        pad = b'A' * (BS - 1 - (offset % BS))

        # Reference
        ref = oracle(pad)[block_idx * BS:(block_idx + 1) * BS]

        # Brute son byte
        for b in range(256):
            guess = pad + secret + bytes([b])
            cand = oracle(guess)[block_idx * BS:(block_idx + 1) * BS]
            if cand == ref:
                secret += bytes([b])
                break

    return secret
```

---

## Saldırı 5 — CBC-MAC Length Extension

### Mantık
CBC-MAC sabit uzunluk için güvenli; değişken uzunluk için extension mümkün.

`CBC-MAC(m1) = T1`, `CBC-MAC(m2) = T2`. Saldırgan `CBC-MAC(m1 || (m2[0] XOR T1) || m2[1:]) = T2` üretebilir.

```python
# exploit_cbc_mac_extension.py

def cbc_mac_extend(m1, T1, m2, T2):
    """m1 ve m2'nin ayrı MAC'leri var. Birleştirilmişin MAC'i T2."""
    # m2'nin ilk bloğunu T1 ile XOR et
    m2_blocks = [m2[i:i+BLOCK] for i in range(0, len(m2), BLOCK)]
    m2_blocks[0] = xor(m2_blocks[0], T1)
    forged_msg = m1 + b''.join(m2_blocks)
    forged_mac = T2   # aynen!
    return forged_msg, forged_mac
```

---

## Saldırı 6 — CBC IV Reuse → Plaintext XOR Leak

### Mantık
Aynı key + aynı IV + iki plaintext: ciphertext'lerin XOR'u plaintext'lerin XOR'una eşit (sadece ilk blok için, ama dikkatli yapılırsa diğerlerine yayılır).

```python
# Aynı key+IV ile encrypt(P1) = C1, encrypt(P2) = C2
# C1 XOR C2 = D_k(C1) XOR D_k(C2)  (CBC modunda IV iptal olur sadece P0 için)
# Daha basit: ECB modunda iki blok = aynı plaintext ise XOR sıfır

# CTR modunda nonce reuse aynı sonuç:
# C1 XOR C2 = P1 XOR P2 → biri biliniyorsa diğeri çözülür (crib dragging)
```

### Crib Dragging
```python
def crib_drag(c1_xor_c2: bytes, crib: bytes) -> list:
    """Bir plaintext kısmı (crib) bilindiyse, diğer plaintext'in ilgili kısmını çıkar."""
    results = []
    for pos in range(len(c1_xor_c2) - len(crib) + 1):
        chunk = c1_xor_c2[pos:pos+len(crib)]
        other = xor(chunk, crib)
        if all(32 <= b <= 126 for b in other):  # printable
            results.append((pos, other.decode()))
    return results
```

---

## Saldırı 7 — Padding Oracle (cross-reference)

Bkz: `skills/ctf/crypto/rsa-padding-oracle/SKILL.md` — RSA padding oracle ve CBC padding oracle aynı genel teknikle çözülür. Bu skill **CBC integrity** odaklıdır, padding oracle ayrı.

---

## ECB Tespit Test Vektörü

```bash
# Hex string verilmiş, ECB mi?
python3 -c "
ct = bytes.fromhex('YOUR_HEX_HERE')
BS = 16
blocks = [ct[i:i+BS] for i in range(0, len(ct), BS)]
print('Total blocks:', len(blocks), 'Unique:', len(set(blocks)))
if len(blocks) != len(set(blocks)):
    print('ECB DETECTED')
"
```

---

## Tuzaklar

1. **CBC bit flip tahrip** — flip edilen bloğun bir önceki bloğu rastgele veri olur. Sunucu o bloğu parse ediyorsa çalışmaz.
2. **Padding bozulması** — bit flip son bloğu etkilerse padding hatası. Padding alanını flip etme.
3. **ECB cut-and-paste hizalama** — blok sınırlarına dikkat. `email=ATTACKER` 6 byte değil mi? Padding hesabı kritik.
4. **CBC-MAC** sabit uzunluk için güvenli — sunucu uzunluğu MAC'in başına ekliyorsa extension çalışmaz.
5. **IV reuse** sadece aynı key ile risk. Her sesion farklı key kullanıyorsa sorun yok.
6. **Authenticated encryption** (GCM, OCB, CCM) bu saldırıların hepsini önler. Eğer GCM görüyorsan padding/bit-flip yerine `aes-gcm-nonce-reuse` skill'ine git.

---

## Tools

```bash
# CBC bit flipping CLI
pip install pycryptodome
# Kendi exploit scriptini yaz

# Padding oracle (CBC)
pip install padding-oracle
padbuster URL COOKIE 16 -encoding 0

# Block cipher araç kiti
pip install cryptography
```

---

## Cross-Skill Pivot

```
AES challenge → mode tespit (ECB / CBC / GCM / CTR)
             ├── ECB → cut-and-paste (bu skill) veya pattern leak
             ├── CBC + padding oracle yanıtı → rsa-padding-oracle skill
             ├── CBC + integrity yok → bu skill (bit flip / IV manip)
             ├── GCM + nonce reuse → aes-gcm-nonce-reuse skill
             └── CTR + nonce reuse → crib dragging (bu skill)
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: b6ae2dbd8410f043
-->

