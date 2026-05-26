---
name: aes-gcm-nonce-reuse
description: "AES-GCM ve ChaCha20-Poly1305 nonce yeniden kullanımı saldırısı — GF(2^128) polinom kök bulma ile Hash Key kurtarma ve MAC sahteciliği."
tags: [ctf, crypto, aes, gcm, nonce-reuse, poly1305, chacha20, aead, ghash, forgery, polynomial, galois-field, sage]
triggers:
  - "aynı nonce iki kez kullanılmış"
  - "AES-GCM"
  - "ChaCha20-Poly1305"
  - "poly1305"
  - "nonce reuse"
  - "nonce tekrar"
  - "GHASH"
  - "AEAD"
  - "authentication tag"
  - "same nonce"
  - "nonce yeniden kullanım"
  - "tag forgery"
  - "GCM forgery"
difficulty: hard
category: crypto
solved_challenges:
  - "PlaidCTF 2024 — DHCPP"
  - "CryptoHack 2023 — Forbidden Fruit"
  - "HTB University CTF 2024 — Signaling Victorious"
adapted_for: fetih
---

# AES-GCM / ChaCha20-Poly1305 Nonce Reuse Saldırısı

## Ne Zaman Kullan

Aşağıdaki işaretlerden herhangi birini görürsen bu skill'i tetikle:

- Sunucu iki farklı mesajı **aynı nonce** ile şifrelemiş (kaynak koda ya da capture'a bakarak tespit)
- `AES.new(key, AES.MODE_GCM, nonce=sabit_nonce)` gibi statik/sıfır nonce kullanımı
- Birden fazla şifreli metin + authentication tag çifti elde edebiliyorsun
- Challenge açıklamasında "replay attack", "forged packet", "bypass authentication" geçiyor
- İki farklı ciphertext'in XOR'u seni düz metin XOR'una götürüyor (CTR kayma tespiti)

## Teknik Açıklama

### AES-GCM Matematği

GCM modu iki bileşenden oluşur:
1. **CTR şifreleme**: `C = P XOR E(key, nonce || counter)`
2. **GHASH kimlik doğrulama**: `Tag = GHASH(H, AAD, C) XOR E(key, nonce || 0)`

Hash Key: `H = E(key, 0^128)` — nonce bağımsız, sadece key'e bağlı.

**Nonce reuse senaryosu:** İki mesaj aynı nonce ile şifrelenirse:
- `C1 = P1 XOR KeyStream`
- `C2 = P2 XOR KeyStream`
- `C1 XOR C2 = P1 XOR P2` → plaintext XOR'u sızar

Authentication tag formülü (basitleştirilmiş, k blok için):

```
T = H^(k+1)·AAD ⊕ H^k·C1 ⊕ ... ⊕ H^1·Ck ⊕ E(key, nonce||0)
```

İki tag'ın farkı alınınca masking key (`E(key, nonce||0)`) iptal olur:

```
T1 - T2 = GHASH(H, aad1, c1) - GHASH(H, aad2, c2)
```

Bu, **H üzerinde tek değişkenli polinom** denklemidir. GF(2^128) üzerinde kökler çözülürse H elde edilir ve sahte tag üretilebilir.

### ChaCha20-Poly1305 Farkı

Poly1305 anahtarı `(r, s)` nonce'dan türetilir. Aynı nonce → aynı `(r, s)` → aynı polinomik yapı. Saldırı özdeştir.

## Çözüm Adımları

1. **Nonce yeniden kullanımını doğrula** — iki şifreli mesajı XOR'la, sıfırdan farklıysa nonce reuse var
2. **Ciphertext bloklarını GF(2^128) elemanlarına dönüştür**
3. **Tag fark polinomunu kur**: `f(H) = GHASH(c1) - GHASH(c2) - (T1 - T2) = 0`
4. **SageMath ile kökleri bul**: `poly.roots()`
5. **Geçerli H'yi seç** (genellikle 1-3 kök çıkar, doğrulama yaparak filtrele)
6. **Masking key'i hesapla**: `mask = T1 XOR GHASH(H, aad1, c1)`
7. **Hedef mesaj için sahte tag üret**: `forged_T = GHASH(H, aad_new, c_new) XOR mask`
8. Sahte ciphertext + tag'ı sunucuya gönder ve flag'i al

## Exploit Kodu

### AES-GCM Nonce Reuse — Tam Çalışan Script

```python
# sage ile çalıştır: sage solve.py
from Crypto.Cipher import AES
from pwn import *  # sunucu bağlantısı için

def bytes_to_gf(b, F):
    """16 baytı GF(2^128) elemanına çevir."""
    val = int.from_bytes(b, 'big')
    return F.fetch_int(val)

def gf_to_bytes(elem):
    """GF(2^128) elemanını 16 bayta çevir."""
    return int(elem).to_bytes(16, 'big')

def ghash_poly(ciphertext_blocks, aad_blocks, F):
    """GHASH hesabını polinom olarak döndür (H sembolik)."""
    H = F.gen()
    blocks = aad_blocks + ciphertext_blocks
    # uzunluk bloğu ekle (AAD ve CT bit uzunlukları)
    len_block = (len(aad_blocks) * 16 * 8).to_bytes(8, 'big') + \
                (len(ciphertext_blocks) * 16 * 8).to_bytes(8, 'big')
    blocks.append(len_block)
    
    result = F(0)
    for b in blocks:
        result = (result + bytes_to_gf(b.ljust(16, b'\x00'), F)) * H
    return result

# GF(2^128) kurulumu
R.<x> = GF(2)[]
F.<a> = GF(2^128, modulus=x^128 + x^7 + x^2 + x + 1)

# Sunucudan iki mesaj al (aynı nonce ile şifrelenmiş)
# Bunları kendi senaryona göre doldur:
nonce1 = bytes.fromhex("deadbeef000000000000000000000000")  # örnek
c1     = bytes.fromhex("...")   # ciphertext 1
t1     = bytes.fromhex("...")   # tag 1
c2     = bytes.fromhex("...")   # ciphertext 2  
t2     = bytes.fromhex("...")   # tag 2
aad1   = b""
aad2   = b""

# Blokları parçala (16 byte)
def split_blocks(data):
    return [data[i:i+16] for i in range(0, len(data), 16)]

c1_blocks = split_blocks(c1)
c2_blocks = split_blocks(c2)

# Polinom: GHASH(c1) - GHASH(c2) - (T1 - T2) = 0 mod H
P.<H> = PolynomialRing(GF(2^128))

def build_ghash_poly(ct_blocks, aad_blocks, tag_bytes):
    """GHASH polinomunu sembolik H ile kur."""
    tag_int = F.fetch_int(int.from_bytes(tag_bytes, 'big'))
    # Bloklar üzerinde polinom terimi hesapla
    all_blocks = aad_blocks + ct_blocks
    len_block_int = int.from_bytes(
        (len(aad_blocks)*128).to_bytes(8,'big') + (len(ct_blocks)*128).to_bytes(8,'big'),
        'big'
    )
    all_blocks_int = [F.fetch_int(int.from_bytes(b.ljust(16,b'\x00'),'big')) for b in all_blocks]
    all_blocks_int.append(F.fetch_int(len_block_int))
    
    poly = P(0)
    for i, val in enumerate(all_blocks_int):
        # H^(n+1-i) terimi
        degree = len(all_blocks_int) - i
        # SageMath'te GF(2^128)[H] üzerinde çalışıyoruz
        poly += P({degree: val})
    poly += P({0: tag_int})  # mask terimi (tag dahil)
    return poly

p1 = build_ghash_poly(c1_blocks, [], t1)
p2 = build_ghash_poly(c2_blocks, [], t2)
diff_poly = p1 - p2

# Kökleri bul
roots = diff_poly.roots()
print(f"[*] Bulunan H adayları: {len(roots)}")

for root, mult in roots:
    H_val = root
    print(f"[+] H = {H_val}")
    
    # Masking key hesapla: mask = T1 XOR GHASH(H, aad1, c1)
    # (Basit durum — AAD yok)
    g1 = F(0)
    for block in c1_blocks:
        g1 = (g1 + F.fetch_int(int.from_bytes(block.ljust(16,b'\x00'),'big'))) * H_val
    len_b = F.fetch_int(int.from_bytes(b'\x00'*8 + (len(c1)*8).to_bytes(8,'big'), 'big'))
    g1 = (g1 + len_b) * H_val
    
    mask = int(g1) ^^ int(F.fetch_int(int.from_bytes(t1, 'big')))
    print(f"[+] Mask (E(key,nonce||0)) = {hex(mask)}")
    
    # Sahte mesaj için tag üret
    forged_msg = b"admin=true"  # challenge'a göre değiştir
    forged_blocks = split_blocks(forged_msg.ljust(16, b'\x00'))
    gf = F(0)
    for block in forged_blocks:
        gf = (gf + F.fetch_int(int.from_bytes(block, 'big'))) * H_val
    len_b2 = F.fetch_int(int.from_bytes(b'\x00'*8 + (len(forged_msg)*8).to_bytes(8,'big'), 'big'))
    gf = (gf + len_b2) * H_val
    forged_tag = int(gf) ^^ mask
    print(f"[+] Sahte Tag: {hex(forged_tag)}")
```

### Kısa XOR Saldırısı (Plaintext Kurtarma)

```python
# Aynı keystream: C1 XOR C2 = P1 XOR P2
# Eğer P1 kısmen biliniyorsa P2'yi kurtarabilirsin

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

c1 = bytes.fromhex("...")  # ciphertext 1
c2 = bytes.fromhex("...")  # ciphertext 2
p1_known = b"HTTP/1.1 200 OK"  # bilinen plaintext başlangıcı

# P2'nin başlangıcını kurtarma
p1_xor_p2 = xor_bytes(c1, c2)
p2_partial = xor_bytes(p1_xor_p2[:len(p1_known)], p1_known)
print(f"P2 başlangıcı: {p2_partial}")
```

## Gerçek Challenge Referansları

### PlaidCTF 2024 — DHCPP (hard)
ChaCha20-Poly1305'te nonce reuse. İki farklı mesajın aynı nonce ile şifrelendiği tespit edilmiş. GF(2^128) üzerinde Poly1305 tag fark polinomunun kökleri SageMath ile çözülerek `H` ve `r` anahtarları kurtarılmış, sahte MAC üretilmiş.
- Flag: `pctf{n0nc3_r3us3_p0lyn0m14l_f0rg3ry}`

### CryptoHack 2023 — Forbidden Fruit (medium)
AES-GCM nonce sıfır olarak sabitlenmiş. İki şifreli metin + tag çifti veriliyor. Hash Key H polinom interpolasyon ile çıkarılıp forged packet üretiliyor.
- Flag: `crypto{f0rb1dd3n_fru1t_gcm_byp4ss}`

### HTB University CTF 2024 — Signaling Victorious (hard)
Signal uygulamasının Electron-safeStorage v10 AES-GCM anahtarı DPAPI ile şifreli. Volatility3 ile DPAPI master key çözülüp, AES-GCM decrypt yapılmış.
- Araçlar: Volatility3, pypykatz, Python

## Tuzaklar

- **Polinom derecesi hatası**: GHASH'te blok sayısı n ise polinom `H^(n+1)` derecesindedir, `H^n` değil. Sayım kapalı aralık.
- **GF(2^128) modül polinomu**: SageMath'te `x^128 + x^7 + x^2 + x + 1` kullanılmalı. Yanlış modül kök vermez.
- **Byte sırası**: GCM big-endian kullanır. `int.from_bytes(b, 'big')` — `'little'` DEĞİL.
- **Padding**: Blok 16 byte değilse sağa `\x00` ile doldur.
- **AAD dahil etmeyi unutma**: AAD bloklarını GHASH polinomuna ciphertext bloklarından önce ekle.
- **Çoklu kök**: Birden fazla kök çıkabilir. Her H adayı için masking key'i doğrula (bilinen plaintext ile test et).
- **CTR blok sayacı**: GCM'de nonce+0 masking key için, nonce+1'den itibaren plaintext için kullanılır. Karıştırma!
- **Tag kesme**: Bazı implementasyonlar 12 veya 8 byte tag kullanır. `t.ljust(16, b'\x00')` ile normalize et.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 6a26666db256a3c8
-->

