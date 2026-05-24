---
name: rsa-padding-oracle
description: RSA PKCS#1 v1.5 padding oracle saldırısı — Bleichenbacher'in 1998 saldırısı
tags: [ctf, crypto, rsa, padding-oracle, bleichenbacher, chosen-ciphertext, pkcs]
triggers:
  - "padding oracle"
  - "PKCS#1"
  - "chosen ciphertext"
  - "decrypt oracle mevcut"
  - "padding valid/invalid yanıtı"
  - "RSA-OAEP değil"
  - "adaptive chosen ciphertext"
difficulty: hard
category: crypto
solved_challenges:
  - "picoCTF 2024 - rsa_oracle (multiplicative homomorphism)"
  - "CryptoHack - Bleichenbacher's attack"
---

# RSA Padding Oracle Saldırısı

## Ne Zaman Kullan

Aşağıdaki koşulların ikisi birden sağlanıyorsa bu tekniği uygula:

1. **Oracle erişimi var:** Sunucuya istediğin şifreli metni gönderebiliyorsun ve şu yanıtlardan birini alıyorsun:
   - "padding valid" / "padding invalid"
   - HTTP 200 / HTTP 500
   - "OK" / hata mesajı
   - Çözülmüş mesaj (multiplicative homomorphism için)

2. **PKCS#1 v1.5 kullanılıyor:** OAEP değil. (OAEP oracle'a karşı kör değildir ama çok daha zorludur.)

**CTF'te sık karşılaşılan iki senaryo:**

| Senaryo | Açıklama | Zorluk |
|---------|----------|--------|
| **Tam Bleichenbacher** | Oracle sadece "valid/invalid" der, adaptif chosen-ciphertext ile binary search | Zor |
| **Multiplicative Homomorphism** | Oracle şifreli metni decrypt edip sonuç döner, modüler aritmetikle flag çıkarılır | Kolay |

---

## Saldırı Türleri

### Tip 1: Tam Bleichenbacher (1998)

RSA şifrelemesi homomorphic'tir:
```
Encrypt(m1) * Encrypt(m2) mod n  ==  Encrypt(m1 * m2 mod n)
```

Saldırgan `s` seçer, `c' = c * s^e mod n` gönderir.
Oracle "valid" derse: `s * m mod n` başlıyor `\x00\x02` ile.
Bu, `m`'nin hangi aralıkta olduğuna dair bilgi verir.
Adaptif binary search ile `m`'yi tam olarak buluruz.

**Karmaşıklık:** O(n^(1/3)) oracle sorgusu — 1024-bit RSA için ~2^(340/3) ≈ milyonlarca sorgu.

### Tip 2: Multiplicative Homomorphism (CTF'te çok daha yaygın)

Oracle şifreli metni decrypt eder ve sonucu döner. Biz hiçbir padding bilgisi kontrol etmeyiz:

```
c_flag  = m^e mod n          (sunucunun verdiği)
c_2     = 2^e mod n          (bizim hesapladığımız)
c_new   = c_flag * c_2 mod n (biz gönderiyoruz)

Oracle decrypt eder: c_new^d = (m * 2)^ed = m * 2 mod n

Sonuç = 2 * m mod n  →  m = sonuc * pow(2, -1, n) mod n
```

---

## Multiplicative Homomorphism Saldırısı (picoCTF Tarzı)

### Senaryo

- Sunucu `encrypt(input)` ve `decrypt(input)` endpoint'leri sunuyor
- `flag`'i direkt decrypt edemiyoruz (sunucu reddediyor)
- Ama başka şifreli metinleri decrypt ettirebiliyoruz

### Adım Adım

```
1. Sunucudan c_flag al (flag'in şifreli hali)
2. c_2 = pow(2, e, n) hesapla (2'nin şifreli hali)
3. c_blind = (c_flag * c_2) % n gönder
4. Oracle'dan m_blind = decrypt(c_blind) al
5. m_flag = (m_blind * pow(2, -1, n)) % n hesapla
6. long_to_bytes(m_flag) ile flag'i çöz
```

Neden çalışır?
```
decrypt(c_flag * c_2 mod n)
= decrypt((m^e * 2^e) mod n)
= decrypt((2*m)^e mod n)
= 2*m mod n
```

---

## Tam Python Exploit Şablonu

### Multiplicative Homomorphism (picoCTF rsa_oracle tarzı)

```python
#!/usr/bin/env python3
"""
RSA Multiplicative Homomorphism Saldırisi
picoCTF 2024 rsa_oracle ve benzeri challengelar icin.

Gereksinimler:
  pip install pycryptodome requests

Kullanim:
  1. HOST, PORT, e, n degerlerini challenge'dan al
  2. get_encrypted_flag() ve decrypt_oracle() fonksiyonlarini
     challenge'in API'sine gore duzenle
  3. Calistir
"""

import socket
import json
import re
from Crypto.Util.number import long_to_bytes, bytes_to_long

# =========================================================
# CHALLENGE-SPESIFIK AYARLAR — BURASI DEGISTIRILMELI
# =========================================================
HOST = "mercury.picoctf.net"
PORT = 12345

# Sunucu RSA parametrelerini acikliyor mu?
# Evet ise asagidaki satirlari guncelle:
e = 65537
n = 0  # Challenge'dan al

# =========================================================

def talk(sock, msg: str) -> str:
    """Sunucuya satir gonder, yanit al."""
    sock.send((msg.strip() + "\n").encode())
    resp = b""
    while True:
        chunk = sock.recv(4096)
        resp += chunk
        if b"\n" in chunk or len(chunk) < 4096:
            break
    return resp.decode(errors="replace")


def get_server_params():
    """Sunucuya baglan ve RSA parametrelerini al."""
    global e, n
    with socket.socket() as s:
        s.connect((HOST, PORT))
        banner = s.recv(4096).decode()
        print("[*] Banner:", banner[:200])

        # Challenge'a gore satir degistir:
        # Ornek: "e = 65537\nn = 123456789..."
        e_match = re.search(r"e\s*=\s*(\d+)", banner)
        n_match = re.search(r"n\s*=\s*(\d+)", banner)
        if e_match:
            e = int(e_match.group(1))
        if n_match:
            n = int(n_match.group(1))
        print(f"[*] e = {e}")
        print(f"[*] n (ilk 60 rakam) = {str(n)[:60]}...")


def get_encrypted_flag() -> int:
    """Sunucudan sifreli flag'i al."""
    with socket.socket() as s:
        s.connect((HOST, PORT))
        s.recv(4096)  # banner

        # Challenge'a gore menu secimi:
        resp = talk(s, "E")   # "Encrypt" secenegi
        print("[*] Encrypt menu:", resp[:100])

        # "flag" kelimesini gonder — sunucu flag'i sifreler
        # Bazi challengelarda direkt c_flag verilir
        resp = talk(s, "flag")
        print("[*] c_flag yaniti:", resp[:200])

        # Sifreli flag'i parse et
        hex_match = re.search(r"[0-9a-fA-F]{64,}", resp)
        if hex_match:
            return int(hex_match.group(), 16)

        int_match = re.search(r"\d{20,}", resp)
        if int_match:
            return int(int_match.group())

        raise ValueError("c_flag parse edilemedi!")


def decrypt_oracle(ciphertext: int) -> int:
    """Oracle'a sifreli metin gonder, plaintext int olarak al."""
    with socket.socket() as s:
        s.connect((HOST, PORT))
        s.recv(4096)  # banner

        # Challenge'a gore menu secimi:
        resp = talk(s, "D")   # "Decrypt" secenegi

        # Sifreli metni gonder (hex veya int olarak)
        ct_hex = hex(ciphertext)[2:]
        resp = talk(s, ct_hex)
        print(f"[*] Decrypt yaniti: {resp[:150]}")

        # Sonucu parse et
        hex_match = re.search(r"[0-9a-fA-F]{10,}", resp)
        if hex_match:
            return int(hex_match.group(), 16)

        int_match = re.search(r"\d{10,}", resp)
        if int_match:
            return int(int_match.group())

        # Sunucu direkt plaintext string donuyor mu?
        try:
            return bytes_to_long(resp.strip().encode())
        except Exception:
            raise ValueError("Decrypt sonucu parse edilemedi!")


def multiplicative_homomorphism_attack():
    """Ana saldiri fonksiyonu."""
    global e, n

    print("[*] Parametreler aliniyor...")
    if n == 0:
        get_server_params()

    print("\n[*] Adim 1: Sifreli flag aliniyor...")
    c_flag = get_encrypted_flag()
    print(f"[+] c_flag = {hex(c_flag)[:60]}...")

    print("\n[*] Adim 2: Blinding carpani hesaplaniyor...")
    # 2'yi RSA ile sifrele: c_2 = 2^e mod n
    c_2 = pow(2, e, n)

    # Kör metin: c_blind = c_flag * c_2 mod n
    # Bu, 2*m'yi sifreler (RSA'nin multiplicative homomorphism ozelligi)
    c_blind = (c_flag * c_2) % n
    print(f"[+] c_blind = {hex(c_blind)[:60]}...")

    print("\n[*] Adim 3: Oracle'dan kör metin cozuluyor...")
    m_blind = decrypt_oracle(c_blind)
    print(f"[+] m_blind = {m_blind}")

    print("\n[*] Adim 4: Gercek mesaj hesaplaniyor...")
    # m_blind = 2 * m_flag mod n
    # m_flag = m_blind * 2^(-1) mod n
    inv2 = pow(2, -1, n)
    m_flag = (m_blind * inv2) % n
    print(f"[+] m_flag (int) = {m_flag}")

    flag_bytes = long_to_bytes(m_flag)
    print(f"\n[!!!] FLAG: {flag_bytes.decode(errors='replace')}")
    return flag_bytes


if __name__ == "__main__":
    multiplicative_homomorphism_attack()
```

---

### Çarpan Değiştirme (Genelleştirme)

2 yerine başka bir çarpan da kullanılabilir:

```python
def blind_decrypt(c_flag, k, e, n, oracle_fn):
    """
    c_flag'i k ile kör ederek oracle'dan coz.
    oracle_fn: int -> int (sifreli metin -> plaintext)
    """
    c_k = pow(k, e, n)
    c_blind = (c_flag * c_k) % n
    m_blind = oracle_fn(c_blind)
    inv_k = pow(k, -1, n)
    m_flag = (m_blind * inv_k) % n
    return m_flag

# Ornek kullanim:
# m = blind_decrypt(c_flag, 2, e, n, decrypt_oracle)
# m = blind_decrypt(c_flag, 3, e, n, decrypt_oracle)  # 2 calismazsa 3 dene
```

---

## Tam Bleichenbacher Implementasyonu (Kisaltilmis)

Tam Bleichenbacher cok uzun — sadece kritik lojiği göster:

```python
import math

def bleichenbacher(c, n, e, oracle, k_bytes):
    """
    Bleichenbacher'in adaptif chosen-ciphertext saldirisi.
    oracle(ct: int) -> bool  (True: PKCS valid, False: invalid)
    k_bytes: RSA key uzunlugu byte cinsinden (ornek: 128 = 1024-bit)
    """
    B = pow(2, 8 * (k_bytes - 2))  # PKCS uyumlu aralik baslangici
    M = [(2 * B, 3 * B - 1)]       # Baslangic aralik seti
    s0 = 1  # Blinding: c0 = c * s0^e mod n (burada s0=1, blinding atlandı)

    c0 = c  # Eger oracle blinding gerektiriyorsa: c0 = c * pow(s0,e,n) % n

    i = 1
    s = math.ceil(n / (3 * B))  # Ilk s degeri

    while True:
        # Adim 2: Yeni s bul (oracle'a sor)
        if i == 1 or len(M) > 1:
            # Dogrusal arama (yavas)
            while True:
                ct_test = (c0 * pow(s, e, n)) % n
                if oracle(ct_test):
                    break
                s += 1
        else:
            # Tek aralik: ikili arama (hizli)
            a, b = M[0]
            r = math.ceil(2 * (b * s - 2 * B) / n)
            found = False
            while not found:
                s_lo = math.ceil((2 * B + r * n) / b)
                s_hi = math.floor((3 * B - 1 + r * n) / a) + 1
                for s_cand in range(s_lo, s_hi):
                    ct_test = (c0 * pow(s_cand, e, n)) % n
                    if oracle(ct_test):
                        s = s_cand
                        found = True
                        break
                r += 1

        # Adim 3: Aralik guncelle
        M_new = []
        for a, b in M:
            r_lo = math.ceil((a * s - 3 * B + 1) / n)
            r_hi = math.floor((b * s - 2 * B) / n)
            for r in range(r_lo, r_hi + 1):
                lo = max(a, math.ceil((2 * B + r * n) / s))
                hi = min(b, math.floor((3 * B - 1 + r * n) / s))
                if lo <= hi:
                    M_new.append((lo, hi))
        M = M_new

        # Adim 4: Cozum bulundu mu?
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = (M[0][0] * pow(s0, -1, n)) % n
            return m

        i += 1
        print(f"[*] Iterasyon {i}, aralik sayisi: {len(M)}, s: {s}")
```

---

## Gerçek Challenge: picoCTF 2024 — rsa_oracle

**Kategori:** Crypto
**Puan:** 300

**Senaryo:**
- Sunucu RSA ile şifrelenmiş bir flag veriyor
- Aynı sunucu herhangi bir şifreli metni decrypt edebiliyor
- Ama "flag" dizesini direkt decrypt etmeye çalışınca reddediyor

**Çözüm:**
1. Sunucudan `c_flag` al (encrypt("flag") veya direkt veriliyor)
2. `c_2 = pow(2, e, n)` hesapla
3. `c_blind = c_flag * c_2 % n` oluştur
4. `m_blind = decrypt(c_blind)` oracle'dan al
5. `m = m_blind * pow(2, -1, n) % n` hesapla
6. `long_to_bytes(m)` → flag

**Neden flag'i direkt decrypt ettiremiyoruz?**
Sunucu `c_flag`'ı blacklist'te tutuyor — tam olarak o değeri gördüğünde reddediyor.
Ama `c_flag * c_2` farklı bir değer, reddedilmiyor.

---

## Tuzaklar

| Tuzak | Çözüm |
|-------|-------|
| `pow(2, -1, n)` Python 3.8+ gerektirir | Eski Python'da `modinv(2, n)` yaz (genişletilmiş Öklid) |
| Sunucu sonucu hex mi int mi döndürüyor? | Her ikisini de parse et |
| `m_blind` bytes ise int'e çevir | `bytes_to_long(m_blind)` |
| n değerini yanlış almak (ondalık vs hex) | `int(n_str, 16)` veya `int(n_str)` — parse dikkatli yap |
| Oracle her bağlantıda taze session açıyor mu? | Context manager içinde yönet |
| `c_flag * c_2 % n == c_flag` olabilir mi? | n küçükse başka k dene; pratikte olmaz |
| flag sonu padding içeriyor | `strip()` veya `rstrip(b'\x00')` dene |

---

## Hızlı Referans

```python
from Crypto.Util.number import long_to_bytes

# Multiplicative homomorphism — tek satirda:
flag = long_to_bytes((decrypt_oracle((c_flag * pow(2, e, n)) % n) * pow(2, -1, n)) % n)
```
