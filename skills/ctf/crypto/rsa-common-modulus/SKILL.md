---
name: rsa-common-modulus
description: Aynı N ile iki farklı e kullanılarak şifrelenmiş mesaj, extended GCD ile çözülür
tags: [ctf, crypto, rsa, common-modulus, ortak-modul, extended-gcd, bezout]
triggers:
  - "aynı N iki farklı e"
  - "common modulus"
  - "ortak modül"
  - "two ciphertexts same n"
  - "e1 e2 coprime"
  - "gcd(e1,e2)=1"
difficulty: medium
category: crypto
solved_challenges:
  - "CryptoCTF 2021 - DoRSA (continued fraction variant)"
  - "CryptoHack - Everything is Big"
adapted_for: fetih
---

# RSA Common Modulus Saldırısı

## Ne Zaman Kullan

Aşağıdaki koşullar sağlanıyorsa bu tekniği dene:

- Aynı `N` (modulus) kullanılmış, **farklı** `e1` ve `e2` ile
- Aynı mesaj `m` her iki anahtarla şifrelenmiş:
  ```
  c1 = m^e1 mod N
  c2 = m^e2 mod N
  ```
- `gcd(e1, e2) == 1` (coprime — birbirlerine göre asallar)

**Nereden anlarsın?**
- Challenge iki farklı public key veriyor ama N aynı
- Kaynak kodda `n = p * q` bir kez üretiliyor, e farklı seçiliyor
- "Bob her mesajı iki farklı alıcıya gönderdi" senaryosu

**Bu teknik çalışmaz eğer:**
- `gcd(e1, e2) > 1` — bu durumda farklı yaklaşım gerekir (aşağıda açıklandı)
- Mesajlar farklı (`m1 ≠ m2`) — şifreleme farklı plaintext üzerinde yapılmış

---

## Matematiksel Temel

### Bezout Lemması

İki tamsayı `a` ve `b` için `gcd(a, b) = 1` ise, şunu sağlayan `x` ve `y` tam sayıları vardır:

```
a*x + b*y = 1
```

### Saldırının Mantığı

Bezout lemmasını `e1` ve `e2` için uygula:

```
e1*a + e2*b = 1        (a, b < 0 veya > 0 olabilir)
```

Extended GCD algoritması bunu bulur. Sonra:

```
c1^a * c2^b mod N
= (m^e1)^a * (m^e2)^b mod N
= m^(e1*a) * m^(e2*b) mod N
= m^(e1*a + e2*b) mod N
= m^1 mod N
= m
```

Negatif üsler için modüler ters gerekir:
```
c^(-k) mod N  ≡  modinv(c, N)^k mod N
```

---

## Tam Python Exploit Kodu

```python
#!/usr/bin/env python3
"""
RSA Common Modulus Saldirisi
Ayni N, farkli e1 ve e2 ile sifrelenip gcd(e1,e2)=1 ise calısır.

Gereksinimler: pycryptodome
  pip install pycryptodome
"""

import math
from Crypto.Util.number import long_to_bytes


def extended_gcd(a: int, b: int):
    """
    Genisletilmis Oklid algoritmasi.
    Dondurur: (g, x, y) oyle ki a*x + b*y = g = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a: int, m: int) -> int:
    """a'nin m modülundeki tersi. gcd(a,m)=1 olmali."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modüler ters yok: gcd({a},{m}) = {g}")
    return x % m


def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int) -> bytes:
    """
    RSA Common Modulus saldırısı.

    Parametreler:
        n  : Ortak modulus
        e1 : Birinci public exponent
        e2 : Ikinci public exponent
        c1 : c1 = m^e1 mod n
        c2 : c2 = m^e2 mod n

    Dondurur: plaintext (bytes)
    """
    # On kontrol
    g = math.gcd(e1, e2)
    if g != 1:
        print(f"[!] UYARI: gcd(e1, e2) = {g}, saldiri dogrudan calismayabilir.")
        print(f"    e1 = {e1}, e2 = {e2}")
        print(f"    Fallback: e1,e2'yi {g}'ye bol ve dene.")
        # Fallback: ortak boleni at
        e1_r, e2_r = e1 // g, e2 // g
        return common_modulus_attack(n, e1_r, e2_r, c1, c2)

    # Bezout katsayılarını bul: e1*a + e2*b = 1
    gcd_val, a, b = extended_gcd(e1, e2)
    print(f"[*] e1*a + e2*b = 1 cozumu:")
    print(f"    a = {a}")
    print(f"    b = {b}")
    print(f"    Dogrulama: {e1}*{a} + {e2}*{b} = {e1*a + e2*b}")

    # Negatif usler icin modüler ters kullan
    if a < 0:
        # c1^a mod n = modinv(c1, n)^(-a) mod n
        c1_part = pow(modinv(c1, n), -a, n)
    else:
        c1_part = pow(c1, a, n)

    if b < 0:
        c2_part = pow(modinv(c2, n), -b, n)
    else:
        c2_part = pow(c2, b, n)

    # m = c1^a * c2^b mod n
    m = (c1_part * c2_part) % n
    print(f"[+] Mesaj (int): {m}")

    result = long_to_bytes(m)
    print(f"[+] Mesaj (bytes): {result}")
    return result


# =========================================================
# CHALLENGE DEGERLERİNİ BURAYA KOY
# =========================================================
if __name__ == "__main__":
    # Ornek — gercek challenge degerlerini buraya yapistir:
    n  = 0xDEADBEEFCAFEBABE   # Ortak modulus
    e1 = 17                    # Birinci exponent
    e2 = 65537                 # Ikinci exponent
    c1 = 0xAAAA                # Birinci sifreli metin
    c2 = 0xBBBB                # Ikinci sifreli metin

    flag = common_modulus_attack(n, e1, e2, c1, c2)
    print(f"\n[!!!] FLAG: {flag.decode(errors='replace')}")
```

---

## CryptoCTF 2021 — DoRSA Detaylı Örneği

**Challenge Açıklaması:**
"RSA with a twist. The twist is continued fractions."

**Verilen:**
```
n  = [büyük sayı]
e1 = [büyük sayı — n'ye yakın]
e2 = [büyük sayı — n'ye yakın]
c1 = m^e1 mod n
c2 = m^e2 mod n
```

**Özellik:** `e1` ve `e2` çok büyük — neredeyse `n` kadar. Bu durumda standart common modulus
saldırısı çalışır ama Bezout katsayıları `a` ve `b` astronomik büyür.

**CryptoCTF varyantında ek zorluk:** Challenge adında "DoRSA" ve continued fraction ipucu
verilmiş. Aslında `e1 * e2 ≈ n` ve `d ≈ sqrt(N)` gibi ilişkiler kurulabiliyor.

```python
# CryptoCTF DoRSA - genellestirilmis cozum cercevesi
from math import gcd, isqrt
from Crypto.Util.number import long_to_bytes

def solve_dorsa(n, e1, e2, c1, c2):
    """
    DoRSA tarzı challenge için ortak modulus + fallback yaklaşımı.
    """

    # Adim 1: gcd(e1, e2) kontrol
    g = gcd(e1, e2)
    print(f"[*] gcd(e1, e2) = {g}")

    if g == 1:
        # Klasik common modulus yeterli
        return common_modulus_attack(n, e1, e2, c1, c2)

    # Adim 2: gcd > 1 durumu — ortak faktoru indir
    # e1/g ve e2/g hala coprime mi?
    e1r, e2r = e1 // g, e2 // g
    g2 = gcd(e1r, e2r)
    print(f"[*] Indirgenmis: e1/g = {e1r}, e2/g = {e2r}, gcd = {g2}")

    if g2 == 1:
        # m^g'yi bul, sonra g. koku al
        m_g = common_modulus_attack(n, e1r, e2r, c1, c2)
        m_g_int = int.from_bytes(m_g, 'big')
        print(f"[*] m^{g} bulundu: {m_g_int}")

        # g. kok (tam sayi), ozellikle g=2 veya 3 ise makul
        m_candidate, is_perfect = gmpy2_iroot(m_g_int, g)
        if is_perfect:
            return long_to_bytes(m_candidate)
        else:
            print(f"[-] {g}. kök tam sayi degil — başka yaklasım lazim")
            return None

    print("[-] Indirgenmiş exponentler de coprime degil. Daha karmasik durum.")
    return None


def gmpy2_iroot(n, k):
    """gmpy2 olmadan tam kök kontrolü (küçük k için)."""
    try:
        import gmpy2
        return gmpy2.iroot(n, k)
    except ImportError:
        # Basit Newton yöntemi
        if k == 2:
            r = isqrt(n)
            return r, r * r == n
        # Genel Newton
        r = int(n ** (1/k))
        for candidate in [r-1, r, r+1]:
            if candidate ** k == n:
                return candidate, True
        return r, False
```

---

## Tuzaklar

### 1. `gcd(e1, e2) > 1` Durumu

En sık karşılaşılan zorluk. Örnek:

```
e1 = 6,  e2 = 10  →  gcd = 2

Bezout: 6a + 10b = 2  →  3a + 5b = 1
Cozum: a = 2, b = -1
Yani: 6*2 + 10*(-1) = 2

Elde edilen:  c1^2 * c2^(-1) mod n = m^2
Sonra: m = integer_sqrt(m^2)  — sadece m küçükse veya tam kare ise calısır
```

**Ne yapılır:**
- `m^g` elde edilir
- `g`'nin tam kökü alınır (`gmpy2.iroot`)
- Kök tam değilse: `m` modüler kareköke bakılır (`Tonelli-Shanks`)
- Hala olmuyorsa: başka teknik gerekir

### 2. Bezout Katsayıları Astronomik Büyük

`e1` ve `e2` büyük olduğunda `a` ve `b` çok büyür. Hesaplama yine de doğru çalışır
çünkü `pow(c, a, n)` Python'da verimli (modüler üs alma).

### 3. `modinv(c1, n)` Çalışmıyor

`gcd(c1, n) > 1` ise `c1` ve `n` ortak bir çarpana sahip — bu durumda:
```python
g = gcd(c1, n)
if g > 1:
    p = g          # n'nin bir asal çarpanı bulundu!
    q = n // p
    # RSA private key hesapla...
```
Bu aslında büyük bir hediyedir — N direkt çözüldü.

### 4. Şifreli Metin Hex mi Decimal mi?

```python
# Otomatik parse:
def parse_int(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    # Hex mi kontrol et (sadece 0-9, a-f)
    try:
        v = int(s, 16)
        # Eger buyuk buyuk int, hex olabilir
        if len(s) > 15:
            return v
    except ValueError:
        pass
    return int(s)
```

### 5. Sonuç Anlamsız Görünüyorsa

- `long_to_bytes(m)` yerine `long_to_bytes(m).strip(b'\x00')` dene
- Flag formatını kontrol et: `picoCTF{`, `flag{`, vb.
- `m` yanlış seçilmiş olabilir — `n - m` dene (negatif sonuç durumu)
- Mesaj UTF-8 değil başka encoding olabilir: `errors='replace'`

---

## Hızlı Kontrol Listesi

```
[ ] n1 == n2 mi? (ortak modulus var mı?)
[ ] gcd(e1, e2) == 1 mi? (coprime)
[ ] c1 ve c2 aynı mesaj için mi şifrelenmiş?
[ ] extended_gcd(e1, e2) → (1, a, b) bul
[ ] a < 0 ise modinv(c1, n)^|a| kullan
[ ] b < 0 ise modinv(c2, n)^|b| kullan
[ ] m = (c1^a * c2^b) % n
[ ] long_to_bytes(m) ile decode et
```

---

## Hızlı Tek Satır Çözüm

```python
from math import gcd
from Crypto.Util.number import long_to_bytes

def quick_common_modulus(n, e1, e2, c1, c2):
    from sympy import gcdex
    a, b, _ = gcdex(e1, e2)  # e1*a + e2*b = 1
    a, b = int(a), int(b)
    inv_c1 = pow(c1, -1, n)
    inv_c2 = pow(c2, -1, n)
    p1 = pow(c1, a, n) if a >= 0 else pow(inv_c1, -a, n)
    p2 = pow(c2, b, n) if b >= 0 else pow(inv_c2, -b, n)
    return long_to_bytes((p1 * p2) % n)

# Kullanim:
# flag = quick_common_modulus(n, e1, e2, c1, c2)
# print(flag.decode())
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: d49661272a2194a5
-->

