---
name: rsa-wiener-attack
description: "RSA'da özel üs d küçük olduğunda (d < N^0.25) sürekli kesirler (continued fractions) genişlemesi ile d'yi kurtarma ve şifreyi çözme saldırısı."
tags: [ctf, crypto, rsa, wiener, continued-fraction, small-d, low-private-exponent]
triggers:
  - "e çok büyük N'e göre"
  - "d küçük private key"
  - "continued fraction"
  - "private exponent small"
  - "e is very large"
  - "low private component"
  - "n2/n1 ratio convergent"
  - "e/N expansion"
difficulty: medium
category: crypto
solved_challenges:
  - "CryptoCTF 2021 - DoRSA"
  - "CryptoHack - Everything is Big (Wiener's attack)"
  - "LACTF 2024 - very-hot (çarpan bulma varyantı)"
---

# RSA Wiener Attack

Wiener'in 1990 yılında yayımladığı saldırı: RSA özel üssü d, N^0.25'ten küçükse sürekli kesirler genişlemesiyle d tam olarak kurtarılır.

## Ne Zaman Kullan

Challenge'da şunlardan biri görünüyorsa bu saldırıyı dene:

- `e` değeri `N`'e yakın büyüklükte veya `N`'den büyük
- "small private exponent", "low d", "d < N^0.25" ifadeleri
- `e/N` oranı verilmiş ve `e` açıkça devasa (örneğin `N`'nin yarısı büyüklüğünde)
- İki modül verilip `n2/n1` oranı veya sürekli kesir açılımından bahsediliyorsa (CryptoCTF DoRSA varyantı)
- "continued fraction" açıkça geçiyorsa
- Şifreli metin verilmiş ama `d` ya da `p`, `q` verilmemişse ve `e` şüpheli büyük

## Matematiksel Arka Plan

Wiener saldırısının çekirdeği, **sürekli kesirler teoremidir** (continued fraction theorem). RSA'da `e·d ≡ 1 (mod φ(N))` ilişkisi vardır. Bu ifadeyi yeniden yazmak gerekirse:

```
e·d = k·φ(N) + 1  →  e/N ≈ k/d
```

Eğer `d < N^0.25 / 3` ise, `k/d` kesri, `e/N`'nin sürekli kesir açılımındaki yakınsamalardan (convergents) biri olarak tam olarak ortaya çıkar. Tüm yakınsamalar denendikten sonra her `(k, d)` çifti için `φ(N)` hesaplanabilir ve bu φ değerinin gerçek bir Euler totient olup olmadığı p, q'nun diskriminantlı kuadratik denklem çözümüyle doğrulanır.

DoRSA varyantında ise iki modül `n1`, `n2` verilir ve `n2/n1 ≈ k/x` ilişkisi kurulur. Aynı sürekli kesir tekniği `k` ve `x` değerlerini kurtarmak için `n2/n1` oranına uygulanır; ardından `φ(n1)` türetilir.

## Çözüm Adımları

1. `e` ve `N` değerlerini challenge'dan al.
2. `e/N` oranının sürekli kesir açılımını hesapla.
3. Her yakınsama `(k, d)` için:
   - `φ(N) = (e·d - 1) // k` hesapla.
   - `p + q = N - φ(N) + 1` ve `p·q = N` üzerinden diskriminantı kontrol et: `(p+q)^2 - 4N` tam kare mi?
   - Tam kare ise `p`, `q` bulunmuştur.
4. Bulunan `d` ile `m = pow(c, d, N)` hesapla.
5. `long_to_bytes(m)` ile bayrağı çöz.

**Araçlar:**
- `owiener` Python modülü (tek satır çözüm)
- SageMath `continued_fraction()` fonksiyonu
- El yazımı yakınsama döngüsü

## Exploit Kodu

### Yöntem 1 — owiener modülü (hızlı)

```python
import owiener
from Crypto.Util.number import long_to_bytes

# Challenge verisi — CryptoHack "Everything is Big" tarzı
# e burada N'e yakın büyüklükte
n = 0xAE053B85FA4A15C8A0C48AF70B4C6B3BF58DF6F4D0B02F4F78BC2A8BAD87BE
e = 0x2B3DF21A5B85CFC80D02A1F22EBAF3F3A7B84B3C1AE8B45E8A5C5A5D1B2E4F

d = owiener.attack(e, n)

if d is None:
    print("Wiener saldırısı başarısız — d N^0.25'ten büyük olabilir")
else:
    # Şifreli metin
    c = 0x1234ABCD...
    m = pow(c, d, n)
    print(long_to_bytes(m).decode())
```

### Yöntem 2 — El yazımı sürekli kesir (SageMath)

```python
# SageMath ortamında çalıştır
from Crypto.Util.number import long_to_bytes

def wiener_attack(e, n):
    cf = continued_fraction(e / n)
    convergents = cf.convergents()
    for kd in convergents:
        k = kd.numerator()
        d = kd.denominator()
        if k == 0:
            continue
        # phi(n) kontrolü
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # p ve q bulmak için kuadratik denklem
        # x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        discriminant = b^2 - 4*n
        if discriminant >= 0:
            sqrt_disc = Integer(discriminant).isqrt()
            if sqrt_disc^2 == discriminant:
                p = (b + sqrt_disc) // 2
                q = (b - sqrt_disc) // 2
                if p * q == n:
                    return d
    return None

# CryptoCTF 2021 DoRSA — n2/n1 varyantı
def dorsa_attack(n1, n2, e, c):
    cf = continued_fraction(Integer(n2) / Integer(n1))
    convergents = cf.convergents()
    for conv in convergents:
        k = conv.numerator()
        x = conv.denominator()
        if k == 0:
            continue
        # n2 = k * n1 / x  yaklaşımı üzerinden phi(n1) hesabı
        # phi(n1) = (e * d - 1) / k gibi değil; n1 = p*q olduğundan
        # x ≈ p veya q, k ortak çarpan
        # Deneme: phi1 = n1 - x - (n1//x) + 1 (p=x, q=n1//x)
        if n1 % x == 0:
            q_candidate = n1 // x
            phi1 = (x - 1) * (q_candidate - 1)
            d = pow(e, -1, phi1)
            m = pow(c, d, n1)
            flag = long_to_bytes(int(m))
            if b'CTF' in flag or b'flag' in flag.lower():
                return flag
    return None

# Kullanım
n = <N değeri>
e = <e değeri>
c = <şifreli metin>

d = wiener_attack(e, n)
if d:
    m = pow(c, d, n)
    print(long_to_bytes(int(m)))
```

### Yöntem 3 — Saf Python (SageMath yoksa)

```python
from Crypto.Util.number import long_to_bytes
import math

def isqrt(n):
    if n < 0:
        raise ValueError("Negatif sayının karekökü alınamaz")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

def continued_fraction_convergents(e, n):
    """e/n'nin yakınsamalarını üretir"""
    a0 = e // n
    convergents = [(a0, 1)]
    r0, r1 = n, e % n
    p0, p1 = 1, a0
    q0, q1 = 0, 1
    while r1 != 0:
        a = r0 // r1
        p0, p1 = p1, a * p1 + p0
        q0, q1 = q1, a * q1 + q0
        convergents.append((p1, q1))
        r0, r1 = r1, r0 % r1
    return convergents

def wiener(e, n):
    convergents = continued_fraction_convergents(e, n)
    for k, d in convergents:
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Kuadratik: x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc >= 0:
            sqrt_disc = isqrt(disc)
            if sqrt_disc * sqrt_disc == disc and (b + sqrt_disc) % 2 == 0:
                return d
    return None

# --- Challenge parametreleri ---
n = 0x...  # N değerini buraya yaz
e = 0x...  # e değerini buraya yaz
c = 0x...  # Şifreli metni buraya yaz

d = wiener(e, n)
if d:
    print(f"[+] d bulundu: {d}")
    m = pow(c, d, n)
    print(f"[+] Flag: {long_to_bytes(m).decode()}")
else:
    print("[-] Wiener başarısız, d N^0.25'ten büyük")
```

## Gerçek Challenge Referansları

### CryptoCTF 2021 — DoRSA (Hard)
- **Writeup:** https://blog.cryptohack.org/cryptoctf2021-hard
- **Özet:** İki RSA modülü `n1`, `n2` verilmiş; `n2/n1 ≈ k/x` ilişkisi tespit edilmiş. Wiener'in sürekli kesir tekniği `n2/n1` oranına uygulanarak `k` ve `x` kurtarılmış, `φ(n1)` hesaplanmış ve şifreli metin çözülmüştür.
- **Araçlar:** SageMath, `continued_fraction()`, Python
- **Flag:** `CCTF{...}` (CryptoCTF flag formatı)

### CryptoHack — Everything is Big (Wiener's Attack, Platform Referansı)
- **Writeup:** https://cryptohack.gitbook.io/cryptobook/untitled/low-private-component-attacks/wieners-attack
- **Özet:** Kanonik Wiener örneği — `e/n` sürekli kesir açılımı uygulanmış, yakınsamalar üzerinde geçerli `(k, d)` bulunmuş, kuadratik denklemle `p`, `q` elde edilmiş.
- **Araçlar:** `owiener` Python modülü, SageMath
- **Not:** CTF platformu referansı olmakla birlikte bu teknik CryptoCTF 2021, corCTF 2023 ve benzeri yarışmalarda da kullanılmıştır.

## Tuzaklar

- **d N^0.25'ten büyük:** Wiener saldırısı başarısız olur. Boneh-Durfee saldırısını (d < N^0.292) dene — SageMath `coppersmith()` gerektirir.
- **owiener None döndürüyor:** Önce `e` ve `n`'nin doğru sırayla girildiğini kontrol et. Bazı challenge'lar parametreleri ters verir.
- **Yakınsama bulunamıyor:** `e` ve `n` aynı boyutta değil mi? `e > n` ise önce `e = e % phi(n)` adımını dene (phi bilinmiyorsa n ile yaklaş: `e % n`).
- **SageMath olmadan:** `owiener` pip paketi veya el yazımı yakınsama döngüsü kullan — her ikisi de SageMath gerektirmez.
- **Yanlış FLAG format kontrolü:** `long_to_bytes(m)` bazen baştaki boş baytlar içerir; `.lstrip(b'\x00')` ile temizle.
- **DoRSA varyantı:** İki modül verildiğinde sadece tek modüle Wiener uygulamak yetmez — oran yaklaşımı (`n2/n1`) gereklidir.
