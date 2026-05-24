---
name: rsa-close-primes
description: RSA'da p ve q birbirine çok yakınsa Fermat factorization ile N çarpanlarına ayrılır
tags: [ctf, crypto, rsa, fermat, close-primes, factorization, yakın-asal]
triggers:
  - "yakın asal sayılar"
  - "p ve q yakın"
  - "fermat factorization"
  - "N'in karekökü yakınında"
  - "p-q küçük"
  - "factordb bulamıyor"
  - "üç asal çarpım N=p*q*r"
difficulty: medium
category: crypto
solved_challenges:
  - "LACTF 2024 - very-hot (N=p*q*r, p,q,r ardışık aralıkta)"
  - "CryptoCTF 2023 - closeprimes"
---

# RSA Close Primes — Fermat Factorization

## Ne Zaman Kullan

Aşağıdaki belirtilerden biri varsa bu tekniği dene:

- N sayısı FactorDB, yatools, SageMath `factor()` ile çözülemiyor
- Chall kaynağı mevcut ve asal sayılar şöyle üretilmiş:
  ```python
  p = getPrime(512)
  q = getPrime(512)   # p'den bağımsız, ama her ikisi de getStrongPrime ile üretilmişse yakın olmayabilir
  ```
- Challenge açıklamasında "very close primes", "nearby primes", "p ≈ q" gibi ipuçları var
- `|p - q|` değeri 2^(bitlen/2) civarında veya daha küçük
- N = p * q * r şeklinde üç çarpan var ve aralarındaki fark küçük (LACTF very-hot vakası)
- msieve / yafu çok yavaş ya da sonuç vermiyor

**Altın kural:** `sqrt(N)` 'i integer alıp kare mı diye bak. Değilse Fermat iteration başlat.

---

## Fermat Factorization Mantığı

Her tek sayı N, iki kare farkı olarak yazılabilir:

```
N = a² - b²  =  (a+b)(a-b)
```

Dolayısıyla:
```
p = a + b
q = a - b
```

p ve q birbirine yakınsa `a ≈ sqrt(N)` ve b çok küçük olur — iterasyon hızla çalışır.

**Yakınsama koşulu:** `|p - q| < N^(1/4)` olduğunda pratik süreler içinde çözülür.
`|p - q| < N^(1/3)` için makul sürede sonuç alınır.
`|p - q| > N^(1/2)` ise artık Fermat verimsizleşir, Pollard rho veya ECM tercih edilmeli.

---

## Çözüm Adımları

1. `a = ceil(sqrt(N))` hesapla (integer square root — gmpy2.isqrt kullan)
2. `b² = a² - N` hesapla
3. `b²` tam kare mi diye bak
4. Değilse `a += 1`, tekrar et
5. Tam kare bulunduğunda: `p = a + b`, `q = a - b`
6. `assert p * q == N` ile doğrula
7. `phi = (p-1)*(q-1)`, `d = pow(e, -1, phi)`, `m = pow(c, d, n)`

---

## Exploit Kodu

### Standart 2-Asal Fermat (N = p * q)

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

def fermat_factor(n):
    """
    Fermat factorization: N = a^2 - b^2 = (a+b)(a-b)
    p ve q birbirine yakınsa hızla çalışır.
    """
    a = gmpy2.isqrt(n)
    if a * a < n:
        a += 1  # ceil(sqrt(n))

    b2 = a * a - n

    iterations = 0
    while True:
        b, is_perfect = gmpy2.isqrt_rem(b2)
        if is_perfect == 0:   # b2 tam kare
            break
        a += 1
        b2 = a * a - n
        iterations += 1
        if iterations % 100_000 == 0:
            print(f"[*] iteration {iterations}, a = {a}")
        if iterations > 5_000_000:
            print("[-] Fermat başarısız — p ve q yeterince yakın değil")
            return None, None

    p = int(a + b)
    q = int(a - b)
    assert p * q == n, "Çarpanlara ayırma hatalı!"
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")
    return p, q


# --- Challenge değişkenlerini buraya koy ---
n = 0xDEADBEEF  # örnek — gerçek N buraya
e = 65537
c = 0xCAFEBABE  # şifreli metin

p, q = fermat_factor(n)

if p and q:
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    print(f"[+] Flag: {flag.decode(errors='replace')}")
```

---

### 3-Asal Fermat: N = p * q * r (LACTF 2024 very-hot)

LACTF 2024 "very-hot" challenge'ında `p`, `q`, `r` ardışık küçük aralıkta seçilmişti.
Kaynak koda göre:

```python
# Orijinal challenge üretimi (LACTF very-hot)
from Crypto.Util.number import getPrime
import random

bits = 256
p = getPrime(bits)
q = p + random.randint(1, 2**24)   # p'ye çok yakın
r = q + random.randint(1, 2**24)   # q'ya çok yakın
n = p * q * r
```

Saldırı stratejisi:
- `cbrt(N)` ≈ p ≈ q ≈ r olduğu için küp kökten başla
- Her potansiyel `p` için `N % p == 0` kontrol et (kaba kuvvet, ama aralık küçük)

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

def factor_three_close_primes(n, e, c, search_range=2**25):
    """
    N = p * q * r, p < q < r ve r - p < search_range varsayımı.
    Küp kökten itibaren arama yapar.
    """
    cbrt_n, _ = gmpy2.iroot(n, 3)

    print(f"[*] Küp kök aramasi basliyor: cbrt(N) ≈ {cbrt_n}")
    print(f"[*] Arama araligi: {search_range} adim")

    # cbrt(N) civarina git — p bu civarda olmali
    start = int(cbrt_n) - search_range // 2

    for candidate in range(start, start + search_range):
        if n % candidate == 0:
            p = candidate
            remaining = n // p
            # remaining = q * r — bunu da iki asal olarak coz
            q, r = fermat_two(remaining)
            if q and r:
                print(f"[+] p = {p}")
                print(f"[+] q = {q}")
                print(f"[+] r = {r}")
                assert p * q * r == n
                phi = (p - 1) * (q - 1) * (r - 1)
                d = pow(e, -1, phi)
                m = pow(c, d, n)
                flag = long_to_bytes(m)
                print(f"[+] Flag: {flag.decode(errors='replace')}")
                return flag
            # Eger q*r asal degilse, dogrudan bolelim
            # remaining'i kontrol et
            q2 = gmpy2.isqrt(remaining)
            for offset in range(-search_range, search_range):
                cand_q = int(q2) + offset
                if cand_q > 1 and remaining % cand_q == 0:
                    r2 = remaining // cand_q
                    if gmpy2.is_prime(cand_q) and gmpy2.is_prime(r2):
                        print(f"[+] p={p}, q={cand_q}, r={r2}")
                        phi = (p-1)*(cand_q-1)*(r2-1)
                        d = pow(e, -1, phi)
                        m = pow(c, d, n)
                        return long_to_bytes(m)

    print("[-] Bulunamadi — arama araligini genislet")
    return None


def fermat_two(n, max_iter=2_000_000):
    """Standart iki-asal Fermat."""
    a = gmpy2.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    for _ in range(max_iter):
        b, rem = gmpy2.isqrt_rem(b2)
        if rem == 0:
            return int(a + b), int(a - b)
        a += 1
        b2 = a * a - n
    return None, None


# --- LACTF very-hot cozumu ---
n = 0x...   # challenge N degeri
e = 65537
c = 0x...   # sifreli metin

flag = factor_three_close_primes(n, e, c)
if flag:
    print(flag)
```

---

## Gerçek Challenge Referansı: LACTF 2024 — very-hot

**Kategori:** Crypto
**Puan:** 488
**Açıklama:** "The primes are very hot right now!"

**Kilit ipucu:** Kaynak kodda `getStrongPrime` yerine standart `getPrime` kullanılmış ve üç asal birbirinin yakınında seçilmiştir. `N`'in bit uzunluğu üç asalın bit uzunluğundan çok daha büyük değil, bu da küp kök yaklaşımının doğru olduğunu gösteriyor.

**Çözüm özeti:**
1. `cbrt(N)` hesapla
2. Civarında kaba kuvvet ile `p`'yi bul (2^25 adım yeterli)
3. `N // p` üzerinde tekrar Fermat uygula
4. `phi(N) = (p-1)(q-1)(r-1)` ile private key hesapla
5. `m = pow(c, d, N)` ile mesajı çöz

**Çözüm süresi:** Yaklaşık 30-90 saniye (PyPy ile daha hızlı).

---

## Tuzaklar

| Tuzak | Çözüm |
|-------|-------|
| `gmpy2.isqrt` yerine `math.isqrt` kullanmak — büyük sayılarda taşabilir | Her zaman `gmpy2` kullan |
| `a * a - n` negatif çıkabilir ilk adımda | `a = ceil(sqrt(n))` garantile: `if a*a < n: a += 1` |
| N = p*q*r için `phi` hatalı hesaplamak | `(p-1)*(q-1)*(r-1)` — üç faktör için |
| Iteration sayısını çok düşük tutmak | `|p-q|` 2^24 civarındaysa milyonlarca iterasyon gerekebilir |
| FactorDB'ye güvenmek | Taze üretilmiş yakın asallar FactorDB'de yoktur — her zaman kendin dene |
| p veya q negatif çıkabilir | `assert p > 0 and q > 0` ekle |

---

## Hızlı Tanı Scripti

```python
import gmpy2, math

def hizli_tani(n):
    """N'in Fermat saldırısına yatkın olup olmadığını kontrol eder."""
    sqrt_n = gmpy2.isqrt(n)
    print(f"[*] N bit uzunlugu: {n.bit_length()}")
    print(f"[*] sqrt(N) = {sqrt_n}")

    # Ilk 1000 iterasyonu hizlica dene
    a = sqrt_n if sqrt_n * sqrt_n >= n else sqrt_n + 1
    b2 = a * a - n
    for i in range(1000):
        b, rem = gmpy2.isqrt_rem(b2)
        if rem == 0:
            p, q = int(a+b), int(a-b)
            print(f"[!!!] FERMAT BASARILI {i}. iterasyonda!")
            print(f"      p = {p}")
            print(f"      q = {q}")
            print(f"      |p-q| = {abs(p-q)}")
            return True
        a += 1
        b2 = a * a - n

    # Kaba kuvvet ile kucuk faktor ara
    for small in range(2, 100_000):
        if n % small == 0:
            print(f"[!!!] Kucuk faktor bulundu: {small}")
            return True

    print("[-] Ilk 1000 iterasyonda bulunamadi — daha derin arama gerekli")
    return False

# Kullanim:
# hizli_tani(N_degeri)
```
