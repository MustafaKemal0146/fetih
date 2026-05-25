---
name: diffie-hellman-attacks
description: Diffie-Hellman key exchange ve DLP saldırıları — Pohlig-Hellman, Pollard rho/lambda, BSGS, small subgroup confinement, weak parameter detection
tags: [ctf, crypto, dh, diffie-hellman, dlp, discrete-log, pohlig-hellman, pollard-rho, baby-step-giant-step, subgroup, weak-parameters]
triggers:
  - "Diffie-Hellman"
  - "DH key exchange"
  - "DLP"
  - "discrete log"
  - "ayrık logaritma"
  - "g^x mod p"
  - "find x"
  - "shared secret"
  - "g, p, A, B"
  - "subgroup attack"
  - "küçük alt grup"
  - "smooth p-1"
  - "ElGamal"
  - "BSGS"
  - "baby step giant step"
  - "Pollard rho discrete log"
difficulty: medium
category: crypto
solved_challenges:
  - "Crypto CTF 2023 - watery_message (Pohlig-Hellman)"
  - "PicoCTF - Diffie-Hellman intro"
  - "ASIS CTF Quals 2021 - dlp1 (BSGS)"
  - "HKCERT 2023 - dhkey (subgroup confinement)"
related_skills:
  - elliptic-curve-attacks
  - lattice-attacks
---

# Diffie-Hellman ve Ayrık Logaritma Saldırıları

DH: `A = g^a mod p`, `B = g^b mod p`, paylaşılan sır `s = g^(ab) mod p`. CTF'te ya `a` veya `b`'yi kırmaya çalışırsın (DLP) ya da paylaşılan sırrı doğrudan ele geçirirsin (subgroup confinement).

---

## Ne Zaman Kullan

| Senaryo | Saldırı | Karmaşıklık |
|---|---|---|
| `p` küçük (< 2^60) | Baby-Step Giant-Step | O(√p) |
| `p - 1` smooth (küçük asal çarpanlar) | Pohlig-Hellman | O(√(en büyük çarpan)) |
| `p` büyük + rastgele | Pollard rho/lambda | O(√p) ama az bellek |
| Saldırgan `g`'i seçiyor (genericisi yok) | Small subgroup confinement | Çok hızlı |
| `g`'nin küçük alt grupta sırası | Subgroup attack | Çok hızlı |
| ElGamal şifreleme + zayıf params | Yukarıdakiler + ElGamal yapı | DH ile aynı |

---

## Saldırı 1 — Baby-Step Giant-Step (BSGS)

**Koşul:** `p` küçük (< 2^60 ish — bellek ve zaman tradeoff). Genel zorluk O(√p).

```python
# exploit_bsgs.py
from math import isqrt

def bsgs(g: int, h: int, p: int) -> int:
    """g^x ≡ h (mod p), x'i bul."""
    m = isqrt(p) + 1
    # Baby steps: g^j for j = 0..m-1
    table = {}
    cur = 1
    for j in range(m):
        table[cur] = j
        cur = (cur * g) % p

    # Giant steps: h * (g^-m)^i
    factor = pow(g, p - 1 - m, p)   # g^-m mod p (Fermat)
    cur = h
    for i in range(m):
        if cur in table:
            return i * m + table[cur]
        cur = (cur * factor) % p
    raise ValueError('No solution')

# Kullanım
p = 1000003
g = 5
h = 14
x = bsgs(g, h, p)
print(f'g^{x} mod {p} = {pow(g, x, p)}')
```

**Bellek uyarısı:** `m ~ 10^6` denemek için ~16 MB. `m ~ 10^8` denemek için ~16 GB.

---

## Saldırı 2 — Pohlig-Hellman (Smooth Order)

**Koşul:** `n = ord(g) | p - 1` küçük asal çarpanlardan oluşuyor. Her alt grup için DLP çöz, CRT ile birleştir.

```python
# exploit_pohlig_hellman.py
from sympy import factorint
from sympy.ntheory.modular import crt
from math import isqrt

def bsgs(g, h, p, ord_=None):
    """g^x ≡ h (mod p), x ∈ [0, ord_)."""
    n = ord_ or p - 1
    m = isqrt(n) + 1
    table = {}
    cur = 1
    for j in range(m):
        table[cur] = j
        cur = (cur * g) % p
    factor = pow(g, -m, p)
    cur = h
    for i in range(m):
        if cur in table:
            return (i * m + table[cur]) % n
        cur = (cur * factor) % p
    raise ValueError

def pohlig_hellman(g, h, p, n=None):
    """n = ord(g), genelde p - 1."""
    n = n or p - 1
    factors = factorint(n)
    print(f'Order factors: {factors}')

    residues, moduli = [], []
    for q, e in factors.items():
        qe = q ** e
        co = n // qe
        gi = pow(g, co, p)
        hi = pow(h, co, p)
        xi = bsgs(gi, hi, p, ord_=qe)
        residues.append(xi)
        moduli.append(qe)

    x, _ = crt(moduli, residues)
    return int(x)

# Örnek (p-1 smooth)
p = 0x...   # büyük asal ama p-1 = 2 * 3 * 5 * 7 * 11 * ...
g = 5
h = 0x...
x = pohlig_hellman(g, h, p)
print(f'x = {x}')
```

### Pratik Limit
- En büyük asal çarpan < 2^40 → 1 saat içinde
- En büyük asal çarpan < 2^50 → bilgisayar gücüne göre 1 gün
- En büyük asal çarpan > 2^60 → pratik değil

---

## Saldırı 3 — Pollard's Rho (Büyük p, Düşük Bellek)

**Koşul:** `p` büyük (BSGS bellek vermiyor) ama yine de zorluk O(√p). Pollard rho için Floyd cycle detection.

```python
# exploit_pollard_rho_dlog.py
from math import gcd

def pollard_rho_dlog(g, h, p, n):
    """g^x ≡ h (mod p), n = ord(g)."""
    def f(state):
        x, a, b = state
        if x % 3 == 0:
            return (x * h) % p, a, (b + 1) % n
        elif x % 3 == 1:
            return (x * x) % p, (a * 2) % n, (b * 2) % n
        else:
            return (x * g) % p, (a + 1) % n, b

    tortoise = (1, 0, 0)
    hare = f(tortoise)
    while tortoise[0] != hare[0]:
        tortoise = f(tortoise)
        hare = f(f(hare))

    _, a1, b1 = tortoise
    _, a2, b2 = hare

    r = (a2 - a1) % n
    s = (b1 - b2) % n
    d = gcd(s, n)
    if d == 1:
        return (r * pow(s, -1, n)) % n
    else:
        # gcd > 1, birkaç çözüm dene
        s_ = s // d
        n_ = n // d
        x_ = (r // d) * pow(s_, -1, n_) % n_
        for i in range(d):
            x = x_ + i * n_
            if pow(g, x, p) == h:
                return x
    raise ValueError
```

---

## Saldırı 4 — Small Subgroup Confinement

**Koşul:** Sunucu DH'de `A` parametresini doğrulamıyor — saldırgan küçük sıralı bir eleman gönderir, sunucunun `b`'sini `mod (küçük sıra)` öğrenir.

```python
# Saldırı senaryosu
# 1. (p - 1) = q1 * q2 * ... * qn formatında. Küçük qi'yi seç.
# 2. order_qi elemanı bul: x_qi = g^((p-1)/qi) mod p
# 3. Sunucuya x_qi gönder
# 4. Sunucu shared_secret = x_qi^b mod p hesaplar
# 5. Shared secret hangi i için doğru? → BSGS ile O(√qi) zamanda b mod qi sızar
# 6. Birden çok qi ile CRT → b sızar

from sympy import factorint

def find_small_subgroup_elements(p):
    """p - 1'in küçük çarpanlarına ait jeneratörleri bul."""
    factors = factorint(p - 1)
    elements = []
    for q, _ in factors.items():
        if q < 2**30:  # 30-bit altı çarpanlar yararlı
            order_q = pow(g, (p - 1) // q, p)
            elements.append((q, order_q))
    return elements
```

---

## Saldırı 5 — Weak Parameter Detection

CTF'te genelde sunucu `(p, g)` ı verir. Şüpheli durumlar:

```python
def check_weak_dh_params(p, g):
    """DH parametrelerini analiz et."""
    from sympy import isprime, factorint

    flags = []

    # 1. p prime mi?
    if not isprime(p):
        flags.append(f'CRITICAL: p = {p} is not prime')

    # 2. p - 1 smooth mu?
    factors = factorint(p - 1)
    largest = max(factors.keys())
    if largest < 2**40:
        flags.append(f'WEAK: largest factor of p-1 is {largest.bit_length()} bits — Pohlig-Hellman attacks possible')

    # 3. g'nin sırası nedir?
    # g^((p-1)/q) ≡ 1 (mod p) ise g, q-sıralı alt grupta
    for q in factors:
        if pow(g, (p-1) // q, p) == 1:
            flags.append(f'WARNING: g lies in subgroup of order {(p-1)//q}')

    # 4. p küçük mü?
    if p.bit_length() < 1024:
        flags.append(f'WEAK: p is only {p.bit_length()} bits')

    return flags
```

---

## Saldırı 6 — ElGamal İmza ile DLP

**Koşul:** İki imza aynı `k` ile yapılmış (ECDSA gibi DLP). Aynı koşullar ECC için `elliptic-curve-attacks` skill'inde de var.

```python
# ElGamal signature: (r, s) = (g^k mod p, (m - x*r)*k^-1 mod (p-1))
# İki imza (r, s1) ve (r, s2) aynı k → x sızar:
# k = (m1 - m2) / (s1 - s2)  mod (p-1)
# x = (m - s*k) / r          mod (p-1)
```

---

## Sage ile Hızlı Çözüm

```python
# sage
from sage.all import *
F = GF(p)
g_F = F(g)
h_F = F(h)
x = discrete_log(h_F, g_F)   # otomatik en iyi algoritma seçer
print(f'x = {x}')
```

---

## Tuzaklar

1. **`p - 1` ve `q` karıştırma:** DH'te `g`'nin sırası `(p-1)/cofactor`. `g` tam jeneratör değilse Pohlig-Hellman'da `n` ona göre.
2. **BSGS bellek patlaması:** `m = sqrt(p)` çok büyükse Python dict OOM. Sınır `p < 2^60` civarı.
3. **Pollard rho başarısızlık:** `gcd(s, n) > 1` durumunda parça parça çözüm gerekir.
4. **Subgroup confinement** çoğu modern sistem `A^q mod p == 1` kontrolü yapar. CTF'te kontrol eksik olabilir.
5. **Safe prime:** `p = 2q + 1` (Sophie Germain prime) ise `p - 1`'in tek küçük çarpanı 2. Pohlig-Hellman pratik değil → Pollard rho gerekir.

---

## Cross-Skill Pivot

```
DLP / DH challenge → p kontrolü
                  ├── p küçük (<2^60) → BSGS
                  ├── p-1 smooth → Pohlig-Hellman
                  ├── p büyük + safe → Pollard rho
                  ├── g zayıf alt grupta → subgroup confinement
                  └── ElGamal imza, k reuse → algebra
```

---

## Tools

```bash
# SageMath — DLP için altın standart
sage -c "print(discrete_log(F(h), F(g)))"

# CADO-NFS — büyük p (RSA-tarzı) factoring/DLP
# https://gitlab.inria.fr/cado-nfs/cado-nfs

# Custom Python
pip install gmpy2 sympy
```
