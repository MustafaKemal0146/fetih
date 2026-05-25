---
name: elliptic-curve-attacks
description: Elliptic Curve Cryptography saldırıları — ECDLP (Pollard rho/lambda, Pohlig-Hellman), Smart's attack, MOV/Frey-Rück, invalid curve, ECDSA nonce reuse, biased nonce lattice
tags: [ctf, crypto, ecc, elliptic-curve, ecdlp, ecdsa, smart-attack, mov, pohlig-hellman, invalid-curve, nonce-reuse, lattice, sagemath]
triggers:
  - "elliptic curve"
  - "eliptik eğri"
  - "ECC"
  - "ECDSA"
  - "ECDH"
  - "ECDLP"
  - "curve params"
  - "p, a, b, G, P"
  - "anomalous curve"
  - "supersingular"
  - "weak curve"
  - "trace = 1"
  - "smart attack"
  - "MOV"
  - "embedding degree"
  - "nonce reuse"
  - "k aynı"
  - "ECDSA imza"
  - "Curve25519"
  - "secp256k1"
  - "invalid curve"
  - "twist attack"
difficulty: hard
category: crypto
solved_challenges:
  - "PlaidCTF 2018 - special (Smart's attack)"
  - "Google CTF 2017 - oracles (Invalid curve)"
  - "ECSC 2024 - biased_ECDSA (lattice on biased nonces)"
  - "CryptoCTF 2022 - shevid (MOV)"
  - "ASIS CTF 2023 - curveball (Pohlig-Hellman)"
  - "DownUnderCTF 2023 - bad-primes (Pollard rho)"
related_skills:
  - lattice-attacks
  - rsa-common-modulus
  - diffie-hellman-attacks
---

# Elliptic Curve Saldırıları — ECDLP'yi Kırmanın 7 Yolu

ECC (Elliptic Curve Cryptography) modern güvenliğin temeli — Bitcoin (secp256k1), TLS (P-256, X25519), SSH (ed25519) hepsi ECC kullanır. CTF'te ECC challenge'ları **eğrinin kötü seçildiği** durumlarda çözülür.

ECDLP (Elliptic Curve Discrete Log Problem): `P = k*G` verildiğinde `k`'yı bul. Genel durumda `O(sqrt(n))` zorda; ama belirli eğri tipleri çok daha kolay.

---

## Ne Zaman Kullan

Challenge'da `(p, a, b, G, P)` ya da `(eğri, G, P)` verilmiş, `k` aranıyor. **İlk adım: eğri tipini analiz et.**

```python
# sage
from sage.all import *
E = EllipticCurve(GF(p), [a, b])
n = E.order()                # eğri sırası
trace = p + 1 - n            # Frobenius trace

print(f'p = {p}')
print(f'n = {n}')
print(f'trace = {trace}')
print(f'p - n = {p - n}')   # 0 ise anomalous
print(f'n factor: {factor(n)}')  # smooth mu?
```

### Saldırı Seçim Tablosu

| Eğri Özelliği | Saldırı | Karmaşıklık |
|---|---|---|
| `trace = 1` (anomalous, n = p) | Smart's attack | Polinom zamanda |
| `n` smooth (küçük asal çarpanlar) | Pohlig-Hellman | O(sqrt(en büyük çarpan)) |
| Embedding degree `k ≤ 6` | MOV / Frey-Rück | sub-exponential |
| Supersingular eğri | MOV | sub-exponential |
| Standart eğri, küçük `n` (<= 2^60) | Pollard rho | O(sqrt(n)) |
| Birden çok eğri üzerinde işlem | Invalid curve | Pohlig-Hellman gibi |
| ECDSA `k` reuse | Direkt private key | Algebra |
| ECDSA `k` biased | Lattice (HNP) | LLL |
| ECDH twist hatası | Twist attack | sub-exponential |

---

## Saldırı 1 — Smart's Attack (Anomalous Curves)

**Koşul:** `#E(F_p) = p`. Yani eğri sırası asal modülün kendisine eşit. Bu durum aşırı nadir ama CTF'te kasıtlı yerleştirilir.

```python
# sage exploit_smart.sage
from sage.all import *

def smart_attack(P, Q):
    """P, Q ∈ E(F_p) ve #E = p ise k = log_P(Q) bul."""
    E = P.curve()
    Fp = E.base_field()
    p = Fp.characteristic()
    assert E.order() == p, 'Eğri anomalous değil!'

    # p-adic lift
    Eqp = EllipticCurve(Qp(p), [int(a) for a in E.a_invariants()])
    P_lift = Eqp.lift_x(ZZ(P.xy()[0]))
    Q_lift = Eqp.lift_x(ZZ(Q.xy()[0]))

    # P_lift hangi P üzerinde lift olmalı
    if (P_lift - Eqp(P.xy())) != 0:
        P_lift = -P_lift
    if (Q_lift - Eqp(Q.xy())) != 0:
        Q_lift = -Q_lift

    pP = p * P_lift
    pQ = p * Q_lift

    x_P = (pP[0] / pP[1]).lift()
    x_Q = (pQ[0] / pQ[1]).lift()

    k = (x_Q / x_P) % p
    return ZZ(k)

p = ...
a, b = ..., ...
Gx, Gy = ..., ...
Px, Py = ..., ...

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
P = E(Px, Py)

k = smart_attack(G, P)
print(f'[+] k = {k}')
assert k * G == P
```

---

## Saldırı 2 — Pohlig-Hellman (Smooth Order)

**Koşul:** `n = #E` küçük asal çarpanların çarpımı. Her alt grupta ECDLP çöz, CRT ile birleştir.

```python
# sage exploit_pohlig_hellman.sage
from sage.all import *

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
P = E(Px, Py)
n = G.order()

factors = factor(n)
print(f'n = {n}')
print(f'factors: {factors}')

# En büyük çarpanın boyutu — Pohlig-Hellman'ın zorluğu bu
largest = max(int(p) for p, _ in factors)
print(f'largest factor: {largest} ({largest.bit_length()} bit)')

if largest > 2**40:
    print('[-] En büyük çarpan çok büyük, Pohlig-Hellman pratik değil')
else:
    k = discrete_log(P, G, ord=n, operation='+')
    print(f'[+] k = {k}')
```

### Manuel Pohlig-Hellman (eğitim için)
```python
def pohlig_hellman_ec(P, Q, factors):
    """factors = [(prime, exp), ...] for #E"""
    residues, moduli = [], []
    for q, e in factors:
        qe = q**e
        co = n // qe
        Pi = co * P
        Qi = co * Q
        # Pi'nin sırası qe, baby-step giant-step ile log
        ki = discrete_log(Qi, Pi, ord=qe, operation='+')
        residues.append(ki)
        moduli.append(qe)
    return CRT(residues, moduli)
```

---

## Saldırı 3 — MOV / Frey-Rück Attack

**Koşul:** Embedding degree `k` küçük (genelde `k ≤ 6`). Supersingular eğriler için `k = 2`. Weil veya Tate pairing kullanarak ECDLP'yi `F_{p^k}` üzerindeki DLP'ye indirger; orada index calculus çalışır.

```python
# sage exploit_mov.sage
from sage.all import *

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy); P = E(Px, Py)
n = G.order()

# Embedding degree
k = 1
while (p**k - 1) % n != 0:
    k += 1
print(f'embedding degree k = {k}')

assert k <= 6, 'MOV pratik değil'

# Pairing kullan
Fpk = GF(p**k)
EE = E.base_extend(Fpk)
GG = EE(G); PP = EE(P)

# Rastgele yardımcı nokta R bul (k-torsion subgrubunda)
while True:
    R = EE.random_point()
    R = (R.order() // n) * R
    if R != EE(0):
        break

a_pair = GG.weil_pairing(R, n)
b_pair = PP.weil_pairing(R, n)

# Şimdi b_pair = a_pair^k mod p^k — Fpk üzerinde DLP
k_val = discrete_log(b_pair, a_pair, ord=n)
print(f'[+] k = {k_val}')
```

---

## Saldırı 4 — Invalid Curve Attack

**Koşul:** Sunucu kullanıcının verdiği noktayı bir başka (zayıf) eğri üzerinde işliyor. ECDH gibi protokoller `(x, y)`'i doğrulamadan kullanırsa, saldırgan smooth-order eğri üzerinde nokta gönderir, sunucunun `k`'sını parça parça leak eder.

```python
# 1. Zayıf eğri ara (orjinal eğri E0, modulus p)
# Aynı p, aynı a, FARKLI b ile yeni eğri
for new_b in primes(10000):
    Ealt = EllipticCurve(GF(p), [a, new_b])
    factors = factor(Ealt.order())
    if max(int(q) for q, _ in factors) < 2**20:
        # Smooth! Bu eğri kullanılabilir
        small_prime = factors[0][0]
        # Bu prime'lık alt grubun jeneratörü bul
        Galt = Ealt.gen(0)
        Q_target = (Ealt.order() // small_prime) * Galt
        # Sunucuya Q_target gönder, k mod small_prime sızar
        # Birden çok prime ile CRT yap
```

---

## Saldırı 5 — ECDSA Nonce Reuse

**Koşul:** İki imza aynı private key + aynı `k` ile yapılmış. PlayStation 3'ün ünlü Sony hatası.

```python
# exploit_ecdsa_nonce_reuse.py
from hashlib import sha256
from sympy import mod_inverse

n = ...        # eğri sırası
r = ...        # iki imzanın ortak r
s1, h1 = ..., ...
s2, h2 = ..., ...

# k = (h1 - h2) / (s1 - s2) mod n
k = ((h1 - h2) * mod_inverse(s1 - s2, n)) % n

# d = (s1 * k - h1) / r mod n
d = ((s1 * k - h1) * mod_inverse(r, n)) % n

print(f'[+] private key d = {hex(d)}')
print(f'[+] nonce k = {k}')
```

---

## Saldırı 6 — Biased Nonce (LLL / Hidden Number Problem)

**Koşul:** ECDSA imzalarındaki `k` değerleri tam rastgele değil, küçük (örn. `k < 2^l, l << n.bit_length()`). Birden fazla imza topla, lattice ile `d`'yi çıkar.

```python
# sage exploit_hnp.sage
# Klasik Hidden Number Problem (HNP) çözümü
# Toplanan: (r_i, s_i, h_i) için i = 1..N
# k_i küçük → k_i = t_i * 2^l + bilinmeyen düşük l bit
# LLL ile private d sızar
# Referans: https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecdsa/biased_nonce.py

from sage.all import *

def hnp_attack(sigs, n, l):
    """sigs = [(r, s, h)], l = biased bit sayısı"""
    N = len(sigs)
    B = matrix(QQ, N + 2, N + 2)

    # Lattice kurulumu... (uzun, GitHub'dan al)
    # M = ...

    return d
```

---

## Saldırı 7 — Twist Attack (ECDH)

**Koşul:** ECDH'de sadece x-koordinatı paylaşılıyor (Montgomery ladder, Curve25519 stili). Saldırgan `x`'i eğrinin değil "twist" eğrisinin (`E_t: by^2 = x^3 + ax^2 + x`) noktası olarak gönderir. Twist eğri smooth ise CRT ile gizli k çıkar.

```python
# Twist eğri sırası
n_twist = 2 * (p + 1) - n
# Eğer n_twist smooth ise, x sadece x olduğu için sunucu hangi eğride olduğunu fark etmez
# Pohlig-Hellman → CRT
```

---

## Standart Eğriler ve Bilinen Güvenlikleri

| Eğri | Sıra `n` | Smart? | MOV? | Notlar |
|---|---|---|---|---|
| secp256k1 (Bitcoin) | prime | Hayır | Hayır | Güvenli ama nonce reuse zayıflık |
| P-256 (NIST) | prime | Hayır | Hayır | Güvenli, NSA backdoor şüphesi (Dual_EC değil) |
| P-384, P-521 | prime | Hayır | Hayır | Güvenli |
| Curve25519 | 8 × prime | Hayır | Hayır | Cofactor 8, twist resistant |
| ed25519 | 8 × prime | Hayır | Hayır | Güvenli |
| Brainpool (rfc5639) | prime | Hayır | Hayır | Almanya menşeli, güvenli |

Custom eğri verilmişse (CTF'in tipik tuzağı) parametreler şüpheli — yukarıdaki saldırıları sırayla dene.

---

## Tuzaklar

1. **Cofactor unutma:** Curve25519 ve ed25519'da `#E = 8 * n_prime`. ECDLP'yi `n_prime` üzerinde çöz, sonra `8*` çarp.
2. **Smart's attack hassas:** `p` ve `n` tam eşit olmalı, başka koşul yok. `n = p - 1` veya `n = p + 1` Smart değil.
3. **Pohlig-Hellman zaman:** En büyük çarpan 2^50'den büyükse pratik değil. Bilgisayar gücüne göre 2^60'a kadar zorlanabilir.
4. **MOV embedding degree:** `k > 12` ise pratik değil (genel kural). Supersingular eğride `k = 2`, hızla çözülür.
5. **Invalid curve testi:** Önce `assert P.is_on_curve()` yapan sunucularda işlemez. Test et.
6. **ECDSA imza farklı eğride:** Her imzayı doğrulamak ister varsa biased nonce LLL daha fazla imza gerektirir (genelde N=100+ örnek).
7. **Sage versiyon:** Bazı saldırılar (Smart) eski SageMath versiyonlarında bug'lı. Güncel sürüm (9.5+) kullan.

---

## Cross-Skill Pivot

```
ECC challenge → eğri parametreleri kontrol et
              ├── trace = 1 → Smart's attack
              ├── n smooth → Pohlig-Hellman
              ├── k embedding küçük → MOV
              ├── ECDSA imza var → nonce reuse / biased
              ├── ECDH x-only → twist attack
              └── Standart eğri → başka açık ara, lattice-attacks'a bak
```

---

## Ek Kaynaklar

- Joachim Vandersmissen crypto-attacks: https://github.com/jvdsn/crypto-attacks/tree/master/attacks/ecc
- SageMath ECDLP belgeleri: https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/
- CryptoHack ECC course: https://cryptohack.org/courses/elliptic/
- "A Survey on Cryptographic Attacks Against Bitcoin" (paper)
