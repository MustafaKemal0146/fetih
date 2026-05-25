---
name: lattice-attacks
description: RSA ve crypto için kafes (lattice) tabanlı saldırılar — Coppersmith, LLL/BKZ, Boneh-Durfee, Hastad broadcast, Franklin-Reiter, stereotyped message
tags: [ctf, crypto, rsa, lattice, coppersmith, lll, bkz, boneh-durfee, hastad, franklin-reiter, stereotyped, sagemath, fpylll]
triggers:
  - "küçük root"
  - "small root"
  - "Coppersmith"
  - "LLL"
  - "BKZ"
  - "lattice reduction"
  - "kafes saldırısı"
  - "Boneh-Durfee"
  - "d < N^0.292"
  - "Hastad broadcast"
  - "aynı m farklı n"
  - "Franklin-Reiter"
  - "stereotyped message"
  - "mesajın kısmı biliniyor"
  - "partial private key"
  - "e küçük, m küçük değil"
  - "MSB/LSB known"
  - "p'nin yarısı biliniyor"
  - "small_roots()"
  - "PartialPlaintext"
difficulty: hard
category: crypto
solved_challenges:
  - "PlaidCTF 2020 - bonzi (Coppersmith)"
  - "SECCON 2017 - very-smooth (Coppersmith partial p)"
  - "ASIS CTF 2023 - Sirage (Boneh-Durfee)"
  - "Google CTF 2022 - cycling (Hastad broadcast)"
  - "Crypto CTF 2023 - mariana (Franklin-Reiter)"
  - "0CTF Quals 2020 - babyring (lattice)"
related_skills:
  - rsa-wiener-attack
  - rsa-close-primes
  - rsa-padding-oracle
  - rsa-common-modulus
  - elliptic-curve-attacks
---

# Lattice (Kafes) Saldırıları — RSA'nın Matematiksel Sınırları

CTF crypto kategorisinin en güçlü silahı. Klasik RSA saldırıları (Wiener, Fermat) belirli koşullarda çalışır; lattice saldırıları **kısmi bilginin matematiksel olarak yetip yetmediğini** sorar ve genelde yeter.

---

## Ne Zaman Kullan

| Senaryo | Saldırı |
|---|---|
| Mesajın bir kısmı biliniyor (örn. flag formatı `picoCTF{...}`) | Coppersmith stereotyped |
| `e` küçük (3, 5, 17) ve `m^e` sadece biraz `n`'den büyük | Coppersmith small root |
| Aynı `m` birden fazla `n`'e (en az `e` tane) şifrelenmiş | Hastad broadcast |
| `d` küçük ama Wiener çalışmıyor (`N^0.25 < d < N^0.292`) | Boneh-Durfee |
| `p`'nin yarısından çoğu biliniyor | Coppersmith factor recovery |
| İki ilişkili mesaj `m1`, `m2 = m1 + Δ` aynı `n` ile şifrelenmiş | Franklin-Reiter |
| RSA değil ama "modüler denklemler" var | Genel Coppersmith small_roots() |

---

## Teknik Arka Plan

### LLL Nedir?
LLL (Lenstra-Lenstra-Lovász) algoritması, bir kafesin (lattice) "kısa" tabanını polinom zamanda bulur. Bir kafes = `{c1*v1 + c2*v2 + ... : ci ∈ Z}` formunda tam sayı katsayılı vektör kombinasyonları.

LLL'in sihri: kısa vektörler genelde "küçük çözümleri" kodlar. Bir polinom denklemi `f(x) = 0 mod N`'in küçük kökü `x0` varsa, doğru kafesi kurarak LLL çalıştırıp `x0`'ı çıkarabilirsin.

### Coppersmith Teoremi
> Monic, derecesi `d` olan `f(x) ∈ Z[x]` polinomu için `f(x0) ≡ 0 (mod N)` olan kök `x0` aranıyorsa ve `|x0| < N^(1/d)` ise, polinom zamanda `x0` bulunabilir.

Çıkarımı: Eğer RSA `e=3` ise, `m^3 = c (mod N)` denkleminin küçük `m`'leri (örn. `|m| < N^(1/3)`) hızla bulunabilir.

### Boneh-Durfee (Wiener'in güçlendirilmiş hali)
Wiener `d < N^0.25` için çalışır. Boneh-Durfee bivariate Coppersmith ile `d < N^0.292`'ye uzatır. Lattice boyutu büyük olduğu için pratikte `d < N^0.27`'ye kadar güvenilir.

---

## Çözüm Adımları (Genel)

1. **SageMath'i hazır tut.** Lattice saldırıları için fiili standart.
2. **Kafesi kur.** Saldırıya özel matris (aşağıda örnekler).
3. **LLL veya BKZ uygula.** SageMath: `M.LLL()`, `M.BKZ()`.
4. **Kısa vektörü yorumla.** Polinom katsayılarını çıkar, kökü hesapla.
5. **Doğrula.** Kök gerçekten `f(x0) = 0 (mod N)` mı?

---

## Exploit 1 — Coppersmith Stereotyped Message

**Senaryo:** Flag formatı `picoCTF{XXX_GIZLI_XXX}` bilinen. RSA `e=3` ile şifrelenmiş.

```python
# sage exploit_stereotyped.sage
from sage.all import *

n = 0x...           # modulus
e = 3
c = 0x...           # ciphertext
prefix = b'picoCTF{'
suffix = b'}'

# Bilinmeyen uzunluk (denenir)
for unknown_len in range(8, 50):
    msg_len = len(prefix) + unknown_len + len(suffix)

    # Mesaj = prefix*256^(unknown_len+1) + x*256 + suffix
    # şeklinde modüler polinom
    known_prefix = int.from_bytes(prefix, 'big') << (8 * (unknown_len + len(suffix)))
    known_suffix = int.from_bytes(suffix, 'big')
    shift = 8 * len(suffix)

    P.<x> = PolynomialRing(Zmod(n))
    f = (known_prefix + (x << shift) + known_suffix)^e - c

    # Beklenen kök <= 256^unknown_len
    X = 2^(8 * unknown_len)

    # small_roots üst sınır, epsilon ile dene
    roots = f.small_roots(X=X, epsilon=1/30)
    if roots:
        m = int(roots[0])
        flag = prefix + m.to_bytes(unknown_len, 'big') + suffix
        print(f'[+] Flag: {flag}')
        break
else:
    print('[-] Coppersmith başarısız — daha büyük epsilon dene')
```

---

## Exploit 2 — Hastad Broadcast Attack

**Senaryo:** Aynı `m` üç farklı `n` ile (her biri farklı, `e=3` sabit) şifrelenmiş.

```python
# sage exploit_hastad.sage
from sage.all import *

# Toplanan veriler
ns = [n1, n2, n3]
cs = [c1, c2, c3]
e = 3

assert len(ns) >= e, 'En az e tane ciphertext gerekli'

# CRT ile birleştir
N = prod(ns)
M = sum(c * (N // n) * inverse_mod(N // n, n) for c, n in zip(cs, ns)) % N

# Şimdi M = m^e mod N, m küçük olduğu için doğrudan e. kök
m, ok = M.nth_root(e, truncate_mode=True)
assert ok, 'Tam kök değil — broadcast varsayımı yanlış olabilir'

print(f'[+] m = {m}')
print(f'[+] Flag: {int(m).to_bytes((int(m).bit_length() + 7) // 8, "big")}')
```

### Padding'li versiyon — Hastad with linear padding
```python
# Padding varsa: ci = (ai*m + bi)^e mod ni
# Cohen-Hastad ile multivariate Coppersmith
from sage.all import *

# ... ai, bi, ci, ni biliniyor
# Bkz: https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/hastad_attack.py
```

---

## Exploit 3 — Boneh-Durfee (d küçük, Wiener yetmiyor)

**Senaryo:** `e ~ N`, Wiener saldırısı başarısız (`d > N^0.25`), ama `d < N^0.292`.

```python
# sage exploit_boneh_durfee.sage
# Standart Boneh-Durfee implementasyonu (David Wong / Mikael Aleksanyan versiyonu)
from sage.all import *

def boneh_durfee(N, e, delta=0.28, m=5):
    """
    delta: d / N^delta beklenen üst sınır (0.292 teorik max)
    m: lattice boyutu (büyük → yavaş ama güçlü)
    """
    P.<x, y> = PolynomialRing(ZZ)
    A = (N + 1) // 2
    pol = 1 + x * (A + y)

    # Lattice kur
    X = 2 * floor(N^delta)
    Y = floor(N^0.5)

    # ... (uzun implementasyon, GitHub'dan al)
    # https://github.com/mimoo/RSA-and-LLL-attacks
    return d

d = boneh_durfee(N, e)
m = pow(c, d, N)
print(f'flag = {int(m).to_bytes(256, "big").strip(b"\\x00")}')
```

---

## Exploit 4 — Franklin-Reiter Related Message

**Senaryo:** Aynı `n`, aynı `e=3`, iki mesaj `m1` ve `m2 = m1 + 1` (veya bilinen küçük fark).

```python
# sage exploit_franklin_reiter.sage
from sage.all import *

n = ...; e = 3
c1 = ...; c2 = ...
delta = 1  # m2 - m1

R.<x> = PolynomialRing(Zmod(n))
f1 = x^e - c1
f2 = (x + delta)^e - c2

def gcd_mod(a, b):
    while b:
        a, b = b, a % b
    return a.monic()

m = -gcd_mod(f1, f2).coefficients()[0]
print(f'm1 = {m}')
```

---

## Exploit 5 — Coppersmith Partial Factor (p'nin yarısı bilindi)

**Senaryo:** `p`'nin yüksek bitlerinin (örn. 512 bitin 320'si) sızdı.

```python
# sage exploit_partial_p.sage
from sage.all import *

n = ...; e = 65537; c = ...
p_high = ...   # bilinen yüksek bitler (gerisi 0)
unknown_bits = 192  # bilinmeyen düşük bitler

P.<x> = PolynomialRing(Zmod(n))
f = p_high + x
roots = f.small_roots(X=2^unknown_bits, beta=0.4)

if roots:
    p = int(p_high + roots[0])
    q = n // p
    phi = (p - 1) * (q - 1)
    d = inverse_mod(e, phi)
    m = pow(c, d, n)
    print(f'flag = {int(m).to_bytes((int(m).bit_length()+7)//8, "big")}')
```

---

## SageMath Kurulum

```bash
# Ubuntu / Debian
sudo apt install sagemath

# Conda (önerilen)
conda create -n sage sage python=3.11
conda activate sage

# Docker (CI'da)
docker run -it -v $PWD:/work sagemath/sagemath
```

Python-only alternatif (lattice için):
```bash
pip install fpylll sympy gmpy2
```

---

## Gerçek CTF Örnekleri

### Google CTF 2022 — cycling
RSA cycling attack: `m^(e^k) = m (mod n)` için `k` küçükse mesaj sızar. Hastad broadcast varyasyonu.

### PlaidCTF 2020 — bonzi
Coppersmith stereotyped — mesajın orta kısmı bilinmiyor. `small_roots(X, epsilon)` ile çözüldü.

### Crypto CTF 2023 — mariana
Franklin-Reiter related message. İki mesaj `delta = 0x123` farkıyla şifrelenmiş.

---

## Tuzaklar

1. **`small_roots()` çağrısı uzun sürer** — `epsilon=1/30` deneyin, küçük epsilon = büyük lattice = yavaş. Başlangıç değeri olarak 0.05.
2. **Boneh-Durfee `m` parametresi** çok küçük (m=3) olursa kafes zayıf, çok büyük (m=12+) RAM/zaman alır. m=5-7 ideal başlangıç.
3. **Coppersmith üst sınır** (`X`) doğru tahmin edilmeli — gerçek kök bu sınırı aşıyorsa LLL kökü bulamaz. Önce küçük X dene, başarısızsa kademeli büyüt.
4. **Hastad'da padding** varsa standart broadcast çalışmaz; Cohen-Hastad veya Coppersmith Howgrave-Graham gerekir.
5. **SageMath'siz çözüm sınırlı** — fpylll Python paketi var ama Coppersmith wrapper yok; manuel kurman gerekir. Mümkünse SageMath kullan.
6. **Modulus çarpanlarına ayrılmış olmamalı** — Coppersmith güvenlik, `gcd(x0, N) = 1` varsayımına dayanır. Aksi halde direkt çarpanlama.

---

## Cross-Skill Pivot

```
RSA challenge → rsa-wiener-attack başarısız
              → rsa-close-primes başarısız
              → factordb yok
              → buraya gel (lattice-attacks)
                ├── Mesaj kısmi biliniyor → Coppersmith stereotyped
                ├── Aynı m, farklı n → Hastad broadcast
                ├── d küçük (Wiener çalışmadı ama yakın) → Boneh-Durfee
                ├── İki ilişkili mesaj → Franklin-Reiter
                └── p kısmi biliniyor → Coppersmith partial factor
```

---

## Ek Kaynaklar

- David Wong'un RSA lattice notebook'u: https://github.com/mimoo/RSA-and-LLL-attacks
- Joachim Vandersmissen crypto-attacks: https://github.com/jvdsn/crypto-attacks
- Coppersmith orjinal makale: "Finding Small Solutions to Small Degree Polynomials" (1996)
- Boneh-Durfee orjinal: "Cryptanalysis of RSA with Private Key d Less than N^0.292" (1999)
