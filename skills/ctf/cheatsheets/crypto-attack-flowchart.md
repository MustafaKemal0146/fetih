# Crypto Saldırı Karar Ağacı

CTF'te bir crypto challenge gördüğünde hangi saldırıyı deneyeceğini hızla seçmek için karar ağaçları.

---

## RSA Karar Ağacı

```
RSA challenge geldi
├── Sadece (n, e, c) verilmiş, başka yok
│   ├── e küçük (3, 5, 7, 17, 65537)
│   │   ├── m^e < n (mesaj küçük) → cube root attack (gmpy2.iroot)
│   │   ├── aynı m birden çok n'e → Hastad broadcast (CRT + iroot)
│   │   └── m kısmen biliniyor → Coppersmith stereotyped
│   ├── e çok büyük (n'e yakın)
│   │   ├── d < N^0.25 → Wiener attack (continued fraction)
│   │   └── d < N^0.292 → Boneh-Durfee (lattice)
│   └── e normal (65537)
│       ├── factordb'de n var → direkt çöz
│       ├── p ve q yakın → Fermat factorization
│       ├── n = p*q*r → küp kök Fermat
│       ├── p-1 smooth → Pollard p-1
│       ├── p+1 smooth → Williams p+1
│       └── kısmi p biliniyor → Coppersmith partial factoring
├── İki ciphertext (c1, c2) aynı n, farklı e
│   └── gcd(e1, e2) = 1 → Common modulus attack (Bezout)
├── Birden çok n, aynı m, aynı küçük e
│   └── Hastad broadcast attack
├── (m, c) çiftleri verilmiş, e küçük
│   └── Franklin-Reiter related message
├── Padding oracle var (encrypt/decrypt yanıtı)
│   ├── Multiplicative oracle → homomorphism (m * 2^e)
│   └── Padding valid/invalid → Bleichenbacher PKCS#1
└── Şifreleme sürecini değiştirebiliyorsun
    └── Chosen ciphertext attack
```

**Hızlı Karar Tablosu:**

| Gözlem | Saldırı | Skill |
|---|---|---|
| e=3, m küçük | Cube root | `crypto/rsa-padding-oracle` |
| e büyük, d küçük | Wiener | `crypto/rsa-wiener-attack` |
| Wiener çalışmadı, d < N^0.292 | Boneh-Durfee | `crypto/lattice-attacks` |
| p,q yakın | Fermat | `crypto/rsa-close-primes` |
| Aynı n, iki e | Common modulus | `crypto/rsa-common-modulus` |
| Aynı m, farklı n | Hastad broadcast | `crypto/lattice-attacks` |
| m'in kısmı biliniyor | Coppersmith | `crypto/lattice-attacks` |
| factordb'de n var | Direkt | `crypto/rsa-close-primes` |
| Decrypt oracle | Multiplicative | `crypto/rsa-padding-oracle` |

---

## AES Karar Ağacı

```
AES challenge geldi
├── ECB modu (tespit: aynı plaintext blokları → aynı ciphertext)
│   ├── Plaintext kontrolünüz var → ECB cut-and-paste
│   ├── Penguin görüntü → ECB pattern visible
│   └── Oracle var → byte-at-a-time decryption
├── CBC modu
│   ├── Padding oracle (valid/invalid yanıtı) → Bleichenbacher CBC
│   ├── IV manipülasyonu mümkün → IV bit flipping
│   ├── Bilinen plaintext + kontrollü ciphertext → bit flipping
│   ├── IV reuse → XOR ile plaintext leak
│   └── CBC-MAC ile MAC → length extension
├── GCM modu
│   ├── Nonce reuse → polynomial root → forge MAC
│   └── Short tag (kısaltılmış) → forgery
├── CTR modu
│   └── Nonce/counter reuse → XOR ile plaintext leak
└── Custom mode / cipher
    └── Ayrıntılı analiz, lineer ilişki ara
```

**Hızlı Karar Tablosu:**

| Gözlem | Saldırı | Skill |
|---|---|---|
| Aynı plaintext → aynı ciphertext blokları | ECB | `crypto/aes-cbc-bitflip` |
| Padding oracle yanıtı | CBC Bleichenbacher | `crypto/aes-cbc-bitflip` |
| IV kontrol edilebiliyor | IV manipulation | `crypto/aes-cbc-bitflip` |
| Bilinen pt + ct kontrolü | CBC bit flipping | `crypto/aes-cbc-bitflip` |
| AES-GCM nonce reuse | Polynomial root | `crypto/aes-gcm-nonce-reuse` |

---

## Hash Karar Ağacı

```
Hash challenge geldi
├── Format tespit (uzunluk + prefix)
│   ├── 32 hex → MD5
│   ├── 40 hex → SHA1
│   ├── 64 hex → SHA256
│   ├── $2[abxy]$ → bcrypt
│   ├── $1$/$5$/$6$ → MD5/SHA256/SHA512 crypt
│   └── $argon2 → Argon2
├── Plaintext small space (PIN, kısa parola)
│   └── Brute-force (hashcat -a 3 mask)
├── Plaintext wordlist'de
│   └── Dict attack (hashcat -a 0 rockyou.txt)
├── Plaintext hibrit (kelime + son ekler)
│   └── Hybrid attack (hashcat -a 6)
├── Length extension mümkün (SHA1, SHA256 ama bcrypt değil)
│   └── hashpump / Python ile uzatma
├── Hash collision aranıyor (custom hash)
│   └── Z3 SMT solver
└── Salted hash
    ├── Salt biliniyor → standart brute
    └── Salt yok → hash unsalted
```

---

## Elliptic Curve Karar Ağacı

```
ECC challenge geldi (p, a, b, G, P verilmiş, k = ?)
├── Eğri parametrelerini kontrol et
│   ├── trace(E) = 1 (anomalous) → Smart's attack (p-adic, polynomial time)
│   ├── Embedding degree küçük (k <= 6) → MOV / Frey-Rück (pairing)
│   ├── Order = p (n = p, supersingular) → MOV mümkün
│   ├── Order smooth → Pohlig-Hellman
│   ├── İki nokta farklı eğri üzerinde → Invalid curve attack
│   └── Twist hatalı → Twist attack
├── ECDSA imza
│   ├── Aynı k iki imzada → private key direkt
│   ├── Biased k (high/low bits known) → Lattice (HNP)
│   └── Küçük k → Direct brute
└── Standart eğri (secp256k1, P-256, P-384)
    └── Bilinen eğri = bilinen güvenlik, başka açık ara
```

**Hızlı Tablo:**

| Gözlem | Saldırı | Skill |
|---|---|---|
| trace(E)=1 | Smart's attack | `crypto/elliptic-curve-attacks` |
| Order smooth | Pohlig-Hellman | `crypto/elliptic-curve-attacks` |
| ECDSA k reuse | Direct recovery | `crypto/elliptic-curve-attacks` |
| ECDSA biased k | Lattice/HNP | `crypto/elliptic-curve-attacks` |
| MOV (k küçük) | Pairing-based | `crypto/elliptic-curve-attacks` |

---

## Encoding/Klasik Cipher

```
Garip string geldi
├── [A-Za-z0-9+/=]{4k} → Base64
├── [A-Za-z2-7=]{8k} → Base32
├── [0-9a-fA-F\s]+ → Hex
├── [01\s]+ → Binary
├── Sadece harf, küçük frekans → ROT13 / Caesar
├── Boşluklu sayılar (32-127) → ASCII decimal
├── . ve - → Morse
├── Tekrar eden 4-letter blok → Vigenère (keyleri test et)
├── Görüntü/dosya başlangıcı (89 50 4E 47 = PNG) → Hex'ten dosyaya
└── Hiçbirine uymuyor → ent ile entropi ölç, CyberChef'e at
```

---

## Genel CTF Crypto Stratejisi

1. **Önce kaynağı oku** — `chal.py`/`server.py` her şeyi açıklar
2. **Sabit/değişken parametreleri ayır** — n, e, primes hangileri değişiyor?
3. **factordb.com'a n at** — 5 saniyede ezilir
4. **Bilinen saldırıları sırayla dene** — bu cheatsheet sırasıyla
5. **3 başarısız denemeden sonra pivot** — yanlış kategorideyim demektir
6. **SageMath/SymPy hazır olsun** — kompleks matematik için
7. **Writeup ara** — benzer challenge daha önce çözülmüş mü? (ctftime.org)

---

## İlgili Skill'ler

- `skills/ctf/crypto/rsa-wiener-attack/SKILL.md`
- `skills/ctf/crypto/rsa-close-primes/SKILL.md`
- `skills/ctf/crypto/rsa-padding-oracle/SKILL.md`
- `skills/ctf/crypto/rsa-common-modulus/SKILL.md`
- `skills/ctf/crypto/lattice-attacks/SKILL.md`
- `skills/ctf/crypto/elliptic-curve-attacks/SKILL.md`
- `skills/ctf/crypto/aes-cbc-bitflip/SKILL.md`
- `skills/ctf/crypto/aes-gcm-nonce-reuse/SKILL.md`
- `skills/ctf/crypto/diffie-hellman-attacks/SKILL.md`
- `skills/ctf/crypto/encoding-multilayer/SKILL.md`
- `skills/ctf/crypto/hash-crack/SKILL.md`
- `skills/ctf/crypto/jwt-attacks/SKILL.md`
