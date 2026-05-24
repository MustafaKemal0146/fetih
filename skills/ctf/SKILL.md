---
name: ctf-master-solver
description: CTF challenge ana orkestratörü — kategori tespiti, ilgili skill arama, çözüm koordinasyonu
tags: [ctf, orchestrator, master, solver, triage, category-detection]
triggers:
  - "CTF challenge"
  - "flag bul"
  - "capture the flag"
  - "challenge dosyası"
  - "flag{"
  - "yarışma görevi"
---

# CTF Master Solver — Ana Orkestratör

Bu dosya FETIH'in CTF challenge'larını ele alırken ilk okuduğu dosyadır.
Bir challenge geldiğinde bu akışı takip et, ardından ilgili skill'i yükle.

---

## Triage Akışı

Challenge alındığında SIIRAYLA yap:

```bash
# 1. Dosya tipi tespiti
file ./challenge_dosyasi
xxd ./challenge_dosyasi | head -20    # magic bytes
strings ./challenge_dosyasi | head -40

# 2. Arşiv mi?
file * | grep -i 'zip\|tar\|gzip\|7z\|rar'
# Arşivi aç → içindeki dosyalara triage uygula

# 3. Ağ servisi mi?
# "nc host port" verilmişse → pwn veya crypto kategorisi
nc -v host port  # bağlan, banner gör

# 4. Web URL mi?
# Tarayıcıda aç → kaynak kodu incele → cookie/header bak

# 5. Flag formatı tahmin et
# Organizasyona göre: HTB{}, picoCTF{}, flag{}, CTF{}, IRIS{}
```

---

## Kategori → Skill Eşleme Tablosu

| Challenge ipucu | Kategori | Skill yolu |
|---|---|---|
| n, e, c verilmiş | Crypto/RSA | `skills/ctf/crypto/rsa-wiener-attack` veya `rsa-close-primes` veya `rsa-common-modulus` |
| JWT token, eyJ başlıyor | Crypto/Web | `skills/ctf/crypto/jwt-attacks` |
| base64/hex/encoded veri | Crypto | `skills/ctf/crypto/encoding-multilayer` |
| hash kır, MD5/SHA/bcrypt | Crypto | `skills/ctf/crypto/hash-crack` |
| ELF binary, nc host port (pwn) | Pwn | `skills/ctf/pwn/buffer-overflow-rop` → `ret2libc` → `heap-exploit` |
| format string, %n, %p%p | Pwn | `skills/ctf/pwn/format-string` |
| .dmp, .vmem, memory dump | Forensics | `skills/ctf/forensics/volatility-memory-analysis` |
| .pcap, .pcapng, ağ trafiği | Forensics | `skills/ctf/forensics/pcap-network-analysis` |
| PNG, JPG, BMP, görsel stego | Forensics | `skills/ctf/forensics/steganography-image` |
| WAV, MP3, ses dosyası | Forensics | `skills/ctf/forensics/steganography-audio` |
| ELF binary, tersine mühendislik | Rev | `skills/ctf/rev/elf-static-analysis` |
| anti-debug, GDB bağlanamıyor | Rev | `skills/ctf/rev/anti-debug-obfuscation` |
| validator fonksiyonu, constraint | Rev | `skills/ctf/rev/z3-constraint-solving` |
| Web, URL, login formu | Web | `skills/ctf/web/sqli-exploitation` → `jwt-web-bypass` → `ssrf-ssti-chain` |
| GraphQL, __schema, introspection | Web | `skills/ctf/web/graphql-attacks` |
| pickle, deserialization, __reduce__ | Web | `skills/ctf/web/deserialization` |
| kişi araştır, OSINT, fictional person | OSINT | `skills/ctf/osint/persona-tracking` |

---

## Skill Okuma Komutu

Kategori belirlendikten sonra:

```
Read skills/ctf/[kategori]/[teknik]/SKILL.md
```

Okunan skill'deki `triggers` listesi ile kendi challenge'ını karşılaştır.
Eşleşen trigger varsa → o skill'deki metodoloji ile devam et.

Eğer tam eşleşme yoksa birden fazla skill oku ve en yakını seç.

---

## Hızlı Karar Ağacı

```
Dosya var mı?
├── ELF → Rev veya Pwn
│   ├── nc bağlantısı da var → Pwn (buffer overflow, ret2libc)
│   ├── sadece dosya, "flag gir" → Rev
│   │   ├── GDB çalışmıyor → anti-debug-obfuscation
│   │   ├── validator fonksiyonu görüyorum → z3-constraint-solving
│   │   └── UPX/packed → elf-static-analysis (UPX bölümü)
│   └── format string ipucu → format-string
│
├── Görsel (PNG/JPG/BMP/GIF)
│   ├── "flag içinde gizli" → steganography-image
│   ├── "kişi kim?" → persona-tracking (EXIF + geolocation)
│   └── QR kod → zbarimg ile çöz
│
├── Ses (WAV/MP3/FLAC)
│   └── → steganography-audio (spectogram, LSB)
│
├── .pcap / .pcapng
│   └── → pcap-network-analysis (Wireshark, tshark)
│
├── .dmp / memory dump
│   └── → volatility-memory-analysis
│
├── Metin / sayılar
│   ├── n, e, c → RSA crypto
│   ├── eyJ... → JWT
│   ├── base64/hex string → encoding-multilayer
│   └── hash (md5/sha/bcrypt) → hash-crack
│
├── Web URL
│   ├── login formu → sqli-exploitation
│   ├── GraphQL endpoint → graphql-attacks
│   ├── cookie/JWT → jwt-web-bypass
│   └── template, SSTI ipucu → ssrf-ssti-chain
│
└── Hiçbiri değil → strings + file + xxd ile tekrar triage
```

---

## Başarısız Olunca Pivot

```
Deneme 1 → İlk skill metodolojisi
Deneme 2 → Aynı kategoride farklı teknik (tablodaki alternatif)
Deneme 3 → Komşu kategori (örn: Rev başarısız → Pwn dene)
Deneme 4 → Genel CTF solver:
           Read skills/red-teaming/ctf-challenge-solver/SKILL.md
```

Pivot kararı ver:
- Aynı yerde 15 dakikadan fazla takılıysan → pivot
- Yeni bir ipucu gelirse → tablodan yeniden eşleştir
- "Bu çalışmıyor" yerine "Neden çalışmıyor?" diye düşün

---

## Ortam Hazırlama

```bash
# CTF çalışma dizini oluştur
mkdir -p /tmp/ctf/$(date +%Y%m%d)_challengeName
cd /tmp/ctf/...

# Araçlar kurulu mu?
which ghidra pwntools z3 hashcat john exiftool sherlock 2>/dev/null
# Eksik olanları kur:
pip install pwntools z3-solver

# pwntools template (pwn category için)
pwn template ./binary --host HOST --port PORT > solve.py

# GDB + pwndbg/peda
gdb -q ./binary
```

---

## Flag Doğrulama

```
Desteklenen flag formatları:
  flag{...}
  FLAG{...}
  CTF{...}
  HTB{...}
  picoCTF{...}
  IRIS{...}
  0CTF{...}
  ACSC{...}
  <yarışma_ismi>{...}

Flag bulununca:
1. Format doğru mu? (açılan parantez + içerik + kapanan parantez)
2. İnsan tarafından okunabilir metin mi? (anlamsız hex değilse şüphe et)
3. Binary ile doğrula: echo "flag{...}" | ./binary → "Correct!" beklenir
4. Yarışma platformuna gönder

Sahte flag tuzakları:
- Binary içinde "flag{test}" veya "flag{XXXXXXXXX}" → sahte
- "wrong flag" mesajı veriyorsa → doğru formata bak
```

---

## Paralel Strateji

Birden fazla olası kategori varsa:

```bash
# Terminal 1: Rev
strings ./binary | grep -i flag
# Terminal 2: Forensics (içinde gizli dosya var mı?)
binwalk ./binary
foremost ./binary -o /tmp/foremost_out/
# Terminal 3: Stego (görsel mi?)
steghide info ./binary 2>/dev/null
```

---

## Sık Kullanılan Tek Satırlıklar

```bash
# Tüm printable stringleri çıkar
strings -n 8 ./file | sort -u

# Magic byte kontrolü
xxd ./file | head -3

# Arşiv içini listele (çıkarmadan)
7z l ./archive.zip
tar -tzvf ./archive.tar.gz

# Base64 çöz
echo "SGVsbG8=" | base64 -d

# Hex çöz
echo "48656c6c6f" | xxd -r -p

# ROT13
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# XOR ile bir byte
python3 -c "data=open('./file','rb').read(); print(bytes(b^0x42 for b in data))"

# MD5/SHA hash kır (online)
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash

# CyberChef (çevrimiçi Swiss Army Knife)
# https://gchq.github.io/CyberChef/
```

---

## Notlar

- Flag bulunduğunda hemen platformdaki submission arayüzüne yaz
- CTF writeup'larına bak (benzer challenge daha önce çözülmüş olabilir)
- `site:ctftime.org writeup "challenge_adi"` ile ara
- Zaman baskısında önce kolay görünen bölümleri çöz (puan/zaman optimizasyonu)
- Ekip çalışmasında kim neye baktığını söyle (aynı şeyi tekrar araştırmayın)
