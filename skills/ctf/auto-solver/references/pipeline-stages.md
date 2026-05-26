# Pipeline Stages — Detaylı Aşama Rehberi

Her stage için detaylı komutlar, karar ağaçları ve edge case'ler.

---

## Stage 1: Extract — Detaylı

### Desteklenen Arşiv Formatları
| Format | Komut | Gereksinim |
|--------|-------|------------|
| .zip | `unzip -o file.zip -d out/` | unzip |
| .tar | `tar xf file.tar -C out/` | tar |
| .tar.gz | `tar xzf file.tar.gz -C out/` | tar |
| .tar.bz2 | `tar xjf file.tar.bz2 -C out/` | tar |
| .tar.xz | `tar xJf file.tar.xz -C out/` | tar |
| .7z | `7z x file.7z -oout/` | p7zip |
| .rar | `unrar x file.rar out/` | unrar |
| .gz | `gunzip file.gz` | gzip |
| .bz2 | `bunzip2 file.bz2` | bzip2 |

### Edge Cases
- **İç içe zip:** recursive extract — her zip için Stage 1'i tekrar çalıştır
- **Şifreli zip:** common passwords dene (infected, password, flag, 123456)
- **Sahte uzantı:** `file` komutuyla gerçek tipi kontrol et
- **Binwalk fallback:** Hiçbir arşiv aracı çalışmazsa `binwalk -e` dene

---

## Stage 2: Classify — Karar Ağacı

```
Dosya var mı?
├── EVET → Dosya tipini kontrol et
│   ├── ELF/PE/Mach-O → REVERSE
│   ├── pcap/pcapng → FORENSICS
│   ├── PNG/JPG/GIF/BMP → STEGO (görsel)
│   ├── WAV/MP3/OGG/FLAC → STEGO (ses) VEYA FORENSICS (SSTV)
│   ├── ZIP/TAR/RAR → EXTRACT (Stage 1'e dön)
│   ├── PDF → içinde gömülü dosya ara
│   └── Diğer → strings ile analiz et
│
├── URL verilmiş → WEB
│   ├── Login formu var → SQLi/NoSQLi testi
│   ├── API endpoint'leri var → API security testi
│   └── Statik site → source inspection
│
├── netcat adresi → PWN
│   └── Banner'da ne yazıyor? Binary exploit mi?
│
└── Şifreli metin / sayılar → CRYPTO
    ├── Base64 görünümlü → encoding chain
    ├── p=, q=, n=, e= var → RSA
    └── Hash formatı → hash cracking
```

---

## Stage 3: Route — Tool Zinciri

### Web Tool Zinciri
```
curl (headers) → curl (body) → gobuster/ffuf (dir enum) → Burp Suite (intercept) → exploit
```

### Crypto Tool Zinciri
```
detect encoding → decode layer 1 → decode layer N → identify cipher → solve
```

### Reverse Tool Zinciri
```
file → strings → objdump → Ghidra → GDB → angr
```

### Forensics Tool Zinciri
```
file → strings → binwalk → foremost → volatility (memory) / wireshark (pcap)
```

### Stego Tool Zinciri
```
exiftool → zsteg → steghide → binwalk → spectrogram (audio)
```

---

## Stage 4: Solve — Timeout Yönetimi

Her alt-aşama için maksimum süre:

| Alt-aşama | Max Süre |
|-----------|---------|
| Directory brute force | 3 dakika |
| Hash cracking (rockyou) | 2 dakika |
| angr symbolic execution | 5 dakika |
| PCAP analizi | 3 dakika |
| Binwalk extract | 2 dakika |

Timeout aşılırsa → sonuçları log'la → bir sonraki alt-aşamaya geç.

---

## Stage 5: Validate — Flag Kontrol Listesi

1. ASCII printable mı?
2. Flag formatına uyuyor mu? (`flag{...}`, `CTF{...}`, `SiberVatan{...}` vs)
3. Base64 encode edilmiş hali mi? (decode etmeyi dene)
4. Boşluk/satır sonu karakteri var mı? (trim yap)
5. Aynı flag daha önce bulundu mu? (flags.txt'yi kontrol et)
