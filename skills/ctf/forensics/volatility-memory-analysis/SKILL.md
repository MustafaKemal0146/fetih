---
name: volatility-memory-analysis
description: "Windows/Linux memory dump, hiberfil.sys analizi — volatility3 ile process, credential, env var çıkarma, DPAPI master key kurtarma ve pypykatz entegrasyonu."
tags: [ctf, forensics, volatility, memory-dump, windows, dpapi, hibernate, credential, pypykatz, lsadump, envars, filescan]
triggers:
  - ".dmp dosyası"
  - "memory dump"
  - "hiberfil.sys"
  - "volatility"
  - "crash dump"
  - "windows memory forensics"
  - "process tree"
  - "DPAPI"
  - "lsadump"
  - "pypykatz"
  - "RAM dump"
  - "memdump"
  - "process injection"
  - "windows credentials"
  - "lsass dump"
difficulty: hard
category: forensics
solved_challenges:
  - "HTB Cyber Apocalypse 2024 - Oblique Final (hiberfil.sys → volatility3 hibernation plugins)"
  - "HTB University CTF 2024 - Signaling Victorious (DPAPI + Signal config decrypt)"
  - "CyberSpaceCTF 2024 - Memory (WINWORD + AES encrypted PNG, envars)"
adapted_for: fetih
---

# Volatility3 ile Memory Forensics

## Ne Zaman Kullan

Aşağıdaki işaretlerden herhangi birini görürsen bu skill'i tetikle:

- `.dmp`, `.raw`, `.mem`, `.vmem`, `.lime` uzantılı dosya var
- `hiberfil.sys` verilmiş (Windows hibernation = compressed RAM dump)
- Challenge'da "memory forensics", "RAM analysis", "process dump" geçiyor
- Credential/parola çıkarma, DPAPI key recovery, lsass içeriği istenmiş
- Bir sürecin çalıştırdığı komut ya da ortam değişkenleri (env var) aranıyor

---

## Kurulum

```bash
# volatility3 — pip ile
pip install volatility3

# Geliştirme sürümü (en güncel plugin'ler için)
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3 && pip install -e .

# pypykatz — DPAPI / LSASS parse
pip install pypykatz

# Yardımcı araçlar
sudo apt install -y python3-capstone yara-python
```

---

## Temel Komut Şablonları

### Sistem Bilgisi

```bash
# İlk komut — her zaman buradan başla
vol -f dump.dmp windows.info

# Çıktı örneği:
# Variable           Value
# Kernel Base        0xf80002a52000
# DTB                0x187000
# Symbols            file:///...ntkrnlmp.pdb/...
# Is64Bit            True
# IsPAE              False
# primary            0 WindowsIntel32e
# memory_layer       1 FileLayer
# KdVersionBlock     0xf80002c430f8
# Major/Minor        15.7601   (= Windows 7 SP1)
```

### Process Listesi

```bash
# Standart süreç listesi
vol -f dump.dmp windows.pslist

# Ağaç görünümü (parent-child ilişkisi)
vol -f dump.dmp windows.pstree

# Gizli/unlinked process tespiti (rootkit analizi)
vol -f dump.dmp windows.psscan

# Her üçünü karşılaştır: pslist'te olmayıp psscan'da olanlar şüpheli!
```

### Komut Satırı ve Argümanlar

```bash
# Tüm süreçlerin cmdline'ı
vol -f dump.dmp windows.cmdline.CmdLine

# Belirli süreç adı filtrele
vol -f dump.dmp windows.cmdline.CmdLine | grep -i "powershell\|cmd\|python"

# Örnek çıktı:
# PID    Process    Args
# 1234   cmd.exe    C:\Windows\system32\cmd.exe /c "python decrypt.py --key=S3cr3t"
```

### Ortam Değişkenleri (Env Vars)

```bash
# Tüm süreçlerin env var'ları
vol -f dump.dmp windows.envars

# Belirli PID
vol -f dump.dmp windows.envars --pid 1234

# Şüpheli değişken adı ara (ctf'lerde sıkça AES key, IV, flag parçası olur)
vol -f dump.dmp windows.envars | grep -i "key\|pass\|secret\|flag\|enc\|aes"
```

### Dosya Tarama ve Çıkarma

```bash
# Memory'deki tüm dosya nesnelerini listele
vol -f dump.dmp windows.filescan

# Belirli uzantı filtrele
vol -f dump.dmp windows.filescan | grep -i "\.txt\|\.pdf\|\.png\|\.zip\|\.py"

# PID'e göre süreç memory dump al
vol -f dump.dmp windows.dumpfiles --pid 1234

# Belirli fiziksel adres ile dosya dump (filescan'dan offset al)
vol -f dump.dmp windows.dumpfiles --physaddr 0xXXXXXXXX

# Çıktı varsayılan olarak ./volatility_dump/ altına kaydedilir
```

### Credential Analizi

```bash
# LSA secrets (SAM, cached credentials)
vol -f dump.dmp windows.lsadump

# pypykatz entegrasyonu — LSASS'tan NTLM hash ve cleartext parola
vol -f dump.dmp windows.pypykatz

# Örnek pypykatz çıktısı:
# username: Administrator
# NT: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
# lm: ""
# sha1: d0f0132b308a0c4e5d1029cc06f48692ddcf72ed
```

### Registry Analizi

```bash
# Hive listesi
vol -f dump.dmp windows.registry.hivelist

# Belirli anahtar oku
vol -f dump.dmp windows.registry.printkey --key "SOFTWARE\Microsoft\Windows NT\CurrentVersion"

# Kullanıcı ayarları (NTUSER.DAT hive'ı için)
vol -f dump.dmp windows.registry.printkey --key "Control Panel\International"
```

### Network Bağlantıları

```bash
# Aktif + kapalı TCP bağlantıları
vol -f dump.dmp windows.netstat

# Çıktı: PID, Proses adı, yerel/uzak IP:port, durum, timestamp
```

---

## Gerçek Örnek: CyberSpaceCTF 2024 — Memory

### Senaryo
`memory.dmp` verilmiş. WINWORD.EXE çalışıyor, şifreli PNG dosyası açık. AES key/IV ortam değişkeninde gizlenmiş.

### Çözüm Adımları

```bash
# 1. Süreç listesini al, WINWORD'u bul
vol -f memory.dmp windows.pslist | grep -i "WINWORD"
# PID: 2488

# 2. WINWORD'un env var'larını çıkar
vol -f memory.dmp windows.envars --pid 2488

# Çıktıdan şüpheli satırlar:
# ENCD = 5f3a8b...   (encrypted data)
# ENCK = 3d9a1c...   (AES key hex)
# ENCV = a1b2c3...   (IV hex)

# 3. Dosya tara — şifreli PNG bul
vol -f memory.dmp windows.filescan | grep -i "\.png"
# 0xXXXXX  secret_document.png

# 4. Dosyayı çıkar
vol -f memory.dmp windows.dumpfiles --physaddr 0xXXXXX

# 5. Python ile AES-CBC decrypt
python3 << 'EOF'
from Crypto.Cipher import AES
import binascii

# Env var'lardan elde edilen değerler
key = binascii.unhexlify("3d9a1c...")  # ENCK
iv  = binascii.unhexlify("a1b2c3...")  # ENCV

with open("file.0xXXXXX.png", "rb") as f:
    ciphertext = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)

# PKCS7 padding kaldır
pad_len = plaintext[-1]
plaintext = plaintext[:-pad_len]

with open("decrypted.png", "wb") as f:
    f.write(plaintext)
print("Decrypted! Dosya: decrypted.png")
EOF
```

---

## Gerçek Örnek: HTB University CTF 2024 — Signaling Victorious

### Senaryo
Signal Desktop uygulamasının config database'i DPAPI ile şifreli. Memory dump'tan DPAPI master key kurtarılacak, Signal DB decrypt edilecek.

### Çözüm Adımları

```bash
# 1. LSA dump — DPAPI master key adayları
vol -f signaling.dmp windows.lsadump

# 2. pypykatz ile LSASS parse — NTLM hash al
vol -f signaling.dmp windows.pypykatz
# username: john_doe  NT: 8846f7eaee8fb117ad06bdd830b7586c

# 3. Signal config dosyasını filescan ile bul
vol -f signaling.dmp windows.filescan | grep -i "signal\|config"
# AppData\Roaming\Signal\config.json
# AppData\Roaming\Signal\sql\db.sqlite

# 4. Dosyaları dump et
vol -f signaling.dmp windows.dumpfiles --physaddr 0xXXXX

# 5. pypykatz ile DPAPI master key çöz
pypykatz dpapi prekey password \
  --sid "S-1-5-21-XXXX" \
  --password "kurtarılan_parola" \
  masterkey_dosyası.mk

# 6. Signal Electron safeStorage key'i decrypt et (AES-GCM)
python3 << 'EOF'
import json, base64
from Crypto.Cipher import AES

# config.json içindeki encryptedKey
with open("config.json") as f:
    config = json.load(f)

enc_key = base64.b64decode(config["encryptedKey"])
# İlk 3 byte "v10" prefix — Electron safeStorage formatı
prefix = enc_key[:3]   # b'v10'
nonce  = enc_key[3:15] # 12 byte nonce
tag    = enc_key[-16:] # son 16 byte GCM tag
ct     = enc_key[15:-16]

# DPAPI'dan kurtarılan AES-256 anahtarı
dpapi_key = bytes.fromhex("DPAPI_cikti_hex")

cipher = AES.new(dpapi_key, AES.MODE_GCM, nonce=nonce)
db_key = cipher.decrypt_and_verify(ct, tag)
print(f"Signal DB Key: {db_key.hex()}")
# sqlcipher ile: PRAGMA key = "x'<db_key_hex>'";
EOF
```

---

## hiberfil.sys Analizi (HTB Oblique Final)

### Senaryo
`hiberfil.sys` verilmiş — Windows hibernation dosyası. Sıkıştırılmış RAM dump'ı içerir.

```bash
# Yöntem 1: volatility3 doğrudan hiberfil.sys destekler
vol -f hiberfil.sys windows.info

# Yöntem 2: Önce raw dump'a çevir (bazı versiyonlarda gerekli)
pip install libhibr2  # veya
python3 -c "
import libhibr2
libhibr2.convert('hiberfil.sys', 'memory.raw')
"

# Yöntem 3: volatility2 hibernation plugin (eski CTF dump'ları için)
volatility --plugins=/path/to/community -f hiberfil.sys \
  --profile=Win10x64_19041 hibinfo

# hiberfil.sys boyutu büyükse (8-32 GB) — sadece ilgili plugin'i çalıştır
# Tüm pslist yerine hedefli:
vol -f hiberfil.sys windows.cmdline.CmdLine 2>/dev/null | head -100
```

---

## Tuzaklar

- **Windows profil otomatik tespiti**: volatility3 genellikle profili otomatik bulur. `windows.info` ile doğrula. Yanlış profil — tüm plugin'ler anlamsız sonuç verir.
- **pypykatz boş çıktı**: LSASS süreci dump alınmamışsa pypykatz çalışmaz. `windows.dumpfiles --pid <lsass_pid>` ile önce LSASS'ı dosyaya çıkar, sonra `pypykatz lsa minidump lsass.dmp` çalıştır.
- **Env var encoding**: Bazı CTF'lerde env var değerleri base64 ya da hex encode edilmiş olur. Ham çıktıyı decode etmeyi dene.
- **hiberfil.sys boyutu**: Hibernation dosyası makine RAM'inin ~%75-85'i kadar. 16 GB RAM → ~12 GB hiberfil.sys. Yavaş olur, sabırlı ol.
- **filescan vs dumpfiles offset**: `filescan`'deki offset değeri `dumpfiles --physaddr` parametresine olduğu gibi girer. `0x` prefix'ini eklemeyi unutma.
- **volatility3 vs volatility2 farkı**: volatility3'te `windows.pslist`, volatility2'de `pslist` (prefix yok). Plugin adları farklı — hangisini kullandığını kontrol et.
- **lsadump şifreli çıkabilir**: LSA secrets bazı Windows sürümlerinde DPAPI ile ekstra şifreli. Ham hex değerini DPAPI pipeline'a besle.
- **PID 4 = System**: lsass.exe genellikle PID 600-700 aralığında. `windows.pslist | grep lsass` ile bul.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 9c0be64d80494884
-->

