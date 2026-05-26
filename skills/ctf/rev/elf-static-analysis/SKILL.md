---
name: elf-static-analysis
description: ELF binary statik analiz — file, strings, objdump, readelf, nm, Ghidra workflow
tags: [ctf, rev, elf, static-analysis, strings, objdump, ghidra, ida, binary-analysis]
triggers:
  - "ELF binary"
  - "binary analiz"
  - "tersine mühendislik"
  - "reverse engineering"
  - "./binary çalıştır"
  - "stripped binary"
  - "strings komutu"
  - "disassembly"
difficulty: medium
category: rev
solved_challenges:
  - "HTB Cyber Apocalypse 2024 - PackedAway (UPX detect + strings)"
  - "LACTF 2024 - glottem (polyglot POSIX/Node.js)"
adapted_for: fetih
---

# ELF Binary Statik Analiz

Bu skill bir ELF binary aldığında ilk yapılacakları ve derinlemesine analiz metodolojisini kapsar.
Hızlı triage'dan Ghidra decompile akışına kadar adım adım yol gösterir.

---

## 1. İlk Triage (file → strings → checksec → ltrace/strace)

Yeni bir binary geldiğinde HEMEN şunları çalıştır:

```bash
# 1. Dosya tipi
file ./binary
# Örnek çıktı: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

# 2. Temel string taraması
strings ./binary | grep -i flag
strings ./binary | grep -E 'HTB{|CTF{|flag{|picoCTF{'
strings ./binary | head -60    # ilk 60 satır genel bağlamı verir

# 3. Güvenlik flag'leri
checksec --file=./binary
# PIE, RELRO, Canary, NX kontrol et

# 4. Dinamik bağımlılıklar
ldd ./binary
file ./binary | grep -o "interpreter.*"

# 5. Hızlı çalıştırma (sandbox'ta)
strace ./binary 2>&1 | head -30   # syscall akışı
ltrace ./binary 2>&1 | head -30   # kütüphane çağrıları
```

### Triage Sonucu Yorum Tablosu

| Çıktı | Anlam | Sonraki Adım |
|---|---|---|
| `UPX compressed` | Packer var | upx -d ./binary |
| `stripped` | Sembol yok | Ghidra/IDA + manual rename |
| `statically linked` | ldd çalışmaz | readelf -d, strings daha önemli |
| `PIE enabled` | Rastgele adres | GDB set offset |
| string içinde flag | Çok kolay | Direkt teslim et |

---

## 2. objdump / readelf Cheat Sheet

```bash
# Tüm section header'ları listele
readelf -S ./binary

# Sembol tablosu (stripped değilse)
nm ./binary
nm ./binary | grep -i main
nm ./binary | grep -i ' T '   # text (kod) sembolleri

# Disassembly — main fonksiyonu
objdump -d ./binary | grep -A 100 '<main>:'

# Belirli section'ı disassemble et
objdump -d -j .text ./binary | less

# Tüm binary disassembly (büyük dosyalarda dikkatli)
objdump -M intel -d ./binary > /tmp/binary_asm.txt

# Header bilgileri
readelf -h ./binary       # ELF header
readelf -l ./binary       # Program headers (segment'lar)
readelf -d ./binary       # Dinamik bölüm

# GOT/PLT adresleri (dinamik bağlantılı)
objdump -d -j .plt ./binary
objdump -R ./binary       # relocation tablosu

# .rodata içindeki stringler (sabit veri)
objdump -s -j .rodata ./binary

# Hex dump — belirli section
readelf -x .rodata ./binary
readelf -x .data ./binary
```

---

## 3. HTB PackedAway: UPX Tespiti ve Çözme

**Challenge Özeti:** Binary çalışmıyor, strings boş, şüpheli.

```bash
# Adım 1: Packer var mı?
file ./packed_binary
# "UPX compressed" görürsen veya:
strings ./packed_binary | grep -i upx
# "UPX!" magic bytes ara

# Adım 2: Entropy analizi (packer'ı doğrula)
python3 -c "
import math
data = open('./packed_binary','rb').read()
freq = {}
for b in data:
    freq[b] = freq.get(b,0) + 1
entropy = -sum((c/len(data))*math.log2(c/len(data)) for c in freq.values())
print(f'Entropy: {entropy:.2f}')
print('Packer şüphesi: YÜksek' if entropy > 7.0 else 'Normal')
"

# Adım 3: UPX çöz
upx -d ./packed_binary -o ./unpacked_binary
# veya
upx -d ./packed_binary    # yerinde çözer

# Adım 4: Çözülmüş binary'ye tekrar triage
file ./unpacked_binary
strings ./unpacked_binary | grep -i flag

# HTB PackedAway çözümü:
# strings sonrası doğrudan flag görünüyordu → HTB{...}
```

**UPX magic bytes bozuksa (CTF trick):**
```bash
# Binary'yi hex editor ile aç
xxd ./packed_binary | head -5
# "UPX!" yerine değiştirilmiş magic → elle düzelt
python3 -c "
data = bytearray(open('./packed_binary','rb').read())
# UPX magic restore
idx = data.find(b'UPX')  # veya manuel offset
# data[idx:idx+4] = b'UPX!'
open('./fixed.bin','wb').write(bytes(data))
"
upx -d ./fixed.bin
```

---

## 4. LACTF glottem: Polyglot Script Analizi

**Challenge Özeti:** Dosya hem shell script hem Node.js olarak çalışıyordu.

```bash
# Adım 1: Dosyayı gerçekten incele (file komutu yanıltabilir)
file ./glottem
head -10 ./glottem    # ilk satırlar kritik

# Adım 2: Polyglot tespiti — aynı anda iki dil
# POSIX shell'de geçerli + Node.js'te geçerli bloklar ara
grep -n "eval\|require\|#!/" ./glottem

# LACTF glottem yapısı:
# #!/bin/sh
# # Node.js bu kısmı yorum sayar ama sh çalıştırır
# ...
# js kodu buraya (sh yorum satırlarının arkasında)

# Adım 3: Her yorumlayıcıda ayrı ayrı çalıştır
bash ./glottem
node ./glottem

# Adım 4: Validator mantığını izole et
# Node.js katmanını çıkar
node -e "$(tail -n +5 ./glottem)" 2>&1

# LACTF çözümü: z3 ile validator bypass → bkz. z3-constraint-solving SKILL.md
```

---

## 5. Ghidra Temel Workflow

```
1. Ghidra aç → New Project → Import File → Binary seç
2. Auto Analysis → Tümünü kabul et (özellikle "Decompiler Parameter ID")
3. Symbol Tree → Functions → main'i bul
4. Decompiler penceresinde C kodu oku
5. Şüpheli fonksiyon isimlerini ara: check, validate, compare, strcmp

Kritik kısayollar:
  L     → Rename (sembol adlandır)
  ;     → Comment ekle
  Ctrl+E → Edit Function Signature
  G     → Go to address
  Ctrl+F → String/symbol ara
  Space  → Listing ↔ Decompiler geçiş

String'den geriye git:
  .rodata içindeki string'e çift tıkla
  → References → Show References to Address
  → Kullanan fonksiyonu bul
```

---

## 6. Otomatik Triage Bash One-Liner

```bash
#!/bin/bash
# Kullanım: ./elf-triage.sh ./binary_dosyası

BINARY="$1"
echo "=== ELF TRIAGE: $BINARY ==="
echo ""

echo "[*] Dosya tipi:"
file "$BINARY"
echo ""

echo "[*] Checksec:"
checksec --file="$BINARY" 2>/dev/null || python3 -c "
import struct, sys
data = open('$BINARY','rb').read()
print('Manuel kontrol — checksec yok')
"
echo ""

echo "[*] String flag taraması:"
strings "$BINARY" | grep -iE 'flag\{|HTB\{|CTF\{|picoCTF\{|FLAG\{' || echo "  Direkt flag yok"
echo ""

echo "[*] UPX/Packer tespiti:"
strings "$BINARY" | grep -i 'upx\|packed\|compressed' || echo "  Belirgin packer yok"
echo ""

echo "[*] Import tablosu:"
nm -D "$BINARY" 2>/dev/null | grep ' U ' | head -20
echo ""

echo "[*] İlginç stringler:"
strings "$BINARY" | grep -iE 'password|secret|key|token|admin|auth|crack|solve|answer' | head -15
echo ""

echo "[*] Ldd (dinamik bağımlılıklar):"
ldd "$BINARY" 2>/dev/null || echo "  Statik bağlantılı"
echo ""

echo "=== TRIAGE TAMAMLANDI ==="
echo "Sonraki adım: Ghidra veya objdump -d için yukarıdaki cheat sheet'e bak"
```

---

## Notlar ve Tuzaklar

- **Stripped binary** → `nm` boş döner, Ghidra'da fonksiyon isimlerini elle koy
- **Anti-debug** → bkz. anti-debug-obfuscation SKILL.md
- **Constraint/validator** → bkz. z3-constraint-solving SKILL.md
- Binary çalışmıyorsa: doğru mimariye bak (ARM? MIPS?), `qemu-user-static` dene
- `strings -n 6` ile minimum uzunluğu artır (kısa sahte stringleri filtreler)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 79bbc85129defcb9
-->

