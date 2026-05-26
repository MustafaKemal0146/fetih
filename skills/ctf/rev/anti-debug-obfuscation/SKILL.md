---
name: anti-debug-obfuscation
description: Anti-debug bypass ve obfuscation çözme — ptrace, UPX, PRNG, packer tespiti
tags: [ctf, rev, anti-debug, obfuscation, ptrace, upx, packer, prng, self-modifying]
triggers:
  - "anti-debug"
  - "ptrace detection"
  - "packed binary"
  - "UPX"
  - "obfuscated"
  - "self-modifying code"
  - "custom PRNG"
  - "relocation"
  - "GDB bağlanamıyor"
difficulty: hard
category: rev
solved_challenges:
  - "DEF CON CTF Qualifier 2023 - IFUCKUP (F2-linear PRNG, SageMath 512×512 linear system over F2)"
  - "HTB Cyber Apocalypse 2024 - PackedAway"
adapted_for: fetih
---

# Anti-Debug ve Obfuscation Çözme

Bu skill bir binary GDB'de düzgün çalışmıyorsa, ptrace ile korunuyorsa, packer kullanıyorsa
veya custom PRNG/obfuscation içeriyorsa devreye girer.

---

## 1. Anti-Debug Bypass Teknikleri

### ptrace Tabanlı Anti-Debug

Anti-debug'ın en yaygın yöntemi: binary kendi üzerine ptrace çağırır.
Bir işlem zaten trace ediliyorsa ikinci ptrace başarısız olur → program çıkar.

```bash
# Tespit: binary GDB altında farklı davranıyor mu?
strace ./binary 2>&1 | grep ptrace
# "ptrace(PTRACE_TRACEME, ...)" görürsen → anti-debug var

# Yöntem 1: LD_PRELOAD ile ptrace'i sahte yap
cat > /tmp/noptrace.c << 'EOF'
#include <sys/ptrace.h>
long ptrace(enum __ptrace_request req, ...) {
    return 0;   // her zaman başarılı döndür
}
EOF
gcc -shared -fPIC -o /tmp/noptrace.so /tmp/noptrace.c
LD_PRELOAD=/tmp/noptrace.so ./binary

# Yöntem 2: GDB içinde ptrace syscall'ı geç
# GDB'de:
catch syscall ptrace
run
# ptrace çağrısında dur → return değerini sıfırla
set $rax = 0
continue

# Yöntem 3: ptrace çağrısını NOP ile patch'le
# objdump ile ptrace çağrısının adresini bul
objdump -d ./binary | grep -A 2 'ptrace\|PTRACE'
# Binary'yi hex editor'da aç, call ptrace → NOP (0x90) ile doldur
python3 -c "
data = bytearray(open('./binary','rb').read())
# offset'i objdump'tan al (örn: 0x1234)
offset = 0x1234
data[offset:offset+5] = b'\x90\x90\x90\x90\x90'  # 5-byte NOP
open('./patched','wb').write(bytes(data))
"
chmod +x ./patched
```

### Diğer Anti-Debug Teknikleri

```bash
# /proc/self/status kontrolü → TracerPid satırına bakar
strace ./binary 2>&1 | grep "open.*proc"
# → Binary /proc/self/status okuyor mu?

# Yöntem: Sahte /proc/self/status oluştur
mkdir -p /tmp/fakeproc/self
echo "TracerPid:	0" > /tmp/fakeproc/self/status
# LD_PRELOAD + readlink override veya chroot trick

# RDTSC tabanlı timing kontrolü
# Binary çok hızlı mı çalışıyor? → zamanlama anti-debug var
# GDB'de:
set scheduler-locking on    # threading sorunlarını önler

# IsDebuggerPresent (Windows/Wine binary)
strings ./binary | grep -i "IsDebuggerPresent\|CheckRemoteDebugger"
```

---

## 2. UPX / Packer Tespiti ve Çözme

```bash
# Entropy ile packer tespiti
python3 << 'EOF'
import math
data = open('./binary', 'rb').read()
# 256-byte bloklarda entropy hesapla
block_size = 256
for i in range(0, min(len(data), 4096), block_size):
    block = data[i:i+block_size]
    if not block: break
    freq = {}
    for b in block:
        freq[b] = freq.get(b, 0) + 1
    e = -sum((c/len(block))*math.log2(c/len(block)) for c in freq.values())
    print(f"Blok {i:04x}: entropy={e:.2f} {'<<< PACKER?' if e > 7.2 else ''}")
EOF

# UPX standart çözme
upx -d ./binary -o ./unpacked

# UPX magic header bozuksa (CTF trick: magic değiştirilmiş)
python3 << 'EOF'
data = bytearray(open('./binary', 'rb').read())
# UPX magic: 0x55 0x58 0x21 0x00 veya "UPX!"
# CTF'lerde genelde ilk byte'lar değiştirilir
# Orijinal UPX header imzası: "UPX!" at offset 0, 8, ...
for i in range(len(data)-4):
    if data[i:i+3] == b'UPX' and data[i+3] != ord('!'):
        print(f"Bozuk UPX magic @ offset {i:#x}: {bytes(data[i:i+8]).hex()}")
        data[i+3] = ord('!')
        break
open('./fixed.bin', 'wb').write(bytes(data))
print("Düzeltildi → fixed.bin")
EOF
upx -d ./fixed.bin
```

---

## 3. DEF CON IFUCKUP: F2 PRNG Kırma

**Challenge Özeti:** Binary F2 (GF(2)) üzerinde 512-bit PRNG kullanıyordu.
Her adımda state = M * state (mod 2), M 512×512 ikili matris.
Birkaç output veriliyordu, state'i geri hesaplamak gerekiyordu.

```python
# SageMath ile F2 üzerinde 512x512 lineer sistem çözme
from sage.all import *

# F2 tanımla
F2 = GF(2)

# Matris M'yi binary'den çıkar (objdump/Ghidra ile bul)
# Örnek: M = Matrix(F2, 512, 512, [bit_listesi])

# Gözlemlenen output'ları topla (binary'yi çalıştır, output yakala)
# outputs = [o1, o2, o3, ...] — her biri 512-bit vektör

def crack_linear_prng(M, outputs):
    """
    state_n = M^n * state_0
    output_i = C * state_i (C = çıktı maskeleme matrisi)
    """
    # Output vektörlerini stack'le → büyük lineer sistem
    rows = []
    for i, out in enumerate(outputs):
        Mi = M ** i
        rows.extend(Mi.rows())

    A = Matrix(F2, rows)
    b = vector(F2, sum([list(o) for o in outputs], []))

    # Çöz
    try:
        state0 = A.solve_right(b)
        return state0
    except ValueError:
        print("Çözüm yok — daha fazla output gerekli")
        return None

# Sonucu doğrula
# state0 bulununca flag'i hesapla (binary'nin flag üretim mantığına göre)
```

**Pratik adımlar:**

```bash
# 1. Binary'den PRNG matrisini çıkar
# Ghidra'da PRNG init fonksiyonunu bul
# Matris .data section'da sabit olabilir

# 2. Binary'yi birkaç kez çalıştır, output topla
for i in $(seq 1 20); do ./binary 2>&1 | tee -a /tmp/outputs.txt; done

# 3. SageMath script'ini çalıştır
sage ifuckup_solve.sage

# 4. state0'dan flag'i derive et
```

---

## 4. Custom PRNG Analiz Metodolojisi

```python
# Genel PRNG analiz şablonu
# Adım 1: PRNG gözlemle
outputs = []
for _ in range(50):
    outputs.append(binary_output())  # binary'yi çalıştır

# Adım 2: Lineer mi? (Z modülü veya F2)
# Lineer: a[n] = c1*a[n-1] + c2*a[n-2] + ... (mod p)
# LCG: X_{n+1} = (a*X_n + c) mod m

# LCG tespiti
def detect_lcg(outputs, mod=None):
    if mod is None:
        # mod'u tahmin et (genelde 2^32 veya 2^64)
        mod = 2**64
    # a ve c'yi bul
    # a = (o2 - o1) * modular_inverse(o1 - o0) mod m
    diffs = [outputs[i+1] - outputs[i] for i in range(len(outputs)-1)]
    # Eğer diffs sabit orana sahipse → LCG var
    pass

# Mersenne Twister tespiti (Python random)
# 624 output yeterli → tüm state recover edilir
from randcrack import RandCrack
rc = RandCrack()
for o in outputs[:624]:
    rc.submit(o)
predicted = rc.predict_getrandbits(32)
```

---

## 5. GDB ile Relocation-Aware Debugging

```bash
# PIE binary'de gerçek adresi bul
gdb ./binary
# GDB içinde:
info proc map          # memory layout
# Base adres: 0x555555554000 (typical)
# offset + base = gerçek adres

# ASLR'ı devre dışı bırak (debugging için)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
# veya GDB'de:
set disable-randomization on

# Breakpoint: fonksiyon adı (stripped değilse)
break main
break *0x401234   # manuel adres

# Self-modifying code: .text section'ı izle
watch -l *(char *)0x401000@4096   # .text başlangıcını izle
# Değişince dur → hangi kod kendini modifiye ediyor?

# Anti-debug bypass sonrası devam
catch syscall ptrace
run
# ptrace'de dur
set $rax = 0
continue

# Core dump analizi (binary crash'lerse)
ulimit -c unlimited
./binary
gdb ./binary core
bt   # backtrace
```

---

## 6. Self-Modifying Code Tespiti

```bash
# Statik olarak tespit et
objdump -d ./binary | grep -E 'mprotect|mmap.*PROT_EXEC'
readelf -d ./binary | grep TEXTREL

# Dinamik olarak izle
strace -e mprotect,mmap ./binary 2>&1 | grep PROT_EXEC

# Hangi bölge değişiyor?
gdb ./binary
# Process map'e bak
info proc map
# Sonra watchpoint koy ilgili adresi
awatch *0x<adres>
```

---

## Notlar ve Tuzaklar

- `strace` kendisi de bir tracer → anti-debug tetiklenebilir, LD_PRELOAD daha güvenli
- Packer çözerken bazen birden fazla kat olur (UPX içinde başka packer)
- F2 lineer sistem çözmek için SageMath zorunlu — Python'da manuel yapma
- Custom PRNG'de 64-bit overflow'a dikkat et (Python integer overflow yapmaz, C yapar)
- Self-modifying code → statik analiz yetersiz kalır, her zaman dinamik doğrula
- bkz. elf-static-analysis SKILL.md (temel triage için)
- bkz. z3-constraint-solving SKILL.md (constraint tabanlı çözümler için)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 552cbc2c19f6ded0
-->

