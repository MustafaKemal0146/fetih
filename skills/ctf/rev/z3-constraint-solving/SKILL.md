---
name: z3-constraint-solving
description: Z3 SMT solver ile CTF constraint çözme — byte equations, hash collision, validator bypass
tags: [ctf, rev, z3, smt-solver, constraint, sat, byte-equations, symbolic-execution]
triggers:
  - "validator fonksiyonu"
  - "byte by byte kontrol"
  - "constraint satisfaction"
  - "z3"
  - "SMT solver"
  - "doğrulama algoritması"
  - "her byte için koşul"
  - "hash collision"
  - "linear equations"
difficulty: medium-hard
category: rev
solved_challenges:
  - "HTB Cyber Apocalypse 2024 - ROT128 (linear hash collision, z3)"
  - "LACTF 2024 - glottem (cross-language validator)"
adapted_for: fetih
---

# Z3 SMT Solver ile CTF Çözme

Z3, Microsoft Research'ün SMT (Satisfiability Modulo Theories) solver'ı.
CTF'lerde validator fonksiyonlarını, byte kısıtlamalarını ve hash collision'ları çözmek için kullanılır.

---

## 1. Z3 Temel Kullanım

```python
from z3 import *

# Temel tipler
x = Int('x')           # tam sayı
y = BitVec('y', 32)    # 32-bit bitvector
b = Bool('b')          # boolean
r = Real('r')          # gerçek sayı

# Solver oluştur
s = Solver()

# Kısıtlama ekle
s.add(x > 0)
s.add(x < 100)
s.add(x * 3 + 7 == 64)

# Çöz
if s.check() == sat:
    m = s.model()
    print(m[x])     # → 19
else:
    print("Çözüm yok")

# Tüm çözümleri bul
solutions = []
while s.check() == sat:
    m = s.model()
    solutions.append(m[x].as_long())
    s.add(x != m[x])   # bu çözümü hariç tut
print(solutions)
```

---

## 2. Byte Equation Şablonu (Flag Baytları İçin)

CTF'lerin büyük çoğunluğunda flag baytları bir validator fonksiyonundan geçirilir.
Bu şablonu direkt kullan:

```python
from z3 import *

# Flag uzunluğunu binary'den öğren (strings, Ghidra, vs.)
FLAG_LEN = 32

# Her flag baytı için bir BitVec değişkeni
flag = [BitVec(f'flag_{i}', 8) for i in range(FLAG_LEN)]

s = Solver()

# Temel kısıtlamalar: printable ASCII
for b in flag:
    s.add(b >= 0x20)   # space
    s.add(b <= 0x7e)   # tilde

# Flag formatı (bilinen prefix varsa)
prefix = b'HTB{'
for i, c in enumerate(prefix):
    s.add(flag[i] == c)

# Son byte genelde '}'
s.add(flag[-1] == ord('}'))

# ==== BURAYA BINARY'DEN ÇIKARIILAN KISIITLAMALARI EKLE ====
# Örnek: validator şunu yapıyorsa:
#   if (flag[0] + flag[1] != 0xA3) exit(1);
#   if (flag[2] ^ flag[3] != 0x1F) exit(1);
s.add(flag[0] + flag[1] == 0xA3)
s.add(flag[2] ^ flag[3] == 0x1F)
# ... tüm kontroller

# Çöz
if s.check() == sat:
    m = s.model()
    result = bytes([m[flag[i]].as_long() for i in range(FLAG_LEN)])
    print(f"Flag: {result.decode()}")
else:
    print("Çözüm yok — kısıtlamaları kontrol et")
```

---

## 3. HTB ROT128: Linear Hash Collision ile Z3

**Challenge Özeti:** ROT128 adlı custom hash fonksiyonu input'u dönüştürüyor.
Hedef hash değeri verilmiş, bu hash'i üreten input'u bulmak gerekiyor.

```python
from z3 import *

# ROT128: her byte'a 128 ekle (mod 256) → döngüsel
# hash: tüm dönüştürülmüş byte'ların XOR toplamı = target

TARGET_HASH = 0x4A  # binary'den alınan hedef

FLAG_LEN = 20
flag = [BitVec(f'b_{i}', 8) for i in range(FLAG_LEN)]

s = Solver()

# Printable ASCII kısıtlaması
for b in flag:
    s.add(b >= 0x21)
    s.add(b <= 0x7e)

# ROT128 hash kısıtlaması
# rot128(b) = (b + 128) % 256
def rot128(b):
    return (b + 128) & 0xFF  # Z3 BitVec operasyonu

# Tüm rot128 değerlerinin XOR'u = target
xor_result = rot128(flag[0])
for i in range(1, FLAG_LEN):
    xor_result = xor_result ^ rot128(flag[i])

s.add(xor_result == TARGET_HASH)

# Flag format kısıtlaması
prefix = b'HTB{'
for i, c in enumerate(prefix):
    s.add(flag[i] == c)
s.add(flag[-1] == ord('}'))

if s.check() == sat:
    m = s.model()
    result = bytes([m[flag[i]].as_long() for i in range(FLAG_LEN)])
    print(f"Flag: {result.decode()}")
```

**Daha karmaşık linear hash:**

```python
# Eğer hash = A[0]*flag[0] + A[1]*flag[1] + ... + A[n]*flag[n] (mod M)
# Z3 lineer aritmetik çok iyi çözer

coefficients = [0x13, 0x37, 0x42, ...]  # binary'den çıkar
target = 0xDEADBEEF

s = Solver()
flag = [BitVec(f'f_{i}', 32) for i in range(len(coefficients))]

hash_val = sum(coefficients[i] * flag[i] for i in range(len(coefficients)))
s.add(hash_val == target)
# + printable kısıtlamalar
```

---

## 4. LACTF glottem: Çapraz Dil Validator Bypass

**Challenge Özeti:** Script hem bash hem Node.js yorumluyordu. Her dil farklı kısıtlama yapıyordu.

```python
from z3 import *

# Bash katmanı: length kontrolü
# Node.js katmanı: karakter toplamı + XOR kontrolü

FLAG_LEN = 15
flag = [BitVec(f'c_{i}', 8) for i in range(FLAG_LEN)]
s = Solver()

for b in flag:
    s.add(b >= 0x61)   # lowercase a-z only (bash'in kabul ettiği)
    s.add(b <= 0x7a)

# Node.js validator'dan çıkarılan kısıtlamalar
# charCodeAt toplamı = 1337
char_sum = sum(flag)
s.add(char_sum == 1337)

# XOR kontrolü (Node.js)
xor_val = flag[0]
for b in flag[1:]:
    xor_val = xor_val ^ b
s.add(xor_val == 0x42)

if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[flag[i]].as_long()) for i in range(FLAG_LEN)))
```

---

## 5. Symbolic Execution (angr Alternatif)

Kısıtlamaları manuel çıkarmak yerine angr otomatik analiz yapabilir:

```python
import angr
import claripy

project = angr.Project('./binary', auto_load_libs=False)

# Symbolic input oluştur
flag_len = 32
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars)

# stdin'den flag oku
stdin = angr.SimFile('stdin', content=flag, size=flag_len)
state = project.factory.full_init_state(
    stdin=angr.SimFileStream(name='stdin', content=flag, has_end=True)
)

# Printable ASCII ekle
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# Simülasyon
simgr = project.factory.simulation_manager(state)

# Başarı adresine git, crash adresinden kaçın
success_addr = 0x401234  # binary'de "Correct!" mesajının adresi
fail_addr = 0x401300     # "Wrong!" mesajının adresi

simgr.explore(find=success_addr, avoid=fail_addr)

if simgr.found:
    sol_state = simgr.found[0]
    flag_val = sol_state.solver.eval(flag, cast_to=bytes)
    print(f"Flag: {flag_val.decode()}")
```

---

## 6. Tam Z3 CTF Şablonu

Herhangi bir CTF challenge'ına uygulanabilir genel şablon:

```python
#!/usr/bin/env python3
"""
Z3 CTF Solver - Genel Şablon
Kullanım: Ghidra/objdump ile validator'ı analiz et,
          kısıtlamaları add_constraints() içine ekle.
"""
from z3 import *
import sys

def solve_ctf(flag_len: int, prefix: bytes = b'', suffix: bytes = b'') -> bytes | None:
    s = Solver()
    flag = [BitVec(f'f{i}', 8) for i in range(flag_len)]

    # ---- Temel kısıtlamalar ----
    for b in flag:
        s.add(b >= 0x20, b <= 0x7e)  # printable ASCII

    # ---- Bilinen prefix/suffix ----
    for i, c in enumerate(prefix):
        s.add(flag[i] == c)
    for i, c in enumerate(suffix):
        s.add(flag[flag_len - len(suffix) + i] == c)

    # ---- BURAYA KISIITLAMALARI EKLE ----
    def add_constraints(f):
        """
        f: flag baytlarının listesi (z3 BitVec)
        Ghidra'daki her if koşulunu buraya çevir.

        Örnekler:
        s.add(f[4] + f[5] == 0x9A)
        s.add(f[6] ^ f[7] == 0x3C)
        s.add((f[8] * f[9]) & 0xFF == 0x12)
        s.add(f[10] - f[11] == -3)  # negatif fark olabilir
        """
        pass  # ← SİL VE KISIITLAMALARI EKLE

    add_constraints(flag)
    # ---- KISIITLAMA SONU ----

    # Çöz
    result = s.check()
    if result == sat:
        m = s.model()
        sol = bytes(m[flag[i]].as_long() for i in range(flag_len))
        print(f"[+] Çözüm bulundu: {sol}")
        return sol
    elif result == unsat:
        print("[-] Çözüm yok — kısıtlamalar çelişiyor")
        return None
    else:
        print("[?] Bilinmiyor — timeout veya belirsiz")
        return None


def verify(candidate: bytes, binary_path: str) -> bool:
    """Bulunan flag'i binary ile doğrula."""
    import subprocess
    result = subprocess.run(
        [binary_path],
        input=candidate,
        capture_output=True,
        timeout=5
    )
    return b'Correct' in result.stdout or b'flag' in result.stdout.lower()


if __name__ == '__main__':
    FLAG_LEN = 32          # ← binary'den öğren
    PREFIX = b'HTB{'       # ← bilinen prefix
    SUFFIX = b'}'          # ← bilinen suffix

    flag = solve_ctf(FLAG_LEN, PREFIX, SUFFIX)

    if flag:
        binary = sys.argv[1] if len(sys.argv) > 1 else './binary'
        if verify(flag, binary):
            print(f"[+] DOĞRULANDI: {flag.decode()}")
        else:
            print(f"[!] Doğrulanamadı ama flag adayı: {flag.decode()}")
            print("[!] Kısıtlamalar eksik olabilir, daha fazla validator koşulu ekle")
```

---

## Notlar ve Tuzaklar

- **BitVec boyutu önemli:** 8-bit overflow Z3'te otomatik; manuel mod almana gerek yok
- **Çok yavaşsa:** `Optimize()` yerine `Solver()` kullan; Z3 optimize çok ağır
- **Unsat gelirse:** Bir kısıtlama yanlış çevrilmiş; sıfıra indir, teker teker ekle
- **angr çok yavaş:** Büyük binary'lerde hook ekle: `project.hook(addr, angr.SIM_PROCEDURES[...])`
- **Signed vs Unsigned:** BitVec karşılaştırmalarında `UGT`, `ULT` (unsigned) ile `>`, `<` (signed) farkına dikkat
- bkz. elf-static-analysis SKILL.md (validator'ı bulmak için)
- bkz. anti-debug-obfuscation SKILL.md (validator çalışmıyorsa)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: ea5e6cb1d29a87b6
-->

