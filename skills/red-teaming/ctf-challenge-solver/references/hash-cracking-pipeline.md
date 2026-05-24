# Hash Cracking — NovaPay Pipeline Example

## Problem
Token format: `[a-z]{4}[0-9]{2}` (4 lowercase letters + 2 digits = 45,697,600 combinations)
Token hash (2-stage pipeline): 
```
f870a8ffe5f8fd64b0b1767563b6620b
ffdf64f3f121cc8f77e6ea5515390a30
```

Pipeline mode: "binary" — first hash output (raw bytes) is input to second hash.

## Solution

```python
import hashlib, string, itertools

target_1 = bytes.fromhex('f870a8ffe5f8fd64b0b1767563b6620b')  # Stage 1 target
target_2 = bytes.fromhex('ffdf64f3f121cc8f77e6ea5515390a30')  # Stage 2 target

for letters in itertools.product(string.ascii_lowercase, repeat=4):
    prefix = ''.join(letters)
    for d1, d2 in itertools.product(range(10), repeat=2):
        token = f"{prefix}{d1}{d2}"
        
        # Stage 1: MD5(token) -> 16 bytes binary
        h1 = hashlib.md5(token.encode()).digest()
        if h1 != target_1:
            continue
        
        # Stage 2: MD5(stage1_binary) -> 16 bytes
        h2 = hashlib.md5(h1).hexdigest()
        if h2 == target_2.hex():
            print(f"TOKEN: {token}")
            break
```

## Key Details
- **Binary mode**: `.digest()` NOT `.hexdigest()` for the chain
- **MD5**: Both stages confirmed MD5 (32 hex chars = 128 bits = 16 bytes)
- **Performance**: ~1.6M checks/second on single core → full space in ~28s
- **Whitespace/typos**: Double-check hex strings for hidden bytes, extra spaces

## Other Common Pipeline Variations
1. `MD5(token) → MD5(result_hex)` — hash of the hex string
2. `SHA256(token)` — single hash, split into two 32-char parts
3. `token + static_salt → MD5 → MD5`
4. `MD5(MD5(token))` — double hash (rare but possible)
