# CTF Reverse Engineering — YARA Rule Decoding

YARA rules define byte-level conditions. Solve by reversing each equation.

## Generic Solver

For conditions of the form `((byte[i] OP1 val1) OP2 val2) == result`:

```python
def solve_byte(result, op1, d1, op2, d2):
    # Step 1: Reverse outer operation (OP2)
    if op2 == '+':  tmp = result - d2
    elif op2 == '-': tmp = result + d2
    elif op2 == '^': tmp = result ^ d2
    
    # Step 2: Reverse inner operation (OP1)
    if op1 == '+':  val = tmp - d1
    elif op1 == '-': val = tmp + d1
    elif op1 == '^': val = tmp ^ d1
    
    return val
```

## Operation Table

| Equation | Solve for x |
|----------|-------------|
| `(x + a) ^ b == c` | `x = (c ^ b) - a` |
| `(x - a) ^ b == c` | `x = (c ^ b) + a` |
| `(x ^ a) + b == c` | `x = (c - b) ^ a` |
| `(x ^ a) - b == c` | `x = (c + b) ^ a` |
| `(x + a) - b == c` | `x = c + b - a` |
| `(x - a) + b == c` | `x = c - b + a` |
| `(x ^ a) ^ b == c` | `x = c ^ b ^ a` |

## Flag Assembly

After solving all bytes, convert to ASCII:

```python
flag = ''.join(chr(b) for b in solved_bytes)
```

## YARA Example

From `amele_isi.yar` — 21 equations with format `((uint8(i) ^ 0x12) + 0x05) == 0x46`:

Result: `SiberVatan{Rev_Rules}`

Verified: bytes at positions 0-20 produce a valid ASCII flag matching `SiberVatan{...}` format.
