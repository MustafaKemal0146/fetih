# Proof of Work (PoW) Solving for CTF Web Challenges

## Detection

Login/register pages with hidden inputs containing `pow*` name patterns:
```html
<input type="hidden" name="powNonce" id="pow-nonce">
<input type="hidden" name="powSolution" id="pow-solution">
<input type="hidden" name="powSig" id="pow-sig">
<input type="hidden" name="powExpires" id="pow-expires">
<input type="hidden" name="powDifficulty" id="pow-difficulty">
```

The page also has inline JavaScript that:
1. Fetches from `/api/pow/challenge`
2. Solves SHA-256 hash with difficulty prefix
3. Fills hidden inputs with solved values

## API Endpoint

```
GET /api/pow/challenge
→ {"nonce":"...", "sig":"...", "expires": 1778865409, "difficulty": 4}
```

## Solving (Python)

```python
import hashlib, requests

s = requests.Session()
BASE = "https://web-XXXX.hacker.zone"

# Step 1: Fetch challenge
r = s.get(f"{BASE}/api/pow/challenge")
ch = r.json()

# Step 2: Solve SHA-256
prefix = '0' * ch['difficulty']
n = 0
while True:
    h = hashlib.sha256(f"{ch['nonce']}{n}".encode()).hexdigest()
    if h.startswith(prefix):
        break
    n += 1

# Step 3: Submit login/register with PoW fields
r = s.post(f"{BASE}/login", data={
    "username": "user",
    "password": "pass",
    "powNonce": ch['nonce'],
    "powSolution": str(n),
    "powSig": ch['sig'],
    "powExpires": ch['expires'],
    "powDifficulty": str(ch['difficulty'])
}, allow_redirects=True)
```

## Performance

| Difficulty | Avg Hashes | Time (Python) |
|-----------|-----------|--------------|
| 4         | ~50K      | < 1s         |
| 5         | ~500K     | ~5s          |
| 6         | ~5M       | ~30-60s      |

## Pitfalls

- Both register AND login need separate PoW challenges
- Hidden input `value` attributes are EMPTY in HTML — JavaScript fills them after solving
- The `sig` field comes from the API response — NOT computed client-side
- Fresh challenge needed for each submit attempt
