---
name: ctf-challenge-solver
description: "Capture The Flag challenge solving — reverse engineering, steganography, forensics, crypto, web exploitation, binary exploitation, OSINT. Pattern recipes for fast triage and direct exploitation."
tags: [ctf, capture-the-flag, reverse-engineering, steganography, forensics, crypto, web-exploitation, siber-güvenlik, osint]
triggers:
  - user shares a CTF challenge (zip, file, text, URL)
  - user asks to find a flag in a file or system
  - user mentions a CTF competition
  - user shares a hash/encoding to crack
  - user sends a challenge description with file attachments
adapted_for: fetih
---

# CTF Challenge Solver

A pattern catalog for Capture The Flag challenges — reverse engineering, steganography, forensics, cryptography, web exploitation, OSINT, and blockchain. Each section is a recipe: detect the pattern, apply the technique, recover the flag.

## Workflow

1. **Identify the category**: reverse, crypto, web, forensics, steganography, binary, OSINT, misc
2. **Triage with direct tools**: terminal, browser, Python for quick solves (encoding, simple crypto, web inspection)
3. **Pivot fast on failure**: after 3 wrong flag submissions on the same approach, switch attack vectors entirely — do not iterate small variations of a failing technique
4. **Validate before submitting**: confirm the flag format matches the challenge's stated pattern before submission

## Direct Tools (Tier 1)

### Flag Format Detection
Always check the flag format first. Common formats:
- `SiberVatan{...}`, `SIBERVATAN{...}`, `sibervatan{...}`
- `CTF{...}`, `flag{...}`, `FLAG{...}`

Grep is your first tool: `grep -roP '[A-Za-z]*[Vv]atan?{[^}]+}' ./`

### Reverse Engineering
For YARA rules or math-based reverse engineering problems:
1. Parse the condition as a series of byte-level equations: `((byte[i] OP1 val1) OP2 val2) == result`
2. Apply inverse operations in reverse order:
   - `(x + a) ^ b == c` → `x = (c ^ b) - a`
   - `(x - a) ^ b == c` → `x = (c ^ b) + a`
   - `(x ^ a) + b == c` → `x = (c - b) ^ a`
3. Convert result bytes to ASCII string

### Steganography
For PNG/images with hidden data:
- Check metadata: `identify -verbose image.png | grep -i flag`
- Check IEND trailer: `xxd image.png | tail`
- LSB steganography: extract LSB from each pixel's R/G/B/A channel
  ```python
  bits = [pixel[ch] & 1 for row in arr for pixel in row]
  bytes_arr = bytes(sum(bits[i+j] << (7-j) for j in range(8)) for i in range(0, len(bits)-7, 8))
  text = bytes_arr.decode('latin-1')
  ```
- Try all channels (0=R, 1=G, 2=B, 3=A)

### Hash Cracking
For brute-force style problems:
- Identify hash type by length (MD5=32 hex, SHA1=40, SHA256=64)
- Identify token format from problem description
- Use Python itertools: `itertools.product(string.ascii_lowercase, repeat=4)`
- 2-stage hashing: chain hash outputs as binary inputs to next stage
- Always use `hashlib.md5(token.encode()).digest()` (binary) not `.hexdigest()` for stage chaining

### Encoding Detection
Auto-detect common encodings:
- Base64: contains only `[A-Za-z0-9+/=]`, length is multiple of 4
- Hex: only `[0-9a-fA-F\s]`, decode with `bytes.fromhex()`
- Binary: only `[01\s]`
- ASCII codes: space-separated numbers `68 97 121`

### Web Challenges
- Browser tools: view-source, network tab, cookies, storage
- curl: check headers, API responses, follow redirects with `-L`
- For hidden parameters: try common ones (admin, flag, secret, token)

#### Multi-Stage Web Game (Yavuzkraft Pattern)

Minecraft-themed or quest-based web games with resource gathering and multiple stages:

**Game Flow:**
1. Login with captcha → overworld.php (redirect target)
2. Gather resources by POSTing to `/overworld.php` with action name
3. Each resource stage requires accumulating units (click buttons 5x each)
4. Special passwords required for advanced resources
5. Progress through: Overworld → Nether → End stages
6. `/flag.php` is the ultimate target, returns 302 if game incomplete

**CRITICAL: URL distinction**
- Login POST goes to `/` (index.php) with `oyuncu_adi` + `captcha_cevap`
- On success, 302 redirects to `/overworld.php` — this is where ALL game actions happen
- Game-action POSTs go to `/overworld.php`, NOT back to `/`
- Posting game actions to `/` triggers a re-login with captcha check, breaking the session flow
- Always use `allow_redirects=True` or follow the Location header

**Resource gathering:**
```python
for _ in range(5):
    s.post(OVERWORLD_URL, data={"odun_topla": "1"})  # NOT base URL!
```

**Stage tracking:**
- Inventory shows counts: Odun, Taş, Demir, Elmas, Obsidyen
- Each stage requires 5 of previous resource to unlock
- Buttons show `disabled` class until requirements met
- Game actions use simple button names in POST data: `odun_topla`, `tas_topla`, `demir_topla`, `elmas_topla`, `obsidyen_topla`, `nether_portal`

**Special password format discovery:**
- The HTML reveals the password pattern in `pattern` attribute: `^!Y[a-z]{6}r\d{3}$`
- Format: `!Y` + 6 lowercase letters + `r` + 3 digits
- Common Turkish 6-letter words work: "madeni" → `!Ymadenir000`
- Try Minecraft-themed words first: madeni (mineshaft), elmas, yavuz, kraft, gizli, sifre, oyuncu
- Brute-force approach: for each word, try 000-999 (1000 combos per word)

**Stage advancement:**
```python
s.post(OW, data={"elmas_sifre": "!Ymadenir000", "elmas_topla": "1"})  # 10 elmas
s.post(OW, data={"obsidyen_topla": "1"})                                # 10 obsidyen
s.post(OW, data={"nether_portal": "1"})                                 # to Nether
```

### SVG / Pixel-Art Captcha Recognition

CTF web challenges sometimes use SVG-based pixel art captchas (e.g., Minecraft-style block font). Each number is an inline `<img>` with a `data:image/svg+xml;base64,...` source.

**Recognition technique:**
1. Extract the base64 from each SVG image's `src` attribute
2. Decode and parse the SVG for `fill="#f0f0f0"` (white pixel) path elements
3. Each path `Mx y Hw Vh Z` defines a filled rectangle — these are the visible pixels
4. Build a 64×64 grid marking which cells are filled
5. Determine which quadrants are filled (top-left, top-right, bottom-left, bottom-right, middle)
6. Recognize the digit based on the quadrant pattern:
   - All 4 quadrants + middle = **8**
   - All 4 quadrants, no middle = **0**
   - Top-right + bottom-right + middle = **3**
   - Top-right + bottom-right only = **7**
   - Top-left + bottom-left + middle = **2** or **5** (check right side)
   - Top-left + top-right + bottom-left = **9**
7. Operator: `+` = 2 rectangles (horizontal + vertical), `-` or `×` = other
8. Compute the result and submit

**When recognition fails:** Brute-force all 100-200 arithmetic combinations (0-9, + - *). Each wrong answer returns an error message — session persists so you can retry quickly.

#### Hidden Elements & Base64 Extraction
HTML elements with `style="display: none;"` or `hidden` attributes often contain base64-encoded URLs or clues. CSS comments (`/* ... */`) are also common hiding spots. Always scan both — across ALL pages and ALL static assets (CSS, JS, PHP, HTML):
```bash
curl -s "URL" | grep -oP '[A-Za-z0-9+/]{30,}={0,2}'
# Then decode each:
echo "BASE64_STRING" | base64 -d 2>/dev/null
```
Key locations to scan: index page, login page, admin page, every JS file, every CSS file. Do NOT stop after one page — the chain may span multiple.

#### robots.txt Enumeration
Check `/robots.txt` first — `Disallow` directives reveal hidden endpoints (`/admin.php`, `/login.php`). Always check these discovered paths immediately.

#### JavaScript-Based Auth (AJAX/API Login)
Modern CTF web apps use JavaScript `fetch()` instead of HTML form submits, making direct form POST fail (404).
1. Check `/js/app.js` or inline `<script>` tags for `fetch()` calls — the actual endpoint is typically `/api/login`, `/api/register`, etc.
2. The content type is `application/json`, not `form-urlencoded`
3. Request body is `JSON.stringify({username, password, captcha})`
4. Captcha is fetched from `/api/captcha` (returns JSON `{"question":"123 + 456"}`)
5. Captcha answer changes on every request — use a session (requests.Session) to keep cookies
6. The `onclick` attribute on the submit button may show an alert but the backend endpoint still works when hit directly
7. After login, profile API (`/api/profile`) shows `isAdmin` field — target this for privilege escalation
8. Profile PATCH endpoint (`/api/profile` with PATCH, JSON `{"email":"..."}`) may be vulnerable to NoSQL injection
9. UNION-based SQLi may not work because the field is used in an UPDATE query, not SELECT — but the email value IS reflected back in the response, confirming injection point

#### NoSQL Injection (Express.js + MongoDB)
For challenges running Express.js (`x-powered-by: Express`) with MongoDB:

**Profile escalation pattern:** PATCH endpoints often use `$set: req.body` — extra fields pass through:
```json
{"email": "test@test.com", "isAdmin": true}
```
Other fields to try: `"role"`, `"is_admin"`, `"user_level"`, `"permissions"`, `"__v"`, `"admin"`.

**Login/Register NoSQL injection:**
- Login: `{"username": {"$gt": ""}, "password": {"$gt": ""}}` — but may be blocked by input validation
- Register with extra fields: `{"username":"x","password":"Test1234!","isAdmin":true}` — backend may silently ignore unknown fields

**MongoDB regex/$where rejection:** Backend email validation will reject object-type values for email. Stick to flat JSON field injection.

#### OTP/2FA Bypass Via Debug Header
When a 2FA verification page is encountered:
1. Check for a `/otp.php` endpoint (old deployment artifact — look for `<!-- TODO: remove debug before production -->` comments in HTML)
2. With an active session cookie (`PHPSESSID`), accessing `/otp.php` returns a **debug response header** `x-debug-otp` containing MD5 hash of the OTP
3. The hash is of a 6-digit numeric code (000000-999999) — crack with Python:
   ```python
   import hashlib
   target = "hash_from_x-debug-otp"
   for i in range(1000000):
       if hashlib.md5(f"{i:06d}".encode()).hexdigest() == target:
           print(f"OTP: {i:06d}")
   ```
4. Submit the cracked OTP to `verify_action.php` via POST: `otp=312888`
5. On success, access the dashboard/flag page

**Cookie is key:** `/otp.php` requires an active session. Without cookies, it 302-redirects to login. With cookies, it returns the debug header AND the 2FA page simultaneously.

#### Origin Header Bypass
Some admin panels check `Origin` header for CSRF-like protection. Send `Origin: https://same-domain.zone` with the POST to bypass:
```bash
curl -s -X POST "https://site/admin.php" \
  -H "Origin: https://site.hacker.zone" \
  -d "action=get_secret_recipe" \
  -L  # follow redirect
```
This works when the server uses `same-origin` checks but doesn't validate sessions. Without the header, the server 302-redirects to login. With it, the POST succeeds and returns the protected content.

#### Chained YouTube Puzzles (Kulaktan Kulağa Pattern)
Hidden base64 YouTube links can appear in MULTIPLE locations across the same site:
- `index.html` in `<h3 style="display:none">` elements
- Secondary pages (`login.php`) in `<p style="display:none">` elements
- Static assets (`style.css`) in `/* CSS comments */`

Workflow:
1. Extract all base64 strings from ALL pages and assets
2. Decode each to get YouTube URLs — the `pp` query parameter contains a base64 search term
3. Follow the chain of videos — the final video or a page in the chain reveals admin credentials or AES keys in HTML comments
4. POST to admin endpoint with `Origin: <same-domain>` header
5. Decrypt the returned base64 ciphertext with AES-256-CBC

#### AES-256-CBC Decryption (Known Key/IV)
```python
from Crypto.Cipher import AES
import base64

key = b"your_32_byte_key_here"  # 32 bytes for AES-256
iv = b"1234567890123456"        # 16 bytes IV
enc = base64.b64decode("base64_ciphertext")

cipher = AES.new(key, AES.MODE_CBC, iv)
dec = cipher.decrypt(enc)
pad = dec[-1]
flag = dec[:-pad].decode('utf-8')
```

#### Chained Multi-Page Hidden Base64 (YouTube Puzzle Pattern)
Multiple hidden base64 strings across DIFFERENT pages form a chain that must be traversed sequentially:
1. **Index page**: `<tag style="display:none">base64</tag>` → decodes to YouTube link
2. **Login page**: Same pattern → different YouTube link
3. **CSS file**: `/* CSS comment with base64 */` → third YouTube link (often a Shorts video)

The search terms in the YouTube URLs (`pp` parameter, base64-decoded) correlate to the page's context/login credentials. Eventually, one of the accessed pages' HTML comments reveals an AES encryption key and IV.

**Always scan ALL pages and ALL static assets in sequence** — don't stop at the first find.

#### CSS/JS Comment Scanning
Always check static assets (`style.css`, `app.js`, `main.js`) for:
- CSS comments `/* ... */` containing base64 data, URLs, or credentials
- JavaScript comments `// TODO`, `/* TODO */` with debug endpoints, keys, or credentials
- CSS class names that reveal hidden page structure (e.g., `.flag-box`, `.flag-container`)
- JavaScript variables or config objects that may contain API endpoints, tokens, or flags

#### Admin Panel Bypass (Disabled Login Form)
When login forms are disabled client-side (`onclick="alert('bakımda')"`):
- The backend POST endpoint may still work when hit directly via curl
- Try default credentials (admin/admin, yavuz/yavuz, kafe/kafe)
- SQL injection in POST body
- IP spoofing headers (`X-Forwarded-For: 127.0.0.1`)
- Referer header manipulation

### Blockchain / EVM Transaction Analysis

For challenges involving blockchain transactions (BNB Chain, Ethereum, etc.):

**When explorer sites are bot-blocked:**
- BSCScan, Etherscan, and similar use Cloudflare — try `browser_navigate` with user-agent spoofing
- Alternative explorers: `explorer.bnbchain.org`, `debank.com`, `oklink.com`
- Public RPC endpoints bypass browser entirely:
  ```bash
  curl -s -X POST "https://bsc-dataseed.binance.org/" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["0xADDRESS","latest"],"id":1}'
  ```
  Response `0x3` = 3 transactions (nonces 0, 1, 2)

**Transaction search via RPC (when tx hash unknown):**
- `eth_getBlockByNumber` with `"latest"` returns recent block's tx list
- Compare `from`/`to` addresses in each transaction to find target wallet
- For historical transactions (old nonces), you need the block number — impossible without an indexer (BSCScan)
- Fallback: search the address on search engines — someone may have shared a tx link

**Transaction input data decoding:**
- Hex in `tx.input` field — common hiding spot for flags/messages
- Strip `0x` prefix and decode as ASCII:
  ```python
  bytes.fromhex(tx_input[2:]).decode('utf-8', errors='replace')
  ```

### SSTV (Slow Scan Television) Signal Analysis

Radio-based CTF challenges involving `.wav` audio files that decode to images:

**Detection indicators:**
- WAV file ~7.5 seconds = Scottie 1 format (7.1s = Martin M1)
- Frequency analysis shows bands in 1200-2300 Hz range
- Sync pulse at 1200 Hz, black level at 1500 Hz, white at 2300 Hz
- The dominant frequency (e.g. 107 Hz) is ambient/DC noise — ignore it
- Check the spectrogram for the actual signal in the 800-2800 Hz band

**Challenges with decoding:**
- `qsstv` and `fldigi` are the standard tools but BOTH require a GUI/display
- `pysstv` (Python) is encode-only — no decode support
- No Python SSTV decoder is available on PyPI
- Custom implementation from scratch requires implementing the Scottie 1 protocol: 9ms sync + 1.5ms channel sync + 1.5ms porch + 138.24ms × 3 (G, B, R) per line, ~18 lines total

**Fallback strategies:**
- Upload WAV to an online SSTV decoder service (if browser works)
- Try calling `qsstv` with Xvfb (virtual framebuffer): `xvfb-run qsstv`
- The decoded image typically contains the flag as text overlaid on the image
- if all else fails and you know the format (Scottie 1), attempt a brute-force pixel decode: the frequency at each 138ms block maps to a grayscale value (1500Hz=black, 2300Hz=white)

For people/organization research:

**Try multiple search engines**: Google blocks automated queries (bot detection CAPTCHA). Fallback options:
- DuckDuckGo (lite/html modes also blocked by CAPTCHA)
- Bing (least aggressive bot detection)
- Yandex (heavy CAPTCHA)
- Direct API calls (GitHub API, etc.)

**Social media research:**
- LinkedIn: public profiles require login → check Google cache first, `site:linkedin.com/in "Name"`
- Twitter/X: login wall since 2024
- GitHub: API-first, works without login for public repos
- Instagram/Facebook: login required

**When browser search is blocked:**
- Use `curl` with proper `User-Agent` headers (`Mozilla/5.0 ...`)
- Try Google cache: `webcache.googleusercontent.com/search?q=cache:URL`
- Use programmatic APIs (GitHub API, etc.) which don't require browser
- Try whois/domain lookups for website research

**Flag location patterns:**
- LinkedIn profile headline/summary/about section
- GitHub README or profile bio
- Personal website/blog posts
- Social media posts with specific hashtags
- Numeric clues in profiles (follower count, profile IDs, post numbers)

**When all search fails:**
- Consider that the flag might be derived from the numeric/text clues themselves
- Common patterns: `SiberVatan{150}`, `SiberVatan{kisi_adi}`, `SiberVatan{sayisal_deger}`
- **Initials as ASCII sum**: A person's initials (e.g., "Kemal Kahramanoğlu" = KK) can sum to a numeric clue (K=75, K=75 → 150). The initials appended or the sum itself may be the flag or a clue.
- If a number (like "150") appears in the challenge but no direct match is found, check if it's the sum of ASCII values of related words/names

## Sub-Agent Escalation (Tier 2)

For medium-complexity challenges (multi-step crypto, coded reverse, chained pattern search) delegate to a sub-agent:

```bash
fetih -p "challenge description and files to analyze"
```

Print mode (`-p`) is non-interactive and exits when done. Useful when the parent agent wants to fan out file-system grep / search / pattern-matching work without polluting its own context.

### When to delegate
- Multi-step problems requiring tool chaining
- File-system heavy work (mass extract, search across many files)
- Encoding / simple-crypto puzzles that just need iteration
- When the parent agent's context is getting noisy and a clean sub-context will help

### Strategy
1. Analyze the challenge, identify the approach
2. Formulate the sub-agent query with explicit instructions and the file paths to analyze
3. Sub-agent executes the query and returns results
4. Parent validates the flag against the stated format before submission

## External LLM Escalation (Tier 3)

For hard problems where 3+ direct attempts failed (complex cryptography, binary exploitation / ROP chains, advanced reverse engineering), escalate to an external LLM (e.g. `claude -p "..."`). Treat the third failed flag submission as a hard pivot trigger: switch attack vector, switch tool chain, or hand off to a different model with a fresh context — do not keep banging on the same approach.

## File Management
- Use a dedicated working directory per competition: `~/Desktop/<competition>/`
- Extract all zips and organize by challenge
- Save found flags to `flag.txt` in the directory
- Clean up downloaded models/tools after the competition

## Common Pitfalls
- **Flag format changes mid-competition**: Check each challenge's stated format (`SIBERVATAN{}` vs `SiberVatan{}`)
- **Hash pipeline ordering**: 2-stage hashing — the output of stage 1 (binary `.digest()`) enters stage 2, not the hex string. Order matters!
- **Brute force range**: 45M combinations (26⁴ × 10²) = ~1M/s in Python → ~45 seconds for full scan
- **Stego file size**: Tiny PNGs (~4KB) are suspicious — check metadata, trailer, LSB
- **MFT/forensics**: File records in MFT give timestamps, filenames, and parent directory references
- **Supply chain attacks**: Python setup.py files can contain obfuscated payload — check `sys.call_tracing` or base64-encoded exec
- **Sample rate confusion**: When outputting TTS/audio, verify sample rate matches model native rate. Supertonic outputs at 44100Hz — writing to 24000Hz makes audio play 1.83x slower and deeper.
- **Multi-stage web games**: Some challenges require completing a multi-step game (resource gathering, passwords, portal navigation). The flag is NOT in the challenge description HTML but at a dedicated endpoint (`/flag.php`) only accessible after completing all game stages. Don't waste time trying to find the flag in challenge pages — progress the game.
- **Game session confusion**: Login POST goes to `index.php` (root), but the game page is at `/overworld.php` (a 302 redirect target). If you keep hitting the login page, check your redirect handling. Resource-gathering POSTs go to `/overworld.php`, NOT the root URL. If you POST a resource action to the root, the server treats it as a new login attempt and asks for captcha again.
- **SVG captcha brute-force**: 100 combinations max (10×10), each taking ~1s with session overhead. Total ~100s worst case. Optimize by guessing common operations first (`+`, `*`). Session cookies MUST persist across attempts.
- **Elmas şifresi pattern**: `!Y + 6 lowercase letters + r + 3 digits`. Common Turkish 6-letter words work: "madeni" (mineshaft) → `!Ymadenir000`. Try relevant Minecraft-themed words first.

#### Proof of Work (PoW) Authentication Bypass\n\nSome CTF web challenges (like \"Bartzabel\") require solving a Proof of Work puzzle before login/register.\n\n**Detection:** Check login page HTML for hidden inputs like `powNonce`, `powSolution`, `powSig`, `powExpires`, `powDifficulty`. These indicate JavaScript-generated PoW.\n\n**Workflow:**\n1. Fetch the PoW challenge from the API:\n   ```python\n   ch = s.get(f\"{BASE}/api/pow/challenge\").json()\n   # Returns: {nonce, sig, expires, difficulty}\n   ```\n2. Solve SHA-256 hash puzzle:\n   ```python\n   import hashlib\n   prefix = '0' * ch['difficulty']  # e.g., \"0000\" for difficulty=4\n   n = 0\n   while True:\n       h = hashlib.sha256(f\"{ch['nonce']}{n}\".encode()).hexdigest()\n       if h.startswith(prefix): break\n       n += 1\n   ```\n3. Submit with all PoW fields in the POST:\n   ```python\n   s.post(url, data={\n       \"username\": \"...\",\n       \"password\": \"...\",\n       \"powNonce\": ch['nonce'],\n       \"powSolution\": str(n),\n       \"powSig\": ch['sig'],\n       \"powExpires\": ch['expires'],\n       \"powDifficulty\": str(ch['difficulty'])\n   })\n   ```\n\n**PoW difficulty estimation:** difficulty=4 (~50K hashes, <1s), difficulty=5 (~500K, ~5s), difficulty=6 (~5M, ~30s).\n\n**Pitfalls:**\n- PoW is needed for BOTH register AND login — each requires its own fresh challenge\n- The PoW API endpoint is `/api/pow/challenge` — NOT on the HTML page\n- Hidden input `value` attributes are EMPTY in HTML; they're filled by JS after PoW solves\n- The `sig` field comes from the API, NOT computed client-side\n\n#### NPort 5110 / IoT Device Default Credentials\n\nWhen encountering an \"Akıllı Ev Sistemi\" (Smart Home System) or any page mentioning \"NPort 5110\" or \"Moxa\":\n1. Check the HTML meta tags — `NPort 5110 Web Console` is a dead giveaway\n2. Look for the `user:user` credential hint — often displayed in an alert or secondary text\n3. The captcha is a simple inline SVG math problem (e.g., `<text>5 + 6 = ?</text>`) — parse directly\n4. Default credentials: `user:user` with random arithmetic captcha\n5. After login, you get an IoT device management dashboard with:\n   - Device list (lamps, AC, TV, etc.)\n   - REST API: `POST /api/v1/device/status/control` with JSON body `{\"device_id\": X, \"status\": \"on/off\"}`\n   - Device add/delete via `?delete=X` parameter\n\n**Vulnerability exploitation:**\n- `?delete=X` parameter may be SQL injectable — test with `?delete=1 AND 1=1` vs `?delete=1 AND 1=2` (boolean-based blind SQLi)\n- API endpoint expects proper JSON — passing raw text returns \"Cihaz bulunamadı\"\n- SQL injection may return 500 errors due to syntax — adjust comment syntax (`-- `, `#`, `/*`)\n\n### Reference Walkthroughs (in skill directory)
- `references/yavuzkraft-walkthrough.md` — Minecraft-themed web game with SVG captcha, resource gathering, multi-stage portal navigation
- `references/kulaktan-kulaga-walkthrough.md` — Chained YouTube puzzle with hidden base64, AES-256-CBC decryption, Origin header bypass
- `references/yara-reverse-engineering.md` — YARA rule reverse engineering: byte-by-byte math unrolling
- `references/ghostknock-apk-analysis.md` — Android APK reverse with native `.so` library JNI calls
- `references/trust-the-code-walkthrough.md` — OTP/2FA bypass via debug endpoint and MD5 hash cracking
- `references/sewer-pollutants-walkthrough.md` — NoSQL injection in Express.js + MongoDB, mass assignment for privilege escalation
- `references/0xsimsar-blockchain-analysis.md` — BNB Chain transaction analysis via public RPC
- `references/hash-cracking-pipeline.md` — 2-stage hashing pipeline brute-force
- `references/ying-yang-pcap-analysis.md` — PCAP HTTP body extraction, trap message chains, base64 decoding

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 9859e8b3e4235ecc
-->

