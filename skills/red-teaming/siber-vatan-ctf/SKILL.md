---
name: siber-vatan-ctf
description: Siber Vatan CTF playbook — flag formats, web/reverse/forensics/blockchain/OSINT/stego/crypto recipes, and pivot heuristics tailored to the Turkish CTF circuit.
tags: [ctf, siber-vatan, capture-the-flag, web-exploitation, reverse-engineering, forensics, crypto, blockchain, osint, turkce]
triggers:
  - "Siber Vatan"
  - "siber vatan"
  - "sibervatan"
  - "SiberVatan"
  - "SIBERVATAN"
  - "SiberVatan{"
  - "SIBERVATAN{"
  - "sibervatan{"
  - "yavuzkraft"
  - "Siber Vatan yarışması"
  - "Siber Vatan CTF"
  - "TR-circuit CTF"
  - "Türk CTF yarışması"
---

# Siber Vatan CTF Playbook

Playbook for the Turkish "Siber Vatan" CTF competition (and similar TR-circuit events). Companion to the more general `ctf-challenge-solver` skill — same patterns, but with Siber-Vatan-specific flag formats, challenge naming conventions, and walkthroughs.

## Flag Formats
- `SiberVatan{...}` (mixed case, capital `S`/`V`)
- `SIBERVATAN{...}` (all caps)
- `sibervatan{...}` (lower case — rare)

Detect with: `grep -roP '[Ss][Ii][Bb][Ee][Rr][Vv][Aa][Tt][Aa][Nn]\{[^}]+\}' ./`

Challenges are usually delivered as `.zip` bundles. Extract to a dedicated working directory per challenge before touching anything.

## Solver Workflow

1. **Triage**: read the challenge text, classify (web / reverse / forensics / crypto / stego / blockchain / OSINT)
2. **Direct attempt**: terminal + browser + Python — most challenges solve here
3. **Sub-agent delegate**: `fetih -p "..."` for multi-step file-system / pattern-search work
4. **External LLM escalation**: hand off to an external model with fresh context after 3 failed flag submissions on the same approach
5. **Pivot on failure**: 3rd wrong flag = hard pivot trigger. Switch tool chain, switch vulnerability class, switch attack vector. Do NOT iterate small variations of a broken approach.

## Web Challenge Techniques

1. **Source inspection** — HTML comments, CSS comments, hidden inputs, base64 in `display:none` elements, JS comments, hidden HTML files
2. **Endpoint enumeration** — `robots.txt`, common paths (`/admin`, `/api`, `/debug`), API discovery via JS `fetch()` calls
3. **Header-based bypass** — `Origin`, `X-Forwarded-For`, `Referer` manipulation. Admin panels that 302-redirect to login often unblock when `Origin` matches the site's domain.
4. **Login bypass**
   - SQLi: classic `' OR 1=1--`, time-based blind, UNION-based
   - NoSQLi (MongoDB): `{"username":{"$gt":""},"password":{"$gt":""}}`, mass-assignment via `isAdmin:true`
   - Default creds: `user:user` (NPort 5110), `admin:admin`, themed `yavuz:yavuz`, `kafe:kafe`
   - Mass assignment / prototype pollution: extra JSON fields like `"isAdmin": true`, `"role": "admin"`
5. **Captcha**
   - Brute-force arithmetic (10 digits × 10 digits × 3 ops = ~100-300 combinations)
   - SVG pixel-art OCR — decode `<path>` fill regions to recognize block digits
   - API-based — `/api/captcha/challenge` returns JSON with the question
6. **2FA / OTP**
   - Debug headers — `x-debug-otp` may contain MD5 of the OTP code (crack with `hashlib`)
   - Forgotten endpoints — `/otp.php` left from deployment, returns debug info with active session cookie
   - Hash cracking — 6-digit numeric OTP MD5 brute-force is sub-second
7. **Proof of Work**
   - Fetch challenge from `/api/pow/challenge` → returns `{nonce, sig, expires, difficulty}`
   - Solve SHA-256 hash starting with `difficulty` zeros (difficulty 4 ≈ 50K hashes / <1s; 5 ≈ 500K / ~5s; 6 ≈ 5M / ~30s)
   - Submit nonce + solution + sig + expires + difficulty with the login/register payload
   - Both register AND login may require independent PoW challenges
8. **File upload** — extension bypass (`shell.php.jpg`), content-type manipulation, magic-byte spoofing, RCE via web shell
9. **SSTI / SSRF** — template injection (`{{7*7}}`), webhook URL testers for internal-network probing
10. **JS-only auth flows** — modern apps use `fetch()` to `/api/*` JSON endpoints, not HTML form submits. Inspect `app.js` for the real endpoint, use `requests.Session()` to keep cookies, send JSON payloads.
11. **Profile / privilege escalation** — PATCH endpoints with mass-assignment (`{"email":"x","isAdmin":true}`)
12. **Game-based CTF (Yavuzkraft-style)** — multi-stage progressive games with captcha entry, resource gathering, password unlocks, portal progression. See `references/web-bypass-patterns.md`.

### Web Game CTF Pattern (Yavuzkraft Model)

Progressive web games with token economies and multi-stage progression:

1. **Entry** — SVG captcha (often pixel-art / Minecraft-style block fonts). Brute-force or decode SVG paths.
2. **Resource loop** — POST actions (`odun_topla`, `tas_topla`, `demir_topla`) increment server-side counters
3. **Password unlock** — HTML `pattern` attribute reveals format (`^!Y[a-z]{6}r\d{3}$`). Brute-force with a themed word list × digit range.
4. **Portal progression** — game POSTs go to `/overworld.php` (the redirect target), NOT the root. Captcha is only needed at initial entry.
5. **Flag endpoint** — direct GET to `/flag.php` after completing all stages. 302 = prerequisites not met.
6. **Key insight** — each stage teaches a separate exploitation pattern; the security lesson IS the challenge.

## Reverse Engineering

- **PE32 + story-driven passwords** — old-school challenges embed the full plot in `strings`. Read the narrative end-to-end and extract password clues (dates, times, numeric values mentioned in the story, e.g. `1955`, `1.21`, `88`).
- **Embedded YouTube links** — sometimes a binary has YouTube URLs as `strings`. Use `oembed` API (`https://www.youtube.com/oembed?url=...`) to fetch titles without browser.
- **Wine for 32-bit PE on Linux** — `wine32` (i386 architecture) required. `dpkg --add-architecture i386 && apt install wine32:i386`.
- **YARA-based math reverse** — see `ctf-challenge-solver/references/yara-reverse-engineering.md` for byte-by-byte equation unrolling
- **Android APK** — decompile with `apktool` / `jadx`, inspect `.so` JNI calls with Ghidra

## Forensics / Audio

- **SSTV (Slow Scan Television)** — radio image protocols encoded into `.wav` files
  - Scottie 1: ~7.5s, Martin M1: ~7.1s — detect by file length
  - Tools: `qsstv` and `fldigi` (both GUI; use `xvfb-run` headless), or implement decoder
  - See `scripts/sstv_decoder.py` for a custom Python implementation
- **PCAP analysis** — Scapy for body extraction, `grep -P` for flag patterns, `foremost` / `binwalk` for embedded files. Watch for **trap messages** — multiple fake flags planted in HTTP bodies to mislead; the real flag may be in TLS streams, C2 server messages, or non-HTTP protocols.
- **WAV steganography** — LSB extraction, spectrogram analysis (Audacity / sox), frequency-domain data hiding

## Crypto

- **AES-256-CBC** (known key + IV) — `pycryptodome`:
  ```python
  from Crypto.Cipher import AES
  cipher = AES.new(key, AES.MODE_CBC, iv)
  pt = cipher.decrypt(base64.b64decode(ct))
  flag = pt[:-pt[-1]].decode()  # strip PKCS7 padding
  ```
- **Base64 chains** — decode iteratively until plain text emerges (often 2-5 layers)
- **Hash cracking** — MD5 rainbow tables, known-plaintext brute-force for short inputs
- **Custom XOR / Caesar / substitution** — frequency analysis, known-plaintext attacks

## Blockchain

- **BSC / Ethereum transaction analysis**
  - BSCScan / Etherscan blocked by Cloudflare → use public RPC endpoints directly:
    ```bash
    curl -X POST https://bsc-dataseed.binance.org/ \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"eth_getTransactionCount",
            "params":["0xADDRESS","latest"],"id":1}'
    ```
  - `tx.input` hex often contains encoded flag/message data — strip `0x`, decode as UTF-8
- **Token contracts** — read methods (`name`, `symbol`, `totalSupply`), event logs (`Transfer`, custom events)
- **Wallet history** — `eth_getBlockByNumber` for recent blocks, address comparison for target wallet

## OSINT

- **People research** — LinkedIn (Google cache: `site:linkedin.com/in "Name"`), GitHub (API works without login), Twitter (login wall since 2024)
- **Search engines** — DuckDuckGo > Bing > Yandex when Google blocks automated queries
- **Numeric flag derivation** — when no direct match: `SiberVatan{<initial-ascii-sum>}` is a common pattern. For "Kemal Kahramanoğlu" (KK), sum = 75 + 75 = 150 → flag candidate `SiberVatan{150}`.

## Pivot Heuristics

When stuck on a challenge, switch dimensions in this order:

1. **Different tool** — `curl` → browser → sub-agent (`fetih -p`) → external LLM escalation
2. **Different endpoint / path** — `gobuster`, `ffuf`, `dirb` against common paths
3. **Different vulnerability class** — SQLi → NoSQLi → XSS → LFI → RCE → SSTI → SSRF
4. **Different analysis angle** — static → dynamic → side-channel
5. **Hard pivot trigger** — after 3 wrong flag submissions on the same approach, abandon the approach completely. Switch tool chain, switch attack vector. Iterating minor variations of a broken approach burns time without converging.

## Reference Material

- `references/web-bypass-patterns.md` — Full catalog of web exploitation patterns observed in Siber-Vatan-style competitions
- `references/webhook-ssrf-testing.md` — SSRF testing via webhook/URL-tester functionality
- `scripts/sstv_decoder.py` — Custom Scottie 1 SSTV decoder for headless environments
