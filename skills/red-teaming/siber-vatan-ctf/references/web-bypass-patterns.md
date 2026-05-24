# Web Challenge Bypass Patterns (Siber Vatan 2026)

Summary of web challenge bypass techniques discovered and verified during the 15 May 2026 CTF session.

## Origin Header Bypass (admin.php 302 → 200)
- admin.php returns 302 → login.php redirect
- Adding `Origin: https://web-xxxx.hacker.zone` header bypasses redirect
- Backend validates Origin matches site domain

## Debug Header OTP Bypass
- /otp.php exposes `x-debug-otp: MD5_HASH` in response headers
- Brute-force 6-digit OTP from MD5 hash (1M combos, <1s)
- Todo comment "remove debug before production" was the trail

## Minecraft SVG Captcha Brute-Force
- 64x64 SVG captcha with block-style numbers
- Brute-force 10x10 combos instead of pixel OCR
- Session-based captcha; use requests.Session() for cookie persistence

## NoSQL Mass Assignment (Express + MongoDB)
- PATCH /api/profile with `{"email":"x","isAdmin":true}` grants admin
- Key signs: x-powered-by: Express, JSON body API, mass assignment
- Backend likely uses `$set` or Object.assign without field whitelist

## PoW + Captcha Dual Auth (Bartzabel)
- /api/pow/challenge (SHA-256 prefix) for login
- /api/captcha/challenge (arithmetic) for register
- PoW: SHA-256(nonce + counter) until difficulty zeros prefix
- Register uses JSON body, login uses form-data
- Dashboard has SSRF via Webhook Tester

## API Discovery via JS
- /js/app.js contains fetch() endpoint definitions
- Common CTF endpoints: /api/login, /api/register, /api/profile, /api/articles, /api/captcha, /api/pow/challenge, /api/check-auth

## Game-Based CTF (Yavuzkraft)
- Progressive web game with session-state tracking
- Captcha → /overworld.php → resources → password → portal
- Password patterns hidden in HTML comments or input regex attributes

## Back-to-the-Future PE32 Reverse
- 50MB PE32 with embedded YouTube links as story hints
- Use Wine + wine32 for execution on Linux
- Extract full narrative from strings, correlate with film trivia