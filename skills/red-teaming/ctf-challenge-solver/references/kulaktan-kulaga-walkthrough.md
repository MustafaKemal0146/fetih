# Kulaktan Kulağa — Full Solution Walkthrough

## Challenge
**Title:** Kulaktan Kulağa (200 points)
**Quote:** "İki kişinin bildiği şey sır değildir"
**URL:** `https://web-a7f8c1a9.hacker.zone`

## Discovery Chain

### Step 1: Hidden base64 in index.html
Found in `<h3 style="display: none;">` element on main page:
```
aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj0tVW5yTXdodzNxdyZwcD15Z1VTZVdGMmRYb2daMlZzYVhsdklIbGhkblY2
```
→ Decodes to: `https://www.youtube.com/watch?v=-UnrMwhw3qw&pp=ygUSeWF2dXogZ2VsaXlvIHlhdnV6`
→ pp param decodes to: "yavuz geliyo yavuz" (Turkish Navy song)

### Step 2: Hidden base64 in login.php
Found in `<p style="display: none;">` on `/login.php`:
```
aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1OLWFLNkpueUZtayZwcD15Z1VTWTJGc2FXWnZjbTVwWVNCa2NtVmhiV2x1
```
→ Decodes to: `https://www.youtube.com/watch?v=N-aK6JnyFmk&pp=ygUSY2FsaWZvcm5pYSBkcmVhbWlu`
→ pp param decodes to: "california dreamin" (song)

### Step 3: Hidden base64 in style.css
Found in `/* CSS comment */`:
```
aHR0cHM6Ly95b3V0dWJlLmNvbS9zaG9ydHMvRzI5eFVaT182RW8/c2k9VkVuUF9NdGxnTXhWMTc2Zw==
```
→ Decodes to: `https://youtube.com/shorts/G29xUZO_6Eo` (Cat laughing meme)

### Step 4: robots.txt enumeration
Disallowed paths: `/admin.php`, `/login.php`

### Step 5: Admin panel discovery
`/admin.php` reveals HTML comments:
```html
<!-- TODO(Dev): Gizli tarif AES-256-CBC ile şifrelendi. 
     Anahtar: bir_kahvenin_40_yil_hatri_vardir
     IV: 1234567890123456 
     Geliştirici notu: Çözücü aracı panele entegre etmeyi unutma! -->
```

### Step 6: Origin header bypass
A simple POST to `/admin.php` with `action=get_secret_recipe` redirects to login page.
Adding `Origin: https://web-a7f8c1a9.hacker.zone` header bypasses the check:
```bash
curl -s -X POST "https://web-a7f8c1a9.hacker.zone/admin.php" \
  -H "Origin: https://web-a7f8c1a9.hacker.zone" \
  -d "action=get_secret_recipe"
```

### Step 7: Extract ciphertext
Response contains:
```html
<div class="flag-box">
Gizli Tarif: 3h3rFNSg1m41qGK41wez7HmtvPGYLcnKclC3CSqNxyU=
</div>
```
Plus another base64 YouTube link (4th one).

### Step 8: AES-256-CBC decryption
```python
from Crypto.Cipher import AES
import base64

key = b"bir_kahvenin_40_yil_hatri_vardir"
iv = b"1234567890123456"
enc = base64.b64decode("3h3rFNSg1m41qGK41wez7HmtvPGYLcnKclC3CSqNxyU=")
cipher = AES.new(key, AES.MODE_CBC, iv)
dec = cipher.decrypt(enc)
pad = dec[-1]
flag = dec[:-pad].decode('utf-8')
```

### Flag
```
SiberVatan{b4n4_kul4k_v3r1n!}
```

## Key Takeaways
1. Hidden elements (`display: none`) in HTML across multiple pages
2. CSS comments as hiding spots for base64
3. Origin header bypass for CSRF-style admin protection
4. AES-256-CBC with key/IV in HTML comments
5. YouTube links as puzzle pieces in a chain
