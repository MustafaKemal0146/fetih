# Trust The Code Walkthrough (solved: OTP Debug Header Leak + Origin Bypass)

**Challenge**: Trust The Code (200 pts) — web, OTP/2FA bypass via debug artifact  
**Flag**: `SiberVatan{Br0k3n_2F4_0TP_L0g1c}`

## Steps

1. **Login page** with admin credentials `admin:admin` embedded in HTML comment: `<!--Admin Credentials > admin:admin-->`

2. **First login**: POST `login_action.php` with `username=admin&password=admin` sets session cookie (`PHPSESSID`) and redirects to `verify_action.php` (2FA page — asks for 6-digit OTP)

3. **Debug endpoint discovery**: `/otp.php` found by brute-force of common paths. Without session cookie → redirects to `index.php`. **With** valid session cookie (from step 2) → returns 200 with debug header:
   ```
   x-debug-otp: 2271632958e3e89d01a458efe5e003bd
   ```
   This is MD5 of current OTP (6 digits, 000000-999999).

4. **Crack OTP hash**:
   ```python
   import hashlib
   target = "2271632958e3e89d01a458efe5e003bd"
   for i in range(1000000):
       if hashlib.md5(f"{i:06d}".encode()).hexdigest() == target:
           print(f"OTP: {i:06d}")  # → 312888
   ```

5. **Submit OTP**: POST `verify_action.php` with `otp=312888` reveals dashboard with flag.

6. **Alternative: Origin header bypass**: The 2FA verification page can also be bypassed by submitting POST to `admin.php` with `Origin` header matching the site domain, without any authentication.

## Key Techniques
- **Debug artifact discovery**: `/otp.php` left from development (TODO comment: "remove debug before production")
- **Debug header leak**: `x-debug-otp` header in response contains MD5 of OTP
- **Session-dependent endpoints**: `/otp.php` only works with active `PHPSESSID` cookie
- **Hidden HTML credentials**: `admin:admin` in HTML comments
- **CSS structure hints**: `.flag-box`, `.flag-container` classes in `style.css` reveal dashboard structure
