# GhostKnock APK Analysis (600 pts)

## Challenge
"Ghost Knock bir erişim aracısıdır. İçeride bir kanal var ama kapı kilitli. Statik analiz seni kapıya kadar götürür, içeri girmek için başka bir yol gerekir."

## Given
- `GhostKnock.zip` containing `GhostKnock.apk` (6.3MB)
- Package: `com.sibervatan.ghostknock`

## Analysis Steps

### 1. Initial Recon
```bash
unzip -l GhostKnock.zip
unzip -o GhostKnock.zip
file GhostKnock.apk
# Android package (APK), with APK Signing Block

# Extract APK contents
mkdir ghost_apk && cd ghost_apk
unzip -o ../GhostKnock.apk
```

### 2. Manifest & Layout Inspection
```bash
strings AndroidManifest.xml | grep -i "activity\|permission\|main"
```

Key findings:
- `activity_main.xml` — main activity
- `activity_secret.xml` — **secret activity!** Contains strings: "GHOST KNOCK", "[CHANNEL]", "secret channel / authenticated"
- `res/layout/activity_secret.xml` shows a LinearLayout with TextView displaying channel status

### 3. Code Analysis (DEX)
```bash
strings classes.dex | grep -i "secret\|ghost\|knock\|channel\|siber"
```

Classes discovered:
- `com.sibervatan.ghostknock.MainActivity`
- `com.sibervatan.ghostknock.SecretActivity`
- `com.sibervatan.ghostknock.SecretActivity$Companion`
- `com.sibervatan.ghostknock.TokenEngine`
- `com.sibervatan.ghostknock.R$id`, `R$layout`, `R$string`

### 4. Native Library Analysis
```bash
ls -la lib/arm64-v8a/libghostknock.so  
# 250KB ELF binary

strings lib/arm64-v8a/libghostknock.so | grep -i "siber\|flag"
# → Only finds: Java_com_sibervatan_ghostknock_SecretActivity_ghost
```

The native function `Java_com_sibervatan_ghostknock_SecretActivity_ghost`:
- JNI function called by `com.sibervatan.ghostknock.SecretActivity.ghost()`
- Uses `_ZN7_JNIEnv12NewStringUTFEPKc` (NewStringUTF) — returns a string
- The string/flag is **constructed at runtime**, not stored in plaintext
- Compiled with clang 19.0.0 (Android NDK), with PGO/LTO/BOLT optimizations

### 5. XOR Brute-Force Attempt
```python
with open("lib/arm64-v8a/libghostknock.so", "rb") as f:
    data = f.read()
for key in range(1, 256):
    decoded = bytes(b ^ key for b in data)
    if b'Siber' in decoded:
        print(f"XOR-0x{key:02x}: found!")
```
No XOR-encoded flag found in static analysis.

## Conclusion
"Statik analiz seni kapıya kadar götürür, içeri girmek için başka bir yol gerekir."
- Static analysis reveals the structure (SecretActivity, TokenEngine, native ghost())
- Flag is generated at runtime in native code
- Solvable via: Android emulator, Frida hooking, Ghidra/IDA reverse engineering

## Key Files
```
classes.dex                — 8.9MB DEX (app code)
lib/arm64-v8a/libghostknock.so — 250KB native lib
res/layout/activity_secret.xml  — hidden activity layout
```
