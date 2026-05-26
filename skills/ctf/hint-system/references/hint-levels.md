# Hint Level Reference — Detaylı İpucu Pattern Kataloğu

Bu dosya, her CTF kategorisi için 3 seviyeli ipucu pattern'lerini içerir.

---

## Web Exploitation

### Level 1 Patterns
- "Sayfa kaynağını görüntüle (Ctrl+U veya view-source:). Gizli HTML yorumları var mı?"
- "JavaScript dosyalarını incele. fetch() çağrıları hangi endpoint'lere gidiyor?"
- "Bu bir web challenge'ı. Input validation, authentication bypass, veya injection odaklı olabilir."
- "HTTP response header'larını kontrol et. Cookie'lerde özel bir şey var mı?"
- "robots.txt dosyasını kontrol et — gizli endpoint'ler olabilir."

### Level 2 Patterns
- "Login formunda SQL injection dene: username alanına `'` karakteri koy, hata dönüyor mu?"
- "/api/ endpoint'ini keşfet. JSON dönen bir admin endpoint'i olabilir."
- "Cookie'deki JWT token'ını decode et (jwt.io). Header'da `alg: none` yapmayı dene."
- "File upload varsa, extension bypass dene: shell.php.jpg, shell.php%00.jpg"
- "SSRF için URL parametrelerini kontrol et. İç ağa istek yapılabiliyor mu?"
- "SSTI testi: `{{7*7}}` yaz, 49 dönüyor mu?"

### Level 3 Patterns
- "`' OR 1=1--` ile login bypass. Admin paneline yönlendirileceksin."
- "JWT'yi şu şekilde forge'la: Header: `{'alg':'none'}`, Payload: `{'username':'admin'}`"
- "File upload'da Content-Type: image/png ama içerik PHP web shell olsun."
- "SSRF ile `http://localhost:8080/admin` endpoint'ine istek at."

---

## Cryptography

### Level 1 Patterns
- "Bu şifreli bir metin. Önce encoding katmanlarını kontrol et — base64, hex, ROT13?"
- "Ciphertext uzunluğuna bak. Blok cipher (AES/DES) mı, stream cipher mı?"
- "Anahtar tekrar kullanımı var mı? Aynı key'le şifrelenmiş birden fazla mesaj var mı?"

### Level 2 Patterns
- "Base64 decode et, sonra XOR dene. Key uzunluğunu bulmak için Hamming distance kullan."
- "RSA'da n, e, c verilmiş. n'i factorize etmeyi dene (factordb.com)."
- "AES-CBC'de IV sabit mi? Padding oracle attack'ı mümkün olabilir."
- "Hash formatına bak: $2a$ bcrypt, $6$ SHA-512. Rockyou wordlist ile dene."

### Level 3 Patterns
- "Python ile çözüm: `Crypto.Cipher.AES.new(key, AES.MODE_CBC, iv)` kullanarak decrypt et."
- "RSA için: factordb'dan p ve q'yu al, phi = (p-1)*(q-1), d = inverse(e, phi), m = pow(c, d, n)"
- "Hashcat komutu: `hashcat -m 3200 hash.txt rockyou.txt`"

---

## Reverse Engineering

### Level 1 Patterns
- "Binary dosyasını `file` ve `strings` komutlarıyla analiz et."
- "32-bit mi 64-bit mi? Hangi mimari için derlenmiş?"
- "strings çıktısında 'flag', 'password', 'correct', 'wrong' gibi kelimeler ara."

### Level 2 Patterns
- "Ghidra'da main() fonksiyonunu bul. Karşılaştırma (CMP) instruction'larına bak."
- "Sembolik execution dene — angr ile flag'i otomatik bulabilirsin."
- "Anti-debugging var mı? ptrace, isDebuggerPresent çağrılarını kontrol et."
- "APK ise: apktool ile decompile et, smali kodunda flag kontrolü ara."

### Level 3 Patterns
- "main+0x1234 adresindeki JNE instruction'ını NOP'la patch'le."
- "angr ile: `proj = angr.Project('./binary'); state = proj.factory.entry_state(); simgr = proj.factory.simgr(state); simgr.explore(find=0xADDR_SUCCESS)`"
- "APK'da: libnative.so'yu Ghidra'da aç, JNI fonksiyonunda string karşılaştırması var."

---

## Forensics

### Level 1 Patterns
- "Dosya tipini doğrula (`file` komutu). Uzantı ile gerçek tip uyuşuyor mu?"
- "Metadata'ya bak: exiftool ile EXIF, ID3 tag'leri, gizli veri ara."
- "strings komutuyla dosyada düz metin ara. 'flag', 'password' geçiyor mu?"

### Level 2 Patterns
- "binwalk ile gömülü dosyaları çıkar. İçinde zip, resim, veya başka dosya var mı?"
- "PCAP ise: Wireshark'ta TCP stream'lerini takip et. HTTP objelerini export et."
- "Memory dump ise: volatility ile process list, network connections, cmdline ara."
- "Disk image ise: Autopsy ile silinmiş dosyaları kurtar."

### Level 3 Patterns
- "PCAP'te HTTP stream 5'te base64 encoded flag var. Export et ve decode et."
- "Memory dump'ta PID 2184'ün memory'sini dump et: `vol3 -f mem.dmp windows.memmap --pid 2184 --dump`"
- "Silinmiş dosyayı kurtar: sleuthkit ile inode'u bul ve icat ile extract et."

---

## Steganography

### Level 1 Patterns
- "Bu bir steganografi challenge'ı. Dosyada gizli veri var."
- "Görsel ise: LSB (Least Significant Bit), metadata, renk kanallarına bak."
- "Ses dosyası ise: spektrogram, LSB, faz kodlaması olabilir."

### Level 2 Patterns
- "zsteg ile PNG'deki tüm LSB kombinasyonlarını tara: `zsteg -a image.png`"
- "steghide ile şifre dene: `steghide extract -sf image.jpg` (boş şifre veya 'password')"
- "Ses dosyasında: Sonic Visualiser veya Audacity ile spektrogram görüntüle."
- "exiftool ile tüm metadata'yı gör: `exiftool -a -u -g1 file.jpg`"

### Level 3 Patterns
- "zsteg çıktısında b1,rgb,lsb,xy kanalında flag var: `zsteg -E b1,rgb,lsb,xy image.png`"
- "SSTV sinyali var! qsstv ile decode et veya scripts/sstv_decoder.py kullan."
- "binwalk -e ile içinden zip çıktı. Zip'in şifresini kirala."

---

## Binary Exploitation (Pwn)

### Level 1 Patterns
- "Binary'de buffer overflow olabilir. ASLR, DEP, Stack Canary kontrollerini yap."
- "checksec ile güvenlik önlemlerini gör: `checksec --file=binary`"
- "Hangi fonksiyonlar çağrılıyor? system(), execve(), win() fonksiyonu var mı?"

### Level 2 Patterns
- "GDB ile buffer boyutunu bul. Pattern create ile offset hesapla."
- "ROP chain oluştur. Gadget'ları ROPgadget ile bul."
- "Format string varsa: %x,%x ile stack leak, %n ile arbitrary write."

### Level 3 Patterns
- "pwntools template: offset=40, pop_rdi=0x400123, system=0x400456, /bin/sh=0x600789"
- "Exploit: `payload = b'A'*40 + p64(pop_rdi) + p64(binsh) + p64(system)`"
- "Return-to-libc: leak libc adresi, offset hesapla, one_gadget kullan."
