---
name: pcap-network-analysis
description: "PCAP/network capture analizi — Wireshark, tshark, Python scapy/pyshark ile SMTP/FTP/DNS/custom protokol çözme, gizli veri çıkarma."
tags: [ctf, forensics, pcap, wireshark, tshark, network, smtp, ftp, dns, custom-protocol, scapy, pyshark, tcp-stream, base64, exfiltration]
triggers:
  - ".pcap dosyası"
  - ".pcapng"
  - "network capture"
  - "wireshark"
  - "SMTP"
  - "FTP cleartext"
  - "custom protocol"
  - "TCP stream"
  - "base64 in email"
  - "ağ trafiği"
  - "paket analizi"
  - "DNS exfiltration"
  - "HTTP traffic"
  - "network forensics"
difficulty: medium
category: forensics
solved_challenges:
  - "HTB Cyber Apocalypse 2024 - Phreaky (SMTP, 15 ZIP parça birleştirme → PDF)"
  - "corCTF 2024 - the-conspiracy (custom Python protokol, per-message key decrypt)"
adapted_for: fetih
---

# PCAP / Network Forensics

## Ne Zaman Kullan

Aşağıdaki işaretlerden herhangi birini görürsen bu skill'i tetikle:

- `.pcap`, `.pcapng`, `.cap` uzantılı dosya var
- Challenge'da "network capture", "traffic analysis", "intercepted communication" geçiyor
- HTTP/SMTP/FTP üzerinden veri sızdırma (exfiltration) şüphesi var
- DNS sorgularında garip subdomain'ler görünüyor (DNS exfiltration)
- Tanımlanamayan/custom protokol trafiği var

---

## Araç Seti

```bash
# Wireshark — GUI analiz
sudo apt install wireshark

# tshark — CLI (script dostu, büyük pcap için hızlı)
sudo apt install tshark

# Python kütüphaneleri
pip install scapy pyshark

# NetworkMiner (Windows — dosya otomatik çıkarma için güçlü)
# Bağlantı: https://www.netresec.com/?page=NetworkMiner
```

---

## Wireshark Hızlı Filtreler

```
# HTTP GET istekleri
http.request.method == "GET"

# SMTP trafiği
smtp

# SMTP veri (base64 attachment'lar burada)
smtp.req.command == "DATA"

# FTP — komut kanalı
ftp

# FTP — veri kanalı (asıl dosya transferi)
ftp-data

# DNS sorguları
dns.qry.name contains "flag"
dns.qry.name contains "base64karakter"

# Belirli IP'den/IP'ye
ip.src == 192.168.1.100
ip.dst == 10.0.0.1

# TCP stream izole et (Wireshark → sağ tık → Follow → TCP Stream)
tcp.stream eq 0

# Belirli port
tcp.port == 25    # SMTP
tcp.port == 21    # FTP kontrol
tcp.port == 20    # FTP veri

# Paket boyutu filtrele (büyük paket = muhtemelen dosya transferi)
frame.len > 1000

# Hex içerik arama (payload'da "PK" = ZIP magic bytes)
frame contains "PK"
frame contains "flag"
```

### tshark ile Hızlı Çıkarma

```bash
# SMTP mail içeriğini çıkar
tshark -r capture.pcap -Y "smtp" -T fields -e smtp.req.command -e smtp.req.parameter

# FTP komutlarını listele
tshark -r capture.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg

# DNS sorgularını çıkar (exfiltration tespiti)
tshark -r capture.pcap -Y "dns.qry.type == 1" -T fields -e dns.qry.name

# HTTP GET URL'leri
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Tüm TCP stream'leri dosyaya yaz (stream 0, 1, 2...)
tshark -r capture.pcap -q -z follow,tcp,raw,0
```

---

## Gerçek Örnek: HTB Cyber Apocalypse 2024 — Phreaky

### Senaryo
`phreaky.pcap` verilmiş. SMTP trafiğinde 15 adet ZIP parçası base64 ile email attachment olarak gönderilmiş. Parçalar birleştirince şifreli ZIP, şifresi de email body'de gizlenmiş.

### Çözüm

```python
#!/usr/bin/env python3
"""
Phreaky çözücü — SMTP stream'den ZIP parçaları topla, birleştir, şifreyle aç.
Çalıştır: python3 solve_phreaky.py phreaky.pcap
"""
import pyshark
import base64
import zipfile
import io
import os
import re
import sys

PCAP_FILE = sys.argv[1] if len(sys.argv) > 1 else "phreaky.pcap"

# pyshark ile SMTP paketlerini oku
cap = pyshark.FileCapture(PCAP_FILE, display_filter="smtp")

zip_parts = {}   # {parça_no: bytes}
passwords = {}   # {parça_no: str}
current_stream = None
collecting_data = False
data_buffer = []

print("[*] SMTP stream'leri taranıyor...")

for pkt in cap:
    try:
        # Her SMTP DATA komutunu yakala
        if hasattr(pkt, 'smtp'):
            smtp_data = str(pkt.smtp)
            
            # Şifreyi email body'den çıkar
            # Örnek: "The password for part 3 is: Sup3rS3cur3P4ss"
            pw_match = re.search(r'password for part (\d+) is[:\s]+(\S+)', smtp_data, re.IGNORECASE)
            if pw_match:
                part_num = int(pw_match.group(1))
                password = pw_match.group(2).strip()
                passwords[part_num] = password
                print(f"[+] Parça {part_num} şifresi: {password}")
    except Exception:
        pass

cap.close()

# tshark ile raw stream'leri çıkar — daha güvenilir
print("\n[*] ZIP attachment'ları çıkarılıyor (tshark)...")

import subprocess

# Kaç stream var?
result = subprocess.run(
    ["tshark", "-r", PCAP_FILE, "-Y", "smtp", "-T", "fields", "-e", "tcp.stream"],
    capture_output=True, text=True
)
streams = sorted(set(result.stdout.strip().split('\n')))
print(f"[*] Toplam {len(streams)} TCP stream bulundu")

for stream_id in streams:
    if not stream_id:
        continue
    
    raw = subprocess.run(
        ["tshark", "-r", PCAP_FILE, "-q", "-z", f"follow,tcp,raw,{stream_id}"],
        capture_output=True, text=True
    ).stdout
    
    # Base64 ZIP içeriğini bul
    # SMTP DATA section'ı "Content-Transfer-Encoding: base64" sonrası başlar
    lines = raw.split('\n')
    in_attachment = False
    b64_lines = []
    part_num = None
    
    for line in lines:
        line = line.strip()
        
        # Parça numarasını bul
        m = re.search(r'part[_\s-]?(\d+)', line, re.IGNORECASE)
        if m:
            part_num = int(m.group(1))
        
        # base64 section başladı
        if 'content-transfer-encoding: base64' in line.lower():
            in_attachment = True
            continue
        
        # Boş satır = section sonu
        if in_attachment and line == '':
            if b64_lines:
                in_attachment = False
                continue
        
        if in_attachment:
            # Sadece geçerli base64 karakterleri
            if re.match(r'^[A-Za-z0-9+/=]+$', line):
                b64_lines.append(line)
    
    if b64_lines and part_num is not None:
        try:
            zip_data = base64.b64decode(''.join(b64_lines))
            zip_parts[part_num] = zip_data
            print(f"[+] Parça {part_num}: {len(zip_data)} byte ZIP alındı")
        except Exception as e:
            print(f"[-] Parça {part_num} decode hatası: {e}")

# Parçaları birleştir
print(f"\n[*] {len(zip_parts)} parça birleştiriliyor...")
all_parts = b''.join(zip_parts[i] for i in sorted(zip_parts.keys()))

# ZIP'i aç — şifreli olabilir
with zipfile.ZipFile(io.BytesIO(all_parts)) as zf:
    names = zf.namelist()
    print(f"[*] ZIP içeriği: {names}")
    
    # Şifreli ZIP
    if passwords:
        password = list(passwords.values())[0].encode()
        for name in names:
            content = zf.read(name, pwd=password)
            with open(f"extracted_{name}", "wb") as f:
                f.write(content)
            print(f"[+] Çıkarıldı: extracted_{name}")
    else:
        zf.extractall("extracted/")
        print("[+] Tüm dosyalar extracted/ altına çıkarıldı")

print("\n[+] Tamamlandı! Flag için PDF/çıkarılan dosyaları incele.")
```

---

## Gerçek Örnek: corCTF 2024 — the-conspiracy

### Senaryo
Custom Python protokol: sunucu her mesaj için farklı key üretiyor, key mesaj başına ekleniyor, mesaj XOR ile şifrelenmiş.

### Protokol Tersine Mühendislik

```python
#!/usr/bin/env python3
"""
corCTF the-conspiracy — custom protocol çözücü.
Her mesajın ilk N byte'ı key, geri kalanı XOR şifreli payload.
"""
import pyshark

PCAP_FILE = "the-conspiracy.pcap"
KEY_LEN = 16  # protokol analizi ile tespit edildi

cap = pyshark.FileCapture(PCAP_FILE, display_filter="tcp.port == 1337")
messages = []

for pkt in cap:
    try:
        if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload'):
            raw = bytes.fromhex(pkt.tcp.payload.replace(':', ''))
            if len(raw) > KEY_LEN:
                messages.append(raw)
    except Exception:
        pass

cap.close()

print(f"[*] {len(messages)} mesaj bulundu")

def xor_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))

for i, msg in enumerate(messages):
    key = msg[:KEY_LEN]
    ct  = msg[KEY_LEN:]
    pt  = xor_decrypt(key, ct)
    try:
        decoded = pt.decode('utf-8', errors='replace')
        # Flag içeriyor mu?
        if 'corctf{' in decoded or 'flag' in decoded.lower():
            print(f"\n[!] FLAG BULUNDU mesaj {i}: {decoded}")
        else:
            print(f"[{i}] {decoded[:80]}...")
    except Exception:
        print(f"[{i}] Binary: {pt[:30].hex()}...")

# Tüm decrypt edilmiş mesajları dosyaya yaz
with open("decrypted_messages.txt", "w") as f:
    for i, msg in enumerate(messages):
        key = msg[:KEY_LEN]
        ct  = msg[KEY_LEN:]
        pt  = xor_decrypt(key, ct)
        f.write(f"=== Mesaj {i} ===\n")
        f.write(pt.decode('utf-8', errors='replace'))
        f.write("\n\n")

print("\n[+] Tüm mesajlar decrypted_messages.txt'e yazıldı")
```

---

## DNS Exfiltration Tespiti

```python
#!/usr/bin/env python3
"""
DNS exfiltration: veri base32/base64 encode edilmiş subdomain olarak gönderilir.
Örnek: "4f4646543232...evil.com" → decode et → flag
"""
import pyshark
import base64
import re

cap = pyshark.FileCapture("traffic.pcap", display_filter="dns")

target_domain = "attacker.com"  # şüpheli domain
collected = {}

for pkt in cap:
    try:
        if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
            qname = str(pkt.dns.qry_name)
            
            if target_domain in qname:
                # Subdomain'i çıkar (domain kısmını sil)
                subdomain = qname.replace(f'.{target_domain}', '').replace(target_domain, '')
                
                # Sıralı exfiltration: "chunk1.chunk2..." gibi
                # Ya da "seq_NO.data.domain" formatı
                m = re.match(r'^(\d+)\.([A-Za-z0-9+/=]+)', subdomain)
                if m:
                    seq = int(m.group(1))
                    data = m.group(2)
                    collected[seq] = data
                else:
                    print(f"[DNS] {subdomain}")
    except Exception:
        pass

cap.close()

if collected:
    # Sıralı parçaları birleştir
    full_data = ''.join(collected[k] for k in sorted(collected.keys()))
    print(f"[*] Ham veri: {full_data[:100]}...")
    
    # Base32 decode dene
    try:
        decoded = base64.b32decode(full_data.upper())
        print(f"[+] Base32 decode: {decoded}")
    except Exception:
        pass
    
    # Base64 decode dene
    try:
        decoded = base64.b64decode(full_data + '==')
        print(f"[+] Base64 decode: {decoded}")
    except Exception:
        pass
    
    # Hex decode dene
    try:
        decoded = bytes.fromhex(full_data)
        print(f"[+] Hex decode: {decoded}")
    except Exception:
        pass
```

---

## Python scapy ile Ham Paket Analizi

```python
from scapy.all import rdpcap, TCP, Raw

packets = rdpcap("capture.pcap")

# Belirli porta giden TCP payload'larını topla
payloads = []
for pkt in packets:
    if TCP in pkt and Raw in pkt:
        if pkt[TCP].dport == 1234:  # hedef port
            payloads.append(bytes(pkt[Raw]))

print(f"[*] {len(payloads)} paket toplandı")

# İlk 10 paketi hex+ASCII olarak göster
for i, p in enumerate(payloads[:10]):
    ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in p)
    print(f"[{i}] {p.hex()[:32]}... | {ascii_repr[:16]}...")
```

---

## Tuzaklar

- **TCP stream sırası**: scapy/pyshark paketleri ağ sırasıyla okur. Yeniden iletim (retransmission) paketleri duplikasyon yapabilir. Stream'e göre grupla, ACK numarasını takip et.
- **FTP pasif mod**: Veri kanalı dinamik port kullanır. Wireshark'ta "ftp-data" filtresi tüm veri akışlarını yakalar, "ftp" (port 21) sadece komut kanalını gösterir.
- **SMTP base64 satır kesmesi**: MIME base64 her 76 karakterde satır keser. `''.join(lines)` yapıp tek seferde decode et, satır satır decode etme.
- **TLS şifreli trafik**: Pre-master secret log dosyası varsa (CTF bazen verir) Wireshark'ta Edit → Preferences → Protocols → TLS → Master Secret Log File ile çöz.
- **Wireshark "Follow TCP Stream"**: GUI'de en hızlı yöntem. Sağ tık → Follow → TCP Stream → Show data as: C Arrays ya da Raw.
- **pyshark yavaşlığı**: Büyük PCAP'larda pyshark çok yavaş olabilir. tshark CLI ya da scapy rdpcap() daha hızlı.
- **Encoding katmanları**: CTF'lerde sıklıkla base64(zlib(base64(flag))) gibi iç içe encoding olur. Her decode adımında magic byte kontrol et.

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 18ee827b2fa561f4
-->

