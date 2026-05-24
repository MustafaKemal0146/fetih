---
name: steganography-image
description: "Görüntü steganografi — LSB/MSB, alpha kanal, metadata, file carving tespiti ve Python Pillow ile her kanalın bit-seviyesinde analizi."
tags: [ctf, forensics, stego, steganography, png, jpg, lsb, msb, exif, zsteg, stegsolve, pillow, binwalk, alpha-channel, pixel-analysis]
triggers:
  - "PNG dosyası"
  - "görüntüde gizli veri"
  - "LSB steganografi"
  - "MSB"
  - "alpha kanal"
  - "EXIF metadata"
  - "stego"
  - "hidden in image"
  - "pixel analizi"
  - "JPG/JPEG analizi"
  - "görüntü içinde flag"
  - "image forensics"
  - "zsteg"
  - "stegsolve"
difficulty: medium
category: forensics
solved_challenges:
  - "picoCTF 2023 - MSB (bit 7, R/G/B kanalları — LSB değil MSB!)"
  - "HTB Cyber Apocalypse 2024 - CyberSpaceCTF Memory (AES encrypted PNG)"
  - "çeşitli CTF LSB/alpha kanal stego"
---

# Görüntü Steganografi Analizi

## Ne Zaman Kullan

Aşağıdaki işaretlerden herhangi birini görürsen bu skill'i tetikle:

- `.png`, `.jpg`, `.jpeg`, `.bmp`, `.gif`, `.tiff` dosyası verilmiş
- Görsel normal görünüyor ama içinde veri gizlenmiş şüphesi var
- Challenge açıklamasında "hidden", "stego", "secret in image" geçiyor
- Dosya boyutu beklenenden büyük (içine dosya gömülmüş olabilir)
- Metadata'da şüpheli yorum/açıklama alanı var

---

## Araç Seti

```bash
# zsteg — PNG/BMP LSB analizi (en hızlı başlangıç)
gem install zsteg

# steghide — JPG/BMP şifreli gizleme
sudo apt install steghide

# stegsolve — Java GUI, çoklu bit düzlemi görselleştirme
wget https://github.com/zardus/ctf-tools/raw/master/stegsolve/install
# ya da doğrudan jar: Stegsolve.jar

# exiftool — EXIF/metadata okuma
sudo apt install exiftool

# binwalk — gömülü dosya tespiti ve çıkarma
sudo apt install binwalk

# Python — PIL/Pillow
pip install Pillow

# strings — ham metin arama
strings image.png | grep -i "flag\|ctf\|secret"
```

---

## LSB vs MSB Farkı

Bu fark CTF'lerde sıkça tuzak olarak kullanılır.

**LSB (Least Significant Bit) — bit 0:**
- En yaygın stego tekniği
- Her piksel byte'ının en az önemli biti değiştirilir
- Görsel fark minimum → insan gözüyle fark edilmez
- Araçların çoğu LSB arar

**MSB (Most Significant Bit) — bit 7:**
- picoCTF 2023 "MSB" challenge'ında kullanıldı
- Her piksel byte'ının en önemli biti alınır
- `zsteg` varsayılan olarak LSB arar — MSB için özel parametre lazım

```bash
# zsteg LSB (varsayılan)
zsteg image.png

# zsteg MSB — tüm bit düzlemlerini tara
zsteg -a image.png

# Sadece MSB (bit 7), R kanalı
zsteg -b 7 -o rgb image.png

# Tüm kombinasyonları dene (yavaş ama kapsamlı)
zsteg --all image.png 2>/dev/null | grep -i "flag\|ctf\|pico\|htb"
```

---

## Python Pillow ile Kanal Analizi

### Tam LSB/MSB Çıkarıcı

```python
#!/usr/bin/env python3
"""
Görüntü steganografi — her kanal, her bit düzlemi için veri çıkarıcı.
Çalıştır: python3 stego_extract.py image.png
"""
from PIL import Image
import sys

def extract_bits(img_path: str, bit: int, channels: str = "RGB", order: str = "row") -> bytes:
    """
    img_path : PNG dosyası
    bit      : 0 = LSB, 7 = MSB, 1-6 = ara bitler
    channels : "R", "G", "B", "A", "RGB", "RGBA" gibi kombinasyonlar
    order    : "row" (satır satır) ya da "col" (sütun sütun)
    """
    img = Image.open(img_path).convert("RGBA")
    width, height = img.size
    pixels = img.load()
    
    channel_map = {"R": 0, "G": 1, "B": 2, "A": 3}
    ch_indices = [channel_map[c] for c in channels if c in channel_map]
    
    bits = []
    
    if order == "row":
        pixel_coords = [(x, y) for y in range(height) for x in range(width)]
    else:
        pixel_coords = [(x, y) for x in range(width) for y in range(height)]
    
    for (x, y) in pixel_coords:
        pixel = pixels[x, y]
        for ch in ch_indices:
            b = (pixel[ch] >> bit) & 1
            bits.append(b)
    
    # Bit dizisini byte'lara çevir
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_bits = bits[i:i+8]
        byte = 0
        for b in byte_bits:
            byte = (byte << 1) | b
        result.append(byte)
    
    return bytes(result)

def is_printable(data: bytes, threshold: float = 0.7) -> bool:
    """Verinin büyük çoğunluğu yazdırılabilir ASCII ise True döner."""
    printable = sum(32 <= b < 127 for b in data[:200])
    return printable / min(len(data), 200) > threshold

def try_all_combinations(img_path: str):
    """Tüm bit/kanal kombinasyonlarını dene, anlamlı görünenleri raporla."""
    channel_combos = ["R", "G", "B", "A", "RG", "RB", "GB", "RGB", "RGBA"]
    
    print(f"[*] Analiz ediliyor: {img_path}")
    print(f"[*] {len(channel_combos)} kanal kombinasyonu × 8 bit düzlemi\n")
    
    found = []
    
    for channels in channel_combos:
        for bit in range(8):
            try:
                data = extract_bits(img_path, bit, channels)
                
                # Flag formatı var mı?
                text = data.decode('latin-1', errors='replace')
                
                # Bilinen flag formatlarını ara
                flag_patterns = [
                    "flag{", "Flag{", "FLAG{",
                    "picoCTF{", "HTB{", "corctf{",
                    "CTF{", "ctf{"
                ]
                
                for pat in flag_patterns:
                    if pat in text[:500]:
                        idx = text.index(pat)
                        snippet = text[idx:idx+60]
                        print(f"[!] FLAG BULUNDU — bit={bit}, channels={channels}")
                        print(f"    {snippet}")
                        found.append((bit, channels, snippet))
                
                # Genel okunabilirlik kontrolü
                elif is_printable(data[:100]) and len(data) > 10:
                    preview = text[:50].replace('\n', ' ').replace('\r', '')
                    print(f"[?] Okunabilir — bit={bit}, channels={channels}: {preview}...")
                    
            except Exception as e:
                pass
    
    if not found:
        print("\n[-] Açık flag bulunamadı. Manuel inceleme gerekebilir.")
        print("    → zsteg --all ile dene")
        print("    → steghide extract -sf image.jpg ile dene (şifreli gizleme)")
    
    return found

# Belirli kombinasyon
def extract_and_save(img_path: str, bit: int, channels: str, out_file: str = "output.bin"):
    data = extract_bits(img_path, bit, channels)
    with open(out_file, "wb") as f:
        f.write(data)
    print(f"[+] {len(data)} byte yazıldı: {out_file}")
    print(f"[+] İlk 100 byte: {data[:100]}")
    print(f"[+] ASCII: {data[:100].decode('latin-1', errors='replace')}")

if __name__ == "__main__":
    img = sys.argv[1] if len(sys.argv) > 1 else "image.png"
    
    # Tüm kombinasyonları otomatik tara
    results = try_all_combinations(img)
    
    # Manuel çıkarım örnekleri:
    # extract_and_save(img, bit=0, channels="RGB")   # LSB RGB
    # extract_and_save(img, bit=7, channels="RGB")   # MSB RGB (picoCTF tarzı)
    # extract_and_save(img, bit=0, channels="A")     # Alpha kanalı LSB
```

### picoCTF 2023 MSB — Özel Çözüm

```python
#!/usr/bin/env python3
"""
picoCTF 2023 "MSB" challenge tam çözümü.
Her pikselin R, G, B kanalının MSB'si (bit 7) alınıp birleştiriliyor.
"""
from PIL import Image

img = Image.open("challenge.png").convert("RGB")
width, height = img.size
pixels = img.load()

bits = []
for y in range(height):
    for x in range(width):
        r, g, b = pixels[x, y]
        bits.append((r >> 7) & 1)  # R MSB
        bits.append((g >> 7) & 1)  # G MSB
        bits.append((b >> 7) & 1)  # B MSB

# Byte'lara çevir
result = bytearray()
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for b in bits[i:i+8]:
        byte = (byte << 1) | b
    result.append(byte)

# Flag'i bul
text = result.decode('latin-1', errors='replace')
if 'picoCTF{' in text:
    start = text.index('picoCTF{')
    end   = text.index('}', start) + 1
    print(f"[+] FLAG: {text[start:end]}")
else:
    # Dosyaya kaydet, elle incele
    with open("msb_output.bin", "wb") as f:
        f.write(result)
    print(f"[-] Flag bulunamadı. msb_output.bin inceleniyor...")
    print(f"    strings msb_output.bin | grep picoCTF")
```

---

## EXIF/Metadata Analizi

```bash
# Tüm metadata alanlarını göster
exiftool image.jpg

# Sadece yorum/açıklama alanları
exiftool -Comment -ImageDescription -UserComment image.jpg

# GPS koordinatları (bazen flag formatında)
exiftool -GPSLatitude -GPSLongitude image.jpg

# Thumbnail'i çıkar (farklı görüntü içerebilir)
exiftool -b -ThumbnailImage image.jpg > thumbnail.jpg

# Tüm binary alanları çıkar
exiftool -b image.jpg > raw_metadata.bin
strings raw_metadata.bin | grep -i "flag\|ctf\|secret"

# Metadata'yı temizlemeden önce inceleme (silinmiş ama hala orada olabilir)
exiftool -all= image.jpg -o clean.jpg  # kopyasını temizle
# Orijinal dosyayı hex editörle incele: hexdump -C image.jpg | grep -A2 "Exif"
```

---

## File Carving — binwalk

```bash
# Gömülü dosya tespiti
binwalk image.png

# Örnek çıktı:
# DECIMAL   HEXADECIMAL   DESCRIPTION
# 0         0x0           PNG image, 800 x 600, 8-bit
# 45231     0xB0AF        Zip archive data, "flag.txt"
# 46892     0xB72C        End of Zip archive

# Otomatik çıkarma (-e = extract, -M = matryoshka/iç içe)
binwalk -e image.png
binwalk -eM image.png   # iç içe dosyaları da çıkar

# Manuel çıkarma (belirli offset'ten)
dd if=image.png bs=1 skip=45231 of=extracted.zip
unzip extracted.zip

# PNG chunk'larını incele (gizli IDAT/tEXt/zTXt chunk)
python3 -c "
import struct, zlib

with open('image.png', 'rb') as f:
    data = f.read()

# PNG signature
assert data[:8] == b'\x89PNG\r\n\x1a\n', 'Geçersiz PNG!'

pos = 8
while pos < len(data):
    length = struct.unpack('>I', data[pos:pos+4])[0]
    chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
    chunk_data = data[pos+8:pos+8+length]
    crc = data[pos+8+length:pos+12+length]
    
    print(f'Chunk: {chunk_type} ({length} byte)')
    
    if chunk_type in ('tEXt', 'zTXt', 'iTXt'):
        print(f'  >>> Metin: {chunk_data[:200]}')
    
    if chunk_type == 'IEND':
        trailing = data[pos+12:]
        if trailing:
            print(f'  [!] IEND sonrası {len(trailing)} byte veri var!')
            with open('trailing_data.bin', 'wb') as f:
                f.write(trailing)
    
    pos += 12 + length
"
```

---

## Tuzaklar

- **LSB arama yönü**: Satır satır (row-major) vs sütun sütun (column-major) vs diagonal — yanlış yön yanlış çıktı verir. `zsteg -a` tüm yönleri dener.
- **MSB tuzağı**: zsteg ve stegsolve varsayılan olarak LSB arar. "Hiçbir şey bulamıyorum" durumunda MSB'yi dene: `zsteg -b 7 -o rgb image.png`.
- **Alpha kanalı**: PNG RGBA olabilir. Sadece RGB bakarsan A kanalını kaçırırsın. `img.convert("RGBA")` kullan.
- **JPEG kayıpsız değil**: JPEG sıkıştırmalıdır, LSB bilgisi sıkıştırmada kaybolur. JPEG için steghide ya da JFIF chunk analizi kullan.
- **steghide şifresi**: Parola gerektiriyorsa `stegcracker image.jpg wordlist.txt` ile brute-force dene.
- **PNG yeniden kaydetme**: Pillow ile okuyup tekrar kaydedersen LSB bilgisi değişebilir. Her zaman orijinal dosya üzerinde çalış.
- **Renk paletli PNG**: Mod `P` (palette) PNG'lerde piksel değerleri renk indeksi, renk değeri değil. `img.convert("RGB")` ile dönüştür.
- **Big-endian bit sırası**: MSB önce mi yoksa LSB önce mi? Bazı CTF'lerde byte içindeki bit sırası tersine çevrilmiştir.
