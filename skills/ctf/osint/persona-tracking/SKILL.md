---
name: persona-tracking
description: OSINT kişi araştırması — sosyal medya, EXIF, bcrypt crack, geolocation
tags: [ctf, osint, persona, social-media, github, exif, bcrypt, geolocation, hashcat]
triggers:
  - "kişi araştır"
  - "OSINT"
  - "sosyal medya"
  - "persona"
  - "fictional character"
  - "profile picture"
  - "bcrypt hash"
  - "password in story"
  - "geolocation"
difficulty: medium
category: osint
solved_challenges:
  - "IRIS CTF 2024 - OSINT set (persona + bcrypt, wordlist from posts)"
---

# OSINT Kişi Araştırması (Persona Tracking)

Bu skill kurgusal (fictional) veya gerçek bir kişiyle ilgili CTF challenge'larında kullanılır.
Sosyal medya profili, fotoğraf metadata, şifre kırma ve geolocation kapsar.

---

## 1. OSINT Akış Şeması

Bir kişi araştırması challenge'ı aldığında BU SIRAYA göre ilerle:

```
Kişi adı / kullanıcı adı verildi
        │
        ▼
1. Google dork → site:platform.com "kullanıcı adı"
        │
        ▼
2. Kullanıcı adı tarama araçları (sherlock, maigret, whatsmyname)
        │
        ▼
3. Bulunan platformlarda profil incele
   ├── Biyografi, link, email
   ├── Post geçmişi → kelime listesi oluştur
   └── Fotoğraflar → EXIF, arka plan, geolocation
        │
        ▼
4. Fotoğraftan geolocation yap (reverse image, yandex maps)
        │
        ▼
5. Hash / şifre crack (bcrypt, md5, sha256)
   └── Wordlist: kişinin kullandığı kelimeler + kişisel bilgiler
        │
        ▼
6. GitHub / email arama
   └── git log'larında email, GitHub profil → bağlantılı repo'lar
```

---

## 2. Platform Araçları

### Kullanıcı Adı Tarama

```bash
# sherlock — 400+ platform tarar
pip install sherlock-project
sherlock kullanici_adi
sherlock kullanici_adi --timeout 10 --output /tmp/sherlock_out.txt

# maigret — daha kapsamlı, 3000+ site
pip install maigret
maigret kullanici_adi
maigret kullanici_adi --html /tmp/rapor.html

# whatsmyname (web tabanlı alternatif)
# https://whatsmyname.app/
```

### Google Dork Şablonları

```
# Temel kullanıcı adı arama
"kullanici_adi" site:twitter.com OR site:instagram.com OR site:reddit.com

# Email arama
"ad.soyad@" OR "@domain.com" "kullanici_adi"

# GitHub
site:github.com "kullanici_adi"
site:github.com "ad soyad"

# Geçmiş (web archive)
site:web.archive.org "platform.com/kullanici_adi"

# Resim ile arama
# → Google Images reverse search
# → TinEye: https://tineye.com/
# → Yandex Images (en iyi yüz tanıma): https://yandex.com/images/
```

### Sosyal Medya Platform Spesifik

```bash
# Twitter/X — eski tweet'ler için
# https://nitter.net/kullanici_adi  (rate limit yok)
# https://search.twitter.com/?q=from:kullanici_adi

# Instagram — public profil scrape
instaloader kullanici_adi --no-videos --no-video-thumbnails
# İndirilenlerin EXIF'ine bak

# Reddit — post geçmişi
# https://www.reddit.com/user/kullanici_adi/
# pushshift.io (arşiv) ya da arctic shift: https://arctic-shift.photon-reddit.com/

# GitHub
gh api users/kullanici_adi
gh api users/kullanici_adi/repos
# Email için: git log'larına bak (repo clone et)
git clone https://github.com/kullanici_adi/repo.git /tmp/repo
cd /tmp/repo && git log --format="%ae %an" | sort -u
```

---

## 3. IRIS CTF 2024: Post'lardan Wordlist → bcrypt Kırma

**Challenge Özeti:**
Kurgusal bir karakter (örn. "Sophie Chen") verildi. Karakterin sosyal medya profilleri
kurulmuştu. Bir yerde bcrypt hash bulundu. Şifreyi bulmak için karakterin post'larını
analiz etmek ve özel wordlist oluşturmak gerekiyordu.

**Adım 1: Tüm post'ları topla**

```python
import re

# Tüm post metinlerini bir dosyaya topla
posts = [
    "Bugün kırmızı bisikletimle parkta dolaştım #cycling",
    "2003 yılında doğdum, İzmir sevdalısıyım",
    "Kedim Pamuk çok sevimli!",
    # ... tüm post'lar
]

words = set()
for post in posts:
    # Kelimeleri ayır
    raw = re.findall(r'\b\w+\b', post.lower())
    words.update(raw)
    # Hashtag'leri de ekle
    tags = re.findall(r'#(\w+)', post.lower())
    words.update(tags)

# Kişisel bilgiler
personal = [
    "sophie", "chen", "sophiechen", "sophie2003", "chen2003",
    "pamuk", "izmir", "cycling", "bisiklet",
    "2003", "1234", "!",  # yaygın ekler
]
words.update(personal)

# Varyasyonlar üret
variations = set()
for w in words:
    variations.add(w)
    variations.add(w.capitalize())
    variations.add(w.upper())
    variations.add(w + "123")
    variations.add(w + "!")
    variations.add(w + "2003")
    variations.add(w + "2024")

with open('/tmp/wordlist.txt', 'w') as f:
    f.write('\n'.join(sorted(variations)))

print(f"Wordlist hazır: {len(variations)} aday")
```

**Adım 2: bcrypt kır**

```bash
# Hash'i dosyaya kaydet
echo '$2b$12$HASH_BURAYA' > /tmp/hash.txt

# hashcat ile bcrypt (mode 3200)
hashcat -m 3200 /tmp/hash.txt /tmp/wordlist.txt --force

# john ile alternatif
john /tmp/hash.txt --wordlist=/tmp/wordlist.txt --format=bcrypt

# Kural tabanlı (john rules)
john /tmp/hash.txt --wordlist=/tmp/wordlist.txt --rules=best64 --format=bcrypt

# hashcat kural
hashcat -m 3200 /tmp/hash.txt /tmp/wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

**bcrypt çok yavaş olunca:**
- Wordlist'i küçük tut (sadece kişisel kelimeler)
- GPU kullan (hashcat -d 1 GPU seç)
- Mantıksal düşün: şifreler genelde isim+yıl+! formatında

---

## 4. EXIF Metadata Analizi

```bash
# exiftool — en kapsamlı
exiftool resim.jpg
exiftool -GPS* resim.jpg     # sadece GPS verisi
exiftool -a -u resim.jpg     # tüm metadata (bilinmeyen dahil)

# Toplu analiz
for f in *.jpg *.png; do
    echo "=== $f ==="
    exiftool -GPSLatitude -GPSLongitude -GPSAltitude -Artist -Author -Comment "$f" 2>/dev/null
done

# GPS koordinatlarını dönüştür
# exiftool çıktısı: 39 deg 57' 27.00" N
# → Ondalık: 39 + 57/60 + 27/3600 = 39.957500

python3 -c "
lat_d, lat_m, lat_s = 39, 57, 27
lon_d, lon_m, lon_s = 32, 51, 42
lat = lat_d + lat_m/60 + lat_s/3600
lon = lon_d + lon_m/60 + lon_s/3600
print(f'Koordinat: {lat:.6f}, {lon:.6f}')
print(f'Google Maps: https://maps.google.com/?q={lat},{lon}')
"

# Gizli metadata: thumbnail içinde farklı GPS olabilir!
exiftool -ThumbnailImage -b resim.jpg > /tmp/thumb.jpg
exiftool /tmp/thumb.jpg
```

---

## 5. Geolocation (Reverse Image / Yandex Maps)

```bash
# Komut satırı reverse image arama
# (API key gerekir genelde, web arayüzü daha kolay)

# Yandex Images — en iyi yüz/bina tanıma
# https://yandex.com/images/ → Görsel ile ara

# Google Lens
# https://lens.google.com/

# Bina/yer tespiti için ipuçları
# 1. Fotoğraftaki tabelalar, levhalar → OCR
# 2. Araba plakaları → ülke/şehir
# 3. Elektrik direği / trafik işareti stili → ülke
# 4. Dil → bölge
# 5. Arka plandaki binalar → Google Street View'da ara

# Sokak görünümü ile doğrulama
# coords bulununca: https://maps.google.com/?q=LAT,LON
# Street View moduna geç → fotoğrafla karşılaştır
```

---

## 6. Tuzaklar ve İpuçları

```
TUZAKLAR:
- Kullanıcı adı farklı platformlarda farklı olabilir (nick rotasyonu)
- Silinmiş içerikler web.archive.org'da olabilir
- Profil fotoğrafı başka kişiye ait olabilir (stolen photo) → TinEye ile doğrula
- bcrypt kırmak çok uzun sürebilir → wordlist'i küçük tut, mantıklı düşün
- EXIF GPS verisi resim düzenlendiyse silinmiş olabilir

İPUÇLARI:
- GitHub'daki commit email'leri çok değerli — kişinin gerçek emailini verebilir
- Instagram bio'sunda gizli link olabilir (linktree vs.)
- Discord sunucularına katılım tarihleri bazen profilde görünür
- Reddit post geçmişi çok açıklayıcı — kişisel detaylar genelde sızar
- Tweet metadata'sında cihaz bilgisi olabilir (iPhone vs Android → lokasyon)
- Fotoğraf sıra numarası (IMG_0001.jpg) → kaç fotoğraf çekilmiş → model tahmini

ARAÇ LİSTESİ:
- sherlock    → kullanıcı adı tarama
- maigret     → detaylı profil
- exiftool    → EXIF analizi
- hashcat     → hash kırma (GPU)
- john        → hash kırma (CPU, kural tabanlı)
- instaloader → Instagram profil indirme
- gh          → GitHub API
- metagoofil  → web'deki dosyaların metadata'sı
- maltego     → görsel OSINT haritası (ücretli)
```

---

## Hızlı Başlangıç Checklist

```
[ ] İsim/kullanıcı adı belirle
[ ] Google dork çalıştır
[ ] sherlock + maigret çalıştır
[ ] Bulunan profillerde biyografi + linkler not al
[ ] Post geçmişini tara → wordlist oluştur
[ ] Fotoğrafları indir → exiftool çalıştır
[ ] GPS varsa → Google Maps + Street View
[ ] GPS yoksa → Yandex/Google Lens ile yer tespiti
[ ] Hash varsa → kişisel wordlist ile hashcat
[ ] GitHub varsa → git log ile email çıkar
[ ] web.archive.org'da silinmiş içerik ara
```
