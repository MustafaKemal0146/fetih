---
name: osint-category-tools
description: OSINT kategorisi SKILL.md — Kullanıcı araştırması, sosyal medya, subdomain keşfi araçları kurma rehberi
tags: [ctf, osint, tools, setup, sherlock, maigret]
adapted_for: fetih
---

# OSINT Kategorisi — Gerekli Araçlar

Open Source Intelligence — kişi araştırması, sosyal medya profil arama, subdomain keşfi ve recon araçları.

## Gerekli Araçlar

| Araç | Açıklama | Kurulum |
|------|----------|---------|
| **sherlock** | Sosyal medya hesap arama | `pip install sherlock-project` |
| **maigret** | Kullanıcı adı OSINT (sherlock'a benzer) | `pip install maigret` |
| **subfinder** | Subdomain keşfi | Go kurulum |
| **amass** | OSINT + subdomain enumeration | Go kurulum |
| **assetfinder** | Asset/subdomain bulucu | Go kurulum |
| **waybackurls** | Wayback Machine URL çıkarma | Go kurulum |
| **gau** | URL toplayıcı (Wayback + otherSources) | Go kurulum |

## Araçları Hızlı Kur

OSINT kategorisine ait tüm araçları kur:

```bash
fetih download-tools osint
```

Bu kurulum:
- pip araçları (`sherlock`, `maigret`) → Python venv
- Go araçları (`subfinder`, `amass`) → `go install`

## Araçlar Kurulu mu Kontrol Et

```bash
# Tüm OSINT araçları
fetih download-tools status | grep -A 10 "OSINT"

# Manuel kontrol
which sherlock maigret subfinder amass
python3 -c "import sherlock; print('OSINT OK')"
```

## Her Araç Neye Yarar?

### Sosyal Medya & Kullanıcı Araştırması

#### sherlock
Sosyal medya hesap arama — username'i birden fazla platform'da ara

**Skill'lerde kullanılır:**
- `osint/persona-tracking` → profile discovery
- Kişi araştırması başlangıç aracı

```bash
sherlock username
sherlock -t 5 --print-found username
sherlock --csv username  # CSV output
```

#### maigret
Sherlock'a benzer ama daha kapsamlı (OSINT framework)

**Skill'lerde kullanılır:**
- `osint/persona-tracking` → comprehensive user search
- Email/username bulma

```bash
maigret username
maigret --username username --output output.html
maigret -e email@domain.com
```

### Subdomain & Domain Enumeration

#### subfinder
Subdomain discovery — Passive sources (certificates, DNS, etc.)

**Skill'lerde kullanılır:**
- OSINT recon fazı → domain'in subdomains'i
- Web target enumeration başlama

```bash
subfinder -d target.com
subfinder -d target.com -all
subfinder -dL domains.txt -o subs.txt
```

#### amass
OSINT + Subdomain enumeration (daha kapsamlı)

**Skill'lerde kullanılır:**
- `osint/persona-tracking` → company domain+subdomain
- Network recon → ASN enumeration

```bash
amass enum -d target.com
amass intel -whois -d target.com
amass enum -d target.com -src activedomains,binaryedge,brute
```

#### assetfinder
Asset/subdomain bulucu (crt.sh, hackertarget vb.)

**Skill'lerde kullanılır:**
- Quick subdomain discovery → minimal output

```bash
assetfinder --subs-only target.com
assetfinder target.com | sort -u
```

### URL Collection

#### waybackurls
Wayback Machine'den URL çıkarma

**Skill'lerde kullanılır:**
- Web recon → historical URL discovery
- Hidden endpoint bulma

```bash
echo target.com | waybackurls
cat domains.txt | waybackurls | unfurl keys
```

#### gau
URL toplayıcı — Wayback + otomatik kaynaklar

**Skill'lerde kullanılır:**
- Web enumeration → URL listesi
- Parametreli endpoint discovery

```bash
gau target.com
gau -providers wayback,urlscan target.com
gau target.com | grep -i api
```

---

## Kurulum Sorunları Çözme

### sherlock "No module named requests"

Bağımlılık eksik:

```bash
pip install --upgrade sherlock-project
# veya
pip install requests bs4 flask
```

### subfinder Go kurulum

Go PATH kontrol et:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### amass DNS timeout

Timeout ayarla:

```bash
amass enum -d target.com -timeout 30 -active
```

---

## Workflow Example: Persona Tracking

```bash
# 1. Username ile sosyal medya ara
sherlock "john_doe"
maigret "john_doe"

# 2. Email bulunmuşsa, domain ara
echo "john@example.com" | cut -d@ -f2 > domain.txt
subfinder -d example.com -o subs.txt

# 3. Subdomains IP'lerini resolve et
cat subs.txt | xargs -I {} dig +short {}

# 4. Çalışan URL'leri kontrol et
gau example.com | head -20

# 5. Bulduklarını organize et
{
  echo "=== Sosyal Medya ==="
  sherlock --csv john_doe | grep -v "Not Found"
  echo "=== Domain & Subdomains ==="
  cat subs.txt
  echo "=== URLs ==="
  gau example.com | sort -u | head -20
} > reconnaissance.txt
```

---

## Hızlı Test Scripti

```bash
python3 << 'EOF'
import shutil

tools = ['sherlock', 'maigret']
go_tools = ['subfinder', 'amass', 'assetfinder', 'waybackurls', 'gau']

print("=== OSINT Python Tools ===")
for tool in tools:
    try:
        if tool == 'sherlock':
            __import__('sherlock')
        elif tool == 'maigret':
            __import__('maigret')
        print(f"✓ {tool}")
    except ImportError:
        print(f"✗ {tool}")

print("\n=== OSINT Go Tools ===")
for tool in go_tools:
    if shutil.which(tool):
        print(f"✓ {tool}")
    else:
        print(f"✗ {tool}")

print("\nÇözüm: fetih download-tools osint")
EOF
```

---

## Notlar

- **sherlock + maigret** → sosyal medya başlangıcı
- **subfinder + amass** → subdomain keşfi temel
- **gau + waybackurls** → historical URL discovery
- **Go araçları** → çok hızlı ve reliable
- **Python araçları** → basit, hızlı başlama

Skill okudoğunda başında hangi araçlar gerekli gösterilecek!

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 5c9301e220c8bbf8
-->

