# 🛡️ FETIH Skill Kataloğu — 913 Hazır Skill

> **"Bir hattın müdafaası yoktur, bir sathın müdafaası vardır. O satıh bütün vatandır."**
>
> FETIH AI Agent, 913 özel skill ile siber güvenlikten CTF yarışmalarına, yaratıcı üretimden yazılım geliştirmeye kadar her alanda hizmet verir.

---

## 📊 Sayılarla FETIH Skill Kataloğu

| Metrik | Sayı |
|--------|------|
| **Toplam SKILL.md** | **913** |
| Ek referans doküman (.md) | 432 |
| Script, şablon ve diğer dosyalar | 265 |
| **Toplam dosya** | **1,610** |
| MITRE ATT&CK tekniği kapsamı | 291 / 14 taktik |
| NIST CSF 2.0 uyumu | Tam (6 fonksiyon) |
| Alt kategori sayısı | 47+ |

---

## 🏗️ Beceri Mimarisi

Her skill, YAML frontmatter ile başlar ve FETIH agent tarafından otomatik tanınır:

```yaml
---
name: skill-adi
description: Ne işe yaradığı
tags: [kategori, araclar]
triggers: ["tetikleyici kelimeler"]   # Kullanıcı bunları söyleyince skill tetiklenir
category: ana-kategori
mitre_attack: [TXXXX]                 # MITRE ATT&CK tekniği
nist_csf: [XX.XX-XX]                 # NIST CSF kontrolü
adapted_for: fetih                    # FETIH için uyarlandı
source: orijinal-kaynak               # İthal skill'ler için
---
```

### Skill Tetikleme Mekanizması

Kullanıcının mesajındaki anahtar kelimeler, skill'lerin `triggers` alanıyla eşleşir. Örneğin:

- Kullanıcı: *"bu sunucuda zararlı yazılım analizi yap"* → `malware-analysis/` skill'leri tetiklenir
- Kullanıcı: *"AWS S3 bucket'larını denetle"* → `cloud-security/` skill'leri tetiklenir
- Kullanıcı: *"şu binary'yi reverse et"* → `ctf/rev/` skill'leri tetiklenir

---

## 🛡️ Siber Güvenlik — 743 Skill (32 Alt Kategori)

En büyük ve en kapsamlı kategorimiz. Savunma, saldırı, analiz ve uyum alanlarının tamamını kapsar.

### Kategori Detayları

| # | Kategori | Skill | Odak Alanı |
|---|----------|-------|------------|
| 1 | **Tehdit Avı** | 63 | Proaktif tehdit arama, anomali tespiti, YARA/Sigma kuralları |
| 2 | **Bulut Güvenliği** | 63 | AWS, Azure, GCP güvenlik denetimi, IAM, S3 |
| 3 | **SOC Operasyonları** | 62 | SIEM, alert triyajı, vaka yönetimi, SecLists pattern-matching |
| 4 | **Tehdit İstihbaratı** | 50 | IOC analizi, APT takibi, MISP, STIX/TAXII |
| 5 | **Web Uygulama Güvenliği** | 50 | OWASP Top 10, SQLi, XSS, WAF bypass, bug bounty, SecLists |
| 6 | **Ağ Güvenliği** | 43 | Nmap, Wireshark, IDS/IPS, paket analizi |
| 7 | **Zararlı Yazılım Analizi** | 42 | Ghidra, IDA, sandbox, web shell tespiti |
| 8 | **Kimlik ve Erişim Yönetimi** | 39 | IAM, MFA, Zero Trust, AD, API key tarama |
| 9 | **Dijital Adli Bilişim** | 37 | Disk imajı, timeline, silinmiş dosya kurtarma |
| 10 | **OT/ICS Güvenliği** | 29 | SCADA, PLC, Modbus, endüstriyel kontrol |
| 11 | **Konteyner Güvenliği** | 29 | Docker, Kubernetes, container escape |
| 12 | **API Güvenliği** | 28 | REST/GraphQL, OWASP API Top 10, OAuth2, JWT |
| 13 | **Olay Müdahalesi** | 26 | IR playbook, eradikasyon, kurtarma |
| 14 | **Zafiyet Yönetimi** | 25 | CVSS, patch yönetimi, risk önceliklendirme |
| 15 | **Sızma Testi** | 24 | Metodoloji, exploitation, raporlama, wordlist |
| 16 | **Sıfır Güven Mimarisi** | 18 | Zero Trust, mikro-segmentasyon, ZTNA |
| 17 | **Uç Nokta Güvenliği** | 17 | EDR/XDR, endpoint hardening |
| 18 | **DevSecOps** | 17 | CI/CD, SAST/DAST, supply chain, IaC |
| 19 | **Oltalma Savunması** | 15 | Email güvenliği, SPF/DKIM/DMARC |
| 20 | **Kriptografi** | 15 | TLS/SSL, PKI, şifreleme denetimi |
| 21 | **Fidye Yazılım Savunması** | 13 | Playbook, yedekleme, kurtarma |
| 22 | **Mobil Güvenlik** | 13 | Android/iOS, APK analizi, MDM |
| 23 | **Uyum ve Yönetişim** | 5 | NIST CSF, ISO 27001, SOC 2, PCI DSS |
| 24 | **Yapay Zeka Güvenliği** | 4 | AI/ML güvenliği, LLM testing, adversarial ML |
| 25 | **Tedarik Zinciri Güvenliği** | 3 | SBOM, üçüncü parti risk |
| 26 | **Aldatma Teknolojisi** | 3 | Honeypot, deception |
| 27 | **Kablosuz Ağ Güvenliği** | 2 | WiFi, Bluetooth, RF güvenliği |
| 28 | **Firmware Güvenliği** | 2 | UEFI, BIOS, firmware analizi |
| 29 | **Gizlilik Uyumu** | 2 | GDPR, KVKK, veri gizliliği |
| 30 | **Sosyal Mühendislik** | 1 | Pretexting, phishing, fiziksel güvenlik |
| 31 | **Veri Koruma** | 1 | DLP, veri sınıflandırma |
| 32 | **Blockchain Güvenliği** | 1 | Smart contract, DeFi güvenliği |

### MITRE ATT&CK Kapsamı

14 taktiğin tamamında **291 benzersiz teknik** kapsanır:

| ATT&CK Taktiği | Teknik Sayısı |
|---|---|
| 🔎 Keşif (Reconnaissance) | 12 |
| 🏗️ Kaynak Geliştirme | 7 |
| 🚪 İlk Erişim (Initial Access) | 18 |
| ⚡ Çalıştırma (Execution) | 18 |
| 🔩 Kalıcılık (Persistence) | 36 |
| ⬆️ Yetki Yükseltme | 11 |
| 🥷 Savunma Atlatma | 48 |
| 🔑 Kimlik Bilgisi Erişimi | 27 |
| 🗺️ Keşif (Discovery) | 20 |
| ↔️ Yatay Hareket | 9 |
| 📦 Toplama (Collection) | 13 |
| 📡 Komuta Kontrol (C2) | 20 |
| 📤 Sızıntı (Exfiltration) | 12 |
| 💥 Etki (Impact) | 6 |

### NIST CSF 2.0 Uyumu

Tüm skill'ler NIST Cybersecurity Framework 2.0 ile hizalanmıştır:
- **Govern (GV)** — Yönetişim, risk yönetimi
- **Identify (ID)** — Varlık yönetimi, risk değerlendirme
- **Protect (PR)** — Erişim kontrolü, veri güvenliği
- **Detect (DE)** — Sürekli izleme, anomali tespiti
- **Respond (RS)** — Müdahale, iletişim, analiz
- **Recover (RC)** — Kurtarma, iyileştirme

---

## 🚩 CTF Yarışmaları — 55 Skill + 109 Referans

CTF (Capture The Flag) yarışmalarında eksiksiz çözüm kabiliyeti. Her kategori için hem skill hem derinlemesine referans dokümanları:

| Kategori | Skill | Referans | Kapsam |
|----------|-------|----------|--------|
| **Web** | 10 | 20 | XSS, SQLi, SSTI, SSRF, XXE, JWT, deserialization, CSP bypass |
| **Crypto** | 14 | 16 | AES, RSA, ECC, padding oracle, LLL lattice, hash cracking |
| **Pwn** | 10 | 18 | Buffer overflow, ROP, heap exploitation, format string, kernel |
| **Reverse** | 6 | 18 | Binary analysis, unpacking, obfuscation, VM reversing |
| **Forensics** | 7 | 14 | Disk, memory, network PCAP, steganografi, log analizi |
| **OSINT** | 3 | 3 | Açık kaynak istihbaratı, sosyal medya analizi |
| **Misc** | 1 | 12 | Encoding, esoteric languages, regex, recon |
| **Auto-Solver** | 1 | 3 | Otomatik sınıflandırma + çözme pipeline'ı |
| **Hint System** | 1 | 1 | 3 seviyeli interaktif ipucu sistemi |
| **Competition** | 1 | — | Yarışma stratejisi ve zaman yönetimi |
| **Cheatsheets** | — | 4 | Hızlı referans kartları |

> **Siber Vatan playbook'u** da `red-teaming/siber-vatan-ctf/` içinde mevcuttur.

---

## 🩸 Red Team Operasyonları — 32 Skill

| Alt Kategori | Skill | Açıklama |
|-------------|-------|----------|
| **Red Team Operations** | 29 | Tam kapsamlı red team playbook'ları |
| **CTF Challenge Solver** | 1 | Challenge çözme asistanı |
| **God Mode** | 1 | Gelişmiş komut zincirleme |
| **Siber Vatan CTF** | 1 | Türkiye Siber Vatan programı özel playbook |

---

## 🎨 Diğer Kategoriler — 83 Skill

Güvenlik dışında kalan, günlük işlerde ve yaratıcı projelerde kullanılan skill'ler:

| Kategori | Skill | Açıklama |
|----------|-------|----------|
| **Creative** | 19 | Diyagram, infografik, pixel art, video, çizgi roman |
| **Software Development** | 11 | Kod üretimi, refactoring, test, API tasarımı |
| **Productivity** | 8 | Görev yönetimi, not alma, takvim |
| **MLOps** | 8 | Model eğitimi, deployment, monitoring |
| **GitHub** | 6 | Issue, PR, Actions, proje yönetimi |
| **Research** | 5 | Literatür tarama, analiz, raporlama |
| **Media** | 5 | Ses, video, görüntü işleme |
| **Apple** | 5 | macOS/iOS geliştirme, Swift, Xcode |
| **Autonomous AI Agents** | 4 | Otonom ajan tasarımı |
| **DevOps** | 3 | CI/CD, infrastructure, monitoring |
| **Gaming** | 2 | Oyun geliştirme |
| **Diğer** (6 kategori) | 6 | Email, sosyal medya, not alma, MCP, data science |

---

## 🗺️ Hızlı Erişim — Mapping Dosyaları

`skills/cybersecurity/` dizininde 6 adet index dosyası, 743 skill arasında anında arama yapmanızı sağlar:

| Dosya | Ne İşe Yarar | Örnek Kullanım |
|-------|-------------|----------------|
| `quick-ref.md` | **İlk bakılacak yer.** ATT&CK tekniği → skill eşlemesi | `grep T1055 quick-ref.md` |
| `mitre-attack-index.md` | 291 tekniğin tam dökümü | Taktik bazlı keşif |
| `mitre-attack-coverage.md` | Taktik → teknik → skill hiyerarşisi | Boşluk analizi |
| `nist-csf-index.md` | NIST CSF → skill eşlemesi | Compliance görevleri |
| `tool-index.md` | 233 araç → hangi skill'lerde kullanıldığı | `grep nmap tool-index.md` |
| `category-full-index.md` | Kategori → tüm skill listesi | Tam envanter |

---

## 🔐 Skill Koruma Sistemi

Her SKILL.md dosyasının sonunda FETIH imzası bulunur:

```html
<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: <benzersiz-sha256>
-->
```

Bu imza:
- Dosyanın FETIH için geliştirildiğini belgeler
- SHA256 hash ile bütünlük doğrulaması sağlar
- Yetkisiz kopyalamayı tespit edilebilir kılar

---

## ➕ Yeni Skill Ekleme

Yeni bir skill eklemek için `CONTRIBUTING.md`'deki rehberi takip edin. Her skill şu yapıda olmalıdır:

```
skills/<ana-kategori>/<alt-kategori>/<skill-adi>/
├── SKILL.md              # Ana skill tanımı (YAML frontmatter + içerik)
└── references/           # Referans dokümanlar (opsiyonel)
    └── ...
```

### Minimum SKILL.md Şablonu

```yaml
---
name: skill-adi
description: Kısa açıklama (bir cümle)
tags: [kategori, araclar]
triggers: ["tetikleyici1", "tetikleyici2"]
category: ana-kategori
mitre_attack: [TXXXX]
nist_csf: [XX.XX-XX]
adapted_for: fetih
---

# Skill Başlığı

Detaylı skill içeriği buraya...

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: <sha256>
-->
```

---

## 📈 Güncelleme Geçmişi

| Tarih | Değişiklik |
|-------|-----------|
| 2026-05-26 | v2.0 — 913 skill, 32 siber alt kategori, ithal skill entegrasyonu, imza sistemi |
| 2026-05-25 | v1.5 — 889 skill, 291 MITRE tekniği, 6 mapping dosyası |
| 2026-05-24 | v1.0 — 754 siber güvenlik skill'i, 29 red team skill'i |

---

> **FETIH AI Agent** — https://github.com/MustafaKemal0146/fetih
>
> *"Zafer, zafer benimdir diyebilenindir. Başarı ise, başaracağım diye başlayarak sonunda başardım diyebilenindir."*
>
> — Mustafa Kemal Atatürk
