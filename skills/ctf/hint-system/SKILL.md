---
name: hint-system
description: >
  CTF challenge'lar icin asamali ipucu sistemi. 3 seviye sunar: Nudge (genel yonlendirme), Direction (spesifik ipucu), Solution (tam cozum). /hint komutuyla calisir.
tags: [ctf, hint, ipucu, learning, progressive, education]
triggers:
  - "ipucu ver"
  - "hint"
  - "/hint"
  - "takıldım"
  - "yardım et"
  - "çözümü göster"
  - "nudge"
category: ctf
adapted_for: fetih
---

# CTF Hint System — Aşamalı İpucu Sistemi

CTF challenge'ında takılan kullanıcıya aşamalı ipucu veren sistem. Her seviye bir öncekinden daha spesifiktir. `/hint` slash komutuyla veya "ipucu ver" diyerek çağrılır.

## İpucu Seviyeleri

| Seviye | Komut | Açıklama | Örnek |
|--------|-------|----------|-------|
| **Level 1** | `/hint` veya `ipucu ver` | **Nudge** — Genel yönlendirme. Challenge kategorisini ve genel yaklaşımı söyler. Çözümü direkt vermez. | "Bu bir SQL injection challenge'ı. Input validation'a odaklan." |
| **Level 2** | `/hint more` | **Direction** — Spesifik yön. Hangi dosyaya/endpoint'e bakılacağını, hangi aracın kullanılacağını söyler. | "Login formundaki username alanını incele. Özel karakterler filtreleniyor mu?" |
| **Level 3** | `/hint solution` | **Solution** — Tam çözüm. Adım adım çözümü veya flag'i verir. | "username=' OR 1=1-- ile giriş yap. Admin paneline yönlendirileceksin." |

## Durum Komutları

| Komut | Açıklama |
|-------|----------|
| `/hint status` | Mevcut challenge ve hint seviyesini göster |
| `/hint reset` | Hint seviyesini sıfırla, yeni challenge için hazırla |

## İş Akışı

### Adım 1: Challenge Bağlamını Analiz Et

```bash
# Hangi dosyalar açık? Hangi URL'deyiz?
ls -la                        # Çalışma dizinindeki dosyalar
pwd                          # Hangi challenge dizinindeyiz?
history | tail -20           # Son çalıştırılan komutlar
```

### Adım 2: Challenge Kategorisini Belirle

Dosya tiplerine ve challenge metnine göre kategoriyi tespit et:

```
Web:      URL verilmiş, HTTP, form, JavaScript
Crypto:   şifreli metin, RSA parametreleri, hash
Reverse:  binary/ELF/PE dosyası, .apk
Forensics: .pcap, .raw, .vmem, disk image
Stego:    .png, .jpg, .wav (gizli veri içeren medya)
Pwn:      netcat bağlantısı, binary exploitation
OSINT:    kişi/yer araştırması, sosyal medya
```

### Adım 3: Uygun Seviyede İpucu Ver

**Level 1 (Nudge) Pattern'leri:**
- Kategoriyi söyle ama çözümü söyleme
- Genel yaklaşımı öner: "Input validation'a bak", "Encoding katmanlarını dene"
- Yaygın tuzaklar konusunda uyar: "flag formatına dikkat et"
- "Şu ana kadar ne denedin?" diye sor

**Level 2 (Direction) Pattern'leri:**
- Spesifik dosya/endpoint: "robots.txt'yi kontrol et"
- Spesifik araç: "Burp Suite ile request'i intercept et"
- Spesifik teknik: "Base64 decode etmeyi dene, sonra XOR"
- Kod parçacığı öner (tam çözüm değil): "Şu pattern'le ara: ..."

**Level 3 (Solution) Pattern'leri:**
- Adım adım çözüm
- Tam komutlar
- Flag veya flag'e götüren son adım
- Alternatif çözüm yolları

## Kategori Bazlı İpucu Kataloğu

### Web Challenge İpuçları
```
Level 1: "Sayfa kaynağını incele (Ctrl+U). Gizli yorumlar, base64 string'ler, JS dosyaları var mı?"
Level 2: "/robots.txt ve /admin endpoint'lerini kontrol et. Cookie'leri incele."
Level 3: "Admin paneline erişmek için Origin header'ını site domain'i ile değiştir."
```

### Crypto Challenge İpuçları
```
Level 1: "Bu bir şifreleme challenge'ı. Encoding katmanlarını (base64, hex) kontrol et."
Level 2: "Ciphertext'in uzunluğu AES blok boyutuna uyuyor mu? IV var mı?"
Level 3: "AES-CBC için padding oracle attack'ı dene. pycryptodome kullan."
```

### Reverse Engineering İpuçları
```
Level 1: "Binary'yi analiz et. strings çıktısına bak, ilginç string'ler var mı?"
Level 2: "Ghidra/IDA ile decompile et. main() fonksiyonundaki karşılaştırmalara bak."
Level 3: "Şu adresteki compare instruction'ı patch'le ya da key'i brute-force et."
```

### Forensics İpuçları
```
Level 1: "Dosya tipini doğrula (file komutu). Magic bytes doğru mu?"
Level 2: "binwalk ile gömülü dosyaları çıkar. strings ile flag pattern'i ara."
Level 3: "PCAP'teki TCP stream'lerini takip et. TLS olmayan stream'de flag var."
```

## Durum Takibi

Hint seviyeleri `~/.fetih/ctf_hints.json` dosyasında challenge başına takip edilir:

```json
{
  "current_challenge": "web-login-bypass",
  "hint_level": 2,
  "history": [
    {"level": 1, "timestamp": "2026-05-26T10:00:00", "hint": "SQL injection challenge..."},
    {"level": 2, "timestamp": "2026-05-26T10:05:00", "hint": "Login formundaki..."}
  ]
}
```

## Pivot Stratejisi (Siber Vatan Playbook ile Uyumlu)

3 başarısız flag denemesinden sonra:
1. Hint seviyesini otomatik artır
2. Tool zincirini değiştir
3. Vulnerability class'ı değiştir
4. `/hint solution` ile tam çözüme geç

## Önemli Notlar

- **Öğrenme odaklı:** Amacın direkt cevabı vermek değil, kullanıcının öğrenmesini sağlamak
- **Level 1 her zaman ilk:** Kullanıcı direkt çözüm istese bile önce Level 1 ver
- **Bağlamı koru:** Her ipucu önceki ipuçlarıyla tutarlı olmalı
- **Türkçe challenge'lar için Türkçe ipucu:** Siber Vatan gibi yarışmalarda Türkçe yanıt ver
- **Flag'i asla düz metin verme:** Level 3'te bile flag'i `SiberVatan{...}` formatında, challenge'ı çözdürecek şekilde ver

## Referanslar

- `references/hint-levels.md` — Detaylı ipucu seviyeleri ve pattern kataloğu
- Siber Vatan CTF Playbook — `skills/red-teaming/siber-vatan-ctf/SKILL.md`
- CTF Master Solver — `skills/ctf/SKILL.md`

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 8b694ce9ebc51ac1
-->

