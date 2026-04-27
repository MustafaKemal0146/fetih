# Değişiklik Günlüğü

## [3.9.6] - 2026-04-27

### 🚀 Yeni Özellikler

- **Self-Update Sistemi** (`src/update-check.ts`): SETH artık kendi kendini güncelleyebiliyor!
  - `/güncelle --auto` ile REPL içinden otomatik güncelleme
  - `seth --update` / `seth -u` ile CLI'dan direkt güncelleme
  - Git clone ortamında: `git fetch` → `git pull` → `npm run build`
  - npm global ortamında: `npm install -g`
  - Yerel değişiklikleri otomatik stash'leme ve geri alma
  - GitHub release kontrolü + cache mekanizması
  - Progress callback ile adım adım ilerleme bildirimi

### 📝 Dokümantasyon
- **Intro mesajı** güncellendi: Yeni sürüm bulunca `/güncelle --auto` öneriyor
- **README güncellenecek**: Self-update kullanım talimatları

## [3.8.4] - 2026-04-19

### 🐛 Hata Düzeltmeleri

- **Oturum kurtarma** (`src/session-recovery.ts`): Crash sonrası kurtarma artık yalnızca metadata (mesaj sayısı, provider) değil, mesajların tamamını, lane B geçmişini, aktif lane'i ve token kullanımını kaydediyor. Eski format geriye dönük uyumlu.

- **Puppeteer** (`package.json`): Kullanımdan kaldırılmış `^23.0.0` sürümünden `^24.0.0` sürümüne yükseltildi (yüklenen: 24.41.0).

### 🔒 Güvenlik

- **Sistem istemi** (`src/prompts/system.ts`): Kurucu sadakat protokolü (LOYALTY) kaldırıldı. Bu blok açık kaynak ve çok kullanıcılı dağıtımlarda güven/denetim riski oluşturuyordu.

### 🧪 Testler

- **Yeni test dosyası** (`tests/seth.test.ts`): 27 yeni test eklendi.
  - Sistem istemi bütünlüğü (sadakat protokolü kaldırma kontrolü dahil)
  - `ToolRegistry`: kayıt, tekrar kayıt engeli, şema dönüşümü, silme
  - `ToolExecutor`: bilinmeyen araç, başarılı çalıştırma, exception yönetimi, engellenen araç
  - `session-recovery`: tam mesaj kayıt/geri yükleme, temizleme, eksik dosya
  - `agent/loop`: tek tur yanıt, abort signal, fallback provider, araç çağrısı akışı
- Toplam test sayısı: 10 → **37**

### ⚙️ CI/CD

- **GitHub Actions** (`.github/workflows/ci.yml`): `actions/setup-node@v4` kullanan GitHub CI pipeline eklendi. Node 18/20/22 matrix testi + `npm audit --audit-level=high` güvenlik taraması.
- **laction.yaml** (proje kökü): Yerel `laction` aracı için manuel apt tabanlı Node kurulumu içeren eşdeğer pipeline eklendi.
