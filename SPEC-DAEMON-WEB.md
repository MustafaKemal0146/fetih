# FETİH Daemon + Web UI Geliştirme SPEC

## Hedef
FETİH'e daemon modu eklemek ve web UI'ı OpenClaw kalitesine yükseltmek.

---

## Bölüm 1: Daemon Modu

### 1.1 `src/daemon.ts` — Daemon Manager

Yeni dosya: `src/daemon.ts`

```typescript
export interface DaemonConfig {
  port: number;          // Web sunucu portu (default: 4321)
  host: string;          // Bağlanılacak host (default: 'localhost')
  pidFile: string;       // PID dosya yolu (default: ~/.fetih/fetih.pid)
  logFile: string;       // Log dosya yolu (default: ~/.fetih/daemon.log)
  stateDir: string;      // State dizini (default: ~/.fetih/)
}

export interface DaemonStatus {
  running: boolean;
  pid: number | null;
  uptime: number | null;   // saniye cinsinden
  port: number;
  sessions: number;
  startedAt: string | null;
}
```

Fonksiyonlar:
- `startDaemon(config?: Partial<DaemonConfig>): Promise<void>`
  - PID dosyası yaz (`~/.fetih/fetih.pid`)
  - process.title = 'fetih-daemon'
  - Web server'ı başlat
  - WebSocket server'ı başlat
  - SIGHUP/SIGTERM/SIGINT handler'ları (graceful shutdown)
  - Log: `~/.fetih/daemon.log` (timestamp'li, rotatable)

- `stopDaemon(): Promise<void>`
  - PID dosyasından PID oku
  - SIGTERM gönder, 5sn bekle, SIGKILL
  - PID dosyasını sil

- `getDaemonStatus(): Promise<DaemonStatus>`
  - PID dosyası var mı kontrol et
  - Proses çalışıyor mu kontrol et (`kill -0 $PID`)
  - Çalışma süresi hesapla

- `isDaemonRunning(): Promise<boolean>`

- `setupDaemonDirectories(stateDir: string): Promise<void>`
  - `~/.fetih/` dizinini oluştur (yoksa)

### 1.2 CLI Flag'leri — `src/cli.ts`

Yeni flag'ler:

```
fetih daemon start     → startDaemon() çağır
fetih daemon stop      → stopDaemon() çağır
fetih daemon status    → getDaemonStatus() çağır, çıktıyı göster
fetih daemon restart   → stop → start
fetih --daemon         → Direkt daemon olarak başlat (REPL yerine)
fetih --port 4321      → Daemon port override
```

CLI arg parsing'ine ekle:
```typescript
case 'daemon':   // fetih daemon ...
case '--daemon':
case '-d':
case '--port':
```

### 1.3 Web Server Güncellemesi — `src/web/server.ts`

Mevcut server'a ekle:
- REST API endpoint'leri:
  - `POST /api/chat` — `{ message: string, session?: string }` → stream response veya JSON
  - `GET /api/status` — DaemonStatus JSON döndür
  - `GET /api/sessions` — Aktif session listesi
  - `GET /api/stats` — Kullanım istatistikleri
  - `POST /api/abort` — Mevcut işlemi iptal et
- CORS desteği (opsiyonel, development için)
- API anahtarı desteği (opsiyonel, `~/.fetih/api-key.txt`)
- Daemon modunda sadece localhost'ta dinle (güvenlik)
- WebSocket'e ek event'ler: `daemon_status`, `daemon_log`

### 1.4 Daemon Log Sistemi — `src/daemon-log.ts`

Yeni dosya: `src/daemon-log.ts`

```typescript
export function createDaemonLogger(logFile: string): {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
  debug: (msg: string) => void;
}
```

Log formatı: `[2026-04-30T18:55:00+03:00] [INFO] Mesaj`

### 1.5 systemd Service Dosyası — `scripts/fetih-daemon.service`

```ini
[Unit]
Description=FETİH AI Agent Daemon
After=network.target

[Service]
Type=simple
User=%i
ExecStart=/usr/local/bin/fetih daemon start
ExecStop=/usr/local/bin/fetih daemon stop
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

### 1.6 Kurulum Scripti — `scripts/install-daemon.sh`

- systemd service'i kur
- `~/.fetih/` dizinini oluştur
- Gerekli izinleri ayarla

---

## Bölüm 2: Web UI İyileştirmesi

### 2.1 Vite Kurulumu

Şu anki `web/public/index.html` (1800+ satır monolitik, CDN bağımlı) → Vite + vanilla JS ile modüler hale getir.

Proje yapısı:
```
web/
├── index.html          ← Ana HTML (çok küçük, sadece yapı)
├── vite.config.js      ← Vite config
├── package.json        ← web için ayrı package.json (opsiyonel)
├── src/
│   ├── main.js         ← Entry point, router
│   ├── ws.js           ← WebSocket client (bağlantı yönetimi, yeniden bağlanma)
│   ├── api.js          ← REST API client (fetch wrapper)
│   ├── state.js        ← Global state yönetimi (proxy-based)
│   ├── utils.js        ← Yardımcı fonksiyonlar
│   ├── views/
│   │   ├── chat.js     ← Sohbet görünümü
│   │   ├── dashboard.js ← Dashboard görünümü (grafikler, istatistikler)
│   │   ├── settings.js ← Ayarlar görünümü
│   │   └── logs.js     ← Log görünümü (daemon logları)
│   ├── components/
│   │   ├── message.js  ← Mesaj balonu bileşeni
│   │   ├── tool-card.js ← Tool çağrısı kartı
│   │   ├── status-bar.js ← Durum çubuğu
│   │   ├── sidebar.js  ← Kenar çubuğu (opsiyonel)
│   │   └── chart.js    ← Chart.js wrapper (opsiyonel)
│   └── styles/
│       ├── main.css    ← Global stiller
│       ├── variables.css ← CSS değişkenleri (tema)
│       ├── chat.css
│       ├── dashboard.css
│       └── components.css
```

### 2.2 Tasarım Hedefleri

- **OpenClaw kalitesi:** Temiz, minimal, koyu tema, grid arka plan
- **Renk paleti:** Mevcut FETİH paletini koru (bg: #060608, accent: #dc2626)
- **Font:** Space Grotesk (başlıklar), Fira Code (kod)
- **Responsive:** Mobil, tablet, masaüstü
- **Animasyonlar:** Geçişlerde subtle fade/slide, loading state'leri
- **Hiç CDN yok prod'da** — Tüm bağımlılıklar bundle içinde (highlight.js, marked, Chart.js)

### 2.3 Chat View Özellikleri

Mevcut özellikleri koru + ekle:
- [x] Mesaj geçmişi (scroll ile)
- [x] Markdown render (code highlighting dahil)
- [x] Streaming mesajlar (cursor animasyonu)
- [x] Tool call kartları (toggle ile açılıp kapanan)
- [x] Kullanıcı girdisi + enter/send
- [x] Komut desteği (/ ile başlayan)
- [x] Auto-scroll
- [ ] **Yeni: Ses kaydı desteği** (opsiyonel, Speech-to-Text)
- [ ] **Yeni: Mesaj düzenleme/gönderme**
- [ ] **Yeni: Prompt geçmişi (↑/↓)**
- [ ] **Yeni: Dosya yükleme desteği**

### 2.4 Dashboard View Özellikleri

- [x] Provider/model bilgisi
- [x] Token kullanım istatistikleri
- [x] Session sayısı
- [ ] **Yeni: Daemon durum kartı** (çalışıyor/durdu, PID, uptime)
- [ ] **Yeni: Tool kullanım grafiği** (en çok kullanılan tool'lar)
- [ ] **Yeni: Provider performans karşılaştırması** (response time, cost)
- [ ] **Yeni: Canlı log akışı** (WebSocket üzerinden)
- [ ] **Yeni: Daemon kontrol düğmeleri** (restart, stop, start)

### 2.5 Settings View Özellikleri

Mevcutları koru:
- [x] Provider seçimi
- [x] Model seçimi
- [x] Effort seviyesi
- [x] Permission seviyesi
- [x] Security profile
- [x] Tema seçimi
- [ ] **Yeni: Daemon config** (port, host ayarları)
- [ ] **Yeni: API key yönetimi**
- [ ] **Yeni: Varsayılan prompt/instruction ayarları**

### 2.6 Logs View

- [ ] **Yeni: Daemon log akışı** (WebSocket üzerinden real-time)
- [ ] **Yeni: Log seviyesi filtresi** (INFO/WARN/ERROR/DEBUG)
- [ ] **Yeni: Log arama**
- [ ] **Yeni: Log temizleme**
- [ ] **Yeni: Otomatik scroll**

### 2.7 Build & Deploy

- `npm run build:web` → Vite build, çıktıyı `web/public/` yerine `dist/web/` yap
- `npm run dev:web` → Vite dev server (HMR ile)
- Mevcut web server statik dosyaları `web/public/` yerine `dist/web/`den serve etsin

---

## Bölüm 3: Tümleştirme

### 3.1 package.json Güncellemesi

Yeni script'ler:
```json
{
  "scripts": {
    "dev:web": "cd web && npx vite",
    "build:web": "cd web && npx vite build",
    "daemon": "node dist/cli.js daemon start",
    "install:daemon": "bash scripts/install-daemon.sh"
  }
}
```

### 3.2 Web Server Statik Dosya Yolu

`src/web/server.ts`'de:
```typescript
// Önce dist/web dene, yoksa web/public
const publicPath = existsSync(join(__dirname, '..', '..', 'dist', 'web'))
  ? join(__dirname, '..', '..', 'dist', 'web')
  : join(__dirname, '..', '..', 'web', 'public');
```

---

## Teslimat Kriterleri

1. `fetih daemon start` → Web server + WebSocket çalışıyor, PID dosyası yazılmış
2. `fetih daemon stop` → Graceful shutdown, PID dosyası silinmiş
3. `fetih daemon status` → Doğru durum bilgisi (çalışıyor/PID/uptime)
4. `curl http://localhost:4321/api/status` → JSON dönüyor
5. `curl -X POST http://localhost:4321/api/chat -d '{"message":"merhaba"}'` → Yanıt dönüyor
6. Web UI: Chat çalışıyor, dashboard daemon durumunu gösteriyor
7. Web UI: Vite build alınıyor, prod'da CDN yok
8. `npm run build:web` → `dist/web/` oluşuyor
9. Web UI mobile'da düzgün görünüyor
10. Tüm mevcut testler geçiyor (`npm test`)

---

## Önemli Uyarılar

- **Mevcut kodu kırma!** Tüm eklemeler geriye dönük uyumlu olmalı
- **Testler geçmeli** — daemon ekledikten sonra `npm test` hata vermemeli
- **Web UI'ın mevcut özelliklerini koru** — sadece iyileştir, silme
- **TypeScript strict mode** — her şey type-safe
- **Kod kalitesi** — OpenClaw seviyesinde temiz kod
