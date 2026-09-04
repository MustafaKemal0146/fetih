# FETİH Windows Uygulaması — Tasarım ve Yapım Planı

> Durum: Taslak v2 (native WinUI 3 mimarisi)
> Önceki taslaktaki **WebView2 / React hibrit** yaklaşımı tamamen iptal edilmiştir.
> Bu belge saf native bir Windows uygulamasını tanımlar.

---

## a) Özet ve Hedef

FETİH bir **siber güvenlik aracıdır**: CTF çözümü, sızma testi, OSINT, adli bilişim ve
kırmızı takım operasyonları için tasarlanmış, model-agnostik bir ajan. Gücü iki yerden gelir:

1. **Her modeli bağlayabilme** — Anthropic, OpenAI, Gemini, Bedrock, Azure, Copilot,
   LM Studio, Codex ve yerel modeller (`agent/*_adapter.py` altındaki sağlayıcı katmanı).
2. **Skill dosyaları** — `skills/` altındaki 28 alan; bunların içinde `cybersecurity/`
   (36 alt disiplin: pentest, malware analizi, threat hunting, cloud/container/OT-ICS
   güvenliği, MITRE ATT&CK indeksleri), `ctf/` (crypto, pwn, rev, web, forensics, osint,
   auto-solver, hint-system) ve `red-teaming/` (red-team-operations, godmode,
   ctf-challenge-solver, siber-vatan-ctf).

Hedef: Bu yeteneklerin **tamamına** erişebilen, **tamamen native** bir Windows masaüstü
uygulaması yapmak.

**Kapsam kararları:**

| Karar | Gerekçe |
|---|---|
| Saf WinUI 3 (C#/.NET), HTML/JS/React **yok** | Kullanıcı talebi. Tek teknoloji yığını, tek derleme zinciri, gerçek Windows 11 görünümü (Mica, Fluent, tema, erişilebilirlik) bedava gelir. |
| Kurulum ekranları uygulamanın **içinde** | Ayrı bir installer + ayrı bir uygulama iki farklı hata yüzeyi demek. Tek `.exe` her şeyi yapar. |
| Linux tarafında GUI **yok** | Linux'ta terminal (TUI) kullanımı zaten mevcut ve yeterli. Linux için yalnızca `scripts/install.sh` kurulum deneyimi iyileştirilecek (opsiyonel, düşük öncelik). |
| Arka uç Python'da kalır | Ajan mantığı, skill'ler, araçlar, sağlayıcılar zaten Python. Bunları C#'a taşımak yeniden yazım olur. Native uygulama **kabuk (shell)**, Python **motor**. |

---

## b) Mimari

### ⚠️ ÖNCE İSİMLENDİRME: "Gateway" kelimesi ZATEN dolu

Bu, plandaki en kolay karıştırılacak nokta. FETİH'in kendi dilinde **"gateway"**
şu anda **mesajlaşma platformu köprüsü** demektir — Telegram, Discord, WhatsApp:

- `gateway/` paketi → `channel_directory.py`, `pairing.py`, `platforms/`, `delivery.py`
- `scripts/fetih-messaging-gateway` → *"Standalone messaging platform integration... NOT tied to
  the CLI"*
- `fetih_cli/gateway.py`, `gateway_windows.py`
- install.ps1'deki `gateway` aşamasının başlığı: *"Starting messaging gateway"*
- README/repo açıklamasındaki "Telegram/Discord gateway"

Native uygulamanın bağlanacağı **yeni katman bambaşka bir şeydir**: bir UI taşıma
katmanı (JSON-RPC/WebSocket). Aynı kelimeyi kullanmak kalıcı kafa karışıklığı yaratır —
"gateway çalışmıyor" diyen bir kullanıcının Telegram köprüsünden mi masaüstü
bağlantısından mı bahsettiği asla anlaşılmaz.

**Karar: yeni bileşenin adı `fetih_desktop_bridge` (TR: "Masaüstü Köprüsü").**
"Gateway" kelimesi mesajlaşma anlamı için saklanır ve yeni kodun hiçbir yerinde
kullanılmaz.

| Kavram | Ad | Ne yapar |
|---|---|---|
| Mesajlaşma köprüsü (mevcut) | **Gateway** — `gateway/` | Telegram/Discord/WhatsApp ↔ ajan |
| UI taşıma katmanı (yeni) | **Masaüstü Köprüsü** — `fetih_desktop_bridge/` | WinUI 3 uygulaması ↔ ajan |

Sınıf/olay adlandırmasında da ayrım korunur: `bridge.ready`, `BridgeClient`,
`FETIH_BRIDGE_PORT`, `FETIH_BRIDGE_TOKEN`. **`FETIH_GATEWAY_*` kullanılmaz** — o ad
alanı mesajlaşma tarafına aittir. ("Hermes" kelimesi de doğal olarak hiçbir yerde geçmez.)

### Genel görünüm

```
┌──────────────────────────────────────┐         ┌────────────────────────────────┐
│  Fetih.Desktop  (WinUI 3 / C# .NET)  │         │  Python: fetih_desktop_bridge  │
│                                      │         │                                │
│  ┌────────────┐  ┌────────────────┐  │  WS /   │  ┌──────────────────────────┐  │
│  │ Shell:     │  │ Fetih.Bridge   │◄─┼─ JSON- ─┼─►│ dispatch()  ← tek giriş  │  │
│  │ NavView    │  │ Client (C#)    │  │  RPC    │  │  methods_*.py            │  │
│  │ + Pages    │  │  - reconnect   │  │ (NDJSON)│  └───────────┬──────────────┘  │
│  └────────────┘  │  - event bus   │  │         │              │                 │
│  ┌────────────┐  │  - typed DTOs  │  │         │  ┌───────────▼──────────────┐  │
│  │ Setup      │  └────────────────┘  │         │  │ agent/ · skills/ ·       │  │
│  │ Wizard     │◄── install.ps1 ──────┼─────────┼─►│ tools/ · providers/      │  │
│  └────────────┘    (stage protocol)  │         │  └──────────────────────────┘  │
└──────────────────────────────────────┘         └────────────────────────────────┘
                                                              │
                                                              ▼
                                                  ┌────────────────────────┐
                                                  │ gateway/  (AYRI ŞEY)   │
                                                  │ Telegram · Discord ·   │
                                                  │ WhatsApp köprüsü       │
                                                  └────────────────────────┘
```

### İletişim protokolü

**Satır sonlu JSON-RPC (NDJSON)**, iki taşıma üzerinde aynı sözleşme:

- **stdio** — uygulama Python sürecini kendi başlatır (varsayılan, en güvenli).
- **WebSocket** — `ws://127.0.0.1:<port>`, uzak/paylaşımlı gateway veya WSL senaryosu için.

Bu ikilik hermes-agent'ın `tui_gateway` modülünden alınan mimari derstir: orada
`transport.py` bir `Transport` protokolü tanımlar, aktif taşıma `contextvars` üzerinden
izlenir ve `server.dispatch()` **aynen** hem `entry.py` (stdio) hem `ws.py` (WebSocket)
tarafından çağrılır. Yani her RPC metodu, her onay akışı, her ajan olayı tek bir yerde
yazılır; istemcinin ne olduğu (TUI, mobil, masaüstü) hiç fark etmez.

### `fetih_desktop_bridge` modülü (yeni)

Önerilen dosya yapısı (hermes'in `tui_gateway` modül ayrımından esinlenilmiş,
sadeleştirilmiş ve FETİH adlandırmasına çevrilmiş):

```
fetih_desktop_bridge/
  __init__.py
  entry.py            # stdio giriş noktası: python -m fetih_desktop_bridge
  ws.py               # WebSocket sunucusu (aynı dispatch'i kullanır)
  transport.py        # Transport protokolü + stdio/WS uygulamaları
  server.py           # dispatch() + metot kayıt defteri
  event_publisher.py  # ajan olaylarını istemciye akıtma
  methods_session.py  # oturum aç/kapat/geçmiş/checkpoint
  methods_prompt.py   # mesaj gönder, stream token, iptal
  methods_tools.py    # araç çağrıları, onay (approval) akışı, çıktı akışı
  methods_config.py   # ayarlar, sağlayıcı/model yönetimi, API anahtarları
  methods_files.py    # dosya ağacı, oku, diff, ek (attachment)
  methods_skills.py   # skill kataloğu, arama, çalıştırma  ← FETİH'e özgü
  methods_setup.py    # kurulum/onboarding durumu ve adımları ← FETİH'e özgü
  methods_audio.py    # ses girişi/çıkışı (TTS/STT)
```

### Köprünün native uygulamaya sunması gereken yüzey

Native uygulamanın **hiçbir şey için** ayrı bir yola ihtiyacı olmamalı. Masaüstü
Köprüsü şunları kapsamalı:

| Alan | Metotlar (öneri) | Açıklama |
|---|---|---|
| Bağlantı | `bridge.ready` (olay), `bridge.capabilities`, `bridge.ping` | Sürüm, yetenek pazarlığı, sağlık |
| Sohbet | `prompt.send`, `prompt.cancel`, `prompt.delta` (olay), `prompt.done` | Token bazlı akış |
| Oturum | `session.list/new/open/rename/delete`, `session.history`, `session.checkpoint` | Geçmiş ve dallanma |
| Araçlar | `tool.call` (olay), `tool.output` (olay), `approval.request` / `approval.respond` | Araç çalıştırma ve **onay** akışı |
| Dosya | `file.tree`, `file.read`, `file.diff`, `file.attach` | Sonuç/kanıt inceleme |
| Skill | `skills.catalog`, `skills.search`, `skills.detail`, `skills.run` | Güvenlik testlerinin kataloğu |
| Sağlayıcı | `providers.list`, `providers.test`, `models.list`, `config.get/set` | Model-agnostiklik burada görünür olur |
| Kurulum | `setup.state`, `setup.manifest`, `setup.run_stage`, `setup.progress` (olay) | install.ps1 sarmalayıcısı |
| Ses | `audio.stt.start/stop`, `audio.tts.speak` | Sesli komut |
| Tanılama | `diagnostics.snapshot`, `diagnostics.logs` | Destek/hata ayıklama |
| Mesajlaşma | `channels.status`, `channels.list` | **Mevcut** `gateway/` köprüsünün *durumunu okur* — onu yönetmez. Kullanıcı Telegram/Discord bağlantısını uygulamadan görebilsin diye. |

**Güvenlik:** WebSocket modu yalnızca `127.0.0.1`'e bağlanır ve her oturumda üretilen
bir **tek kullanımlık token** ister (`FETIH_BRIDGE_TOKEN`). Token, uygulama süreci
Python'u başlatırken ortam değişkeniyle geçirilir; dosyaya yazılmaz. Bu bir siber
güvenlik aracı — kendi kontrol kanalı açıkta durmamalı.

---

## c) OpenClaw Araştırmasının Sonucu

### Soy zinciri (kesinleşti)

```
OpenClaw  ──►  Hermes Agent  ──►  FETİH
(orijinal,     (Nous Research      (bu depo)
 MIT)           fork/rebrand)
```

Depo içi kanıt: `optional-skills/migration/openclaw-migration/SKILL.md` — kullanıcının
`~/.openclaw` kurulumunu FETİH'e taşıyan bir skill; `fetih claw migrate` CLI komutu ve
`scripts/openclaw_to_hermes.py` betiği. Dosya adının kendisi (`openclaw_to_hermes`)
zincirin iki halkasını birden gösteriyor.

Bu, FETİH'in Python tarafındaki kod düzeninin neden OpenClaw/Hermes ile hizalı
olduğunu açıklıyor ve `tui_gateway` mimarisini örnek almanın neden doğal olduğunu
doğruluyor: aynı soydan geliyoruz.

### Önemli düzeltme: Hermes'in masaüstü uygulaması WinUI 3 DEĞİL

Ekran görüntüsündeki WinUI 3 uygulamasının hermes'in masaüstü uygulamasının atası
olduğu hipotezi **doğrulanmadı**. `hermes-agent/apps/desktop/` incelendiğinde:

```
electron/  vite.config.ts  index.html  components.json  playwright.config.ts
tsconfig.electron.json  eslint.config.mjs  src/  e2e/
```

Yani hermes'in masaüstü uygulaması **Electron + Vite + React/TypeScript**. WinUI 3 ile
hiçbir ilgisi yok. Dolayısıyla:

- **İki ayrı masaüstü soyu var.** OpenClaw ekosisteminde hem bir Electron/web tabanlı
  masaüstü (hermes'in devraldığı) hem de ayrı bir native WinUI 3 companion
  (`openclaw-windows-node`) mevcut. Bunlar kardeş projeler, ata-torun değil.
- **Hermes'in `apps/desktop`'undan alacağımız UI kodu yok** — teknoloji yığını
  tamamen farklı ve zaten reddettiğimiz web yaklaşımı. Oradan alınacak tek şey
  *arka uç sözleşmesi*, yani `tui_gateway` protokolü. Bunu zaten yapıyoruz.
- **Bu, native kararımızı güçlendiriyor.** Zincirdeki her masaüstü denemesi
  (OpenClaw'ın WebView2 sohbeti, hermes'in Electron uygulaması) web teknolojisine
  yaslanmış. FETİH bu kalıptan bilinçli olarak ayrılıyor: tek yığın, gerçek native
  kontroller, WebView2/Chromium bağımlılığı yok.

### Windows companion projesi

**Bulundu — proje gerçek, halka açık ve MIT lisanslı.**

| | |
|---|---|
| Ana proje | `github.com/openclaw/openclaw` — TypeScript/Swift, MIT, açık kaynak ajan |
| Windows kabuğu | **`github.com/openclaw/openclaw-windows-node`** — "the native Windows companion for OpenClaw" |
| Lisans | **MIT** (izin verici; atıf şartıyla uyarlama serbest) |
| Hedef çatı | **.NET 10**, WinUI 3 / Windows App SDK, Windows 10 20H2+ |
| Gateway bağlantısı | **WebSocket, varsayılan `ws://localhost:18789`, JSON-RPC** |

Ekran görüntüsündeki uygulama bu projeyle birebir örtüşüyor: "Companion Settings"
gezinme yapısı (Connection / Permissions / Sandbox / Diagnostics), Gateway bağlantı
hatası kutusu ve "Unpackaged (developer)" kurulum tipi hepsi bu depodaki
`OpenClaw.Tray.WinUI` uygulamasının davranışı.

### Depo yapısı (bizim için referans)

| Proje | İşi | Bizdeki karşılığı |
|---|---|---|
| `OpenClaw.Tray.WinUI` | WinUI 3 kabuk, tray, ayar sayfaları | `Fetih.Desktop` |
| `OpenClaw.Shared` | Gateway istemcisi, Windows yetenekleri, tanılama | `Fetih.Core` |
| `OpenClaw.Connection` | Gateway kaydı, kimlik bilgisi, bağlantı ömrü | `Fetih.Connection` |
| `OpenClaw.Chat` | Native sohbet modeli/durumu | `Fetih.Chat` |
| `OpenClaw.SetupEngine` + `.UI` | Kurulum motoru + WinUI sihirbaz sayfaları | `Fetih.Setup` + `Fetih.Setup.UI` |
| — | — | *(Not: bizde `OpenClaw.Connection`+`OpenClaw.Shared`'ın gateway istemcisi karşılığı `Fetih.Bridge`'tir; adlandırma çakışmasını önlemek için "gateway" kelimesi taşınmaz.)* |
| `OpenClawTray.FunctionalUI` | Bildirimsel WinUI yardımcıları | (opsiyonel) |
| `OpenClaw.Cli` | Gateway WebSocket doğrulayıcı | `fetih-gw-probe` |

### Ne alınır, ne alınmaz

**Alınabilir (mimari ilham + MIT kapsamında uyarlanabilir iskelet):**

- **Katman ayrımı**: kabuk / paylaşılan çekirdek / bağlantı / kurulum motorunun ayrı
  projeler olması. Kurulum sihirbazının kendi projesi olması özellikle iyi bir fikir —
  bizim de istediğimiz tam olarak bu.
- **Bağlantı ömrü yönetimi**: kayıt defteri + kimlik bilgisi saklama + yeniden bağlanma
  ve "Transport error" gibi hataların kullanıcıya sayfa üstünde net bir kutuyla
  gösterilmesi.
- **Sayfa iskeleti**: `NavigationView` + sayfa başına ayrı `Page`, alt tarafta
  Diagnostics/Settings sabitleri.
- **Tanılama sayfası deseni**: runtime sürümü, mimari, "Unpackaged (developer)" kurulum
  tipini yüzeye çıkarmak — hata raporlarında paha biçilmez.
- **Unpackaged geliştirme akışı**: `dotnet run --project ... -r win-x64`, ve
  `scripts/setup-dev.ps1` benzeri winget tabanlı ön koşul kurucu.

**Alınmaz:**

- **WebView2 gömülü sohbet penceresi.** OpenClaw'ın tray uygulaması sohbeti WebView2
  içinde gösteriyor. Biz burada **bilinçli olarak ayrılıyoruz** — sohbet dahil her şey
  native WinUI kontrolleriyle çizilecek.
- **Marka varlıkları**: isim, ikonlar (pixel-art logo), metinler. Hiçbiri kopyalanmaz.
- **Tray-öncelikli tasarım**: OpenClaw esas olarak bir tepsi (tray) yardımcısı; FETİH ise
  tam ekran çalışılan bir operasyon konsolu. Tray yalnızca ikincil kısayol olur.
- **WSL/node kayıt mimarisi**: Bizim Python arka ucumuz doğrudan Windows'ta çalışır,
  WSL provizyonuna ihtiyaç yok.

**Hukuki not:** MIT lisansı kod uyarlamaya izin verir ancak **telif ve lisans metninin
korunmasını** şart koşar. Eğer gerçekten dosya uyarlarsak, depoya bir
`THIRD_PARTY_NOTICES.md` eklenip OpenClaw'ın MIT bildirimi oraya yazılmalıdır.
Pratik tavsiye: **dosya kopyalamak yerine yapıyı örnek alıp sıfırdan yazmak** daha
temiz olur; zaten uyarlanacak kısımlar (proje dosyaları, `App.xaml.cs`, NavigationView
kabuğu) Microsoft'un resmi şablonlarında da mevcut.

### Alternatif / tamamlayıcı meşru başlangıç noktaları

- **Visual Studio "Blank App, Packaged (WinUI 3 in Desktop)"** şablonu — resmi iskelet.
- **[WinUI 3 Gallery](https://github.com/microsoft/WinUI-Gallery)** (MIT) — her kontrolün
  canlı örneği ve XAML kaynağı; NavigationView kabuğu için birebir referans.
- **[Windows App SDK Samples](https://github.com/microsoft/WindowsAppSDK-Samples)** (MIT).
- **[Windows Community Toolkit](https://github.com/CommunityToolkit/Windows)** (MIT) —
  `SettingsCard`, `SettingsExpander` kontrolleri ayarlar/kurulum ekranları için hazır.
- **[Template Studio for WinUI](https://github.com/microsoft/TemplateStudio)** (MIT) —
  NavigationView + MVVM + ayar sayfaları olan bir projeyi sihirbazla üretir. **Faz 1
  için en hızlı yol muhtemelen budur.**

---

## d) Kurulum Ekranları — Uygulamanın Bir Parçası

Bu, planın en kritik parçası. Kullanıcının bugün yaşadığı PATH ve bağımlılık sorunları
buradan çözülür.

### Zaten elimizde olan avantaj

`scripts/install.ps1` içinde **hazır bir "stage protocol"** var (protokol sürümü 1) ve
yorumunda aynen şöyle diyor: *"lets programmatic callers (the desktop GUI's onboarding
wizard, CI, ...) drive the install one step at a time and surface progress/errors with
their own UI."* Yani installer, bir GUI sihirbazı tarafından sürülmek üzere **zaten
tasarlanmış**. Sıfırdan bir şey icat etmiyoruz.

Kullanılabilir giriş noktaları:

```powershell
install.ps1 -ProtocolVersion     # protokol sürümü (tamsayı)
install.ps1 -Manifest            # aşama listesi, JSON
install.ps1 -Stage <ad> -Json    # tek aşama çalıştır, JSON sonuç
install.ps1 -NonInteractive      # tüm Read-Host promptlarını kapat
install.ps1 -ShowResolvedPaths   # çözümlenen yolları JSON olarak yaz
```

Manifestteki aşamalar (kategorileriyle) doğrudan sihirbazın adım listesi olur:

- **prereqs**: `uv`, `python`, `git`, `node`, `system-packages` (ripgrep, ffmpeg)
- **install**: `repository`, `venv`, `dependencies`, `node-deps`
- **finalize**: `path`, `config-templates`, `platform-sdks`
- **post-install** (`NeedsUserInput = true`): `configure`, `gateway`
  → Bu ikisi sihirbazda **native ekranlarla** yapılır; installer'ın kendi
  `Read-Host` promptları hiç çalıştırılmaz.

### Sihirbaz akışı (ilk açılış)

1. **Hoş geldiniz** — FETİH nedir, ne yapar (siber güvenlik ajanı), gizlilik notu.
2. **Sistem denetimi** — `-Manifest` çağrılır, her aşama için canlı durum listesi
   (bekliyor / çalışıyor / tamam / atlandı+sebep / hata+günlük). Aşamalar
   `-Stage <ad> -Json` ile **tek tek** çalıştırılır, ilerleme çubuğu gerçek olur.
   `node` gibi opsiyonel aşamalar `skipped=true` + `reason` döndüğünde uyarı olarak
   gösterilir, akış durmaz.
3. **Sağlayıcı ve model seçimi** — `configure` aşamasının native karşılığı.
   Sağlayıcı kartları (Anthropic, OpenAI, Gemini, Bedrock, Azure, Copilot, LM Studio,
   yerel...), API anahtarı girişi ve **"Bağlantıyı test et"** düğmesi
   (`providers.test`). Anahtarlar **Windows Credential Manager**'da saklanır, düz
   metin dosyada değil.
4. **Çalışma alanı** — varsayılan proje/kanıt klasörü, sandbox politikası, hangi
   araçların onay isteyeceği (bir pentest aracı için varsayılan **onay iste**).
5. **Hazır** — özet + "İlk oturumu başlat".

### PATH sorununun kalıcı çözümü

Bu sorun bir daha yaşanmamalı. Kural: **uygulama asla kullanıcının `PATH`'ine güvenmez.**

- Kurulum sırasında çözümlenen mutlak yollar (`python.exe`, `uv.exe`, `git.exe`,
  `rg.exe`, `node.exe`, venv kökü) uygulamanın kendi ayar deposuna yazılır.
- Python süreci **kendi başlatıcımızla** başlatılır: `ProcessStartInfo` ile
  venv içindeki `python.exe`'nin **tam yolu**, `UseShellExecute = false`,
  ortam değişkenleri (`PATH`, `FETIH_HOME`, `PYTHONUNBUFFERED=1`,
  `FETIH_BRIDGE_TOKEN`) **açıkça** kurulur.
- Bir yol geçersizleşirse (kullanıcı Python'u sildi/taşıdı) uygulama bunu bağlantı
  hatası olarak değil, **"Onarım gerekiyor"** ekranı olarak gösterir ve ilgili
  install aşamasını yeniden çalıştırmayı önerir.
- Ayarlar > Tanılama altında her zaman görünür bir **"Çözümlenen yollar"** paneli
  bulunur (`-ShowResolvedPaths` çıktısı). Destek istenen ilk şey bu olacak.

### Onarım ve güncelleme

Sihirbaz tek seferlik değildir. Ayarlar'dan **"Kurulumu onar"** her zaman aynı aşama
motorunu çalıştırır. Aşamalar idempotent olduğu için (install.ps1'in kendi
sözleşmesi) tekrar çalıştırmak güvenlidir.

---

## e) Fazlı Yapım Planı

### Faz 1 — Bağlan ve konuş (iskelet)

**Amaç:** Pencere açılıyor, Python'a bağlanıyor, mesaj gidip cevap akıyor.

- `Fetih.Desktop` WinUI 3 projesi (Template Studio veya boş şablon), NavigationView kabuğu.
- `Fetih.Core`: JSON-RPC istemcisi (NDJSON çerçeveleme), stdio taşıması, olay veri yolu.
- Python: `fetih_desktop_bridge/` iskeleti — `entry.py`, `transport.py`, `server.py`,
  `methods_prompt.py`, `methods_session.py`. `bridge.ready` olayı ve `prompt.send` +
  `prompt.delta` akışı.
- Süreç yöneticisi: Python'u başlat, öldür, çöktüğünde yeniden başlat, stderr'i yakala.
- Tek sayfa: **Sohbet** (mesaj listesi + giriş kutusu + token akışı + iptal).
- **Çıktı:** `dotnet run` ile açılıp gerçek cevap alan bir uygulama.

### Faz 2 — Araç ve dosya görünürlüğü

**Amaç:** Ajanın ne yaptığı görünür ve denetlenebilir olsun.

- **Araç çağrısı kartları**: her `tool.call` sohbet akışında genişletilebilir bir kart —
  araç adı, argümanlar, canlı çıktı (`tool.output`), süre, çıkış kodu.
- **Onay akışı**: `approval.request` geldiğinde satır içi izin ver / reddet / her zaman
  izin ver kartı. Bir güvenlik aracı için bu isteğe bağlı değil, çekirdek özellik.
- **Dosya paneli**: `file.tree` ile çalışma alanı ağacı, `file.read` ile önizleme,
  `file.diff` ile değişiklik görünümü (native `RichTextBlock` üzerinde sözdizimi
  renklendirmesi).
- **Terminal/log görünümü**: uzun süren araçların ANSI çıktısını gösteren monospace panel.
- **Çıktı:** Ajanın her adımı izlenebilir.

### Faz 3 — Ses, ayarlar, kurulum sihirbazı

- `Fetih.Setup` + `Fetih.Setup.UI`: (d) bölümündeki sihirbaz, install.ps1 stage
  protokolü üzerinden.
- **Ayarlar**: sağlayıcı/model yönetimi, çalışma alanı, sandbox politikası, izinler,
  tema, dil (TR/EN — `locales/` zaten var), tanılama.
- **Ses**: `audio.stt` ile bas-konuş girişi, `audio.tts` ile cevap okuma
  (`Windows.Media.SpeechSynthesis` native olarak kullanılabilir).
- **Skill tarayıcısı**: (f) bölümüne bakınız.
- **Çıktı:** Temiz bir makinede sıfırdan kurulabilen, tam özellikli uygulama.

### Faz 4 — Paketleme ve dağıtım

- **MSIX** paketi (kimlik, tam güven, Başlat menüsü, otomatik güncelleme kancası).
- **Unpackaged** geliştirici derlemesi de korunur (tanılamada tip gösterilir).
- Kod imzalama (imzasız MSIX SmartScreen uyarısı üretir — bu bir güvenlik aracı için
  özellikle kötü görünür).
- GitHub Releases üzerinden güncelleme kanalı.
- `winget` manifesti (isteğe bağlı).

---

## f) FETİH'in Siber Güvenlik Kimliğine Özel Tasarım Notları

Uygulama bir "genel amaçlı AI sohbet uygulaması" gibi görünmemeli. Öne çıkan şeyler:

### Skill tarayıcısı ve test kataloğu

- Sol gezinmede **"Yetenekler"** bölümü: `skills/` ağacı kategori kategori
  (Siber Güvenlik / CTF / Kırmızı Takım / Adli Bilişim / OSINT / DevSecOps ...).
- Her skill için kart: adı, kısa açıklaması, gerektirdiği araçlar, risk seviyesi.
- **Arama**: "SQL injection", "ATT&CK T1059", "pcap analizi" gibi sorgular
  `skills.search` ile hem `SKILL.md` içeriğinde hem MITRE indekslerinde arar
  (`cybersecurity/mitre-attack-index.md`, `nist-csf-index.md`, `tool-index.md` zaten
  mevcut — bunlar doğrudan aranabilir veri).
- Bir skill'e tıklamak yeni oturumu o bağlamla başlatır.

### Test/tarama sonuçlarının gösterimi

Sohbet akışı bir güvenlik testinin sonucunu göstermek için yeterli değil. Ek görünümler:

- **Bulgu listesi**: ciddiyet (Kritik/Yüksek/Orta/Düşük/Bilgi) renk kodlu, sıralanabilir,
  filtrelenebilir bir `ListView`. Her bulgu: başlık, hedef, kanıt, öneri, referans (CVE/CWE).
- **Hedef paneli**: üzerinde çalışılan host/URL/dosya ve o hedef için toplanmış tüm
  bulgular tek yerde.
- **Zaman çizelgesi**: hangi aracın ne zaman ne çalıştırdığı (operasyon günlüğü) —
  hem raporlama hem "ajan ne yaptı" denetimi için.
- **Kanıt (evidence) klasörü**: ekran görüntüleri, pcap, çıktı dosyaları; native önizleme.
- **Dışa aktarma**: Markdown ve HTML rapor. (Rapor üretimi zaten skill tarafında var;
  uygulama bunu bir düğmeye bağlar.)
- **CTF modu**: bayrak (flag) yakalandığında belirgin bir kart + panoya kopyala.
  `skills/ctf/hint-system` ve `auto-solver` için ilerleme göstergesi.

### Model/sağlayıcı seçiminin öne çıkarılması

Model-agnostiklik FETİH'in ayırt edici özelliği; bunu gizli bir ayar yapmak yazık olur.

- **Başlıkta (title bar) daima görünen bir model seçici**: aktif sağlayıcı + model,
  tek tıkla değiştirilebilir.
- Oturum ortasında model değiştirme desteklenir; sohbette "model X'e geçildi" ayracı görünür.
- **Sağlayıcı sağlık göstergesi**: yeşil/sarı/kırmızı nokta (anahtar geçerli mi, kota
  var mı, gecikme ne).
- **Maliyet/token sayacı** oturum bazında.
- Ayarlarda "yerel model" (LM Studio / Ollama) sağlayıcıları özellikle vurgulanır —
  hassas hedeflerde veri dışarı çıkmasın isteyen kullanıcı için önemli.

### Güvenlik duruşu (kendi güvenliğimiz)

- **Sandbox politikası sayfası**: araçların hangi izinlerle çalışacağı
  (dosya sistemi kapsamı, ağ erişimi, süreç başlatma).
- **İzin (permissions) sayfası**: hangi araç sınıfı otomatik çalışsın, hangisi onay istesin.
- Varsayılan: **yıkıcı ve ağa çıkan araçlar onay ister.**
- **Kapsam (scope) uyarısı**: hedef tanımlanırken "yalnızca yetkili olduğun sistemlerde
  kullan" hatırlatması — yasal koruma ve doğru kullanım için.

### Genel amaçlı şeylere odaklanılmaz

Takvim/e-posta/CRM tarzı ofis entegrasyonları, `optional-skills` altındaki genel
üretkenlik eklentileri uygulamanın ön yüzünde yer almaz. Erişilebilir kalırlar ama
vitrine güvenlik iş akışları konur.

---

## g) Önkoşullar (gerçek denetim sonucuna göre)

Bu makinede **4 Eylül 2026** itibarıyla yapılan denetim:

```
> dotnet --list-sdks
8.0.424 [C:\Program Files\dotnet\sdk]

> dotnet workload list
(hiç workload kurulu değil)
```

**Sonuç: geliştirme ortamı şu anda WinUI 3 için hazır DEĞİL.** Eksikler:

| Gereksinim | Durum | Yapılacak |
|---|---|---|
| .NET SDK 10 (LTS) | ❌ Yalnızca 8.0.424 var | .NET 10 SDK kurulacak. (Referans OpenClaw projesi ve ekran görüntüsündeki runtime `.NET 10.0.11`.) Alternatif: .NET 8 ile de WinUI 3 derlenir, ancak .NET 10 üzerinde ilerlemek daha uzun ömürlü. |
| Windows App SDK 1.6+ / 2.x | ❌ Yok | NuGet paketi olarak gelir (`Microsoft.WindowsAppSDK`). Ayrı `dotnet workload` gerektirmez, ancak Windows SDK hedefleme paketi gerekir. |
| Windows SDK (hedefleme paketi) | ❌ Yok | TFM `net10.0-windows10.0.19041.0` için gerekli. Visual Studio Installer üzerinden gelir. |
| Visual Studio 2022 (17.12+) | ⚠️ Doğrulanmadı | Zorunlu değil ama şiddetle tavsiye edilir (XAML tasarımcısı, hata ayıklama, MSIX paketleme). |
| VS iş yükleri | — | **".NET Masaüstü Geliştirme"** + **"Windows Uygulama Geliştirme"** (Windows App SDK C# şablonları dahil) |
| WebView2 Runtime | ✅ Muhtemelen mevcut | Bizim planda kullanılmıyor, gerekmiyor. |
| Windows sürümü | ✅ Windows 11 Pro 26200 | Minimum Windows 10 20H2. Sorun yok. |
| Node.js | ⚠️ Kontrol edilmedi | WinUI için gerekli değil; FETİH'in tarayıcı araçları için gerekli. |

**Kurulum komutları (winget ile):**

```powershell
winget install Microsoft.DotNet.SDK.10
winget install Microsoft.VisualStudio.2022.Community `
  --override "--add Microsoft.VisualStudio.Workload.ManagedDesktop `
              --add Microsoft.VisualStudio.Workload.Universal --includeRecommended"
```

Ardından doğrulama:

```powershell
dotnet --list-sdks
dotnet new list winui        # WinUI şablonları görünüyor mu
```

**Not:** WinUI 3 masaüstü uygulamaları `dotnet workload` sistemini kullanmaz
(MAUI'nin aksine). Bu yüzden `dotnet workload list` çıktısının boş olması tek başına
sorun değil — asıl eksik .NET 10 SDK ve Windows SDK hedefleme paketidir.

**Çalışma zamanı önkoşulu (son kullanıcı):** MSIX paketi Windows App SDK bağımlılığını
kendisi taşır; kullanıcı ayrıca bir şey kurmaz. Python tarafını ise uygulamanın kendi
kurulum sihirbazı halleder.

---

## h) Riskler ve Açık Sorular

### Riskler

| Risk | Etki | Azaltma |
|---|---|---|
| **Köprü yüzeyi büyük.** Hermes'in `tui_gateway`'i ~41.000 satır; `server.py` tek başına 18.500 satır. FETİH için bunun tamamı gerekmez ama küçümsemek de hata olur. | Faz 1 planlanandan uzun sürer | Metotları **fazlara göre** ekle. Faz 1 için yalnızca 6-8 metot yeterli. Katman ayrımını (transport/dispatch) baştan doğru kur, metotları sonra doldur. |
| **İsim çakışması yeniden doğabilir.** "Gateway" kelimesi depoda derinlemesine yerleşik; yeni kod yazarken refleksle tekrar kullanılabilir. | Kalıcı kafa karışıklığı, hatalı hata raporları | (b) bölümündeki ayrımı CONTRIBUTING/AGENTS.md'ye taşı; CI'da `fetih_desktop_bridge/` içinde `gateway` kelimesini yasaklayan basit bir lint kuralı ekle. |
| **İki dilli hata ayıklama.** Hata C# tarafında mı Python tarafında mı belli olmaz. | Geliştirme yavaşlar | Baştan: her iki tarafta korele `request_id`, gateway'in stderr'ini uygulamada canlı gösteren bir geliştirici paneli, JSON-RPC trafiğinin isteğe bağlı dökümü. |
| **Süreç ömrü.** Uygulama çökerse yetim Python süreci kalır; Python çökerse uygulama sessizce ölü kalır. | Hayalet süreçler, sessiz bozulma | Job Object ile çocuğu ebeveyne bağla; iki yönlü heartbeat; otomatik yeniden başlatma + kullanıcıya görünür durum rozeti. |
| **XAML/MVVM öğrenme eğrisi.** Ekip Python ağırlıklıysa WinUI veri bağlama, `x:Bind`, dispatcher kuralları zaman alır. | Faz 1 gecikmesi | Template Studio ile hazır MVVM iskeleti; WinUI Gallery'yi canlı referans olarak kullan. |
| **Uzun araç çıktılarında UI donması.** Bir tarama aracı saniyede binlerce satır üretebilir. | Uygulama yanıt vermez | Olayları toplu işle (batching), sanallaştırılmış liste, çıktıya üst sınır + "tam çıktıyı dosyada aç". |
| **Kod imzalama olmadan SmartScreen uyarısı.** | Güvenlik aracına güvensizlik | Faz 4'te sertifika bütçesi ayır. |
| **install.ps1 aşamalarının GUI'den sürülmesi henüz test edilmemiş.** Protokol yazılmış ama bir GUI tarafından hiç çalıştırılmamış. | Sihirbazda beklenmedik promptlar/hatalar | Faz 3'ten önce, temiz bir Windows sanal makinesinde her aşamayı `-Stage ... -Json -NonInteractive` ile tek tek çalıştırıp çıktıları doğrula. |

### Açık sorular

1. **.NET 8 mi 10 mu?** Makinede 8 var, referans proje 10 kullanıyor. .NET 10 kurmak
   ekstra bir indirme; ama uzun vadeli doğru seçim gibi görünüyor. **Karar bekliyor.**
2. **Varsayılan taşıma stdio mu WebSocket mi?** stdio daha güvenli (açık port yok) ve
   basit; WebSocket ileride uzak/WSL/paylaşımlı gateway senaryolarını açar. Öneri:
   **stdio varsayılan, WebSocket opsiyonel.**
3. ~~Modül adı ne olsun?~~ **KARARLAŞTI:** `fetih_desktop_bridge/` ("Masaüstü Köprüsü").
   "Gateway" adı mesajlaşma köprüsüne ait kalır. Bkz. (b) bölümü.
4. **Mevcut TUI ile ilişki ne olacak?** Aynı köprüyü TUI de kullanabilir mi, yoksa
   masaüstü ayrı bir yol mu? Hermes'te tek dispatch her iki istemciyi de besliyor;
   aynı şeyi yapabilirsek bakım maliyeti yarıya iner. **Araştırılmalı.**
5. **API anahtarları nerede saklanacak?** Öneri: **Windows Credential Manager**
   (native, şifreli). Ama FETİH'in mevcut yapılandırması `cli-config.yaml` /
   `.env` bekliyor. Köprü nasıl kurulacak — uygulama anahtarı Credential Manager'dan
   okuyup gateway sürecine ortam değişkeni olarak mı geçirsin? (Muhtemelen evet.)
6. **OpenClaw'dan dosya uyarlanacak mı, yoksa yalnızca mimari ilham mı?**
   MIT izin veriyor ama `THIRD_PARTY_NOTICES.md` gerektirir. **Öneri: yalnızca ilham;
   iskelet Microsoft şablonlarından gelsin — böylece atıf yükü hiç doğmaz.**
7. **Tray (sistem tepsisi) ve global kısayol istiyor muyuz?** OpenClaw'ın merkezinde bu
   var; bizde ikincil. Faz 3+ için opsiyonel özellik.
8. **Linux kurulum iyileştirmesi ne kadar kapsamlı olsun?** `install.sh`'a
   `install.ps1`'deki stage protokolünün eşdeğerini eklemek mantıklı olur
   (aynı JSON sözleşmesi) — ama GUI olmayacağı için faydası sınırlı; sadece daha iyi
   ilerleme çıktısı ve hata mesajları için. **Düşük öncelik.**

---

## Kaynaklar

- OpenClaw Windows companion (MIT): https://github.com/openclaw/openclaw-windows-node
- OpenClaw ana proje (MIT): https://github.com/openclaw/openclaw
- OpenClaw Windows dokümanı: https://docs.openclaw.ai/platforms/windows
- WinUI 3 Gallery (MIT): https://github.com/microsoft/WinUI-Gallery
- Windows App SDK örnekleri (MIT): https://github.com/microsoft/WindowsAppSDK-Samples
- Windows Community Toolkit (MIT): https://github.com/CommunityToolkit/Windows
- Template Studio for WinUI (MIT): https://github.com/microsoft/TemplateStudio
