# OpenClaw Windows Companion — İnceleme Notları

> **Kaynak:** `github.com/openclaw/openclaw-windows-node`, yerel klon:
> `C:\Users\ara\Desktop\Kişisel Projeler\openclaw-windows-node`
> **Lisans:** MIT (`LICENSE`) — mimari uyarlama atıf şartıyla serbest.
>
> **Bu belgenin amacı:** Ne yaptıklarını *anlamak*, iyi mimari kararları
> uyarlamak. **Kod kopyalanmaz**, marka varlıkları (isim, ikon, metin)
> alınmaz. Bkz. `docs/windows-app-plani.md` §c "Ne alınır, ne alınmaz".
>
> **İsimlendirme uyarısı:** OpenClaw kendi Python/TS sunucusuna "gateway" der.
> FETİH'te bu kelime **mesajlaşma köprüsü** (`gateway/`) anlamına gelir ve
> masaüstü bileşenlerinde **kullanılmaz**. Aşağıda OpenClaw'ın kendi terimini
> anlatırken tırnak içinde geçiyor; bizdeki karşılığı **Masaüstü Köprüsü /
> `fetih_desktop_bridge`**'tir.

---

## 1) Teknoloji yığını (doğrulandı)

| | |
|---|---|
| Hedef çatı | **.NET 10** (`global.json`: SDK `10.0.100`), `net10.0-windows10.0.22621.0` |
| UI | **WinUI 3 / Windows App SDK 2.4.0**, `UseWinUI=true`, `WindowsAppSDKSelfContained=true` |
| RID'ler | `win-x64`, `win-arm64` |
| Pencere yardımcısı | **WinUIEx 2.9.3** (`WindowEx` — özel başlık çubuğu, tepsi davranışı) |
| Ayar kontrolleri | **CommunityToolkit.WinUI.Controls.SettingsControls** (`SettingsCard`, `SettingsExpander`) |
| Bildirim | `Microsoft.Toolkit.Uwp.Notifications` (toast) |
| Ses | `NAudio.Wasapi` + **`org.k2fsa.sherpa.onnx`** (yerel STT/TTS) |
| Ağ keşfi / eşleştirme | `Zeroconf` (mDNS ile sunucu keşfi), `ZXing.Net` (QR kod okuma) |
| Telemetri | `OpenTelemetry` + OTLP dışa aktarıcı (isteğe bağlı, kullanıcı tarafından yapılandırılır) |
| Güncelleme | `Updatum` |
| Kimlik bilgisi koruması | `System.Security.Cryptography.ProtectedData` (DPAPI) |
| Kurulum paketi | **Inno Setup** (`installer.iss`), build betiği `build.ps1` (17 KB) |
| Yerel geliştirme | `run-app-local.ps1` |

**Bizim için sonuç:** Yığın seçimimiz (WinUI 3 + .NET) doğrulanıyor. WinUIEx +
CommunityToolkit SettingsControls ikilisi, "elle XAML yazmadan Windows 11 görünümlü
ayar sayfası" için doğru araç — `Fetih.Desktop`'ta da bunları kullanmalıyız.
`sherpa.onnx`'in yerel STT/TTS için tercih edilmesi ilginç: bizde bu iş
Python tarafında (Whisper/Piper/NeuTTS) zaten var, dolayısıyla **C# tarafına
ses motoru koymayız** — köprüden `audio.*` metotlarıyla çağırırız.

---

## 2) Proje ayrımı (9 üretim projesi)

| Proje | İşi | FETİH karşılığı |
|---|---|---|
| `OpenClaw.Tray.WinUI` | WinUI 3 kabuk, tepsi, tüm sayfalar | `Fetih.Desktop` |
| `OpenClaw.Shared` | Protokol sözleşmesi, yetenekler, tanılama, ses, komut kataloğu | `Fetih.Core` |
| `OpenClaw.Connection` | Bağlantı FSM'i, kayıt defteri, kimlik bilgisi çözümü, eşleştirme | `Fetih.Bridge` *(adı "Connection" değil "Bridge")* |
| `OpenClaw.Chat` | Sohbet modeli/durumu (UI'dan bağımsız) | `Fetih.Chat` |
| `OpenClaw.SetupEngine` | Başsız kurulum ardışık düzeni (adımlar, geri alma, günlük) | `Fetih.Setup` |
| `OpenClaw.SetupEngine.UI` | WinUI kurulum sihirbazı sayfaları | `Fetih.Setup.UI` |
| `OpenClawTray.FunctionalUI` | Bildirimsel WinUI yardımcıları | (opsiyonel) |
| `OpenClaw.Cli` | Sunucu WebSocket doğrulayıcı (tek `Program.cs`) | `fetih-bridge-probe` |
| `OpenClaw.WinNode.Cli` | Windows düğüm yeteneklerini CLI'den sürme + `skill.md` | (gerekmez) |

Ayrıca **10 test projesi** — birim, entegrasyon, UI (`Tray.UITests`) ve E2E.
Dikkat çeken desen: **`*.Presentation` sınıfları WinUI'den bağımsız tutulmuş**
(örn. `SettingsAppInfoProjection`) — böylece formatlama/mantık birim testlenebiliyor,
XAML code-behind'ında yalnızca bağlama kalıyor. **Bunu aynen benimsemeliyiz.**

---

## 3) Gezinme yapısı (`HubWindow.xaml`)

Tek `NavigationView`, `Frame` tabanlı sayfa geçişi, `Tag` ile yönlendirme.
Gerçek yapı (plan belgesindeki tahminden **daha zengin**):

```
[Chat]                                  ← Tag="chat"
──────────────────────────────
Başlık: "Gateway"                       ← bizde: "Köprü"
  Connection      Tag="connection"
  Sessions        Tag="sessions"
  Skills          Tag="skills"
  Channels        Tag="channels"
  Instances       Tag="instances"
  Cron            Tag="cron"
  Advanced ▾ (SelectsOnInvoked=False)
      Event Stream   Tag="agentevents"
      Agents ▾
          main       Tag="agent:main"   ← dinamik, ajan başına
      Bindings       Tag="bindings"
      Config         Tag="config"
      Usage          Tag="usage"
──────────────────────────────
Başlık: "This Computer"                 ← bizde: "Bu Bilgisayar"
  Local AI        Tag="local-ai"
  Voice & Audio   Tag="voice"
  Permissions     Tag="permissions"
  Sandbox         Tag="sandbox"
──────────────────────────────
FooterMenuItems (alta sabit):
  Debug           Tag="debug"
  Settings        Tag="settings"
```

**Uyarlanacak üç fikir:**

1. **İki bölgeli menü.** "Sunucu tarafı" (uzak/paylaşılan) ile "bu bilgisayar"
   (yerel yetkiler, donanım) ayrılmış. FETİH'te bu ayrım daha da anlamlı:
   *Ajan/Model/Skills/Kanban/Cron* köprünün ucundaki Python'a ait; *İzinler,
   Sandbox, Ses, Windows gizliliği* bu makineye ait.
2. **`Advanced` alt menüsü.** Nadir kullanılan güçlü sayfalar (ham config
   düzenleyici, olay akışı, kullanım/maliyet) ana menüyü şişirmiyor,
   `SelectsOnInvoked="False"` ile sadece açılır grup olarak duruyor.
3. **Alta sabitlenmiş `Debug` + `Settings`.** Tanılama her zaman bir tık uzakta.

Ek desen: içerik alanının üstünde, sağ ~2/5 genişlikte **kayan `InfoBar`**
(`AppNotificationInfoBar`) — bildirim başlığı, mesaj ve bir eylem düğmesi;
gezinme bölmesinin üzerine taşmıyor, sayfayı aşağı itmiyor. Bağlantı hataları
gibi anlık uyarılar için bizde de bu şekilde olmalı.

Yan pencereler: `ChatWindow`, `TrayMenuWindow`, `VoiceOverlayWindow`,
`CommandPaletteDialog`, `ConnectionStatusWindow`, `DiagnosticsBundleDialog`,
`CanvasWindow` / `A2UICanvasWindow`.

---

## 4) Sayfa sayfa ne gösteriliyor

### 4.1 Connection (`ConnectionPage.xaml`)

En yoğun sayfa. Bölümleri:

- **"Approvals waiting on you"** — bekleyen eşleştirme/onay kuyruğu, satır içi
  "Approve…" düğmesiyle.
- **Bağlantı durumu kartı** — "Not connected" / "Connect", ayrıca
  **"Show technical details"** açılır bölümü ve her alan için **"Copy"** düğmesi.
- **WSL gateway** — yerel WSL'deki sunucu servisi: `Start` / `Stop` / `Restart`
  + `Terminal` (kabuk aç).
- **Operator** — "Send commands and view sessions on this gateway from this PC",
  `See sessions ›` / `See instances ›` kısayolları.
- **Node mode** — bu PC'nin ajana yetenek sunup sunmadığı; `Manage permissions ›`.
- **Hata onarım bloğu** — *"Help us fix this connection:"* başlığı altında
  **duruma özel eylemler**: "SSH tunnel is down." → `Restart tunnel` /
  `Edit tunnel settings`.
- **Eşleştirme (pairing)** — üç yöntem sekmesi: **Direct**, **URL + token**,
  **Setup code**, ayrıca **"Paste QR payload"**. Karşı tarafta çalıştırılacak
  komut gösterilip `Copy` ile kopyalanabiliyor.
- **Saved gateways / Discovered on your network** — kayıtlı sunucular listesi +
  `Scan` (mDNS/Zeroconf keşfi) + `Add gateway` + `Install`.

> **Bizim için en değerli kısım:** hata mesajının yanında **o hataya özel
> düzeltme düğmesi**. Kullanıcıya "Transport error" deyip bırakmıyorlar.
> FETİH'in Bağlantı sayfası da: "Python bulunamadı → PATH'i onar",
> "Token geçersiz → yeniden üret", "Port kullanımda → başka port seç" gibi
> **eyleme dönüşmüş** hata kutuları göstermeli.

### 4.2 Local AI (`LocalAiPage.xaml`)

Yerel model çalıştırıcısının kontrol paneli: `llama-server` **Version**,
**Endpoint**, **Process** satırları; `Start router` / `Stop` / `Restart` /
`Open logs`; **Model** kartı + `Change model` / `Retry setup or download`;
alt kısımda "Gateway connection" durumu ve `Repair connection`.
Ayrıca hazır değilse `See why` (gerekçe) ve `Recheck` düğmeleri.

> FETİH karşılığı: `terminal.backend` yerel/konteyner çalıştırıcısı ve
> **Ollama/LM Studio/llama.cpp** yerel uç yapılandırması. `See why` deseni
> (neden kullanılamıyor sorusuna tıklanabilir cevap) `fetih doctor` çıktısını
> UI'ya taşımanın iyi bir yolu.

### 4.3 Voice & Audio (`VoiceSettingsPage.xaml`)

- **Speech Model** (STT): boyut seçimi radyo düğmeleriyle ve **indirme
  büyüklüğü açıkça yazılmış**: `Tiny (~75 MB): Fast, basic accuracy`,
  `Base (~142 MB): Good balance`, `Small (~466 MB): High accuracy`;
  `Download Model`; **Test Voice Input** + `Record`; **Language** (Auto-detect
  + 9 dil).
- **Voice Chat**: `Silence timeout (seconds)`, `Read responses aloud`,
  `Audio feedback sounds`.
- **Companion Voice** (TTS): `Provider` seçenekleri —
  `Piper (local neural voices)`, `Windows (built-in neural voices)`,
  `ElevenLabs (cloud, requires API key)`, `MiniMax (cloud, requires API key)`;
  seçime göre alanlar değişiyor: yerel için `Download Voice` / `Delete` /
  `Preview`, bulut için `API Key` / `Voice ID` / `Model (optional)` —
  **yer tutucu örneklerle** (`e.g. eleven_turbo_v2`).
- Mikrofon izni yoksa kart üstünde `Open Permissions` kestirmesi.

> **Doğrudan uyarlanabilir:** FETİH'in `tts.provider` (edge / elevenlabs /
> openai / xai / mistral / neutts / piper) ve `stt.provider` (local / openai /
> mistral) yapısı bu forma **birebir oturuyor**. "Sağlayıcıya göre değişen alan
> grubu + indirme boyutunu yaz + önizleme düğmesi" kalıbını aynen alalım.

### 4.4 Permissions (`PermissionsPage.xaml`)

- **Node mode** açma/kapama (bu PC ajana yetenek sunuyor mu).
- **Capabilities** — "Toggle individual features that agents may request from
  this PC" — yetenek başına anahtar.
- **Integrations → Local MCP Server** — yerel MCP sunucusu, `Endpoint:` satırı,
  `Copy token` / `Copy URL`.
- **Exec policy** — **Default action**: `Deny` / `Allow`
  ("What happens when a command doesn't match the executable-path allowlist below").
- **Executable-path allowlist** — kalıp girişi (`**/hostname.exe`), `Add entry`,
  kayıt sayacı ("0 entries") ve `Saved` göstergesi.
- **Node allowlist** — sunucunun düğümlerden kabul ettiği komutlar,
  **salt okunur**: "Read-only: edit via the Config page."
- **Windows privacy** — kamera/mikrofon/ekran erişimi → `Open Windows privacy settings`.

> **FETİH eşleşmesi neredeyse birebir:** `approvals.mode` ↔ Default action,
> `command_allowlist` ↔ Executable-path allowlist,
> `security.*` ↔ Capabilities. **Ödünç alınacak iki detay:** (a) varsayılan
> eylemi allowlist'in *hemen üstünde* göstermek, (b) uzaktan yönetilen listeyi
> **salt okunur** işaretleyip nereden düzenleneceğini yazmak.

### 4.5 Sandbox (`SandboxPage.xaml`)

Bu sayfa, incelenen en iyi tasarlanmış ekran. Yapısı:

- Üstte durum: "🛡 Node sandbox is on — Programs the agent runs on this PC are contained."
- **"What gets contained"** — hangi komut yolunun (`system.run`) bu ayarlarla
  sınırlandığını, hangilerinin **başka kontrollere ihtiyaç duyduğunu** açıkça yazıyor.
- **Security level** — tek tıkla tüm alt kontrolleri ayarlayan **üç hazır profil**,
  her biri sonucu düz Türkçe(İngilizce) anlatan bir cümleyle:
  - `🔒 Locked Down` — "No internet, no clipboard, no standard user folders."
  - `🛡 Recommended` — "Internet on. Read-only on Documents, Downloads, Desktop. Clipboard read."
  - `⚠ Unprotected` — "Internet on. Read+write on Documents, Downloads, Desktop. Clipboard read+write."
  - Not: **"Custom folders stay as you set them"** — profil değiştirmek kullanıcının
    elle eklediklerini silmiyor.
- **📁 Files** — Documents / Downloads / Desktop / Custom folders, her biri için
  `Blocked` / `Read only` / `Read & write` üçlüsü; `Add folder`.
- **📋 Clipboard** — `None (default)` / `Read: agent can see what you copied` /
  `Write: agent can replace your clipboard (cannot read it)` / `Read & write`.
- **📡 Network** — `Off: agent cannot reach the internet` / `On: agent can connect
  to public internet endpoints`.

> **Alınacak ders — güvenlik ayarlarının dili.** Her seçenek etiketi
> *ne olacağını* anlatıyor ("agent can see what you copied"), *ayarın adını*
> değil. FETİH bir siber güvenlik aracı; Sandbox sayfamız (`terminal.backend`,
> `docker_volumes`, `container_*`, `allow_private_urls`) tam olarak bu dille
> yazılmalı. **Üç hazır profil + ince ayar** kalıbı da doğrudan uyarlanmalı.

### 4.6 Debug / Diagnostics (`DebugPage.xaml`)

- **Gateway** → `Run gateway doctor` — "Opens a terminal and runs `openclaw doctor`".
- **Share diagnostics with support** → `Create diagnostics bundle`,
  `Open diagnostics folder` ("Logs and structured diagnostics (.jsonl) live here").
- **Copy specific diagnostic text** — tek tek kopyalanabilir parçalar:
  `Copy support context` ("Connection state, gateway URL, runtime, tunnel"),
  `Copy summary debug bundle`, `Copy browser setup guidance`,
  `Copy port diagnostics`, `Copy capability diagnostics`.
- **Inspect local diagnostics** — `Connection event timeline`
  ("Live state-machine events, websocket frames, credential resolution, and
  pairing handshakes"), `Recent log` ("Last 200 lines … with severity coloring").
- **Device identity** — `Device ID`, `Public key`.
- **Developer tools** — OpenTelemetry: `Endpoint URL`, `Protocol` (OTLP/gRPC |
  OTLP/HTTP), `Save connection`, `Send probe again`, `Clear`; ayrıca
  "Chat surface overrides" (yeniden başlatınca sıfırlanan geçici UI zorlamaları).

> **Alınacak:** `fetih doctor` zaten var — Tanılama sayfası onu bir düğmeye
> bağlamalı. **"Copy X" düğme dizisi** çok değerli: kullanıcı hata bildirirken
> tam olarak neyi yapıştıracağını biliyor. Ayrıca **canlı bağlantı olay zaman
> çizelgesi** (state-machine olayları + WS çerçeveleri) bizim NDJSON köprümüz
> için doğal bir görünüm.

### 4.7 Settings (`SettingsPage.xaml`)

- **General** — `Start with Windows`, `App theme` (System/Light/Dark),
  `Global hotkeys` (Ctrl+Alt+Shift+V ses, Ctrl+Alt+; ayarlar),
  "Use gateway's web chat interface" *(bizde olmayacak — native kalıyoruz)*.
- **Chat** — `Show tool calls and usage` (araç çağrısı ve token kullanımını
  konuşma içinde göster).
- **Notifications** — `Show notifications`, `Sound` (Default/None/Subtle),
  **"Notify me about"** kategori kutuları (Health alerts, Urgent messages,
  Reminders, Email summaries, Calendar events, Build notifications, Stock
  alerts, Info messages), `Send test notification`.
- **Privacy** — `Allow screen capture` (`screen.*`), `Allow camera capture`
  (`camera.*`), `Allow location access` (`location.*`) — her biri hangi komut
  ailesini açtığını söylüyor.
- **Local Gateway** — `Set up or reconfigure Local Gateway` → `Open setup`
  (kurulum sihirbazını **sonradan da** açabilme).

### 4.8 Skills (`SkillsPage.xaml`)

Şaşırtıcı biçimde **zayıf**: `Agent` seçici, Enabled/Disabled anahtarı, liste,
ve boş durumda "Skills extend your agent's capabilities. Install skills via the
CLI or ClawHub." Yani **kurulum CLI'ye havale edilmiş**.

> **FETİH'in ayrışma noktası burası.** Bizde ~916 gömülü skill var ve
> **%80'inden fazlası cybersecurity (743) / CTF (55) / red-teaming (32)**
> (bkz. `docs/fetih-ozellik-envanteri.md` §3). Skill tarayıcısı bizde
> birinci sınıf bir ekran olmalı: kategori ağacı, arama, ayrıntı sayfası,
> "çalıştır" düğmesi. OpenClaw'ın yaptığını yapmayacağız — **onların en zayıf
> sayfası bizim en güçlü sayfamız olmalı.**

### 4.9 Config (`ConfigPage.xaml`)

**Şema güdümlü ham config düzenleyici**: "Edit gateway configuration
(openclaw.json) with a schema-guided form." Sol tarafta bölüm ağacı + `Filter
settings`, sağda `SchemaConfigEditor` kontrolüyle üretilen form, altta
**"JSON preview — Compare the gateway value with the proposed unsaved value"**,
ve `Reset section` / `Discard changes` / `Save Changes`.
Şema yoksa "Schema not available" ile web panosuna yönlendirme.

> **Çok iyi fikir, doğrudan alınmalı.** FETİH'in `config.yaml`'ı **20+ kök
> anahtar, yüzlerce alan** içeriyor; hepsine elle sayfa yazmak imkânsız.
> Çözüm: Masaüstü Köprüsü `config.schema` (veya `config.describe`) metoduyla
> alan tanımlarını yayımlar, C# tarafı **jenerik bir form** üretir. Böylece
> özel olarak tasarlanmış sayfalar (Model, İzinler, Sandbox, Ses) *ilk 20
> ayarı* güzelce kapsar, kalan her şey jenerik düzenleyiciyle **kaybolmaz**.
> "Kaydedilmemiş değeri sunucudaki değerle yan yana göster" deseni de alınmalı.

---

## 5) `SetupEngine` — kurulum motorunun mimarisi

**En çok öğrenilecek yer burası.** Motor tamamen başsız (headless) ve UI'dan
bağımsız; `OpenClaw.SetupEngine.UI` sadece onu sürüyor.

### 5.1 Adım soyutlaması (`SetupPipeline.cs`)

```csharp
public abstract class SetupStep
{
    public abstract string Id { get; }
    public abstract string DisplayName { get; }
    public abstract Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct);

    public virtual Task RollbackAsync(SetupContext ctx, CancellationToken ct) => Task.CompletedTask;
    public virtual bool CanSkip(SetupContext ctx) => false;   // önkoşul zaten sağlanmışsa atla
    public virtual bool CanRetry => true;
    public virtual RetryPolicy Retry => RetryPolicy.Default;
}
```

Dört yetenek her adımda standart: **atlanabilirlik**, **yeniden deneme
politikası**, **geri alma**, **görünen ad**. Sonuç:
`PipelineResult(Outcome, FailedStepId, Message, CompatibilityFailure, Detail)`
ve `ExitCode` (Success=0, Failed=1, Cancelled=3).

### 5.2 Çalıştırma döngüsü — dikkat çeken davranışlar

- Her adımda `CanSkip` kontrolü → atlanan adım da **günlüğe ve olaya işlenir**
  (`StepOutcome.Skipped`, gerekçe: "precondition met"). Kullanıcı neyin neden
  atlandığını görür.
- `RetryExecutor.ExecuteWithRetry` ile politika bazlı yeniden deneme.
- Başarısızlıkta **`RollbackFailedStep` + ters sırayla `RollbackCompletedSteps`**
  — yarım kurulum bırakılmıyor. Geri alma zaman aşımına bağlı
  (`RunRollbackWithTimeout`) ve geri almanın kendisi başarısız olursa bu da
  günlüğe yazılıp devam ediliyor.
- İptal (`CancellationToken`) her noktada yakalanıp aynı geri alma yoluna giriyor.
- **`TransactionJournal`** — `.jsonl` dosyasına append-only olay günlüğü
  (`pipeline_started`, `step started/completed`, `rollback`, `pipeline_failed`,
  `pipeline_completed`). Süreç çökerse **var olan girdiler yeniden okunuyor**
  (`LoadExistingEntries`) → çökme sonrası kurtarma ve adli inceleme.
- `SetupRunLock` — aynı anda ikinci kurulum çalışmasını engelliyor; UI bunu
  görüp "Another setup run is active." diyor.
- `StepProgress` olayı → UI canlı ilerleme çubuğunu bundan besliyor.

### 5.3 Varsayılan adım listesi (`SetupStepFactory.BuildDefaultSteps`)

36 adım, kabaca beş öbek:

1. **Ön kontrol:** `ValidateDistroInstallPath`, `PreflightOs`,
   `PreflightLocalAiHardware`, `PreflightWsl`, `PreflightWindowsTailscale`,
   `PreflightPort`.
2. **Yerel AI:** `EnsureWslPlatform`, `ReconcileLocalAiInstallation`,
   `AcquireLocalAiRuntime`, `AcquireLocalAiModel`, `PersistLocalAiManifest`,
   `StartLocalAiRuntime`, `CaptureLocalAiGpuBaseline`, `VerifyLocalAiInference`,
   `VerifyLocalAiGpuLoad`, `ConfigureLocalAiWslNetworking`.
3. **Temizlik + ortam:** `CleanupStaleDistro`, `CleanupStaleGateway`,
   `CreateWslInstance`, `ConfigureWslInstance`, `ValidateWslLockdown`,
   `InstallCli`, `VerifyLocalAiWsl`.
4. **Ağ + servis:** `InstallTailscale`, `AuthorizeTailscale`, `ConfigureGateway`,
   `ConfigureLocalAiGateway`, `InstallGatewayService`, `StartGateway`,
   `FinalizeTailscaleServe`.
5. **Güven + doğrulama:** `MintBootstrapToken`, `PairOperator`, `PairNode`,
   `VerifyEndToEnd`, `RunGatewayWizard`, `WindowsNodeBootstrapContext`,
   `StartKeepalive`.

Ayrıca `BuildWizardOnlySteps()` — yalnızca sihirbazı çalıştıran kısa yol
(zaten kurulu bir sistemde yeniden yapılandırma için).

> **FETİH için doğrudan uyarlanacak.** Bizim kurulum adımlarımız çok daha az
> ve daha basit ama **aynı iskelet** kullanılmalı:
> `PreflightOs` → `DetectPython` → `ValidatePythonVersion` → `EnsureVenv` →
> `InstallFetih` (pip/uv) → `RepairPath` → `EnsureFetihHome` →
> `WriteConfig` → `MintBridgeToken` → `StartDesktopBridge` → `VerifyEndToEnd`.
> `CanSkip` sayesinde ikinci çalıştırma **onarım moduna** dönüşür — plan
> belgesindeki "Onarım ve güncelleme" maddesi (§d) tam olarak budur.
> `TransactionJournal`'ın `.jsonl` deseni de alınmalı: kurulum çökerse
> kullanıcı bize tek dosya gönderir.

### 5.4 Sihirbaz akışı (`SetupEngine.UI`)

Sayfa sırası (`SetupWindow.xaml.cs` içindeki `NavigateTo*` metotlarından):

```
SecurityNoticePage   "Welcome to OpenClaw" → [Continue]
   ↓
WelcomePage          "Set up OpenClaw" — iki yol kartı:
                       • "Install a local gateway (WSL)"  [Recommended] [Local AI supported]
                       • "Connect to an existing gateway"
   ↓ (yerel kurulum)                      ↓ (mevcut sunucuya bağlan)
CapabilitiesPage                       AdvancedSetupPage
  "Set up the WSL gateway"               "Connect to an existing gateway"
  Üç yetki seviyesi:                      "We'll open Companion Settings next.
   • Read-only                             Nothing gets installed."
   • Standard  [Recommended]              1) Add a gateway
   • Full access                          2) Point it at your gateway
  + "Fine-tune individual capabilities"   3) Pair this device
  + Ubuntu 24.04 kurulumu (Several GB)    + Optional: SSH tunnel
  + Local AI kurulumu, Tailscale           [Open Companion Settings]
  + açık rıza kutusu:
    "I understand and allow this global
     WSL change and one-time shutdown."
   ↓
ProgressPage         "Setting up OpenClaw"
                     [Live activity] açılır bölüm + [Open log file]
                     Ara kilometre taşı: "Gateway installed" →
                       "Up next: OpenClaw onboard" [Start OpenClaw onboard]
   ↓
WizardPage           (sunucunun kendi onboarding'i: sağlayıcı, model, anahtar)
   ↓
CompletePage         "All set!" — doğrulanmış maddeler listesi:
                       ✓ Local gateway running (OpenClawGateway · 127.0.0.1:18789)
                       ✓ Local AI verified
                       ✓ Device paired
                       ✓ Capability profile applied ("Editable any time in
                         Companion Settings")
                     [Launch OpenClaw at startup] [View full log →] [Finish]
                     Hata halinde: [Retry with validated fallback]
```

**Uyarlanacak beş karar:**

1. **Güvenlik uyarısı en başta**, kurulumdan *önce*. Bir güvenlik aracı için
   bu doğru sıra — FETİH'te de ilk ekran ne yaptığımızı ve neyi
   çalıştırabileceğimizi söylemeli.
2. **İki yol kartı, üçüncü seçenek yok.** "Yerel kur" vs "var olana bağlan".
   FETİH'te: "Python'u benim için kur/onar" vs "Var olan `fetih` kurulumumu kullan".
3. **Yetki seviyesi kurulum sırasında seçiliyor**, sonradan aranan bir ayar
   değil — ve "sonra Ayarlar'dan değiştirilebilir" açıkça yazılıyor.
4. **Maliyet önceden söyleniyor**: "Uses several GB", "Several GB", model
   indirme boyutları. Ve geri döndürülemez sistem değişikliği için **ayrı bir
   açık rıza kutusu** var.
5. **Ara kilometre taşı ekranı.** Uzun kurulumda "Gateway installed →
   Up next: onboard" diye bölünmüş; kullanıcı 36 adımlık tek bir çubuğa
   bakmıyor. `ProgressPage`'in `showMilestoneOnly` bayrağı bunun için.

Ek olarak: `SetupPreview.RequestedPage` ile **herhangi bir sihirbaz sayfası
tek başına açılabiliyor** — tasarım/QA için. Bunu biz de yapmalıyız.

---

## 6) `OpenClaw.Connection` — bağlantı ömrü yönetimi

Bizim `Fetih.Bridge` katmanımızın referansı.

**İki bağımsız alt-FSM** (operator + node) ve bunlardan **türetilen** genel
durum (`OverallConnectionState`, "This is NOT a state machine — it's derived"):

`Idle` → `Connecting` → `Connected` → `Ready`, artı
`Degraded` (operator bağlı, node hatalı — *işlevsel ama kısıtlı*),
`PairingRequired`, `Error`, `Disconnecting`.

**Tetikleyiciler** (`ConnectionTrigger`): `ConnectRequested`,
`ConnectRequestSent`, `ChallengeReceived`, `WebSocketConnected`,
`HandshakeSucceeded`, `PairingPending`, `PairingApproved`, `PairingRejected`,
`AuthenticationFailed`, `RateLimited`, `WebSocketDisconnected`,
`WebSocketError`, `DisconnectRequested`, `ReconnectScheduled`,
`ReconnectSuppressed`, `Cancelled`, `Disposed` (+ `Node*` karşılıkları).

**Hata kategorileri, açık yeniden deneme davranışıyla**
(`ConnectionErrorCategory`): `AuthFailure`, `PairingPending`,
`PairingRejected`, `RateLimited`, `NetworkUnreachable`, `ServerClose`,
`ProtocolMismatch`, `MalformedMessage`, `InternalError`, `SshTunnelFailure`,
`Cancelled`, `Disposed`.

Destek sınıfları: `GatewayRegistry` + `GatewayRecord` (kayıtlı sunucular),
`CredentialResolver` + `InteractiveGatewayCredentialResolver`,
`DeviceIdentityStore` (cihaz kimliği/anahtar çifti),
`PairingApprovalQueue` + `DevicePairApprovalCoordinator` + `PendingApproval`,
`BootstrapTokenLifecycle`, `ConnectionDiagnostics` + `ConnectionDiagnosticEvent`.

### Protokol sürüm pazarlığı (`OpenClaw.Shared/GatewayProtocolContract.cs`)

```csharp
public const int SupportedVersion = 4;
public const int MinimumSupportedVersion = 3;
public const int MaximumSupportedVersion = CurrentVersion;
public const string HelloOkType = "hello-ok";
```

İstemci bir **aralık** ilan ediyor; sunucu `hello-ok` içinde kendi güncel
protokol sabitini döndürüyor; istemci yalnızca **kendi tabanının altındaysa**
reddediyor. Yorumda gerekçe de yazılı: *"hello-ok.protocol is the Gateway's
current protocol constant, not a negotiated selection."* İleri uyumlu.

> **FETİH'e uyarlama.** `fetih_desktop_bridge/__init__.py` içinde
> `PROTOCOL_VERSION = 1` zaten var. `bridge.capabilities` yanıtı bunu
> döndürüyor; C# tarafı **aralık kontrolü** yapmalı (`min_supported` /
> `max_supported`), tam eşitlik değil. Böylece köprü sürümü ilerlediğinde eski
> masaüstü sürümü kırılmaz, sadece yeni metotları kullanamaz.
>
> Bizde eşleştirme (pairing) kadar karmaşık bir güven modeline gerek yok
> (köprü **yalnızca 127.0.0.1**), ama `ConnectionErrorCategory` listesi ve
> `Degraded` durumu fikri değerli: "köprü ayakta ama sağlayıcı anahtarı yok"
> gibi *işlevsel ama kısıtlı* durumları göstermeliyiz.

---

## 7) Test ve geliştirme akışı

- **10 test projesi**: `Shared.Tests`, `Connection.Tests`, `SetupEngine.Tests`,
  `Tray.Tests`, `Tray.IntegrationTests`, **`Tray.UITests`**, `E2ETests`,
  `WinNode.Cli.Tests`, `FunctionalUI.Tests`, artı ortak `TestSupport` ve
  `Shared.TestHost`.
- `build.ps1` (17 KB) — tek giriş noktalı derleme/paketleme betiği.
- `run-app-local.ps1` — paketlenmemiş (unpackaged) geliştirme çalıştırması.
- `installer.iss` — Inno Setup betiği (MSIX zorunlu değil).
- Kurulum tipi UI'da açıkça gösteriliyor: **"Packaged (MSIX)"** /
  **"Unpackaged (developer)"** (`SettingsAppInfoProjection.InstallKind`),
  yanında çalışma zamanı yığını
  (`{framework} / {WinUI} / {Windows App SDK}`), güncelleme kanalı ("stable"),
  ve derleme tarihi (assembly dosyasının son yazma zamanı).
- `DEVELOPMENT.md` 35 KB — kurulum, derleme, test ve mimari kararlar tek dosyada.

---

## 8) Özet: FETİH'e ne alıyoruz, ne almıyoruz

### Alıyoruz (mimari fikir olarak, kod kopyalamadan)

| # | Fikir | Nereye |
|---|---|---|
| 1 | `SetupStep` soyutlaması: `CanSkip` + `Retry` + `Rollback` + `DisplayName` | `Fetih.Setup` |
| 2 | `TransactionJournal` (.jsonl, append-only, çökme sonrası yeniden okunur) | `Fetih.Setup` |
| 3 | `SetupRunLock` — eşzamanlı kurulum kilidi | `Fetih.Setup` |
| 4 | Ara kilometre taşı ekranı (uzun kurulumu ikiye bölme) | `Fetih.Setup.UI` |
| 5 | Güvenlik uyarısı → iki yol kartı → yetki seviyesi → ilerleme → özet akışı | `Fetih.Setup.UI` |
| 6 | Türetilmiş genel durum + `Degraded` kavramı, kategorize hata + yeniden deneme | `Fetih.Bridge` |
| 7 | Aralık tabanlı protokol sürüm pazarlığı (`min`/`max`, tam eşitlik değil) | `fetih_desktop_bridge` + `Fetih.Bridge` |
| 8 | Hata kutusunun **yanında duruma özel düzeltme düğmesi** | Bağlantı sayfası |
| 9 | Sandbox'ın "üç profil + ince ayar" ve sonuç-odaklı etiket dili | Sandbox sayfası |
| 10 | Şema güdümlü jenerik config düzenleyici + kaydedilmemiş/sunucu değeri karşılaştırması | Gelişmiş → Config |
| 11 | "Copy X" tanılama düğmesi dizisi + tek tık `doctor` | Tanılama sayfası |
| 12 | Kurulum tipini (Packaged/Unpackaged) ve çalışma zamanı yığınını yüzeye çıkarmak | Hakkında |
| 13 | İki bölgeli menü ("Köprü" / "Bu Bilgisayar") + alta sabit Tanılama+Ayarlar | Kabuk |
| 14 | Sağlayıcıya göre değişen ses formu, indirme boyutunu yazma, önizleme düğmesi | Ses sayfası |
| 15 | `*.Presentation` sınıflarını WinUI'den ayırıp birim testlenebilir tutmak | Tüm projeler |
| 16 | `SetupPreview.RequestedPage` — sihirbaz sayfasını tek başına açabilme | `Fetih.Setup.UI` |

### Almıyoruz

- **WebView2 / web sohbet arayüzü.** OpenClaw'ın "Use gateway's web chat
  interface" anahtarı ve `ChatWindow`'un web tarafı — biz **tamamen native**
  çiziyoruz (plan §c).
- **Tepsi öncelikli tasarım.** OpenClaw esasen bir tray yardımcısı; FETİH tam
  ekran çalışılan bir operasyon konsolu. Tepsi ikincil kısayol.
- **Marka varlıkları** — isim, ikonlar, `Assets/SidebarIcons/*.svg`, metinler.
- **WSL/Tailscale/llama.cpp kurulum adımları.** Bizim ön koşulumuz sadece
  Python; 36 adımlık ardışık düzene ihtiyacımız yok — *iskeleti* alıyoruz,
  *içeriğini* değil.
- **Zayıf Skills sayfası.** Bizim skill kataloğumuz onlarınkinden iki kat
  büyük ve konu odaklı; bu ekranı sıfırdan ve daha iddialı tasarlıyoruz.
- **"gateway" kelimesi.** Hiçbir yeni FETİH bileşeninde geçmez.
