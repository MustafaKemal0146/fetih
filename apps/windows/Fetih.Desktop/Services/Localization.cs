using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Fetih.Desktop.Services;

/// <summary>Arayüz dili.</summary>
public enum UiLanguage
{
    /// <summary>Türkçe.</summary>
    Turkish,

    /// <summary>İngilizce.</summary>
    English,
}

/// <summary>
/// Hafif TR/EN yerelleştirme katmanı. İlk açılışta sistem UI dili Türkçe ise
/// Türkçe, değilse İngilizce seçilir; kullanıcı Ayarlar'dan bunu elle
/// değiştirebilir ve seçim <c>%LOCALAPPDATA%\Fetih\Desktop\ui-prefs.json</c>
/// içine yazılır.
///
/// <para>Bilinçli olarak basit tutuldu: XAML kaynak sözlüğü (.resw) tabanlı
/// tam yerelleştirme yerine, kod arkasında <see cref="T"/> ile çözülen bir
/// anahtar-değer tablosu kullanılır. Ana navigasyon, sohbet ve temel Ayarlar
/// başlıkları kapsanır; kalan sayfaların tam çevirisi ilerideki bir adıma
/// bırakılmıştır (bkz. rapor).</para>
/// </summary>
public static class Loc
{
    private static readonly string PrefsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Fetih", "Desktop", "ui-prefs.json");

    /// <summary>Kaydedilmiş tercih: "tr", "en" veya "auto".</summary>
    private static string _preference = "auto";

    private static UiLanguage _current = UiLanguage.Turkish;

    private static bool _loaded;

    /// <summary>Dil değiştiğinde tetiklenir; kabuk menüsünü yeniden kurar.</summary>
    public static event Action? LanguageChanged;

    /// <summary>Şu an etkin dil.</summary>
    public static UiLanguage Current
    {
        get
        {
            EnsureLoaded();
            return _current;
        }
    }

    /// <summary>Kaydedilmiş tercih ("auto" | "tr" | "en").</summary>
    public static string Preference
    {
        get
        {
            EnsureLoaded();
            return _preference;
        }
    }

    /// <summary>Dil tercihini ayarla ve diske yaz. "auto" sistemi takip eder.</summary>
    public static void SetPreference(string preference)
    {
        EnsureLoaded();
        var normalized = (preference ?? "auto").Trim().ToLowerInvariant();
        if (normalized is not ("auto" or "tr" or "en"))
        {
            normalized = "auto";
        }

        var newLang = Resolve(normalized);
        var changed = normalized != _preference || newLang != _current;

        _preference = normalized;
        _current = newLang;
        Save();

        if (changed)
        {
            try
            {
                LanguageChanged?.Invoke();
            }
            catch
            {
                // Bir dinleyicinin hatası dil değişimini bozmamalı.
            }
        }
    }

    /// <summary>Bir anahtarı etkin dile çevirir. Anahtar yoksa anahtarın kendisi döner.</summary>
    public static string T(string key)
    {
        EnsureLoaded();
        if (Strings.TryGetValue(key, out var pair))
        {
            return _current == UiLanguage.Turkish ? pair.Tr : pair.En;
        }
        return key;
    }

    private static UiLanguage Resolve(string preference) => preference switch
    {
        "tr" => UiLanguage.Turkish,
        "en" => UiLanguage.English,
        _ => DetectFromSystem(),
    };

    /// <summary>
    /// "auto" tercihinin çözümü. FETİH Türkçe-öncelikli bir üründür: küratörlü
    /// sayfaların (Tanılama, Sandbox, Ses, İzinler, Sağlayıcı) sabit metinleri
    /// Türkçe yazılmıştır. Sistem dili İngilizceyken "auto"yu İngilizceye
    /// çözmek, gezinme ve ayar açıklamaları İngilizce, sayfa gövdeleri Türkçe
    /// olan KARIŞIK bir arayüz üretiyordu (kullanıcının bildirdiği sorun).
    /// Bu yüzden "auto" her zaman Türkçedir; İngilizce açık bir tercihtir ve
    /// Görünüm sayfasındaki dil seçicisinden seçilir.
    /// </summary>
    private static UiLanguage DetectFromSystem() => UiLanguage.Turkish;

    private static void EnsureLoaded()
    {
        if (_loaded)
        {
            return;
        }
        _loaded = true;
        try
        {
            if (File.Exists(PrefsPath))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(PrefsPath));
                if (doc.RootElement.TryGetProperty("language", out var lang) &&
                    lang.ValueKind == JsonValueKind.String)
                {
                    _preference = (lang.GetString() ?? "auto").Trim().ToLowerInvariant();
                }
            }
        }
        catch
        {
            _preference = "auto";
        }
        _current = Resolve(_preference);
    }

    private static void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(PrefsPath);
            if (dir is not null)
            {
                Directory.CreateDirectory(dir);
            }
            var json = JsonSerializer.Serialize(new Dictionary<string, string> { ["language"] = _preference });
            File.WriteAllText(PrefsPath, json);
        }
        catch
        {
            // Tercihi yazamazsak oturum içi seçimi yine de geçerli kalır.
        }
    }

    private readonly record struct Pair(string Tr, string En);

    private static readonly Dictionary<string, Pair> Strings = new(StringComparer.Ordinal)
    {
        // ── Navigasyon (normal mod) ──────────────────────────────────────
        ["nav.chat"] = new("Sohbet", "Chat"),
        ["nav.skills"] = new("Yetenekler", "Skills"),
        ["nav.findings"] = new("Bulgular", "Findings"),
        ["nav.diagnostics"] = new("Tanılama", "Diagnostics"),
        ["nav.settings"] = new("Ayarlar", "Settings"),

        // ── Navigasyon (Ayarlar modu) ────────────────────────────────────
        ["settings.header.connection"] = new("Bağlantı", "Connection"),
        ["settings.bridge"] = new("Masaüstü Köprüsü", "Desktop Bridge"),
        ["settings.header.model_tools"] = new("Model ve Araçlar", "Model & Tools"),
        ["settings.provider"] = new("Model ve Sağlayıcı", "Model & Provider"),
        ["settings.tools"] = new("Araçlar", "Tools"),
        ["settings.agent"] = new("Ajan", "Agent"),
        ["settings.voice"] = new("Ses", "Voice"),
        ["settings.header.security_exec"] = new("Güvenlik ve Yürütme", "Security & Execution"),
        ["settings.permissions"] = new("İzinler", "Permissions"),
        ["settings.security"] = new("Güvenlik", "Security"),
        ["settings.sandbox"] = new("Çalışma Ortamı", "Execution Environment"),
        ["settings.shell"] = new("Kabuk (Windows)", "Shell (Windows)"),
        ["settings.header.automation"] = new("Otomasyon ve Bağlam", "Automation & Context"),
        ["settings.channels"] = new("Kanallar", "Channels"),
        ["settings.memory"] = new("Hafıza", "Memory"),
        ["settings.automation"] = new("Otomasyon", "Automation"),
        ["settings.appearance"] = new("Görünüm", "Appearance"),
        ["settings.header.app"] = new("Uygulama", "Application"),
        ["settings.header.advanced"] = new("Gelişmiş", "Advanced"),
        ["settings.system"] = new("Sistem", "System"),

        // Sol menüde ham config editörü artık açıkça "Detaylı Mod" adını taşır;
        // normal ayar sayfalarından ayrılsın diye kendi başlığı altında,
        // ayraçla ayrılmış olarak, tek başına durur (bkz. MainWindow).
        ["settings.all"] = new("Detaylı Mod", "Advanced Mode"),
        ["settings.about"] = new("Hakkında", "About"),

        // ── Sohbet ───────────────────────────────────────────────────────
        ["chat.placeholder"] = new(
            "Bir görev yaz… (ör. hedef alan adı için OSINT toplama)",
            "Type a task… (e.g. OSINT gathering for a target domain)"),
        ["chat.hint"] = new(
            "Enter yeni satır · Ctrl+Enter gönderir",
            "Enter for a new line · Ctrl+Enter to send"),
        ["chat.send"] = new("Gönder", "Send"),
        ["chat.connecting"] = new("Bağlanıyor…", "Connecting…"),
        ["chat.role.user"] = new("Sen", "You"),
        ["chat.role.agent"] = new("FETİH", "FETİH"),
        ["chat.role.system"] = new("Sistem", "System"),
        ["chat.welcome"] = new(
            "FETİH masaüstü kabuğu açıldı. İlk mesajını gönderdiğinde Masaüstü Köprüsü otomatik başlatılır ve yanıtlar gerçek zamanlı olarak buraya akar.",
            "FETİH desktop shell is ready. When you send your first message the Desktop Bridge starts automatically and responses stream here in real time."),

        // ── Kabuk sayfası (Task A) ───────────────────────────────────────
        ["shell.title"] = new("Kabuk (Windows)", "Shell (Windows)"),
        ["shell.intro"] = new(
            "FETİH'in terminal aracı Windows'ta bir POSIX kabuğu üzerinden çalışır. PowerShell bilinçli olarak sunulmaz (araç katmanı export -p, pwd -P ve POSIX tırnaklamaya dayanır). İki seçenek vardır:",
            "FETİH's terminal tool runs through a POSIX shell on Windows. PowerShell is deliberately not offered (the tool layer relies on export -p, pwd -P and POSIX quoting). Two options exist:"),
        ["shell.git_bash"] = new("Git Bash", "Git Bash"),
        ["shell.git_bash.desc"] = new(
            "Git for Windows'un MSYS2 bash'i. Windows dosya sistemine doğrudan erişir (C:\\ ↔ /c/) ve Windows ikililerini çalıştırır. Varsayılan.",
            "Git for Windows' MSYS2 bash. Accesses the Windows filesystem directly (C:\\ ↔ /c/) and runs Windows binaries. Default."),
        ["shell.wsl"] = new("WSL", "WSL"),
        ["shell.wsl.desc"] = new(
            "wsl.exe üzerinden gerçek bir Linux dağıtımı. Windows sürücüleri /mnt/c/ altında görünür; apt, gcc, binwalk gibi Linux araçları kullanılabilir.",
            "A real Linux distro via wsl.exe. Windows drives appear under /mnt/c/; Linux tooling like apt, gcc, binwalk becomes available."),
        ["shell.distro"] = new("Dağıtım", "Distribution"),
        ["shell.wsl_not_installed"] = new(
            "Bu makinede kurulu bir WSL dağıtımı bulunamadı. `wsl --install -d Ubuntu` ile kurabilirsin.",
            "No installed WSL distribution was found on this machine. Install one with `wsl --install -d Ubuntu`."),
        ["shell.create_user"] = new("FETİH için WSL kullanıcısı oluştur", "Create WSL user for FETİH"),
        ["shell.create_user.desc"] = new(
            "WSL içinde 'fetih' adlı ayrılmış bir kullanıcı oluşturur; böylece ajanın yazdığı dosyalar senin ev dizinine karışmaz.",
            "Creates a dedicated 'fetih' user inside WSL so agent-written files stay out of your own home directory."),
        ["shell.user_exists"] = new("'fetih' kullanıcısı zaten var.", "The 'fetih' user already exists."),
        ["shell.saved"] = new("✓ kaydedildi", "✓ saved"),
        ["shell.save_failed"] = new("✗ kaydedilemedi", "✗ save failed"),
        ["shell.effective"] = new("Etkin kabuk", "Effective shell"),
        ["shell.needs_bridge"] = new(
            "Kabuk durumu Masaüstü Köprüsü üzerinden okunur; köprüye bağlanılıyor…",
            "Shell status is read via the Desktop Bridge; connecting…"),

        // ── Görünüm / dil ────────────────────────────────────────────────
        ["appearance.language"] = new("Arayüz dili", "Interface language"),
        ["appearance.language.auto"] = new("Otomatik (sistem)", "Automatic (system)"),
        ["appearance.language.tr"] = new("Türkçe", "Türkçe"),
        ["appearance.language.en"] = new("İngilizce", "English"),
        ["appearance.language.note"] = new(
            "Değişiklik anında uygulanır; kalıcı olarak kaydedilir.",
            "Applied immediately and saved persistently."),

        // ── Kabuk / başlık çubuğu ────────────────────────────────────────
        ["app.tagline"] = new(
            "Siber Güvenlik Operasyon Konsolu",
            "Cyber Security Operations Console"),

        // ── Masaüstü Köprüsü bağlantı durumu ─────────────────────────────
        ["bridge.state.idle"] = new("Bağlantı bekleniyor…", "Waiting to connect…"),
        ["bridge.state.connecting"] = new("Bağlanılıyor…", "Connecting…"),
        ["bridge.state.ready"] = new("Bağlı", "Connected"),
        ["bridge.state.reconnecting"] = new("Yeniden bağlanılıyor…", "Reconnecting…"),
        ["bridge.state.error"] = new("Bağlantı hatası", "Connection error"),
        ["bridge.state.model_error"] = new("Model hatası", "Model error"),
        ["bridge.detail.model_error"] = new(
            "Köprü bağlı ama modele ulaşılamıyor. Ayarlar › Model ve Sağlayıcı'yı denetle.",
            "The bridge is connected but the model is unreachable. Check Settings › Model & Provider."),
        ["bridge.detail.model_ok"] = new("Bağlı — model yanıt veriyor.", "Connected — the model is responding."),
        ["bridge.badge.tooltip_fix"] = new(
            "Düzeltmek için tıkla", "Click to fix"),

        // ── Masaüstü Köprüsü sayfası ─────────────────────────────────────
        ["bridge.title"] = new("Masaüstü Köprüsü", "Desktop Bridge"),
        ["bridge.intro"] = new(
            "Masaüstü uygulaması ile Python ajanı arasındaki taşıma katmanı. Mesajlaşma köprüsünden (Telegram/Discord/WhatsApp) tamamen ayrıdır — o katman yönetimi bu sayfada yer almaz.",
            "The transport layer between the desktop app and the Python agent. Completely separate from the messaging bridge (Telegram/Discord/WhatsApp) — that management is not on this page."),
        ["bridge.section.transport"] = new("Taşıma yapılandırması", "Transport Configuration"),
        ["bridge.section.paths"] = new("Çözümlenen yollar", "Resolved Paths"),
        ["bridge.paths_note"] = new(
            "Uygulama kullanıcının PATH'ine güvenmez; Python süreci mutlak yollarla başlatılacaktır.",
            "The app does not trust the user's PATH; the Python process will be started using absolute paths."),
        ["bridge.phase_title"] = new("Faz 1", "Phase 1"),
        ["bridge.phase_desc"] = new(
            "Bu sürümde köprüye bağlanılmaz; ayarlar diskteki yapılandırma dosyalarından salt okunur biçimde gösterilir.",
            "In this version the bridge is not connected; settings are shown read-only from on-disk configuration files."),
        ["bridge.refresh"] = new("Yeniden oku", "Reload"),
        ["bridge.transport.default"] = new("Varsayılan taşıma", "Default transport"),
        ["bridge.transport.default_note"] = new(
            "Uygulama Python sürecini kendi başlatır; açık port yoktur (en güvenli seçenek).",
            "The app launches the Python process itself; no open ports (safest option)."),
        ["bridge.transport.alt"] = new("Alternatif taşıma", "Alternative transport"),
        ["bridge.transport.alt_val"] = new("WebSocket — ws://127.0.0.1:<port>", "WebSocket — ws://127.0.0.1:<port>"),
        ["bridge.transport.alt_note"] = new(
            "Yalnızca yerel arayüze bağlanır; her oturumda üretilen tek kullanımlık bir belirteç ister.",
            "Connects only to local interface; requires a single-use token generated each session."),
        ["bridge.transport.proto"] = new("Protokol", "Protocol"),
        ["bridge.transport.proto_val"] = new("Satır sonlu JSON-RPC (NDJSON)", "Newline-delimited JSON-RPC (NDJSON)"),
        ["bridge.transport.proto_note"] = new("Aynı sözleşme iki taşıma üzerinde de geçerlidir.", "The same contract applies to both transports."),
        ["bridge.transport.port_var"] = new("Bağlantı noktası değişkeni", "Port variable"),
        ["bridge.transport.token_var"] = new("Belirteç değişkeni", "Token variable"),
        ["bridge.transport.token_note"] = new(
            " Değeri hiçbir zaman gösterilmez ve dosyaya yazılmaz; Python sürecine yalnızca ortam değişkeniyle geçirilir.",
            " Value is never displayed or written to file; passed to Python process solely via environment variable."),
        ["bridge.transport.python_mod"] = new("Python modülü", "Python module"),
        ["bridge.transport.mod_avail"] = new("fetih_desktop_bridge (mevcut)", "fetih_desktop_bridge (available)"),
        ["bridge.transport.mod_missing"] = new("fetih_desktop_bridge (henüz yok)", "fetih_desktop_bridge (not yet available)"),
        ["bridge.transport.mod_avail_note"] = new("python -m fetih_desktop_bridge ile başlatılır.", "Started via python -m fetih_desktop_bridge."),
        ["bridge.transport.mod_missing_note"] = new("Faz 1'in Python tarafı henüz eklenmedi; bağlantı bu yüzden kurulmuyor.", "Python side not yet added; connection cannot be established."),
        ["bridge.path.config"] = new("Yapılandırma", "Configuration"),
        ["bridge.path.env"] = new("Ortam dosyası", "Environment file"),
        ["bridge.path.repo"] = new("Depo kökü", "Repository root"),
        ["bridge.path.app"] = new("Uygulama klasörü", "Application directory"),
        ["bridge.env.active"] = new("Şu an ortamda tanımlı.", "Currently defined in environment."),
        ["bridge.env.file"] = new(".env dosyasında tanımlı.", "Defined in .env file."),
        ["bridge.env.none"] = new("Tanımsız — köprü başlatılırken üretilecek.", "Undefined — will be generated when bridge starts."),
        ["bridge.file.exists"] = new("Dosya mevcut.", "File exists."),
        ["bridge.file.missing"] = new("Dosya yok.", "File does not exist."),
        ["bridge.dir.exists"] = new("Klasör mevcut.", "Directory exists."),
        ["bridge.dir.missing"] = new("Klasör yok.", "Directory does not exist."),
        ["bridge.repo.outside"] = new("Uygulama depo ağacının dışından çalıştırılmış olabilir.", "App may have been run from outside repo tree."),
        ["bridge.repo.catalog"] = new("Yetenek kataloğu buradan okunur.", "Skill catalog is read from here."),

        // ── Hakkında sayfası ─────────────────────────────────────────────
        ["about.title"] = new("Hakkında", "About"),
        ["about.desc"] = new(
            "CTF çözümü, sızma testi, OSINT, adli bilişim ve kırmızı takım operasyonları için model-agnostik bir ajan. Masaüstü uygulaması kabuktur; ajan mantığı Python tarafında çalışır.",
            "A model-agnostic agent for CTF solving, penetration testing, OSINT, forensics, and red team operations. The desktop app is a shell; agent logic runs on Python."),
        ["about.section.app_info"] = new("Uygulama bilgisi", "Application Information"),
        ["about.section.links"] = new("Bağlantılar", "Links"),
        ["about.repo_link"] = new("Proje deposu — github.com/MustafaKemal0146/fetih", "Project repository — github.com/MustafaKemal0146/fetih"),
        ["about.releases_link"] = new("Sürümler ve yayın notları", "Releases and release notes"),
        ["about.design_doc"] = new("Masaüstü uygulaması tasarım belgesi: docs/windows-app-plani.md (depo içinde)", "Desktop application design document: docs/windows-app-plani.md (in repository)"),
        ["about.disclaimer_title"] = new("Kapsam uyarısı", "Scope Warning"),
        ["about.disclaimer_message"] = new(
            "FETİH bir saldırı simülasyonu ve güvenlik testi aracıdır. Yalnızca sahibi olduğun ya da yazılı izin aldığın sistemlerde kullan.",
            "FETİH is an attack simulation and security testing tool. Only use on systems you own or have written permission to test."),
        ["about.row.app_name"] = new("Uygulama adı", "Application name"),
        ["about.row.version"] = new("Sürüm", "Version"),
        ["about.row.build_date"] = new("Derleme tarihi", "Build date"),
        ["about.row.runtime"] = new("Çalışma zamanı", "Runtime"),
        ["about.row.target_framework"] = new("Hedef çatı", "Target framework"),
        ["about.row.architecture"] = new("Mimari", "Architecture"),
        ["about.row.windows"] = new("Windows", "Windows"),
        ["about.row.install_type"] = new("Kurulum tipi", "Installation type"),
        ["about.row.install_desc"] = new(
            "MSIX paketleme Faz 4'te eklenecek; şu anki derleme paket kimliği olmadan çalışır.",
            "Packaging added in Phase 4; current build runs without package identity."),
        ["about.row.app_dir"] = new("Uygulama klasörü", "Application directory"),

        // ── Tanılama sayfası ─────────────────────────────────────────────
        ["diag.title"] = new("Tanılama", "Diagnostics"),
        ["diag.subtitle"] = new(
            "Destek istenirken ilk bakılacak yer: çalışma zamanı bilgisi, çözümlenen yollar ve çökme günlüğü.",
            "First place to look when asking for support: runtime info, resolved paths, and crash log."),
        ["diag.section.system"] = new("Sistem bilgisi", "System Information"),
        ["diag.section.paths"] = new("Çözümlenen yollar", "Resolved Paths"),
        ["diag.section.crash_log"] = new("Çökme günlüğü", "Crash Log"),
        ["diag.copy"] = new("Panoya kopyala", "Copy to clipboard"),
        ["diag.clear"] = new("Günlüğü temizle", "Clear log"),
        ["diag.copied"] = new("Tanılama raporu panoya kopyalandı.", "Diagnostics report copied to clipboard."),
        ["diag.cleared"] = new("Çökme günlüğü temizlendi.", "Crash log cleared."),
        ["diag.no_log"] = new("Temizlenecek günlük yok.", "No log to clear."),
        ["diag.copy_failed"] = new("Panoya kopyalanamadı: ", "Could not copy to clipboard: "),
        ["diag.clear_failed"] = new("Günlük temizlenemedi: ", "Could not clear log: "),
        ["diag.row.app"] = new("Uygulama", "Application"),
        ["diag.row.build_date"] = new("Derleme tarihi", "Build date"),
        ["diag.row.runtime"] = new("Çalışma zamanı", "Runtime"),
        ["diag.row.target_framework"] = new("Hedef çatı", "Target framework"),
        ["diag.row.ui"] = new("Arayüz", "UI"),
        ["diag.row.proc_arch"] = new("Süreç mimarisi", "Process architecture"),
        ["diag.row.os_arch"] = new("İşletim sistemi mimarisi", "OS architecture"),
        ["diag.row.windows"] = new("Windows", "Windows"),
        ["diag.row.install_type"] = new("Kurulum tipi", "Installation type"),
        ["diag.row.machine"] = new("Makine", "Machine"),
        ["diag.row.app_dir"] = new("Uygulama klasörü", "Application directory"),
        ["diag.row.logs"] = new("Günlükler", "Logs"),
        ["diag.row.sandbox"] = new("Sandbox klasörü", "Sandbox folder"),
        ["diag.row.repo"] = new("Depo kökü", "Repository root"),
        ["diag.row.crash_log"] = new("Çökme günlüğü", "Crash log"),
        ["diag.present"] = new("Mevcut", "Present"),
        ["diag.missing"] = new("Yok", "Missing"),
        ["diag.file_missing"] = new("Dosya yok", "File not found"),
        ["diag.keys_read"] = new("kök anahtar okundu", "root keys read"),
        ["diag.keys_defined"] = new("anahtar tanımlı (değerler okunmaz)", "keys defined (values hidden)"),
        ["diag.catalog_unreadable"] = new("Yetenek kataloğu okunamaz", "Skill catalog unreadable"),

        // ── Ses sayfası ──────────────────────────────────────────────────
        ["voice.title"] = new("Ses", "Voice"),
        ["voice.subtitle"] = new(
            "FETİH'in ses yetenekleri: metin okuma (TTS), konuşma tanıma (STT) ve bas-konuş kaydı. Değerler ~/.fetih/config.yaml dosyasından okunur.",
            "FETİH's voice capabilities: text-to-speech (TTS), speech-to-text (STT), and push-to-talk recording. Values are read from ~/.fetih/config.yaml."),
        ["voice.section.tts"] = new("Metin okuma (TTS)", "Text-to-Speech (TTS)"),
        ["voice.section.stt"] = new("Konuşma tanıma (STT)", "Speech-to-Text (STT)"),
        ["voice.section.recording"] = new("Kayıt davranışı", "Recording Behavior"),
        ["voice.phase_title"] = new("Faz 3", "Phase 3"),
        ["voice.phase_desc"] = new(
            "Bas-konuş girişi ve yanıt okuma masaüstü kabuğuna Faz 3'te bağlanacak. Bu sayfa şimdilik Python tarafındaki gerçek ses yapılandırmasını salt okunur gösterir.",
            "Push-to-talk input and response readout will connect to the desktop shell in Phase 3. For now, this page shows the Python side's actual voice configuration read-only."),
        ["voice.provider"] = new("Sağlayıcı", "Provider"),
        ["voice.voice"] = new("Ses", "Voice"),
        ["voice.voice_id"] = new("Ses kimliği", "Voice ID"),
        ["voice.model"] = new("Model", "Model"),
        ["voice.language"] = new("Dil", "Language"),
        ["voice.device"] = new("Aygıt", "Device"),
        ["voice.enabled"] = new("Etkin", "Enabled"),
        ["voice.undefined"] = new("(tanımsız)", "(undefined)"),

        // ── Model ve Sağlayıcı sayfası ───────────────────────────────────
        ["provider.title"] = new("Model ve Sağlayıcı", "Model & Provider"),
        ["provider.subtitle"] = new(
            "FETİH model-agnostiktir. Aşağıdaki liste desteklenen sağlayıcıları ve her biri için gereken ortam değişkenlerinin tanımlı olup olmadığını gösterir. Güvenlik gereği anahtar değerleri asla okunmaz veya gösterilmez.",
            "FETİH is model-agnostic. The list below shows supported providers and whether required environment variables are set. For security, key values are never read or displayed."),
        ["provider.active_config"] = new("Etkin yapılandırma", "Active Configuration"),
        ["provider.change_model"] = new("Etkin modeli değiştir", "Change Active Model"),
        ["provider.change_model_desc"] = new(
            "Sağlayıcıyı ara ve seç, model kimliğini gir. Kaydettiğinde config.set ile ~/.fetih/config.yaml'a yazılır ve bir sonraki mesajda etkili olur. API anahtarı ~/.fetih/.env içinde tanımlı olmalıdır.",
            "Search and select a provider, enter the model ID. When saved, config.set writes to ~/.fetih/config.yaml and it takes effect on the next message. The API key must be defined in ~/.fetih/.env."),
        ["provider.label.provider"] = new("Sağlayıcı", "Provider"),
        ["provider.label.model"] = new("Model", "Model"),
        ["provider.placeholder.provider"] = new("Sağlayıcı ara (ör. groq, anthropic)…", "Search provider (e.g. groq, anthropic)…"),
        ["provider.placeholder.model"] = new("Model kimliği (ör. llama-3.3-70b-versatile)", "Model ID (e.g. llama-3.3-70b-versatile)"),
        ["provider.save"] = new("Kaydet", "Save"),
        ["provider.slots_title"] = new("Diğer model yuvaları", "Other Model Slots"),
        ["provider.slots_intro"] = new(
            "Etkin model dışındaki model seçimleri. Sağlayıcı listesi köprüden (providers.list) gelir; her kayıt config.set ile ~/.fetih/config.yaml'a yazılır. Boş bırakılan model kutusu 'sağlayıcının varsayılanı' demektir.",
            "Model selections other than the active model. Provider list comes from the bridge (providers.list); each entry is written to ~/.fetih/config.yaml via config.set. Leaving the model box blank means 'provider default'."),
        ["provider.search_placeholder"] = new("Sağlayıcı ara…", "Search provider…"),
        ["provider.only_configured"] = new("Yalnızca kimlik bilgisi tanımlı olanlar", "Only configured providers"),

        // ── Bulgular sayfası ─────────────────────────────────────────────
        ["findings.title"] = new("Bulgular", "Findings"),
        ["findings.summary"] = new("Ajan tarafından üretilen güvenlik bulguları burada toplanır.", "Security findings produced by the agent are collected here."),
        ["findings.scan_button"] = new("Güvenlik Taraması Başlat", "Start Security Scan"),
        ["findings.empty_title"] = new("Henüz bulgu yok", "No findings yet"),
        ["findings.empty_desc"] = new(
            "Bir tarama veya görev tamamlandığında bulgular burada listelenecek. Masaüstü Köprüsü üzerinden yetenek ve çalışma alanı güvenlik taraması gerçekleştirilebilir.",
            "Findings will be listed here once a scan or task completes. Skill and workspace security scanning can be performed via the Desktop Bridge."),
        ["findings.empty_disclaimer"] = new("Yalnızca yetkili olduğun sistemlerde test yap.", "Only test on systems you are authorized to test."),
        ["findings.severity.all"] = new("Tüm ciddiyet seviyeleri", "All severity levels"),
        ["findings.severity.critical"] = new("Kritik", "Critical"),
        ["findings.severity.high"] = new("Yüksek", "High"),
        ["findings.severity.medium"] = new("Orta", "Medium"),
        ["findings.severity.low"] = new("Düşük", "Low"),
        ["findings.severity.info"] = new("Bilgi", "Info"),
        ["findings.showing_count"] = new("{0} / {1} bulgu gösteriliyor", "Showing {0} / {1} findings"),

        // ── Yetenekler sayfası ───────────────────────────────────────────
        ["skills.title"] = new("Yetenekler", "Skills"),
        ["skills.scanning"] = new("Yetenek kataloğu taranıyor…", "Scanning skill catalog…"),
        ["skills.search_placeholder"] = new("Ara: ör. SQL injection, pcap, ATT&CK, osint…", "Search: e.g. SQL injection, pcap, ATT&CK, osint…"),
        ["skills.all_categories"] = new("Tüm kategoriler", "All categories"),
        ["skills.failed"] = new("Yetenek kataloğu okunamadı.", "Could not read skill catalog."),
        ["skills.error"] = new("Katalog taranırken hata oluştu:\n", "An error occurred while scanning catalog:\n"),

        // ── Genel ────────────────────────────────────────────────────────
        ["common.reload"] = new("Yenile", "Reload"),
        ["common.on"] = new("açık", "on"),
        ["common.off"] = new("kapalı", "off"),

        // ── Jenerik yapılandırma düzenleyici ─────────────────────────────
        ["config.subtitle"] = new(
            "Bir değeri değiştirdiğinde ~/.fetih/config.yaml dosyasına anında yazılır. Her satırın altındaki açıklama o ayarın ne yaptığını ve değiştirilirse ne olacağını anlatır.",
            "Changing a value writes it to ~/.fetih/config.yaml immediately. The note under each row explains what that setting does and what changes if you touch it."),
        ["config.reload"] = new("Yeniden yükle", "Reload"),
        ["config.saving"] = new("kaydediliyor…", "saving…"),
        ["config.saved"] = new("✓ kaydedildi", "✓ saved"),
        ["config.revert"] = new("Yüklenen değere dön", "Revert to the loaded value"),
        ["config.rejected"] = new(
            "reddedildi (gizli anahtar veya yönetilen kurulum)",
            "refused (secret key or managed installation)"),
        ["config.empty"] = new(
            "Bu bölüm için düzenlenebilir alan bulunamadı.",
            "No editable field was found for this section."),
        ["config.read_failed"] = new("Yapılandırma okunamadı.", "Could not read the configuration."),
        ["config.load_failed"] = new("Yapılandırma yüklenemedi: ", "Could not load the configuration: "),
        ["config.bridge_error"] = new("Köprü hatası", "Bridge error"),
        ["config.secret"] = new(
            "•••••• (gizli — ~/.fetih/.env içinde)",
            "•••••• (secret — kept in ~/.fetih/.env)"),
        ["config.env_ref"] = new(
            "  (ortam değişkeni referansı)",
            "  (environment variable reference)"),
        ["config.complex_list"] = new(
            "  (karmaşık liste — burada düzenlenmez)",
            "  (complex list — not editable here)"),
        ["config.list_placeholder"] = new("virgülle ayrılmış liste", "comma-separated list"),

        // ── Detaylı Mod (ham config editörü) ─────────────────────────────
        ["config.advanced.subtitle"] = new(
            "FETİH'in diskteki yapılandırma dosyasının tamamı, bölüm bölüm. Her satırda ham anahtar adı ve o anahtara özgü açıklama vardır; bir değeri değiştirdiğinde ~/.fetih/config.yaml dosyasına anında yazılır.",
            "The whole of FETİH's on-disk configuration file, section by section. Every row shows the raw key name and a note specific to it; changing a value writes to ~/.fetih/config.yaml immediately."),
        ["config.advanced.warn.title"] = new(
            "Detaylı Mod — ham yapılandırma",
            "Advanced Mode — raw configuration"),
        ["config.advanced.warn.body"] = new(
            "Burada FETİH'in TÜM ham yapılandırma anahtarları bulunur. Ne yaptığınızdan emin değilseniz normal Ayarlar sayfalarını kullanın.",
            "This page holds ALL of FETİH's raw configuration keys. If you are not sure what you are doing, use the normal Settings pages instead."),

        // ── Sadeleştirilmiş ayar sayfaları ───────────────────────────────
        ["simple.reload"] = new("Yenile", "Reload"),
        ["simple.advanced_group"] = new("Gelişmiş", "Advanced"),
        ["simple.reference"] = new("Ayrıntılar", "Details"),
        ["simple.list_empty"] = new("Liste boş.", "The list is empty."),
        ["simple.list_clear"] = new("Listeyi boşalt", "Clear the list"),
        ["simple.unknown_value"] = new(
            "Şu anki değer listede yok: {0}",
            "The current value is not in the list: {0}"),
        ["simple.open_advanced"] = new(
            "Bu ayarların ham hâlini Detaylı Mod'da aç",
            "Open the raw form of these settings in Advanced Mode"),

        // ── Tehlikeli Bölge (Sistem sayfasının en altı) ──────────────────
        ["danger.title"] = new("Tehlikeli Bölge", "Danger Zone"),
        ["danger.intro"] = new(
            "Bu iki işlem geri alınamaz. İkisi arasındaki fark önemlidir: biri yalnızca ayarlarını sıfırlar, diğeri her şeyi siler.",
            "These two actions cannot be undone. The difference between them matters: one only resets your settings, the other deletes everything."),

        ["danger.reset.title"] = new("Sıfırla (Yeni Kurulum)", "Reset (fresh install)"),
        ["danger.reset.desc"] = new(
            "YALNIZCA yapılandırmanı siler: sağlayıcı/model seçimin ve API anahtarların. Sohbet geçmişin, hafızan ve günlüklerin KORUNUR. Uygulamayı bir sonraki açışında ilk kurulum sihirbazı yeniden çalışır.",
            "Deletes ONLY your configuration: your provider/model choice and your API keys. Your conversation history, memory and logs are KEPT. The first-run setup wizard runs again the next time you open the app."),
        ["danger.reset.button"] = new("Sıfırla (Yeni Kurulum)", "Reset (fresh install)"),
        ["danger.reset.confirm_title"] = new(
            "Yapılandırma sıfırlansın mı?", "Reset the configuration?"),
        ["danger.reset.confirm_body"] = new(
            "Sadece sağlayıcı/model ayarların ve API anahtarların (config.yaml ve .env) silinecek. Sohbet geçmişin, hafızan ve günlüklerin korunacak. Uygulamayı yeniden açtığında ilk kurulum sihirbazı çalışacak.\n\nEmin misin?",
            "Only your provider/model settings and API keys (config.yaml and .env) will be deleted. Your conversation history, memory and logs will be kept. The setup wizard will run when you reopen the app.\n\nAre you sure?"),
        ["danger.reset.done"] = new(
            "Yapılandırma sıfırlandı. Sohbet geçmişin duruyor. Uygulamayı yeniden başlatman gerekiyor.",
            "The configuration has been reset. Your conversation history is intact. You need to restart the app."),

        ["danger.wipe.title"] = new("Tüm verileri sil", "Delete all data"),
        ["danger.wipe.desc"] = new(
            "FETİH'in senin hakkında sakladığı HER ŞEYİ siler: sohbet geçmişi, hafıza, günlükler, çalışma alanları VE yapılandırman (API anahtarların dahil). Geri alınamaz.",
            "Deletes EVERYTHING FETİH keeps about you: conversation history, memory, logs, sandboxes AND your configuration (API keys included). It cannot be undone."),
        ["danger.wipe.button"] = new("Tüm verileri sil", "Delete all data"),
        ["danger.wipe.confirm_title"] = new("Emin misiniz?", "Are you sure?"),
        ["danger.wipe.confirm_body"] = new(
            "Bu işlem tüm sohbet geçmişini, hafızayı, günlükleri VE yapılandırmanızı (API anahtarları dahil) kalıcı olarak siler. Geri alınamaz.\n\nDevam edilsin mi?",
            "This permanently deletes all conversation history, memory, logs AND your configuration (API keys included). It cannot be undone.\n\nShall we continue?"),
        ["danger.wipe.done"] = new(
            "Tüm veriler silindi. Uygulamayı yeniden başlatmanız gerekiyor.",
            "All data has been deleted. You need to restart the app."),

        ["danger.yes"] = new("Evet, sil", "Yes, delete"),
        ["danger.yes_reset"] = new("Evet, sıfırla", "Yes, reset"),
        ["danger.cancel"] = new("Vazgeç", "Cancel"),
        ["danger.restart_title"] = new("Yeniden başlatma gerekiyor", "Restart required"),
        ["danger.restart_now"] = new("Şimdi yeniden başlat", "Restart now"),
        ["danger.restart_later"] = new("Sonra", "Later"),
        ["danger.working"] = new("siliniyor…", "deleting…"),
        ["danger.partial"] = new(
            "Bazı dosyalar kullanımda olduğu için silinemedi: ",
            "Some files could not be deleted because they are in use: "),
        ["danger.failed"] = new("İşlem başarısız: ", "The action failed: "),
    };
}
