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
/// anahtar-değer tablosu kullanılır. Gezinme, sohbet, ilk kurulum sihirbazı
/// ve bütün ayar sayfalarının kullanıcıya görünen metinleri bu tablodadır;
/// XAML içinde sabit metin bırakılmaz (bkz. <c>Loc.T</c> çağrıları).</para>
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
    /// "auto" tercihinin çözümü: sistemin arayüz dili neyse o.
    ///
    /// <para>Türkçe kültürler (<c>tr</c>, <c>tr-TR</c> ve türevleri) Türkçeye
    /// çözülür; diğer bütün kültürler İngilizceye. Karşılaştırma kültür adının
    /// köküne göre yapılır, çünkü <c>TwoLetterISOLanguageName</c> sabit
    /// kültürlerde boş dönebiliyor.</para>
    ///
    /// <para>Kültür bilgisi okunamazsa (bozuk kullanıcı profili, kısıtlı
    /// ortam) güvenli varsayılan Türkçedir: ürünün küratörlü içeriği Türkçe
    /// yazıldığı için bu, boş bir ekran yerine okunabilir bir arayüz verir.</para>
    /// </summary>
    private static UiLanguage DetectFromSystem()
    {
        try
        {
            var culture = System.Globalization.CultureInfo.CurrentUICulture;
            if (culture is null)
            {
                return UiLanguage.Turkish;
            }

            var tag = culture.TwoLetterISOLanguageName;
            if (string.IsNullOrWhiteSpace(tag))
            {
                tag = culture.Name;
            }

            return tag.StartsWith("tr", StringComparison.OrdinalIgnoreCase)
                ? UiLanguage.Turkish
                : UiLanguage.English;
        }
        catch
        {
            // Kültür API'si her ortamda güvenilir değil; Türkçe güvenli seçim.
            return UiLanguage.Turkish;
        }
    }

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
        ["bridge.live_title"] = new(
            "Köprü bu sürümde etkin",
            "The bridge is active in this build"),
        ["bridge.live_desc"] = new(
            "Uygulama Python köprüsünü kendisi başlatır ve ilk mesajda bağlanır. Yukarıdaki değerler canlı durumu yansıtır; hepsi salt okunur bilgidir.",
            "The app starts the Python bridge itself and connects on the first message. The values above reflect live state; all of them are read-only information."),
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
        ["bridge.transport.mod_missing"] = new("fetih_desktop_bridge (bulunamadı)", "fetih_desktop_bridge (not found)"),
        ["bridge.transport.mod_avail_note"] = new("python -m fetih_desktop_bridge ile başlatılır.", "Started via python -m fetih_desktop_bridge."),
        ["bridge.transport.mod_missing_note"] = new(
            "Python modülü depo kökünde görünmüyor. Uygulamayı depo ağacının içinden çalıştır; köprü kurulana kadar bağlantı kurulamaz.",
            "The Python module is not visible in the repository root. Run the app from inside the repository tree; the bridge cannot connect until it is there."),
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
            "Bu derleme paketlenmemiş (paket kimliği olmadan) çalışır; güncelleme dağıtımı depodan elle yapılır.",
            "This build runs unpackaged (without package identity); updates are distributed manually from the repository."),
        ["about.row.app_dir"] = new("Uygulama klasörü", "Application directory"),
        ["about.unknown"] = new("bilinmiyor", "unknown"),
        ["about.install.packaged"] = new("Paketli (MSIX)", "Packaged (MSIX)"),
        ["about.install.unpackaged"] = new("Paketlenmemiş (geliştirici)", "Unpackaged (developer)"),

        // ── Tanılama sayfası ─────────────────────────────────────────────
        ["diag.title"] = new("Tanılama", "Diagnostics"),
        ["diag.subtitle"] = new(
            "Destek istenirken ilk bakılacak yer: çalışma zamanı bilgisi, çözümlenen yollar ve çökme günlüğü.",
            "First place to look when asking for support: runtime info, resolved paths, and crash log."),
        ["diag.section.system"] = new("Sistem bilgisi", "System Information"),
        ["diag.section.paths"] = new("Çözümlenen yollar", "Resolved Paths"),
        ["diag.section.crash_log"] = new("Çökme günlüğü", "Crash Log"),
        ["diag.refresh"] = new("Yenile", "Reload"),
        ["diag.copy"] = new("Panoya kopyala", "Copy to clipboard"),
        ["diag.clear"] = new("Günlüğü temizle", "Clear log"),
        ["diag.none"] = new("(bulunamadı)", "(not found)"),
        ["diag.unknown"] = new("bilinmiyor", "unknown"),
        ["diag.log_absent"] = new(" — dosya yok (hiç çökme kaydedilmemiş).", " — file missing (no crash has ever been recorded)."),
        ["diag.log_empty"] = new("Günlük boş.", "The log is empty."),
        ["diag.log_none"] = new("Kayıtlı çökme yok.", "No crash recorded."),
        ["diag.log_bytes"] = new(" bayt · son yazma ", " bytes · last written "),
        ["diag.log_read_failed"] = new("Günlük okunamadı: ", "Could not read the log: "),
        ["diag.log_tail_notice"] = new(
            "… (günlüğün yalnızca son bölümü gösteriliyor) …\n",
            "… (only the tail of the log is shown) …\n"),
        ["diag.report_title"] = new("FETİH Masaüstü — tanılama raporu", "FETİH Desktop — diagnostics report"),
        ["diag.report_created"] = new("Oluşturma: ", "Created: "),
        ["diag.report_crash_log"] = new("Çökme günlüğü:", "Crash log:"),
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
        ["voice.live_title"] = new("Bu sayfa yalnızca bilgi gösterir", "This page is read-only"),
        ["voice.live_desc"] = new(
            "Bas-konuş kaydı ve yanıt okuma Python tarafında yürütülür; masaüstü kabuğunda kayıt düğmesi yoktur. Bu sayfa, diskteki gerçek ses yapılandırmasını değiştirmeden gösterir — düzenlemek için Ayarlar › Detaylı Mod'u kullan.",
            "Push-to-talk recording and response readout run on the Python side; the desktop shell has no record button. This page shows the real on-disk voice configuration without changing it — use Settings › Advanced Mode to edit it."),
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
        ["provider.label.api_key"] = new("API Anahtarı", "API Key"),
        ["provider.placeholder.provider"] = new("Sağlayıcı ara (ör. groq, deepseek, anthropic)…", "Search provider (e.g. groq, deepseek, anthropic)…"),
        ["provider.placeholder.model"] = new("Model seç veya yaz (ör. deepseek-chat)…", "Select or type a model (e.g. deepseek-chat)…"),
        ["provider.placeholder.api_key_configured"] = new("●●●●●●●●  (Tanımlı — değiştirmek için yeni anahtar gir)", "●●●●●●●●  (Configured — enter new key to replace)"),
        ["provider.placeholder.api_key_missing"] = new("API anahtarını gir (ör. sk-…)", "Enter API key (e.g. sk-…)"),
        ["provider.status.key_configured"] = new("Tanımlı", "Configured"),
        ["provider.status.key_missing"] = new("Eksik", "Missing"),
        ["provider.get_key"] = new("Anahtar al ↗", "Get key ↗"),
        ["provider.local_no_key"] = new("Yerel sunucu — API anahtarı gerekmez.", "Local server — no API key required."),
        ["provider.cli_auth_required"] = new("Bu sağlayıcı CLI veya OAuth oturumu gerektirir.", "This provider requires CLI or OAuth login."),
        ["provider.select_button"] = new("Bu Sağlayıcıyı Seç", "Select Provider"),
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
        ["findings.severity_label"] = new("Ciddiyet süzgeci", "Severity filter"),
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
        ["config.error.no_keys"] = new(
            "config.yaml okundu ancak hiçbir anahtar ayrıştırılamadı.",
            "config.yaml was read but no key could be parsed."),
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

        // ── Sohbet: köprü hataları ve bağlantı ───────────────────────────
        ["chat.error.session_unknown"] = new(
            "Köprü bu oturumu tanımıyor; yeni bir oturum açılacak.",
            "The bridge does not recognize this session; a new one will be opened."),
        ["chat.error.busy"] = new(
            "Bu oturumda zaten bir tur çalışıyor; bitmesini bekle.",
            "A turn is already running in this session; wait for it to finish."),
        ["chat.error.agent_failed"] = new("Ajan çalıştı ama başarısız oldu: ", "The agent ran but failed: "),
        ["chat.error.auth"] = new("Köprü kimlik doğrulaması reddedildi.", "The bridge refused authentication."),
        ["chat.error.cancel_failed"] = new("Tur durdurulamadı: ", "The turn could not be stopped: "),
        ["chat.error.bridge"] = new("Köprü hatası (", "Bridge error ("),
        ["chat.warmup_failed"] = new(
            "Masaüstü Köprüsü'ne bağlanılamadı: ",
            "Could not connect to the Desktop Bridge: "),
        ["chat.warmup_retry"] = new(
            " · İlk mesajı gönderdiğinde tekrar denenecek.",
            " · It will be retried when you send your first message."),

        // ── Sohbet: mesaj ve araç kartı etiketleri ───────────────────────
        ["chat.role.tool"] = new("🔧 Araç", "🔧 Tool"),
        ["chat.thought.thinking"] = new("🧠 Düşünülüyor…", "🧠 Thinking…"),
        ["chat.thought.header"] = new("🧠 Düşünce Süreci", "🧠 Reasoning"),
        ["chat.tool.running"] = new("çalışıyor…", "running…"),
        ["chat.tool.done"] = new("tamamlandı", "done"),

        // ── Sohbet: mesaj eylemi düğmeleri ───────────────────────────────
        ["chat.action.copy"] = new("Kopyala", "Copy"),
        ["chat.action.copy.hint"] = new(
            "Bu mesajı panoya kopyala", "Copy this message to the clipboard"),
        ["chat.action.edit"] = new("Düzenle", "Edit"),
        ["chat.action.edit.hint"] = new(
            "Bu mesajı giriş kutusuna yükler; düzeltilmiş hâlini gönderirsin",
            "Load this message into the input box, then send the corrected version"),
        ["chat.action.retry"] = new("Yeniden dene", "Retry"),
        ["chat.action.retry.hint"] = new("Bu turu yeniden gönder", "Send this turn again"),
        ["chat.action.stop"] = new("Durdur", "Stop"),
        ["chat.action.copied"] = new("Mesaj panoya kopyalandı.", "Message copied to the clipboard."),
        ["chat.action.copy_failed"] = new("Panoya kopyalanamadı.", "Could not copy to the clipboard."),
        ["chat.action.busy"] = new(
            "Bir tur zaten çalışıyor. Önce durdur.",
            "A turn is already running. Stop it first."),
        ["chat.action.no_turn"] = new(
            "Yinelenecek bir kullanıcı mesajı yok.",
            "No preceding user message to repeat."),
        ["chat.action.cancelling"] = new("Tur durduruluyor…", "Stopping the turn…"),
        ["chat.action.cancelled"] = new(
            "Tur durduruldu. O ana kadar gelen çıktı yukarıda duruyor.",
            "Turn stopped. Partial output is kept above."),
        ["chat.action.send_failed"] = new("Mesaj gönderilemedi: ", "Message could not be sent: "),
        ["chat.action.edit_restarted"] = new(
            "Mesaj düzenlendi; sonrasındaki turlar kaldırıldı ve yeni bir köprü oturumu başlatıldı.",
            "The message was edited; everything after it was removed and a new bridge session started."),
        ["chat.action.session_gone"] = new(
            "Önceki köprü oturumu artık yok; yeni bir oturum başlatıldı.",
            "The previous bridge session no longer exists; a new one was started."),

        // ── Ses sayfası: satır etiketleri ve notları ─────────────────────
        ["voice.recording.key"] = new("Kayıt kısayolu", "Recording shortcut"),
        ["voice.recording.key.desc"] = new(
            "Bas-konuş kaydını başlatır/durdurur.", "Starts and stops push-to-talk recording."),
        ["voice.recording.max"] = new("Azami kayıt süresi", "Maximum recording length"),
        ["voice.recording.auto_tts"] = new("Yanıtı otomatik seslendir", "Read responses aloud automatically"),
        ["voice.recording.beep"] = new("Kayıt bip sesleri", "Recording beeps"),
        ["voice.recording.beep.desc"] = new(
            "Kayıt başlangıç/bitiş sinyali.", "Start/stop signal for recording."),
        ["voice.recording.silence_threshold"] = new("Sessizlik eşiği", "Silence threshold"),
        ["voice.recording.silence_threshold.desc"] = new(
            "RMS bu değerin altındaysa sessizlik sayılır (0–32767).",
            "Audio below this RMS level counts as silence (0–32767)."),
        ["voice.recording.silence_duration"] = new("Sessizlik süresi", "Silence duration"),
        ["voice.recording.silence_duration.desc"] = new(
            "Sürekli (VAD) modda otomatik durdurma eşiği.",
            "Automatic stop threshold in continuous (VAD) mode."),
        ["voice.tts.options"] = new(
            "Seçenekler: edge (ücretsiz), elevenlabs, openai, xai, minimax, mistral, gemini, " +
            "neutts / kittentts / piper (yerel).",
            "Options: edge (free), elevenlabs, openai, xai, minimax, mistral, gemini, " +
            "neutts / kittentts / piper (local)."),
        ["voice.stt.options"] = new(
            "Seçenekler: local (faster-whisper, ücretsiz), groq, openai (Whisper API), mistral (Voxtral).",
            "Options: local (faster-whisper, free), groq, openai (Whisper API), mistral (Voxtral)."),
        ["voice.stt.model.options"] = new(
            "tiny / base / small / medium / large-v3", "tiny / base / small / medium / large-v3"),
        ["voice.seconds"] = new("{0} sn", "{0} s"),
        ["voice.auto_detect"] = new("(otomatik algıla)", "(detect automatically)"),

        // ── Yetenekler sayfası: özet ve boş durum ────────────────────────
        ["skills.summary.repo_missing"] = new(
            "FETİH deposu bulunamadı — yetenekler yalnızca {0} altından okundu ({1} kayıt).",
            "FETİH repository not found — skills were read only from {0} ({1} entries)."),
        ["skills.summary.counts"] = new(
            "{0} yetenek · skills/ {1} · optional-skills/ {2} · yalnızca kullanıcıda {3} ({4} ms)",
            "{0} skills · skills/ {1} · optional-skills/ {2} · user-only {3} ({4} ms)"),
        ["skills.summary.duplicates"] = new(
            " · {0} kurulu kopya atlandı", " · {0} installed duplicate(s) skipped"),
        ["skills.summary.warning"] = new("{0} — uyarı: {1}", "{0} — warning: {1}"),
        ["skills.empty.none"] = new(
            "Hiç SKILL.md bulunamadı. Depo kökü çözümlenemediyse uygulamayı depo içindeki apps/windows/Fetih.Desktop klasöründen çalıştırın.",
            "No SKILL.md was found. If the repository root could not be resolved, run the app from the apps/windows/Fetih.Desktop folder inside the repository."),
        ["skills.empty.filter"] = new(
            "Bu arama/kategori için sonuç yok.", "No results for this search/category."),

        // ── Kabuk sayfası: durum satırları ───────────────────────────────
        ["shell.bridge_error"] = new("Köprü hatası ({0}): {1}", "Bridge error ({0}): {1}"),
        ["shell.windows_only"] = new(
            "Kabuk seçimi yalnızca Windows'ta geçerlidir.",
            "Shell selection only applies on Windows."),

        // ── Model ve Sağlayıcı: yuvalar ve kaydetme ──────────────────────
        ["provider.config_unreadable"] = new(
            "Yapılandırma okunamadı; köprü bağlı değil.",
            "Could not read the configuration; the bridge is not connected."),
        ["provider.config_error"] = new("Yapılandırma okunamadı: ", "Could not read the configuration: "),
        ["provider.slots.fallback_title"] = new("Yedek model", "Fallback model"),
        ["provider.slots.fallback_desc"] = new(
            "Birincil sağlayıcı 429/503/529 döndüğünde bu model devreye girer. Boş bırakılırsa yedek yoktur.",
            "This model takes over when the primary provider returns 429/503/529. Left empty, there is no fallback."),
        ["provider.slots.chain_note"] = new(
            "Şu anda {0} basamaklı bir yedek zinciri tanımlı; buradan kaydetmek zinciri tek bir yedeğe indirir.",
            "A {0}-step fallback chain is currently configured; saving here reduces the chain to a single fallback."),
        ["provider.slots.aux_header"] = new(
            "Yardımcı modeller — yan görev başına ayrı model ({0} yuva)",
            "Auxiliary models — a separate model per side task ({0} slots)"),
        ["provider.slots.aux_name"] = new("Yardımcı modeller", "Auxiliary models"),
        ["provider.slots.auto"] = new("Otomatik (auto)", "Automatic (auto)"),
        ["provider.slots.none"] = new("(yok)", "(none)"),
        ["provider.slots.model_placeholder"] = new(
            "Model kimliği (boş = sağlayıcının varsayılanı)",
            "Model ID (empty = the provider's default)"),
        ["provider.slots.save"] = new("Kaydet", "Save"),
        ["provider.slots.save_name"] = new("{0} kaydet", "Save {0}"),
        ["provider.slots.saving"] = new("kaydediliyor…", "saving…"),
        ["provider.slots.saved"] = new("✓ kaydedildi", "✓ saved"),
        ["provider.slots.rejected"] = new(
            "reddedildi (yönetilen kurulum)", "refused (managed installation)"),
        ["provider.models.curated"] = new("{0} model listelendi.", "{0} models listed."),
        ["provider.models.live"] = new(
            "{0} model sağlayıcıdan canlı alındı.", "{0} models fetched live from the provider."),
        ["provider.models.ready"] = new("{0} model hazır.", "{0} models ready."),
        ["provider.models.failed"] = new(
            "Model listesi alınamadı; model adını doğrudan yazabilirsin.",
            "Could not fetch the model list; you can type the model ID directly."),
        ["provider.save.need_input"] = new("Sağlayıcı veya model gir.", "Enter a provider or a model."),
        ["provider.save.saving"] = new("kaydediliyor…", "saving…"),
        ["provider.save.model_and_key"] = new(
            "✓ Model ve API anahtarı kaydedildi — bir sonraki mesajda etkili olacak",
            "✓ Model and API key saved — it takes effect on the next message"),
        ["provider.save.model_only"] = new(
            "✓ Model kaydedildi — bir sonraki mesajda etkili olacak",
            "✓ Model saved — it takes effect on the next message"),
        ["provider.save.no_key_yet"] = new(
            " ⚠ API anahtarı henüz girilmedi.", " ⚠ No API key has been entered yet."),
        ["provider.save.rejected"] = new(
            "reddedildi (yönetilen kurulum)", "refused (managed installation)"),
        ["provider.key.defined"] = new("Tanımlı", "Configured"),
        ["provider.key.undefined"] = new("Tanımsız", "Not configured"),
        ["provider.source.environment"] = new("süreç ortam değişkeni", "process environment variable"),
        ["provider.source.env_file"] = new("~/.fetih/.env", "~/.fetih/.env"),
        ["provider.source.none"] = new("hiçbir kaynakta yok", "not found in any source"),
        ["provider.baseurl.overridden"] = new("uç adresi geçersiz kılınmış", "endpoint overridden"),
        ["provider.baseurl.default"] = new("varsayılan uç adresi kullanılır", "default endpoint in use"),
        ["provider.badge.aggregator"] = new("toplayıcı", "aggregator"),
        ["provider.badge.local"] = new("yerel — veri makineden çıkmaz", "local — data never leaves the machine"),
        ["provider.badge.active"] = new("Etkin", "Active"),
        ["provider.badge.not_configured"] = new("Kimlik bilgisi yok", "No credentials"),
        ["provider.badge.configured"] = new("Kimlik bilgisi tanımlı", "Credentials configured"),
        ["provider.count"] = new("{0} / {1} sağlayıcı", "{0} / {1} providers"),
        ["provider.active.custom"] = new("Kullanıcı tanımlı sağlayıcılar", "User-defined providers"),
        ["provider.active.custom_none"] = new("(yok)", "(none)"),
        ["provider.active.custom_note"] = new(
            "config.yaml içindeki providers: bölümüne eklenen özel OpenAI uyumlu uçlar.",
            "Custom OpenAI-compatible endpoints added under the providers: section in config.yaml."),
        ["provider.active.config_file"] = new("Yapılandırma dosyası", "Configuration file"),
        ["provider.active.last_modified"] = new("Son değişiklik: {0}", "Last modified: {0}"),
        ["provider.active.fallback_note"] = new(
            "Birincil sağlayıcı 429/529/503 döndüğünde devreye girer.",
            "Kicks in when the primary provider returns 429/529/503."),

        // ── Model ve Sağlayıcı: yardımcı model yuvaları ──────────────────
        ["provider.aux.vision.title"] = new("Görüntü çözümleme", "Image analysis"),
        ["provider.aux.vision.desc"] = new(
            "Ekran görüntüsü ve resim analizi (vision_analyze, tarayıcı görüntüleri). Çok kipli (multimodal) bir model gerekir.",
            "Screenshot and image analysis (vision_analyze, browser captures). Requires a multimodal model."),
        ["provider.aux.web_extract.title"] = new("Web sayfası özetleme", "Web page summarization"),
        ["provider.aux.web_extract.desc"] = new(
            "Bir sayfayı okuyup özetleyen yan görev.", "The side task that reads and summarizes a page."),
        ["provider.aux.compression.title"] = new("Bağlam sıkıştırma", "Context compression"),
        ["provider.aux.compression.desc"] = new(
            "Sohbet uzayınca eski turları özetleyip yer açar.",
            "Summarizes older turns to free room once the conversation grows."),
        ["provider.aux.skills_hub.title"] = new("Yetenek merkezi", "Skills hub"),
        ["provider.aux.skills_hub.desc"] = new(
            "Yetenek (skill) arama ve eşleştirme çağrıları.", "Skill search and matching calls."),
        ["provider.aux.approval.title"] = new("Onay kararı", "Approval decision"),
        ["provider.aux.approval.desc"] = new(
            "Tehlikeli bir komutun otomatik onaylanıp onaylanmayacağına karar verir. Ucuz ve hızlı bir model önerilir.",
            "Decides whether a dangerous command is approved automatically. A cheap, fast model is recommended."),
        ["provider.aux.mcp.title"] = new("MCP yardımcısı", "MCP helper"),
        ["provider.aux.mcp.desc"] = new(
            "MCP sunucularıyla ilgili kısa çağrılar.", "Short calls related to MCP servers."),
        ["provider.aux.title_generation.title"] = new("Sohbet başlığı üretme", "Chat title generation"),
        ["provider.aux.title_generation.desc"] = new(
            "Bir oturuma kısa bir başlık yazar.", "Writes a short title for a session."),
        ["provider.aux.triage_specifier.title"] = new("Görev ayrıntılandırma", "Task detailing"),
        ["provider.aux.triage_specifier.desc"] = new(
            "Kanban 'triage' sütunundaki tek satırlık bir işi somut bir tarife dönüştürür.",
            "Turns a one-line item in the Kanban 'triage' column into a concrete spec."),
        ["provider.aux.kanban_decomposer.title"] = new("Görev parçalama", "Task decomposition"),
        ["provider.aux.kanban_decomposer.desc"] = new(
            "Bir işi alt görev grafiğine böler; diğerlerinden daha çok token harcar.",
            "Splits a task into a subtask graph; it spends more tokens than the others."),
        ["provider.aux.profile_describer.title"] = new("Profil açıklaması", "Profile description"),
        ["provider.aux.profile_describer.desc"] = new(
            "Bir profilin ne işe yaradığını bir iki cümleyle yazar.",
            "Describes what a profile does in a sentence or two."),
        ["provider.aux.curator.title"] = new("Küratör (yetenek incelemesi)", "Curator (skill review)"),
        ["provider.aux.curator.desc"] = new(
            "Yetenek kullanımını gözden geçiren fork. Uzun sürebilir.",
            "A fork that reviews skill usage. It can take a while."),

        // ── İlk kurulum sihirbazı ────────────────────────────────────────
        ["setup.window_title"] = new("FETİH — İlk Kurulum", "FETİH — First-Time Setup"),
        ["setup.heading"] = new("İlk Kurulum", "First-Time Setup"),
        ["setup.welcome.title"] = new("FETİH'e hoş geldin", "Welcome to FETİH"),
        ["setup.dot.name"] = new("Adım {0}/{1}", "Step {0}/{1}"),
        ["setup.dot.done"] = new(" (tamam)", " (done)"),
        ["setup.model.unavailable"] = new(
            "Model listesi alınamadı. Kurulumu tamamlayıp Ayarlar › Model'den seçebilirsin.",
            "Could not fetch the model list. Finish setup and pick one from Settings › Model."),
        ["setup.model.loading"] = new("Model listesi alınıyor…", "Fetching the model list…"),
        ["setup.model.live"] = new("{0} model sağlayıcıdan CANLI alındı.", "{0} models fetched LIVE from the provider."),
        ["setup.model.offline"] = new("{0} model (çevrimdışı yedek liste).", "{0} models (offline fallback list)."),
        ["setup.model.failed"] = new("Model listesi alınamadı: ", "Could not fetch the model list: "),
        ["setup.provider.local"] = new(" · yerel", " · local"),
        ["setup.provider.aggregator"] = new(" · toplayıcı", " · aggregator"),
        ["setup.brandmark"] = new(
            "FETİH — terminalde çalışan otonom yapay zekâ güvenlik ajanı",
            "FETİH — autonomous AI security agent running in the terminal"),
        ["setup.welcome.body"] = new(
            "Bu sihirbaz bir model sağlayıcısı seçmene, kimlik bilgilerini güvenle kaydetmene ve Masaüstü Köprüsü'nü başlatmana yardımcı olur. Üç adım sürer.",
            "This wizard helps you pick a model provider, store your credentials safely and start the Desktop Bridge. It takes three steps."),
        ["setup.security.title"] = new("Güvenlik notu", "Security note"),
        ["setup.security.body"] = new(
            "API anahtarın yalnızca bu bilgisayardaki ~/.fetih/.env dosyasına yazılır. Değeri hiçbir zaman ekranda gösterilmez, günlüğe yazılmaz veya ağ üzerinden gönderilmez. Yerel sağlayıcı seçersen hiç anahtar istenmez.",
            "Your API key is written only to ~/.fetih/.env on this machine. Its value is never shown on screen, never logged and never sent over the network. If you pick a local provider, no key is asked for at all."),
        ["setup.continue"] = new("Devam", "Continue"),
        ["setup.provider.title"] = new("Model sağlayıcısı", "Model provider"),
        ["setup.provider.header"] = new("Sağlayıcı", "Provider"),
        ["setup.api_key.header"] = new("API anahtarı", "API key"),
        ["setup.provider.body"] = new(
            "FETİH model-agnostiktir. Ücretsiz başlamak için Groq, verinin makineden çıkmasını istemiyorsan Ollama iyi bir seçim.",
            "FETİH is model-agnostic. Groq is a good free starting point; if you do not want your data to leave the machine, Ollama is a good pick."),
        ["setup.api_key.placeholder"] = new("sk-… / gsk_…", "sk-… / gsk_…"),
        ["setup.signup_link"] = new("Anahtar al", "Get a key"),
        ["setup.signup_link.url"] = new("Anahtar al — {0}", "Get a key — {0}"),
        ["setup.reprobe"] = new("Yeniden yokla", "Probe again"),
        ["setup.local_install_link"] = new("Kurulum sayfasını aç", "Open the installation page"),
        ["setup.local_install_link.url"] = new("Kurulum sayfası — {0}", "Installation page — {0}"),
        ["setup.cli_login"] = new("Oturum aç", "Sign in"),
        ["setup.cli_check"] = new("Durumu denetle", "Check status"),
        ["setup.aws.title"] = new("AWS kimlik zinciri", "AWS credential chain"),
        ["setup.aws.message"] = new(
            "Bu sağlayıcı anahtar istemez; AWS_PROFILE / IAM rolü gibi ortam kimlik bilgilerini kullanır.",
            "This provider does not ask for a key; it uses environment credentials such as AWS_PROFILE or an IAM role."),
        ["setup.model.header"] = new("Varsayılan model", "Default model"),
        ["setup.back"] = new("Geri", "Back"),
        ["setup.install"] = new("Kur ve başlat", "Install and start"),
        ["setup.progress.title"] = new("Kuruluyor", "Installing"),
        ["setup.retry"] = new("Yeniden dene", "Retry"),
        ["setup.back_to_provider"] = new("Sağlayıcıya dön", "Back to the provider"),
        ["setup.go_to_chat"] = new("Sohbete geç", "Go to chat"),

        // ── İlk kurulum: çalışma zamanı metinleri ────────────────────────
        ["setup.provider.local.hint"] = new(
            "Bu sağlayıcı bu makinede çalışır; API anahtarı istemez. Veriler bilgisayardan çıkmaz.",
            "This provider runs on this machine; it needs no API key and your data never leaves the computer."),
        ["setup.cli.title"] = new("Tarayıcı oturumu gerekiyor", "A browser session is required"),
        ["setup.cli.message"] = new(
            "{0} bir API anahtarı değil, hesabınla açtığın bir oturum kullanır. \"Oturum aç\" düğmesi FETİH'in GERÇEK giriş akışını bir konsol penceresinde başlatır; tarayıcıda onayladıktan sonra buraya dön.",
            "{0} does not use an API key; it uses a session you open with your account. The \"Sign in\" button starts FETİH's REAL login flow in a console window; come back here after approving it in the browser."),
        ["setup.key.hint.env"] = new(
            "Anahtar {0} adıyla ~/.fetih/.env dosyasına kaydedilir.",
            "The key is saved to ~/.fetih/.env under the name {0}."),
        ["setup.key.hint.none"] = new(
            "Bu sağlayıcı için ortam değişkeni tanımlı değil.",
            "No environment variable is defined for this provider."),
        ["setup.key.required"] = new(
            "Bu sağlayıcı bir API anahtarı gerektirir; lütfen anahtarı gir.",
            "This provider requires an API key; please enter it."),
        ["setup.probing"] = new("Yoklanıyor…", "Probing…"),
        ["setup.local.not_found"] = new("{0} bulunamadı", "{0} not found"),
        ["setup.local.not_found.msg"] = new(
            "{0} adresinde çalışan bir sunucu yok. Sunucuyu başlat, sonra \"Yeniden yokla\"ya bas.",
            "No server is running at {0}. Start it, then press \"Probe again\"."),
        ["setup.local.no_models.hint"] = new(
            "Sunucu ayağa kalkınca modeller burada listelenir.",
            "Models will be listed here once the server is up."),
        ["setup.local.running_no_models"] = new(
            "{0} çalışıyor, ama hiç model inmemiş",
            "{0} is running, but no model has been pulled"),
        ["setup.local.running_no_models.msg"] = new(
            "{0} yanıt veriyor. Önce bir model indir (ör. `ollama pull`).",
            "{0} is responding. Pull a model first (e.g. `ollama pull`)."),
        ["setup.local.running"] = new("{0} çalışıyor", "{0} is running"),
        ["setup.local.found"] = new("{0} model bulundu · {1}", "{0} models found · {1}"),
        ["setup.local.installed_models"] = new(
            "Bu makinede İNDİRİLMİŞ modeller listelendi.",
            "The models PULLED on this machine are listed."),
        ["setup.probe_failed"] = new("Yoklama yapılamadı", "The probe failed"),
        ["setup.python_missing.title"] = new("Python bulunamadı", "Python not found"),
        ["setup.python_missing.msg"] = new(
            "Giriş akışı FETİH CLI üzerinden çalışır; Python 3.11+ gerekiyor.",
            "The login flow runs through the FETİH CLI; Python 3.11+ is required."),
        ["setup.login.opened.title"] = new("Giriş penceresi açıldı", "The login window is open"),
        ["setup.login.opened.msg"] = new(
            "Konsol penceresindeki yönergeleri izle; bitince buraya dön.",
            "Follow the instructions in the console window, then come back here."),
        ["setup.login.failed.title"] = new("Giriş akışı başlatılamadı", "The login flow could not be started"),
        ["setup.login.ok.title"] = new("Oturum açık", "Signed in"),
        ["setup.login.ok.msg"] = new(
            "{0} kimlik bilgileri FETİH kimlik deposunda bulundu.",
            "{0} credentials were found in the FETİH credential store."),
        ["setup.login.pending.title"] = new("Henüz oturum açılmadı", "Not signed in yet"),
        ["setup.login.pending.msg"] = new(
            "Giriş akışı tamamlanmamış görünüyor. \"Oturum aç\"ı yeniden dene.",
            "The login flow looks incomplete. Try \"Sign in\" again."),
        ["setup.needs_login.title"] = new("Oturum açılması gerekiyor", "You need to sign in"),
        ["setup.needs_login.msg"] = new(
            "{0} ile devam etmek için lütfen 'Oturum aç' ile tarayıcıda girişi tamamla.",
            "To continue with {0}, please complete the login in your browser using 'Sign in'."),
        ["setup.step.waiting"] = new("bekliyor", "waiting"),
        ["setup.done.title"] = new("Kurulum tamamlandı", "Setup complete"),
        ["setup.done.msg"] = new(
            "Masaüstü Köprüsü hazır ve model gerçek bir yanıt döndürdü. Sohbete geçebilirsin.",
            "The Desktop Bridge is ready and the model returned a real response. You can go to the chat."),
        ["setup.cancelled"] = new("İptal edildi", "Cancelled"),
        ["setup.failed"] = new("Kurulum başarısız", "Setup failed"),
        ["setup.log_suffix"] = new("  ·  Günlük: ", "  ·  Log: "),

        // ── İlk kurulum: adım adları ve adım sonuçları ───────────────────
        ["setup.step.os.name"] = new("İşletim sistemi denetimi", "Checking the operating system"),
        ["setup.step.os.ok"] = new("Windows algılandı.", "Windows detected."),
        ["setup.step.os.fail"] = new(
            "Bu masaüstü kabuğu yalnızca Windows'ta çalışır.",
            "This desktop shell runs on Windows only."),
        ["setup.step.python.name"] = new("Python bulunuyor", "Looking for Python"),
        ["setup.step.python.ok"] = new("Python bulundu: {0}", "Python found: {0}"),
        ["setup.step.python.fail"] = new(
            "Python bulunamadı. FETİH'i çalıştırmak için Python 3.11+ kurun veya FETIH_PYTHON ortam değişkenini ayarlayın.",
            "Python was not found. Install Python 3.11+ to run FETİH, or set the FETIH_PYTHON environment variable."),
        ["setup.step.home.name"] = new("Durum dizini hazırlanıyor", "Preparing the state directory"),
        ["setup.step.home.ok"] = new("{0} oluşturuldu.", "{0} created."),
        ["setup.step.key.name"] = new("API anahtarı kaydediliyor", "Saving the API key"),
        ["setup.step.key.ok"] = new("{0} .env dosyasına yazıldı.", "{0} written to the .env file."),
        ["setup.step.key.fail"] = new("API anahtarı yazılamadı: ", "Could not write the API key: "),
        ["setup.step.config.name"] = new("Yapılandırma yazılıyor", "Writing the configuration"),
        ["setup.step.config.ok"] = new(
            "model.provider / model.default kaydedildi.",
            "model.provider / model.default saved."),
        ["setup.step.config.fail_managed"] = new(
            "Yapılandırma yazılamadı (yönetilen kurulum): ",
            "Could not write the configuration (managed setup): "),
        ["setup.step.config.fail"] = new(
            "Yapılandırma yazılamadı: ", "Could not write the configuration: "),
        ["setup.step.bridge.name"] = new("Masaüstü Köprüsü başlatılıyor", "Starting the Desktop Bridge"),
        ["setup.step.bridge.ok"] = new("Köprü bağlı (protokol v{0}).", "Bridge connected (protocol v{0})."),
        ["setup.step.auth.name"] = new("Sağlayıcı oturumu denetleniyor", "Checking the provider session"),
        ["setup.step.auth.noprovider"] = new("Sağlayıcı kimliği belirtilmedi.", "No provider id was given."),
        ["setup.step.auth.confirmed"] = new("Oturum doğrulandı{0}.", "Session verified{0}."),
        ["setup.step.auth.nopython"] = new(
            "Giriş akışını çalıştırmak için Python bulunamadı.",
            "Python was not found, so the login flow cannot run."),
        ["setup.step.auth.spawn_failed"] = new(
            "Giriş süreci başlatılamadı ({0} -m fetih_cli auth add {1}).",
            "The login process could not be started ({0} -m fetih_cli auth add {1})."),
        ["setup.step.auth.cancelled"] = new("Giriş işlemi iptal edildi.", "The login process was cancelled."),
        ["setup.step.auth.error"] = new("Giriş akışı sırasında hata: ", "Error during the login flow: "),
        ["setup.step.auth.opened"] = new("Oturum başarıyla açıldı{0}.", "Session opened successfully{0}."),
        ["setup.step.auth.verify_failed"] = new("Giriş doğrulanamadı: ", "The login could not be verified: "),
        ["setup.step.auth.incomplete"] = new(
            "{0} için oturum açma akışı tamamlanmadı. Lütfen açılan tarayıcıda veya konsolda oturum açma işlemini tamamlayıp yeniden deneyin.",
            "The login flow for {0} was not completed. Please finish signing in in the browser or console window, then try again."),
        ["setup.step.verify.name"] = new("Gerçek mesajla doğrulama", "Verifying with a real message"),
        ["setup.step.verify.prompt"] = new(
            "Bu bir kurulum denetimidir. Yalnızca şu kelimeyle yanıt ver: TAMAM",
            "This is a setup check. Reply with only this word: TAMAM"),
        ["setup.step.verify.empty"] = new(
            "Model yanıt verdi (boş metin) — kurulum tamam.",
            "The model responded (empty text) — setup is complete."),
        ["setup.step.verify.ok"] = new("Model yanıt verdi: ", "The model responded: "),
        ["setup.step.verify.fail"] = new(
            "Model yanıt vermedi ({0}): {1}  Sağlayıcıya dönüp anahtarı ya da modeli düzelt.",
            "The model did not respond ({0}): {1}  Go back to the provider and fix the key or the model."),
        ["setup.step.verify.timeout"] = new(
            "Model 90 saniyede yanıt vermedi. Ağ/uç nokta erişilebilir mi?",
            "The model did not respond within 90 seconds. Is the network or endpoint reachable?"),

        // ── Köprü durumu (çalışma zamanı metinleri) ──────────────────────
        ["bridge.detail.idle"] = new(
            "Masaüstü Köprüsü henüz başlatılmadı.", "The Desktop Bridge has not been started yet."),
        ["bridge.detail.connecting"] = new(
            "Masaüstü Köprüsü başlatılıyor…", "Starting the Desktop Bridge…"),
        ["bridge.detail.protocol_mismatch"] = new(
            "Protokol uyumsuz: istemci {0}, sunucu {1}–{2}.",
            "Protocol mismatch: client {0}, server {1}–{2}."),
        ["bridge.detail.protocol_mismatch_ex"] = new(
            "Köprü protokol sürümü uyumsuz (istemci 1, sunucu {0}–{1}).",
            "The bridge protocol version is incompatible (client 1, server {0}–{1})."),
        ["bridge.detail.auth_rejected"] = new(
            "Kimlik doğrulama reddedildi.", "Authentication was rejected."),
        ["bridge.detail.auth_failed"] = new(
            "Köprü kimlik doğrulaması başarısız.", "Bridge authentication failed."),
        ["bridge.detail.connected"] = new(
            "Bağlı · protokol v{0} · pid {1}", "Connected · protocol v{0} · pid {1}"),
        ["bridge.detail.connect_failed"] = new(
            "Köprüye bağlanılamadı: ", "Could not connect to the bridge: "),
        ["bridge.detail.server_closed"] = new(
            "sunucu bağlantıyı kapattı", "the server closed the connection"),
        ["bridge.detail.dropped"] = new(
            "Köprü bağlantısı koptu.", "The bridge connection dropped."),
        ["bridge.detail.reconnecting"] = new(
            "Bağlantı koptu; sonraki istekte yeniden bağlanılacak.",
            "The connection dropped; it will reconnect on the next request."),
        ["bridge.detail.not_connected"] = new(
            "Köprü bağlı değil.", "The bridge is not connected."),
        ["bridge.detail.send_failed"] = new(
            "Köprüye istek gönderilemedi: ", "Could not send the request to the bridge: "),
        ["bridge.proc.start_failed"] = new(
            "Köprü süreci başlatılamadı: {0}", "The bridge process could not be started: {0}"),
        ["bridge.proc.start_failed_ex"] = new(
            "Köprü süreci başlatılamadı ({0}): {1}",
            "The bridge process could not be started ({0}): {1}"),
        ["bridge.proc.handshake_read"] = new(
            "Köprü el sıkışma satırı alınamadı (süreç beklenmedik şekilde sonlandı). ",
            "The bridge handshake line could not be read (the process ended unexpectedly). "),
        ["bridge.proc.detail"] = new("Ayrıntı: ", "Details: "),
        ["bridge.proc.handshake_parse"] = new(
            "Köprü el sıkışma satırı çözümlenemedi: ",
            "The bridge handshake line could not be parsed: "),
        ["bridge.proc.unexpected_event"] = new(
            "beklenen 'bridge.listening', gelen: {0}",
            "expected 'bridge.listening', got: {0}"),
        ["bridge.proc.no_value"] = new("(yok)", "(none)"),
        ["bridge.proc.no_url"] = new(
            "El sıkışma satırında url alanı yok.", "The handshake line has no url field."),
        ["bridge.proc.no_token"] = new(
            "El sıkışma satırında token alanı yok.", "The handshake line has no token field."),
        ["provider.transport.openai_chat"] = new("OpenAI uyumlu sohbet", "OpenAI-compatible chat"),
        ["provider.auth.api_key"] = new("API anahtarı", "API key"),
        ["provider.auth.oauth_device_code"] = new("OAuth (cihaz kodu)", "OAuth (device code)"),
        ["provider.auth.oauth_external"] = new("OAuth (harici akış)", "OAuth (external flow)"),
        ["provider.auth.external_process"] = new("Harici süreç", "External process"),
        ["provider.auth.aws_sdk"] = new("AWS kimlik bilgileri", "AWS credentials"),
        ["provider.auth.none"] = new("Kimlik doğrulama yok", "No authentication"),
        ["chat.md.copy"] = new("Kopyala", "Copy"),
        ["chat.md.copied"] = new("Kopyalandı", "Copied"),

        // ── Ürün adı ─────────────────────────────────────────────────────
        ["app.product_name"] = new("FETİH Masaüstü", "FETİH Desktop"),

        // ── Kurulum hattı (adım listesi) ─────────────────────────────────
        ["setup.pipeline.starting"] = new("başlıyor…", "starting…"),
        ["setup.pipeline.cancelled"] = new("İptal edildi.", "Cancelled."),
        ["setup.pipeline.skipped"] = new("zaten sağlanmış — atlandı", "already satisfied — skipped"),
        ["setup.pipeline.done"] = new("Kurulum tamamlandı.", "Setup completed."),

        // ── Yetenekler: kaynak ağaç adları ve geri düşüşler ──────────────
        ["skills.source.repo"] = new("depo", "repository"),
        ["skills.source.optional"] = new("isteğe bağlı", "optional"),
        ["skills.source.user"] = new("kullanıcı", "user"),
        ["skills.root_segment"] = new("(kök)", "(root)"),
        ["skills.unnamed"] = new("(adsız)", "(unnamed)"),
        ["skills.no_description"] = new("(açıklama yok)", "(no description)"),

        // ── YAML gösterim yardımcıları ───────────────────────────────────
        ["yaml.empty_list"] = new("(boş liste)", "(empty list)"),
        ["yaml.empty_map"] = new("(boş)", "(empty)"),
        ["yaml.nested"] = new("(…)", "(…)"),
        ["yaml.child_keys"] = new("({0} alt anahtar)", "({0} nested keys)"),

        // ── Sağlayıcı adları (marka adı olmayanlar) ──────────────────────
        ["provider.name.codex"] = new("OpenAI Codex (ChatGPT girişi)", "OpenAI Codex (ChatGPT sign-in)"),
        ["provider.name.kimi_cn"] = new("Kimi (Çin)", "Kimi (China)"),
        ["provider.name.minimax_cn"] = new("MiniMax (Çin)", "MiniMax (China)"),
        ["provider.name.ai_gateway"] = new("Vercel AI (model yönlendirici)", "Vercel AI (model router)"),
        ["provider.name.ollama"] = new("Ollama (yerel)", "Ollama (local)"),
        ["provider.name.lmstudio"] = new("LM Studio (yerel)", "LM Studio (local)"),
        ["provider.name.custom"] = new("Özel yerel uç (vLLM / llama.cpp)", "Custom local endpoint (vLLM / llama.cpp)"),
        ["provider.list_name"] = new("Sağlayıcı listesi", "Provider list"),
        ["provider.search_name"] = new("Sağlayıcı ara", "Search providers"),
    };
}
