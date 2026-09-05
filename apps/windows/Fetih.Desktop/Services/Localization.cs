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
    };
}
