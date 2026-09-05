using System;
using System.Collections.Generic;

namespace Fetih.Desktop.Services;

/// <summary>
/// Sadeleştirilmiş ayar sayfalarının içeriği.
///
/// <para><b>Bilgi mimarisi.</b> FETİH'in ayarları iki katmandır:</para>
/// <list type="bullet">
///   <item><description><b>Normal ayar sayfaları</b> (burası): sıradan bir
///   CTF/pentest kullanıcısının açıklamasız anlayabileceği, gündelik dille
///   yazılmış, iyi kontrollere (aç/kapa, seçim listesi) bağlanmış AZ sayıda
///   ayar. İç araç adları (<c>tirith</c>), dosya yolları ve zaman aşımı
///   sayıları burada görünmez ya da "Gelişmiş" genişleticisine saklanır.</description></item>
///   <item><description><b>Detaylı Mod</b> (<c>ConfigEditorPage</c>): TÜM ham
///   yapılandırma anahtarları, kategori kategori.</description></item>
/// </list>
///
/// <para><b>Kural.</b> Buradaki her kontrolün <see cref="SimpleControl.Key"/>
/// alanı gerçek config anahtarıdır ve değişiklik <c>config.set</c> ile diske
/// yazılır. Sadeleştirme yalnızca SUNUM katmanındadır; Detaylı Mod'daki aynı
/// anahtar her zaman aynı değeri gösterir.</para>
/// </summary>
public static class SimpleSettingsCatalog
{
    // ── İkonlar ──────────────────────────────────────────────────────────────

    private const string GShield = "\uE72E";
    private const string GCheck = "\uE73E";
    private const string GWarn = "\uE7BA";
    private const string GGlobe = "\uE774";
    private const string GBox = "\uE7C1";
    private const string GCode = "\uE943";
    private const string GChat = "\uE8BD";
    private const string GBook = "\uE8F1";
    private const string GClock = "\uE916";
    private const string GView = "\uE890";
    private const string GPage = "\uE7C3";
    private const string GApps = "\uE71D";
    private const string GBolt = "\uE945";
    private const string GNet = "\uE839";
    private const string GSave = "\uE74E";
    private const string GLang = "\uE775";

    /// <summary>Kimliğe göre sayfa tanımı; bilinmiyorsa <c>null</c>.</summary>
    public static SimplePage? Get(string id) => id switch
    {
        "permissions" => Permissions(),
        "security" => Security(),
        "sandbox" => Sandbox(),
        "channels" => Channels(),
        "memory" => Memory(),
        "automation" => Automation(),
        "appearance" => Appearance(),
        "system" => SystemPage(),
        "tools" => Tools(),
        "agent" => Agent(),
        _ => null,
    };

    // ── İzinler ──────────────────────────────────────────────────────────────

    private static SimplePage Permissions() => new()
    {
        Id = "permissions",
        Title = new("İzinler", "Permissions"),
        Intro = new(
            "FETİH tehlikeli bir komutu çalıştırmadan önce sana sorabilir. Buradan ne zaman soracağını belirlersin.",
            "FETİH can ask you before it runs a dangerous command. Here you decide when it asks."),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Ne zaman sorsun?", "When should it ask?"),
                Glyph = GCheck,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Choice,
                        Key = "approvals.mode",
                        Title = new("Onay isteme biçimi", "Approval style"),
                        Glyph = GCheck,
                        Options = new[]
                        {
                            new SimpleOption("manual",
                                new("Her riskli komutta bana sor", "Ask me for every risky command"),
                                new("En güvenli seçenek. Dosya silme, disk biçimlendirme, internetten indirilen betik çalıştırma gibi işlemler önce sana sorulur. Önerilen.",
                                    "The safest option. Deleting files, formatting disks, running scripts downloaded from the internet — you get asked first. Recommended.")),
                            new SimpleOption("smart",
                                new("Zararsız olanları kendisi geçsin", "Let it wave through the harmless ones"),
                                new("Yardımcı bir model komuta bakar; zararsız bulursa sormadan çalıştırır, şüphelenirse yine sana sorar. Daha akıcı, biraz daha az denetim.",
                                    "A helper model inspects the command; if it looks harmless it runs without asking, otherwise you are still asked. Smoother, slightly less oversight.")),
                            new SimpleOption("off",
                                new("Hiç sorma", "Never ask"),
                                new("Her komut sorulmadan çalışır. Yalnızca kendi izole test makinende kullan.",
                                    "Every command runs unasked. Only use this on an isolated test machine.")),
                        },
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "approvals.destructive_slash_confirm",
                        Title = new("Sohbeti sıfırlamadan önce sor", "Ask before wiping the conversation"),
                        Glyph = GWarn,
                        Description = new(
                            "Geçmişi silen komutlar uygulanmadan önce onay ister. Kapatırsan yanlışlıkla konuşma geçmişini kaybedebilirsin.",
                            "Commands that erase the history ask for confirmation first. Turn it off and you can lose a conversation by accident."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "delegation.subagent_auto_approve",
                        Title = new("Yardımcı ajanlar sormadan çalışsın", "Let helper agents run without asking"),
                        Glyph = GBolt,
                        Description = new(
                            "FETİH büyük bir işi parçalara bölüp yardımcı ajanlara dağıtabilir. Açıkken bu yardımcılar da onay istemez — hızlanır, denetim azalır.",
                            "FETİH can split a big job across helper agents. When on, those helpers stop asking too — faster, but less oversight."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "approvals.timeout",
                        Title = new("Onay bekleme süresi", "How long it waits for your answer"),
                        Glyph = GClock,
                        Min = 5,
                        Max = 3600,
                        Unit = new("saniye", "seconds"),
                        Description = new(
                            "Bu süre içinde yanıt vermezsen istek kendiliğinden düşer ve komut çalışmaz.",
                            "If you do not answer within this time the request lapses and the command does not run."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Choice,
                        Key = "approvals.cron_mode",
                        Title = new("Sen yokken (zamanlanmış görevlerde)", "While you are away (scheduled jobs)"),
                        Glyph = GClock,
                        Options = new[]
                        {
                            new SimpleOption("deny",
                                new("Riskli komutu engelle", "Block the risky command"),
                                new("Kimse onaylayamayacağı için görev o adımda durur. Güvenli varsayılan.",
                                    "Nobody is there to approve, so the job stops at that step. The safe default.")),
                            new SimpleOption("approve",
                                new("Otomatik onayla", "Approve automatically"),
                                new("Zamanlanmış görevler riskli komutları da sormadan çalıştırır.",
                                    "Scheduled jobs run risky commands unasked.")),
                        },
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "approvals.mcp_reload_confirm",
                        Title = new("Araç listesi yenilenmeden önce sor", "Ask before refreshing the tool list"),
                        Glyph = GApps,
                        Description = new(
                            "Dış araçların listesi yenilendiğinde açık konuşma sıfırdan kurulur; bu yüzden önce sorulur.",
                            "Refreshing the external tool list rebuilds the running conversation, so it asks first."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "hooks_auto_accept",
                        Title = new("Yeni otomatik betikleri sormadan kabul et", "Accept new automation scripts without asking"),
                        Glyph = GCode,
                        Description = new(
                            "Bir proje kendi kabuk betiklerini FETİH'e bağlayabilir. Açıkken bunlar sorulmadan çalışır — güvenmediğin depolarda kapalı tut.",
                            "A project can attach its own shell scripts to FETİH. When on they run unasked — keep it off for repositories you do not trust."),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Kalıcı olarak izin verdiklerin", "What you have permanently allowed"),
                Glyph = GCheck,
                Description = new(
                    "Bir onay isteminde \"her zaman izin ver\" dediğinde o komut kalıcı olarak buraya eklenir ve bir daha sorulmaz.",
                    "When you answer an approval prompt with \"always allow\", the command lands here permanently and is never asked about again."),
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.StringList,
                        Key = "command_allowlist",
                        Title = new("İzin verilen komutlar", "Allowed commands"),
                        Glyph = GCheck,
                        AllowClear = true,
                        EmptyNote = new(
                            "Liste boş — kalıcı izin verilmiş riskli komut yok. En sıkı ve önerilen durum.",
                            "The list is empty — no risky command has a standing allowance. The strictest and recommended state."),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Hangi komutlar sorulur?", "Which commands get asked about?"),
                Glyph = GWarn,
                Description = new(
                    "Bir komut aşağıdaki sınıflardan birine giriyorsa onay istenir. Bu liste bilgi amaçlıdır, değiştirilemez.",
                    "If a command falls into one of these classes, approval is requested. This list is informational and cannot be edited."),
                FactsTitle = new("Riskli komut sınıfları", "Risky command classes"),
                Facts = RiskFacts(),
            },
        },
    };

    private static SimpleFact[] RiskFacts() => new[]
    {
        new SimpleFact
        {
            Title = new("Dosya ve klasör silme", "Deleting files and folders"),
            Detail = new("Toplu silme, kök dizinden silme, arama sonuçlarını silme.",
                "Bulk deletes, deletes from the filesystem root, deleting search results."),
        },
        new SimpleFact
        {
            Title = new("Disk ve dosya sistemi", "Disks and filesystems"),
            Detail = new("Biçimlendirme, doğrudan diske yazma.", "Formatting, writing straight to a device."),
        },
        new SimpleFact
        {
            Title = new("İzin ve sahiplik değiştirme", "Changing permissions and ownership"),
            Detail = new("Dosyaları herkese açık yapma, sahipliği köke devretme.",
                "Making files world-writable, handing ownership to root."),
        },
        new SimpleFact
        {
            Title = new("Sistem ayarlarına dokunma", "Touching system configuration"),
            Detail = new("Sistem yapılandırma dizinine yazma, servis durdurma/kapatma.",
                "Writing into the system config directory, stopping or disabling services."),
        },
        new SimpleFact
        {
            Title = new("Proje gizli dosyaları", "Project secret files"),
            Detail = new("Ortam değişkeni ve yapılandırma dosyalarının üzerine yazma.",
                "Overwriting environment and configuration files."),
        },
        new SimpleFact
        {
            Title = new("İnternetten indirileni çalıştırma", "Running what was just downloaded"),
            Detail = new("İndirilen bir betiği doğrudan kabuğa boru ile verme.",
                "Piping a freshly downloaded script straight into a shell."),
        },
        new SimpleFact
        {
            Title = new("Süreç sonlandırma", "Killing processes"),
            Detail = new("Toplu süreç öldürme; FETİH'in kendi sürecini öldürmesi ayrıca engellenir.",
                "Mass process kills; FETİH killing its own process is blocked outright."),
        },
        new SimpleFact
        {
            Title = new("Veritabanı", "Databases"),
            Detail = new("Tablo/veritabanı silme, koşulsuz toplu silme.",
                "Dropping tables or databases, unconditional bulk deletes."),
        },
        new SimpleFact
        {
            Title = new("Geri alınamayan sürüm işlemleri", "Irreversible version-control operations"),
            Detail = new("Geçmişi geri saran, zorla gönderen veya dal silen işlemler.",
                "Operations that rewind history, force-push, or delete branches."),
        },
        new SimpleFact
        {
            Title = new("Yetki yükseltme", "Privilege escalation"),
            Detail = new("Yönetici hakkıyla çalıştırma denemeleri.", "Attempts to run with administrator rights."),
        },
        new SimpleFact
        {
            Title = new("FETİH'in kendi altyapısı", "FETİH's own plumbing"),
            Detail = new("Kendini güncelleme, mesajlaşma servisini durdurma — çalışan işleri keser.",
                "Self-update, stopping the messaging service — this kills running jobs."),
        },
        new SimpleFact
        {
            Title = new("Makineyi kilitleyen komutlar", "Machine-locking commands"),
            Detail = new("Çatal bombası ve benzerleri kesin olarak engellenir, sorulmaz.",
                "Fork bombs and the like are blocked outright, not asked about."),
        },
    };

    // ── Güvenlik ─────────────────────────────────────────────────────────────

    private static SimplePage Security() => new()
    {
        Id = "security",
        Title = new("Güvenlik", "Security"),
        Intro = new(
            "FETİH'in neye erişebileceği, neyi ekranda gizleyeceği ve komutları çalıştırmadan önce ne yapacağı.",
            "What FETİH may reach, what it hides on screen, and what it does before running a command."),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Koruma", "Protection"),
                Glyph = GShield,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "security.tirith_enabled",
                        Title = new("Gelişmiş tehdit taraması", "Advanced threat scanning"),
                        Glyph = GShield,
                        Description = new(
                            "Komutları çalıştırmadan önce zararlı içerik olup olmadığını tarar. Kapatmak taramayı atlar, biraz hızlandırır ama riski artırır.",
                            "Scans commands for malicious content before running them. Turning it off skips the scan — slightly faster, noticeably riskier."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "security.redact_secrets",
                        Title = new("Parola ve anahtarları ekranda gizle", "Hide passwords and keys on screen"),
                        Glyph = GShield,
                        Description = new(
                            "Çıktıda görünen API anahtarı, oturum jetonu ve parolalar •••• olarak maskelenir. Ekran paylaşırken açık tut.",
                            "API keys, session tokens and passwords appearing in output are masked as ••••. Keep it on when you share your screen."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "security.allow_private_urls",
                        Title = new("Kendi ağındaki adreslere erişebilsin", "Let it reach addresses on your own network"),
                        Glyph = GNet,
                        Description = new(
                            "Kapalıyken yerel ve iç ağ hedeflerine (kendi bilgisayarın, ev/ofis ağın) istek engellenir. Kendi laboratuvarını test edeceksen aç.",
                            "When off, requests to local and internal targets (your own machine, your home/office network) are blocked. Turn it on to test your own lab."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "browser.allow_private_urls",
                        Title = new("Tarayıcı da kendi ağına girebilsin", "Let the browser reach your network too"),
                        Glyph = GGlobe,
                        Description = new(
                            "Yukarıdakinin tarayıcı aracı için olanı. Yerel bir web arayüzünü FETİH'e gezdirmek istiyorsan aç.",
                            "The same thing for the browser tool. Turn it on if you want FETİH to browse a locally hosted web interface."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "security.website_blocklist.enabled",
                        Title = new("Engellenen site listesini uygula", "Apply the blocked-site list"),
                        Glyph = GGlobe,
                        Description = new(
                            "Açıkken listedeki alan adlarına hiç istek yapılmaz. Listenin kendisi Detaylı Mod'dan düzenlenir.",
                            "When on, no request is made to the listed domains. The list itself is edited in Advanced Mode."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "security.allow_lazy_installs",
                        Title = new("Eksik bileşenleri kendiliğinden kursun", "Install missing components on its own"),
                        Glyph = GBolt,
                        Description = new(
                            "Bir özellik için gereken paket yoksa FETİH onu internetten indirip kurar. Kapatırsan hiçbir şey indirilmez — internetsiz veya denetimli ortamlar için.",
                            "If a feature needs a package that is missing, FETİH downloads and installs it. Turn it off and nothing is ever downloaded — for offline or audited environments."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "security.tirith_fail_open",
                        Title = new("Tarama çalışmazsa komuta yine de izin ver", "Allow the command if the scan cannot run"),
                        Glyph = GWarn,
                        Description = new(
                            "Tarayıcı kurulu değilse veya çöktüyse ne olsun? Açık: komut çalışır. Kapalı: komut engellenir (daha sıkı).",
                            "What if the scanner is missing or crashes? On: the command runs. Off: the command is blocked (stricter)."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "security.tirith_timeout",
                        Title = new("Tarama en fazla ne kadar sürsün", "How long the scan may take"),
                        Glyph = GClock,
                        Min = 1,
                        Max = 120,
                        Unit = new("saniye", "seconds"),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Gizlilik", "Privacy"),
                Glyph = GShield,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "privacy.redact_pii",
                        Title = new("Kişisel bilgileri de maskele", "Mask personal information too"),
                        Glyph = GShield,
                        Description = new(
                            "E-posta adresi, telefon, kimlik numarası gibi kişisel veriler kayıtlarda ve çıktıda gizlenir.",
                            "Personal data such as e-mail addresses, phone numbers and ID numbers is hidden in logs and output."),
                    },
                },
            },
        },
    };

    // ── Sandbox / çalışma ortamı ─────────────────────────────────────────────

    private static SimplePage Sandbox() => new()
    {
        Id = "sandbox",
        Title = new("Çalışma Ortamı", "Execution Environment"),
        Intro = new(
            "FETİH'in komutları nerede çalıştıracağı. Doğrudan bu bilgisayarda mı, yoksa makinene dokunamayan izole bir kutunun içinde mi?",
            "Where FETİH runs its commands. Straight on this machine, or inside an isolated box that cannot touch it?"),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Komutlar nerede çalışsın?", "Where should commands run?"),
                Glyph = GBox,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Select,
                        Key = "terminal.backend",
                        Title = new("Yürütme yeri", "Execution location"),
                        Glyph = GBox,
                        Options = new[]
                        {
                            new SimpleOption("local",
                                new("Bu bilgisayarda", "On this computer"),
                                new("Komutlar doğrudan makinende çalışır. En hızlısı ve en az izole olanı — varsayılan.",
                                    "Commands run directly on your machine. Fastest and least isolated — the default.")),
                            new SimpleOption("docker",
                                new("İzole konteynerde (Docker)", "In an isolated container (Docker)"),
                                new("Her şey tek kullanımlık bir kutuda çalışır, makinene dokunmaz. Docker kurulu olmalı.",
                                    "Everything runs in a disposable box that cannot touch your machine. Docker must be installed.")),
                            new SimpleOption("ssh",
                                new("Uzaktaki bir makinede", "On a remote machine"),
                                new("Komutlar SSH ile bağlandığın başka bir makinede çalışır.",
                                    "Commands run on another machine you connect to over SSH.")),
                            new SimpleOption("singularity",
                                new("Singularity/Apptainer konteynerinde", "In a Singularity/Apptainer container"),
                                new("Yönetici hakkı istemeyen konteyner ortamı; üniversite ve HPC kümelerinde yaygın.",
                                    "A container runtime that needs no administrator rights; common on university and HPC clusters.")),
                            new SimpleOption("modal",
                                new("Modal bulut ortamında", "In a Modal cloud environment"),
                                new("Komutlar bulutta, kiralık bir makinede çalışır.",
                                    "Commands run in the cloud on a rented machine.")),
                            new SimpleOption("daytona",
                                new("Daytona bulut ortamında", "In a Daytona cloud environment"),
                                new("Komutlar bulutta, kiralık bir geliştirme ortamında çalışır.",
                                    "Commands run in the cloud in a rented development environment.")),
                            new SimpleOption("vercel_sandbox",
                                new("Vercel Sandbox'ta", "In a Vercel Sandbox"),
                                new("Komutlar Vercel'in kısa ömürlü sanal ortamında çalışır.",
                                    "Commands run in Vercel's short-lived sandbox.")),
                        },
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "terminal.timeout",
                        Title = new("Bir komut en fazla ne kadar sürsün", "How long a single command may run"),
                        Glyph = GClock,
                        Min = 5,
                        Max = 7200,
                        Unit = new("saniye", "seconds"),
                        Description = new(
                            "Bu süreyi aşan komut kesilir. Uzun taramalar yapıyorsan artır.",
                            "A command that exceeds this is cut off. Raise it if you run long scans."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "terminal.persistent_shell",
                        Title = new("Komutlar birbirini hatırlasın", "Let commands remember each other"),
                        Glyph = GCode,
                        Description = new(
                            "Açıkken klasör değiştirme ve ortam değişkenleri sonraki komutta da geçerli kalır — tek bir terminal oturumu gibi davranır.",
                            "When on, changing directory and setting environment variables carry over to the next command — it behaves like one terminal session."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "terminal.auto_source_bashrc",
                        Title = new("Kişisel kabuk ayarlarını da yükle", "Load your personal shell settings too"),
                        Glyph = GCode,
                        Description = new(
                            "Kendi kısayolların ve ortam değişkenlerin FETİH'in çalıştırdığı komutlarda da geçerli olur.",
                            "Your own aliases and environment variables also apply to the commands FETİH runs."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "terminal.container_persistent",
                        Title = new("İzole kutu oturumlar arasında yaşasın", "Keep the isolated box alive between sessions"),
                        Glyph = GBox,
                        Description = new(
                            "Kapalıyken her oturum için sıfırdan temiz bir kutu kurulur; açıkken kurulu paketler korunur.",
                            "When off, a clean box is built for every session; when on, installed packages survive."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "terminal.container_cpu",
                        Title = new("İzole kutuya ayrılan işlemci", "Processor given to the isolated box"),
                        Glyph = GBox,
                        Min = 1,
                        Max = 64,
                        Unit = new("çekirdek", "cores"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "terminal.container_memory",
                        Title = new("İzole kutuya ayrılan bellek", "Memory given to the isolated box"),
                        Glyph = GBox,
                        Min = 256,
                        Max = 262144,
                        Unit = new("MB", "MB"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "terminal.container_disk",
                        Title = new("İzole kutuya ayrılan disk", "Disk given to the isolated box"),
                        Glyph = GSave,
                        Min = 1024,
                        Max = 1048576,
                        Unit = new("MB", "MB"),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Kod çalıştırma", "Running code"),
                Glyph = GCode,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Choice,
                        Key = "code_execution.mode",
                        Title = new("Yazdığı kod nerede çalışsın?", "Where should the code it writes run?"),
                        Glyph = GCode,
                        Options = new[]
                        {
                            new SimpleOption("project",
                                new("Üzerinde çalıştığın klasörde", "In the folder you are working in"),
                                new("Projenin kütüphaneleri ve dosyaları doğrudan kullanılabilir. Varsayılan ve çoğu iş için doğru seçim.",
                                    "The project's libraries and files are directly usable. The default and the right choice for most work.")),
                            new SimpleOption("strict",
                                new("Boş bir geçici klasörde", "In an empty temporary folder"),
                                new("Kod projeden yalıtılmış çalışır. Daha güvenli ama projenin kütüphanelerine erişemez.",
                                    "The code runs isolated from the project. Safer, but it cannot reach the project's libraries.")),
                        },
                    },
                },
            },
        },
    };

    // ── Kanallar ─────────────────────────────────────────────────────────────

    private static SimplePage Channels() => new()
    {
        Id = "channels",
        Title = new("Kanallar", "Channels"),
        Intro = new(
            "FETİH'e Slack, Discord, Telegram gibi uygulamalardan da yazabilirsin. Burası, bağlandıktan sonra oralarda nasıl davranacağını ayarladığın yer. Bağlantı anahtarları burada tutulmaz.",
            "You can also talk to FETİH from Slack, Discord or Telegram. This is where you set how it behaves there once connected. Connection keys are not kept here."),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Slack", "Slack"),
                Glyph = GChat,
                Controls = new[]
                {
                    Mention("slack.require_mention"),
                },
            },
            new SimpleSection
            {
                Title = new("Discord", "Discord"),
                Glyph = GChat,
                Controls = new[]
                {
                    Mention("discord.require_mention"),
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "discord.auto_thread",
                        Title = new("Her işe ayrı bir başlık açsın", "Open a separate thread for each job"),
                        Glyph = GChat,
                        Description = new(
                            "Uzun yanıtlar kanalı doldurmak yerine kendi başlığında akar.",
                            "Long answers flow in their own thread instead of flooding the channel."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "discord.reactions",
                        Title = new("Durumu emojiyle göstersin", "Show status with emoji"),
                        Glyph = GChat,
                        Description = new(
                            "Mesajına tepki koyarak \"aldım\", \"çalışıyorum\", \"bitti\" der.",
                            "It reacts to your message to say \"got it\", \"working\", \"done\"."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "discord.history_backfill",
                        Title = new("Önceki mesajları da okusun", "Read the earlier messages too"),
                        Glyph = GBook,
                        Description = new(
                            "Bir kanala ilk kez katıldığında geçmişi okuyup bağlamı çıkarır.",
                            "When it first joins a channel it reads the history to pick up context."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "discord.history_backfill_limit",
                        Title = new("Kaç eski mesaj okunsun", "How many earlier messages to read"),
                        Glyph = GBook,
                        Min = 1,
                        Max = 1000,
                        Unit = new("mesaj", "messages"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "discord.allow_any_attachment",
                        Title = new("Her tür dosya ekine izin ver", "Allow any kind of attachment"),
                        Glyph = GWarn,
                        Description = new(
                            "Kapalıyken yalnızca güvenli sayılan dosya türleri işlenir. Bilinmeyen kanallarda kapalı tut.",
                            "When off, only file types considered safe are processed. Keep it off in channels you do not control."),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Telegram", "Telegram"),
                Glyph = GChat,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "telegram.reactions",
                        Title = new("Durumu emojiyle göstersin", "Show status with emoji"),
                        Glyph = GChat,
                        Description = new(
                            "Mesajına tepki koyarak işin hangi aşamada olduğunu bildirir.",
                            "It reacts to your message to tell you what stage the job is at."),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Mattermost", "Mattermost"),
                Glyph = GChat,
                Controls = new[] { Mention("mattermost.require_mention") },
            },
            new SimpleSection
            {
                Title = new("Matrix", "Matrix"),
                Glyph = GChat,
                Controls = new[] { Mention("matrix.require_mention") },
            },
        },
    };

    private static SimpleControl Mention(string key) => new()
    {
        Kind = SimpleKind.Toggle,
        Key = key,
        Title = new("Yalnızca adı anıldığında yanıtlasın", "Only answer when it is mentioned"),
        Glyph = GChat,
        Description = new(
            "Açıkken kanaldaki her mesaja değil, sadece kendisine seslenilen mesajlara cevap verir. Kalabalık kanallarda açık tut.",
            "When on it answers only messages addressed to it, not every message in the channel. Keep it on in busy channels."),
    };

    // ── Hafıza ───────────────────────────────────────────────────────────────

    private static SimplePage Memory() => new()
    {
        Id = "memory",
        Title = new("Hafıza", "Memory"),
        Intro = new(
            "FETİH'in konuşmalar arasında neyi hatırlayacağı ve uzayan bir konuşmayı nasıl toparlayacağı.",
            "What FETİH remembers between conversations, and how it keeps a long conversation manageable."),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Hatırlama", "Remembering"),
                Glyph = GBook,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "memory.memory_enabled",
                        Title = new("Öğrendiklerini hatırlasın", "Remember what it learns"),
                        Glyph = GBook,
                        Description = new(
                            "Hedeflerin, araçların ve tekrar eden işlerin hakkında not tutar; yeni sohbette sıfırdan anlatman gerekmez. Kapatırsan her sohbet temiz sayfa olur.",
                            "It keeps notes about your targets, tools and recurring jobs, so you do not explain everything again in a new chat. Turn it off and every chat starts blank."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "memory.user_profile_enabled",
                        Title = new("Senin çalışma tarzını da öğrensin", "Learn your working style too"),
                        Glyph = GBook,
                        Description = new(
                            "Tercih ettiğin araçlar, dil ve rapor biçimi gibi kişisel notlar tutar.",
                            "It keeps personal notes such as your preferred tools, language and report style."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "memory.memory_char_limit",
                        Title = new("Not defterinin boyutu", "Size of the notebook"),
                        Glyph = GBook,
                        Min = 200,
                        Max = 20000,
                        Unit = new("karakter", "characters"),
                        Description = new(
                            "Büyütmek daha çok şey hatırlatır ama her istekte daha fazla yer kaplar.",
                            "A bigger notebook remembers more but takes up more room in every request."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "memory.user_char_limit",
                        Title = new("Senin hakkındaki notların boyutu", "Size of the notes about you"),
                        Glyph = GBook,
                        Min = 200,
                        Max = 20000,
                        Unit = new("karakter", "characters"),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Uzun konuşmalar", "Long conversations"),
                Glyph = GPage,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "compression.enabled",
                        Title = new("Konuşma uzayınca kendiliğinden özetlesin", "Summarise automatically when the chat gets long"),
                        Glyph = GPage,
                        Description = new(
                            "Modelin kapasitesi dolmadan eski mesajlar özete dönüştürülür; konuşma kesilmeden devam eder. Kapatırsan uzun oturumlar bir yerde durur.",
                            "Older messages are folded into a summary before the model's capacity fills up, so the conversation continues uninterrupted. Turn it off and long sessions eventually stall."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "curator.enabled",
                        Title = new("Eski notları arada bir düzenlesin", "Tidy up old notes now and then"),
                        Glyph = GBook,
                        Description = new(
                            "Boşta kaldığı zamanlarda birikmiş notları temizler, tekrar edenleri birleştirir.",
                            "While idle it cleans up accumulated notes and merges duplicates."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "compression.protect_last_n",
                        Title = new("Son kaç mesaj hiç özetlenmesin", "How many recent messages are never summarised"),
                        Glyph = GPage,
                        Min = 1,
                        Max = 200,
                        Unit = new("mesaj", "messages"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "curator.interval_hours",
                        Title = new("Düzenleme sıklığı", "How often it tidies up"),
                        Glyph = GClock,
                        Min = 1,
                        Max = 8760,
                        Unit = new("saat", "hours"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "curator.archive_after_days",
                        Title = new("Kaç gün sonra notlar arşive kaldırılsın", "After how many days notes are archived"),
                        Glyph = GClock,
                        Min = 1,
                        Max = 3650,
                        Unit = new("gün", "days"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "curator.backup.enabled",
                        Title = new("Düzenlemeden önce yedek al", "Back up before tidying"),
                        Glyph = GSave,
                    },
                },
            },
        },
    };

    // ── Otomasyon ────────────────────────────────────────────────────────────

    private static SimplePage Automation() => new()
    {
        Id = "automation",
        Title = new("Otomasyon", "Automation"),
        Intro = new(
            "Zamanlanmış işler, görev panosu ve büyük işleri yardımcı ajanlara bölme davranışı.",
            "Scheduled jobs, the task board, and how big jobs get split across helper agents."),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Zamanlanmış işler", "Scheduled jobs"),
                Glyph = GClock,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "cron.wrap_response",
                        Title = new("Sonuçları özetleyerek bildirsin", "Report results as a summary"),
                        Glyph = GPage,
                        Description = new(
                            "Zamanlanmış bir iş bittiğinde ham çıktı yerine kısa bir özet gönderilir.",
                            "When a scheduled job finishes you get a short summary instead of raw output."),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Görev panosu", "Task board"),
                Glyph = GApps,
                Description = new(
                    "Büyük bir işi kartlara bölüp arka planda sırayla işleten pano.",
                    "The board that splits a big job into cards and works through them in the background."),
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "kanban.auto_decompose",
                        Title = new("Büyük işleri kendiliğinden adımlara bölsün", "Split big jobs into steps automatically"),
                        Glyph = GApps,
                        Description = new(
                            "Panoya attığın kaba bir görevi FETİH kendisi alt adımlara ayırır.",
                            "A rough task you drop on the board gets broken into sub-steps by FETİH itself."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "kanban.failure_limit",
                        Title = new("Bir kart kaç kez denensin", "How many times a card is retried"),
                        Glyph = GWarn,
                        Min = 1,
                        Max = 20,
                        Unit = new("deneme", "attempts"),
                        Description = new(
                            "Bu kadar başarısızlıktan sonra kart durdurulur ve elle bakman beklenir.",
                            "After this many failures the card is parked and waits for you to look at it."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "kanban.auto_decompose_per_tick",
                        Title = new("Aynı anda kaç kart bölünsün", "How many cards get split at once"),
                        Glyph = GApps,
                        Min = 1,
                        Max = 20,
                        Unit = new("kart", "cards"),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Yardımcı ajanlar", "Helper agents"),
                Glyph = GBolt,
                Description = new(
                    "FETİH bir işi paralel çalışan yardımcılara dağıtabilir. Onay davranışı İzinler sayfasındadır.",
                    "FETİH can hand parts of a job to helpers running in parallel. Their approval behaviour lives on the Permissions page."),
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "delegation.orchestrator_enabled",
                        Title = new("İşleri yardımcılara dağıtabilsin", "Allow handing work to helpers"),
                        Glyph = GBolt,
                        Description = new(
                            "Kapatırsan her şeyi tek başına, sırayla yapar — daha yavaş ama takip etmesi kolay.",
                            "Turn it off and it does everything alone, in order — slower but easier to follow."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "delegation.max_concurrent_children",
                        Title = new("Aynı anda en fazla kaç yardımcı", "At most how many helpers at once"),
                        Glyph = GBolt,
                        Min = 1,
                        Max = 20,
                        Unit = new("yardımcı", "helpers"),
                        Description = new(
                            "Artırmak işi hızlandırır, model kotanı daha hızlı tüketir.",
                            "Raising it speeds work up and burns through your model quota faster."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "delegation.max_spawn_depth",
                        Title = new("Yardımcılar kendi yardımcılarını kaç kat açabilsin", "How deep helpers may spawn helpers"),
                        Glyph = GBolt,
                        Min = 0,
                        Max = 5,
                        Unit = new("kat", "levels"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "delegation.max_iterations",
                        Title = new("Bir yardımcı en fazla kaç adım atsın", "At most how many steps a helper takes"),
                        Glyph = GBolt,
                        Min = 1,
                        Max = 500,
                        Unit = new("adım", "steps"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "goals.max_turns",
                        Title = new("Bir hedef için en fazla adım", "At most how many steps per goal"),
                        Glyph = GBox,
                        Min = 1,
                        Max = 500,
                        Unit = new("adım", "steps"),
                    },
                },
            },
        },
    };

    // ── Görünüm ──────────────────────────────────────────────────────────────

    private static SimplePage Appearance() => new()
    {
        Id = "appearance",
        Title = new("Görünüm", "Appearance"),
        Intro = new(
            "Arayüz dili ve FETİH'in yanıtlarını nasıl gösterdiği. Renk temaları terminal arayüzünü etkiler.",
            "The interface language and how FETİH presents its answers. Colour themes affect the terminal interface."),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Dil", "Language"),
                Glyph = GLang,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Language,
                        Title = new("Arayüz dili", "Interface language"),
                        Glyph = GLang,
                        AlwaysShow = true,
                        Description = new(
                            "Bu pencerenin dili. Değişiklik anında uygulanır ve kalıcı olarak kaydedilir.",
                            "The language of this window. Applied immediately and saved persistently."),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Yanıtlar nasıl görünsün?", "How should answers look?"),
                Glyph = GView,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "display.show_reasoning",
                        Title = new("Düşünme adımlarını göster", "Show the thinking steps"),
                        Glyph = GView,
                        Description = new(
                            "Model yanıtı vermeden önceki muhakemesini de yazar. Neden öyle davrandığını anlamak için yararlı, ekranı kalabalıklaştırır.",
                            "The model also writes out the reasoning it did before answering. Useful for understanding why it acted that way, and it clutters the screen."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "display.timestamps",
                        Title = new("Mesajlarda saat göster", "Show timestamps on messages"),
                        Glyph = GClock,
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "display.show_cost",
                        Title = new("Her yanıtın maliyetini göster", "Show what each answer cost"),
                        Glyph = GPage,
                        Description = new(
                            "Kullanılan model için tahmini ücret yanıtın altına yazılır.",
                            "The estimated charge for the model used is printed under the answer."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "display.compact",
                        Title = new("Sıkışık görünüm", "Compact layout"),
                        Glyph = GView,
                        Description = new(
                            "Boşlukları azaltır; küçük ekranlarda daha çok içerik sığar.",
                            "Reduces spacing so more content fits on a small screen."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "dashboard.show_token_analytics",
                        Title = new("Kullanım istatistiklerini göster", "Show usage statistics"),
                        Glyph = GPage,
                        Description = new(
                            "Panoda hangi işin ne kadar model kapasitesi tükettiğini gösterir.",
                            "The dashboard shows how much model capacity each job consumed."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Select,
                        Key = "display.skin",
                        Title = new("Terminal arayüzü teması", "Terminal interface theme"),
                        Glyph = GView,
                        Description = new(
                            "FETİH'in terminal (komut satırı) arayüzünün renk şeması. Bu pencerenin görünümünü değiştirmez.",
                            "The colour scheme of FETİH's terminal (command-line) interface. It does not change this window."),
                        Options = new[]
                        {
                            Skin("default", new("Varsayılan", "Default")),
                            Skin("red", new("Kırmızı", "Red")),
                            Skin("green", new("Yeşil", "Green")),
                            Skin("gold", new("Altın", "Gold")),
                            Skin("heaven", new("Gökyüzü", "Heaven")),
                            Skin("ares", new("Ares", "Ares")),
                            Skin("poseidon", new("Poseidon", "Poseidon")),
                            Skin("sisyphus", new("Sisyphus", "Sisyphus")),
                            Skin("charizard", new("Charizard", "Charizard")),
                            Skin("slate", new("Arduvaz", "Slate")),
                            Skin("mono", new("Tek renk", "Monochrome")),
                            Skin("daylight", new("Gün ışığı (açık)", "Daylight (light)")),
                            Skin("warm-lightmode", new("Sıcak açık", "Warm light")),
                        },
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "display.bell_on_complete",
                        Title = new("İş bitince sesli uyar", "Beep when a job finishes"),
                        Glyph = GBolt,
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "display.inline_diffs",
                        Title = new("Dosya değişikliklerini satır satır göster", "Show file changes line by line"),
                        Glyph = GPage,
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "display.persistent_output_max_lines",
                        Title = new("Ekranda tutulan en fazla satır", "Most lines kept on screen"),
                        Glyph = GPage,
                        Min = 10,
                        Max = 10000,
                        Unit = new("satır", "lines"),
                    },
                },
            },
        },
    };

    private static SimpleOption Skin(string value, Text2 title) => new(value, title, new("", ""));

    // ── Sistem ───────────────────────────────────────────────────────────────

    private static SimplePage SystemPage() => new()
    {
        Id = "system",
        Title = new("Sistem", "System"),
        Intro = new(
            "Kayıtlar, eski sohbetler, yedekler ve güncellemeler. Bir sorunu araştırmadıkça bu sayfaya nadiren dokunursun.",
            "Logs, old conversations, backups and updates. Unless you are chasing a problem you rarely touch this page."),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Kayıtlar", "Logs"),
                Glyph = GPage,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Choice,
                        Key = "logging.level",
                        Title = new("Ne kadar ayrıntı kaydedilsin?", "How much detail is recorded?"),
                        Glyph = GPage,
                        Options = new[]
                        {
                            new SimpleOption("INFO",
                                new("Normal", "Normal"),
                                new("Olağan olaylar ve hatalar kaydedilir. Varsayılan.",
                                    "Ordinary events and errors are recorded. The default.")),
                            new SimpleOption("DEBUG",
                                new("Ayrıntılı (sorun ararken)", "Verbose (while debugging)"),
                                new("Her adım kaydedilir. Bir hatayı bildirirken aç, sonra geri kapat — kayıt dosyaları hızla büyür.",
                                    "Every step is recorded. Turn it on while reporting a bug, then turn it back off — log files grow fast.")),
                            new SimpleOption("WARNING",
                                new("Yalnızca uyarı ve hatalar", "Warnings and errors only"),
                                new("Sessiz kalır, yalnızca ters giden şeyleri yazar.",
                                    "It stays quiet and writes only what goes wrong.")),
                            new SimpleOption("ERROR",
                                new("Yalnızca hatalar", "Errors only"),
                                new("En az kayıt. Sorun araştırmayı zorlaştırır.",
                                    "The least logging. It makes troubleshooting harder.")),
                        },
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "logging.max_size_mb",
                        Title = new("Kayıt dosyası en fazla ne kadar büyüsün", "How large a log file may grow"),
                        Glyph = GSave,
                        Min = 1,
                        Max = 1024,
                        Unit = new("MB", "MB"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "logging.backup_count",
                        Title = new("Kaç eski kayıt dosyası saklansın", "How many old log files are kept"),
                        Glyph = GSave,
                        Min = 0,
                        Max = 50,
                        Unit = new("dosya", "files"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "logging.memory_monitor.enabled",
                        Title = new("Bellek kullanımını izle", "Watch memory usage"),
                        Glyph = GPage,
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Sohbet geçmişi ve yedekler", "History and backups"),
                Glyph = GSave,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "sessions.auto_prune",
                        Title = new("Eski sohbetleri kendiliğinden sil", "Delete old conversations automatically"),
                        Glyph = GSave,
                        Description = new(
                            "Belirli bir süreden eski sohbetler diskten silinir. Kapalıyken hiçbir sohbet kendiliğinden kaybolmaz.",
                            "Conversations older than a set age are removed from disk. When off, nothing disappears on its own."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "checkpoints.enabled",
                        Title = new("Dosyaları değiştirmeden önce yedekle", "Back up files before changing them"),
                        Glyph = GSave,
                        Description = new(
                            "FETİH bir dosyayı düzenlemeden önce kopyasını saklar; yanlış giderse geri alabilirsin. Disk kullanır.",
                            "FETİH keeps a copy before it edits a file, so you can roll back if it goes wrong. It uses disk space."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "updates.pre_update_backup",
                        Title = new("Güncellemeden önce yedek al", "Back up before updating"),
                        Glyph = GSave,
                        Description = new(
                            "Yeni sürüme geçmeden önce mevcut kurulumun kopyası saklanır.",
                            "A copy of the current installation is kept before moving to a new version."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "sessions.retention_days",
                        Title = new("Sohbetler kaç gün saklansın", "How many days conversations are kept"),
                        Glyph = GClock,
                        Min = 1,
                        Max = 3650,
                        Unit = new("gün", "days"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "checkpoints.max_snapshots",
                        Title = new("En fazla kaç dosya yedeği tutulsun", "How many file backups are kept"),
                        Glyph = GSave,
                        Min = 1,
                        Max = 1000,
                        Unit = new("yedek", "backups"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "updates.backup_keep",
                        Title = new("Kaç kurulum yedeği saklansın", "How many installation backups are kept"),
                        Glyph = GSave,
                        Min = 1,
                        Max = 50,
                        Unit = new("yedek", "backups"),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Ağ ve kod desteği", "Network and code support"),
                Glyph = GNet,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "network.force_ipv4",
                        Title = new("Yalnızca IPv4 kullan", "Use IPv4 only"),
                        Glyph = GNet,
                        Description = new(
                            "Bazı ağlarda IPv6 bağlantıları takılır. Beklenmedik ağ zaman aşımları görüyorsan aç.",
                            "On some networks IPv6 connections hang. Turn it on if you see unexplained network timeouts."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "lsp.enabled",
                        Title = new("Kod düzenlerken dil desteği kullan", "Use language support while editing code"),
                        Glyph = GCode,
                        Description = new(
                            "FETİH kod yazarken hataları ve tip bilgisini editörün kullandığı araçlardan okur; düzeltmeleri isabetli olur.",
                            "While writing code FETİH reads errors and type information from the same tooling an editor uses, so its fixes land better."),
                    },
                },
            },
        },
    };

    // ── Araçlar ──────────────────────────────────────────────────────────────

    private static SimplePage Tools() => new()
    {
        Id = "tools",
        Title = new("Araçlar", "Tools"),
        Intro = new(
            "FETİH'in elindeki araçlar ve bunların sınırları.",
            "The tools FETİH has at hand, and the limits placed on them."),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Etkin araç takımları", "Enabled toolsets"),
                Glyph = GApps,
                Description = new(
                    "Şu anda açık olan araç grupları. Yeni bir takım eklemek için Detaylı Mod'u kullan.",
                    "The tool groups currently switched on. Use Advanced Mode to add a new one."),
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.StringList,
                        Key = "toolsets",
                        Title = new("Açık takımlar", "Active toolsets"),
                        Glyph = GApps,
                        EmptyNote = new(
                            "Hiçbir ek araç takımı açık değil; yalnızca yerleşik araçlar kullanılabilir.",
                            "No extra toolset is enabled; only the built-in tools are available."),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Yetenekler", "Skills"),
                Glyph = GBook,
                Description = new(
                    "Yetenekler, FETİH'e hazır iş akışları öğreten paketlerdir (Yetenekler sayfasından yönetilir).",
                    "Skills are packages that teach FETİH ready-made workflows (managed on the Skills page)."),
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "skills.inline_shell",
                        Title = new("Yetenekler kabuk komutu çalıştırabilsin", "Let skills run shell commands"),
                        Glyph = GWarn,
                        Description = new(
                            "Bir yeteneğin metninin içine gömülü komutlar çalıştırılır. Yalnızca kaynağına güvendiğin yetenekler için aç.",
                            "Commands embedded inside a skill's text get executed. Only turn this on for skills whose source you trust."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "skills.guard_agent_created",
                        Title = new("FETİH'in kendi yazdığı yetenekleri onaya tabi tut", "Vet the skills FETİH writes itself"),
                        Glyph = GCheck,
                        Description = new(
                            "FETİH kendine yeni bir yetenek yazdığında sen bakmadan kullanılmaz.",
                            "When FETİH writes itself a new skill it is not used before you look at it."),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Takılma koruması", "Stuck-loop protection"),
                Glyph = GWarn,
                Description = new(
                    "Aynı aracı sonuç alamadan tekrar tekrar çağırma döngüsüne karşı koruma.",
                    "Protection against looping on the same tool call without making progress."),
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "tool_loop_guardrails.warnings_enabled",
                        Title = new("Takılırsa uyarsın", "Warn when it gets stuck"),
                        Glyph = GWarn,
                        Description = new(
                            "Aynı hatayı tekrarlıyorsa FETİH'e \"başka bir yol dene\" uyarısı verilir.",
                            "If it repeats the same failure, FETİH is nudged to try a different route."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "tool_loop_guardrails.hard_stop_enabled",
                        Title = new("Takılırsa tamamen dursun", "Stop outright when it gets stuck"),
                        Glyph = GWarn,
                        Description = new(
                            "Uyarı yetmezse görev kesilir. Gözetimsiz çalıştırıyorsan aç.",
                            "If the warning is not enough the job is cut off. Turn it on when you run it unattended."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "file_read_max_chars",
                        Title = new("Bir dosyadan en fazla okunacak miktar", "Most that is read from one file"),
                        Glyph = GPage,
                        Min = 1000,
                        Max = 2000000,
                        Unit = new("karakter", "characters"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "tool_output.max_lines",
                        Title = new("Bir komut çıktısından en fazla satır", "Most lines kept from one command"),
                        Glyph = GPage,
                        Min = 50,
                        Max = 100000,
                        Unit = new("satır", "lines"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "skills.inline_shell_timeout",
                        Title = new("Yetenek komutu en fazla ne kadar sürsün", "How long a skill command may run"),
                        Glyph = GClock,
                        Min = 1,
                        Max = 600,
                        Unit = new("saniye", "seconds"),
                    },
                },
            },
        },
    };

    // ── Ajan ─────────────────────────────────────────────────────────────────

    private static SimplePage Agent() => new()
    {
        Id = "agent",
        Title = new("Ajan", "Agent"),
        Intro = new(
            "FETİH bir görev üzerinde ne kadar ısrar etsin ve web'de nasıl davransın?",
            "How hard should FETİH push on a task, and how should it behave on the web?"),
        Sections = new[]
        {
            new SimpleSection
            {
                Title = new("Görev sınırları", "Task limits"),
                Glyph = GBolt,
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "agent.max_turns",
                        Title = new("Tek bir görevde en fazla adım", "Most steps in a single task"),
                        Glyph = GBolt,
                        Min = 1,
                        Max = 1000,
                        Unit = new("adım", "steps"),
                        Description = new(
                            "Bu sayıya ulaşınca FETİH durur ve sana döner. Düşürmek maliyeti sınırlar, karmaşık işleri yarım bırakabilir.",
                            "When it reaches this number FETİH stops and comes back to you. Lowering it caps cost and can leave complex jobs unfinished."),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "agent.api_max_retries",
                        Title = new("Model yanıt vermezse kaç kez denensin", "How many retries if the model does not answer"),
                        Glyph = GBolt,
                        Min = 0,
                        Max = 20,
                        Unit = new("deneme", "attempts"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "agent.clarify_timeout",
                        Title = new("Soru sorduğunda ne kadar beklesin", "How long it waits when it asks you a question"),
                        Glyph = GClock,
                        Min = 10,
                        Max = 7200,
                        Unit = new("saniye", "seconds"),
                    },
                },
            },
            new SimpleSection
            {
                Title = new("Web ve tarayıcı", "Web and browser"),
                Glyph = GGlobe,
                Description = new(
                    "Erişim kısıtları Güvenlik sayfasındadır.",
                    "Access restrictions live on the Security page."),
                Controls = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Toggle,
                        Key = "browser.record_sessions",
                        Title = new("Tarayıcı gezintilerini kaydet", "Record browsing sessions"),
                        Glyph = GGlobe,
                        Description = new(
                            "FETİH'in bir sitede ne yaptığı adım adım kaydedilir; sonradan izlemek ve rapora eklemek için yararlı. Disk kullanır.",
                            "What FETİH did on a site is recorded step by step — useful to review later or attach to a report. It uses disk space."),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "browser.command_timeout",
                        Title = new("Bir sayfa işlemi en fazla ne kadar sürsün", "How long one page action may take"),
                        Glyph = GClock,
                        Min = 5,
                        Max = 600,
                        Unit = new("saniye", "seconds"),
                    },
                },
                Advanced = new[]
                {
                    new SimpleControl
                    {
                        Kind = SimpleKind.Number,
                        Key = "browser.inactivity_timeout",
                        Title = new("Tarayıcı ne kadar boş kalınca kapansın", "How long the browser idles before closing"),
                        Glyph = GClock,
                        Min = 10,
                        Max = 3600,
                        Unit = new("saniye", "seconds"),
                    },
                    new SimpleControl
                    {
                        Kind = SimpleKind.Select,
                        Key = "browser.engine",
                        Title = new("Tarayıcı motoru", "Browser engine"),
                        Glyph = GGlobe,
                        Options = new[]
                        {
                            new SimpleOption("auto",
                                new("Otomatik seç", "Choose automatically"),
                                new("Ortama göre en uygun motor kullanılır. Önerilen.",
                                    "The most suitable engine for the environment is used. Recommended.")),
                            new SimpleOption("chromium",
                                new("Chromium", "Chromium"),
                                new("", "")),
                            new SimpleOption("camofox",
                                new("Gizlilik odaklı Firefox", "Privacy-focused Firefox"),
                                new("Bot tespitine karşı daha dirençli, biraz daha yavaş.",
                                    "More resistant to bot detection, a little slower.")),
                        },
                    },
                },
            },
        },
    };
}
