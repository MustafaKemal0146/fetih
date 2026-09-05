using System;
using System.Collections.Generic;

namespace Fetih.Desktop.Services;

/// <summary>
/// Ayar satırları için insan-okur açıklamalar (Görev F). Kaynak:
/// <c>docs/fetih-ozellik-envanteri.md</c>. Her giriş, ayarın ne işe yaradığını,
/// değiştirilirse ne olacağını ve varsayılanının neden öyle olduğunu 2-4 cümleyle
/// anlatır. Anahtar, noktalı config yolu (<c>agent.max_turns</c>) veya bir kök
/// bölüm adıdır (<c>agent</c>).
///
/// <para>Tam config yüzeyi çok geniş olduğundan burada en sık dokunulan/kritik
/// anahtarlar küratörlenir; bilinmeyen bir anahtar için açıklama gösterilmez
/// (satır yine düzenlenebilir kalır). Hem jenerik <c>ConfigEditorPage</c> hem
/// küratörlü sayfalar bu tabloyu kullanır.</para>
/// </summary>
public static class SettingDescriptions
{
    /// <summary>
    /// Bir config yolu için açıklama döndürür; yoksa son segmenti, o da yoksa
    /// kök bölümü dener. Hiçbiri yoksa <c>null</c>.
    /// </summary>
    public static string? For(string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath))
        {
            return null;
        }

        if (Table.TryGetValue(keyPath, out var exact))
        {
            return Localize(exact);
        }

        // Son segment (ör. "agent.retry.max_attempts" → "max_attempts").
        var lastDot = keyPath.LastIndexOf('.');
        if (lastDot >= 0)
        {
            var leaf = keyPath[(lastDot + 1)..];
            if (Table.TryGetValue(leaf, out var byLeaf))
            {
                return Localize(byLeaf);
            }
        }

        // Kök bölüm (ör. "security.xxx" → "security").
        var firstDot = keyPath.IndexOf('.');
        var root = firstDot >= 0 ? keyPath[..firstDot] : keyPath;
        if (Table.TryGetValue(root, out var byRoot))
        {
            return Localize(byRoot);
        }

        return null;
    }

    private static string Localize((string Tr, string En) pair)
        => Loc.Current == UiLanguage.Turkish ? pair.Tr : pair.En;

    private static readonly Dictionary<string, (string Tr, string En)> Table =
        new(StringComparer.Ordinal)
    {
        // ── model / sağlayıcı ────────────────────────────────────────────
        ["model"] = (
            "Etkin model ve sağlayıcı seçimi. FETİH model-agnostiktir; buradaki değerler bir sonraki oturumda kullanılacak varsayılan modeli belirler.",
            "Active model and provider selection. FETİH is model-agnostic; these values set the default model used for the next session."),
        ["model.provider"] = (
            "Kullanılacak sağlayıcının kimliği (ör. groq, anthropic, openrouter). Değiştirirsen sonraki mesajlar o sağlayıcının API'sine gider; ilgili API anahtarı ~/.fetih/.env içinde tanımlı olmalıdır.",
            "The provider id to use (e.g. groq, anthropic, openrouter). Changing it routes the next messages to that provider's API; its API key must be defined in ~/.fetih/.env."),
        ["model.default"] = (
            "Sağlayıcı içindeki varsayılan model kimliği (ör. llama-3.3-70b-versatile). Sağlayıcının desteklediği bir model olmalıdır; yanlış bir kimlik ilk çağrıda hata verir.",
            "The default model id within the provider (e.g. llama-3.3-70b-versatile). It must be a model the provider supports; an invalid id fails on the first call."),
        ["fallback_model"] = (
            "Birincil sağlayıcı 429/529/503 gibi geçici hatalar döndürdüğünde otomatik devreye giren yedek model. Boşsa yedek yoktur ve hata doğrudan sana yansır.",
            "A backup model that kicks in automatically when the primary provider returns transient errors like 429/529/503. If empty there is no fallback and the error surfaces directly."),
        ["fallback_providers"] = (
            "Birincil sağlayıcı başarısız olduğunda sırayla denenecek sağlayıcı listesi. Kesinti dayanıklılığı sağlar; boş bırakılırsa yalnızca birincil sağlayıcı kullanılır.",
            "An ordered list of providers tried in turn when the primary fails. Adds resilience to outages; if empty only the primary provider is used."),

        // ── toolsets / araçlar ───────────────────────────────────────────
        ["toolsets"] = (
            "Ajanın erişebildiği araç kümeleri (file, terminal, web, search, vision …). Daha az küme = daha küçük istem tabanı ve daha hızlı/ucuz çağrı; daha fazla küme = daha yetenekli ama daha büyük bağlam.",
            "The tool groups the agent can access (file, terminal, web, search, vision …). Fewer groups = smaller prompt base and faster/cheaper calls; more groups = more capable but larger context."),
        ["disabled_toolsets"] = (
            "Açıkça devre dışı bırakılan araç kümeleri. Belirli bir aracın hiç yüklenmemesini istiyorsan buraya ekle; güvenlik veya token tasarrufu için kullanılır.",
            "Tool groups that are explicitly disabled. Add a group here to prevent a tool from ever loading; used for safety or to save tokens."),

        // ── agent ────────────────────────────────────────────────────────
        ["agent"] = (
            "Ajan çalışma zamanı davranışı: tur sınırı, zaman aşımı, yeniden deneme ve araç kullanım zorlaması. Bu değerler bir turun ne kadar sürebileceğini ve ne kadar dayanıklı olacağını belirler.",
            "Agent runtime behaviour: turn limit, timeout, retry and tool-use enforcement. These values decide how long a turn may run and how resilient it is."),
        ["max_turns"] = (
            "Bir kullanıcı mesajına yanıt verirken ajanın yapabileceği en fazla model-araç döngüsü sayısı. Yüksek değer karmaşık görevleri bitirmeye izin verir ama maliyeti ve süreyi artırır; düşük değer erken durdurur.",
            "The maximum number of model-tool loops the agent may run while answering one user message. Higher lets it finish complex tasks but raises cost and time; lower stops it early."),
        ["timeout"] = (
            "Tek bir işlemin (model çağrısı veya araç yürütmesi) saniye cinsinden üst sınırı. Aşılırsa işlem iptal edilir; ağ yavaşsa artır, hızlı başarısızlık istiyorsan azalt.",
            "The upper bound in seconds for a single operation (model call or tool execution). Exceeding it cancels the operation; raise it on slow networks, lower it for fast failure."),

        // ── terminal / sandbox ───────────────────────────────────────────
        ["terminal"] = (
            "Terminal aracının yürütme ortamı: yerel makine mi yoksa bir sandbox/konteyner mı, ve kabuk/kaynak sınırları. Yanlış ayar terminal aracını çalışmaz hale getirebilir.",
            "The terminal tool's execution environment: local machine or a sandbox/container, plus shell and resource limits. A wrong setting can make the terminal tool unusable."),
        ["backend"] = (
            "Komutların çalıştığı arka uç: local (doğrudan makine), docker, wsl vb. Sandbox arka uçları izolasyon sağlar ama kurulum gerektirir; local en hızlısıdır ama izolasyon yoktur.",
            "The backend commands run on: local (the machine directly), docker, wsl, etc. Sandbox backends provide isolation but require setup; local is fastest but has no isolation."),
        ["windows_shell"] = (
            "Windows'ta terminal komutlarını çalıştıran POSIX kabuğu: git-bash (varsayılan, Windows dosya sistemine doğrudan erişir) veya wsl (gerçek Linux dağıtımı). PowerShell bilinçli olarak sunulmaz çünkü araç katmanı POSIX semantiğine dayanır.",
            "The POSIX shell that runs terminal commands on Windows: git-bash (default, direct access to the Windows filesystem) or wsl (a real Linux distro). PowerShell is deliberately not offered because the tool layer relies on POSIX semantics."),
        ["wsl_distro"] = (
            "windows_shell=wsl iken kullanılacak WSL dağıtımı. Boş bırakılırsa wsl.exe'nin varsayılan dağıtımı kullanılır; birden çok dağıtımın varsa belirli birini seçmek için doldur.",
            "Which WSL distribution to use when windows_shell=wsl. If empty, wsl.exe's default distribution is used; set it to pick a specific one when you have several."),
        ["wsl_user"] = (
            "WSL kabuğunun hangi kullanıcı olarak çalışacağı. 'fetih' ayrılmış kullanıcısını seçmek, ajanın yazdığı dosyaları kendi ev dizininden ayrı tutar; boşsa dağıtımın varsayılan kullanıcısı kullanılır.",
            "Which user the WSL shell runs as. Choosing the dedicated 'fetih' user keeps agent-written files separate from your own home directory; if empty the distro's default user is used."),
        ["container_memory"] = (
            "Sandbox konteynerine ayrılan bellek (MB). Ağır araçlar (derleyiciler, tersine mühendislik) için artır; çok düşükse süreçler OOM ile ölür. Yalnızca konteyner arka uçlarında geçerlidir.",
            "Memory allotted to the sandbox container (MB). Raise it for heavy tools (compilers, reverse-engineering); too low and processes die with OOM. Only applies to container backends."),

        // ── security ─────────────────────────────────────────────────────
        ["security"] = (
            "Güvenlik korumaları: gizli-veri redaksiyonu, site kara listesi ve danışma uyarıları. Bunları gevşetmek FETİH'i daha esnek ama daha riskli yapar; sıkı varsayılanlar bilinçli tercihtir.",
            "Security guardrails: secret redaction, site blocklists and advisory warnings. Loosening these makes FETİH more flexible but riskier; the strict defaults are intentional."),

        // ── approvals / izinler ──────────────────────────────────────────
        ["approvals"] = (
            "Hangi eylemlerin çalışmadan önce senin onayını gerektirdiği. Daha fazla onay = daha güvenli ama daha yavaş akış; otomasyonda güveniyorsan bazı eylemleri otomatik kabule alabilirsin.",
            "Which actions require your approval before running. More approvals = safer but slower flow; if you trust automation you can auto-accept some actions."),
        ["command_allowlist"] = (
            "Onay istemeden çalışmasına izin verilen komutlar. Sık kullanılan güvenli komutları buraya ekleyerek akışı hızlandırırsın; dikkatli tut, çünkü buradaki her şey sorgusuz çalışır.",
            "Commands allowed to run without asking for approval. Add frequently-used safe commands here to speed up the flow; keep it tight because everything listed runs unquestioned."),

        // ── voice / ses ──────────────────────────────────────────────────
        ["tts"] = (
            "Metin-konuşma (seslendirme) ayarları: motor, ses ve dil. Kapalıysa yanıtlar yalnızca metin olarak gelir; açmak bir TTS sağlayıcısı/anahtarı gerektirebilir.",
            "Text-to-speech settings: engine, voice and language. If off, responses are text only; enabling it may require a TTS provider/key."),
        ["stt"] = (
            "Konuşma-metin (dikte) ayarları: motor ve dil. Sesli mod için mikrofon girişini metne çevirir; kapalıysa sesli komut kullanılamaz.",
            "Speech-to-text (dictation) settings: engine and language. Converts microphone input to text for voice mode; if off, voice commands are unavailable."),

        // ── memory / bağlam ──────────────────────────────────────────────
        ["memory"] = (
            "Kalıcı hafıza: FETİH'in oturumlar arası hatırladığı bilgiler. Açık tutmak süreklilik sağlar; kapatmak her oturumu sıfırdan başlatır ve gizliliği artırır.",
            "Persistent memory: what FETİH remembers across sessions. Keeping it on provides continuity; turning it off starts each session fresh and improves privacy."),
        ["compression"] = (
            "Bağlam sıkıştırma: konuşma uzadığında eski mesajların özetlenmesi. Token tavanına takılmayı önler ama çok agresifse ayrıntı kaybına yol açabilir.",
            "Context compression: summarising older messages as the conversation grows. Prevents hitting the token ceiling but, if too aggressive, can lose detail."),
        ["prompt_caching"] = (
            "İstem önbellekleme: sabit istem önekinin sağlayıcıda önbelleğe alınması. Desteklendiğinde maliyeti ve gecikmeyi düşürür; desteklenmeyen sağlayıcılarda etkisizdir.",
            "Prompt caching: caching the stable prompt prefix at the provider. Lowers cost and latency where supported; a no-op on providers that don't support it."),

        // ── display / görünüm ────────────────────────────────────────────
        ["display"] = (
            "Arayüz görünümü: tema, renkler ve dil gibi sunum tercihleri. İşlevi değil yalnızca görünümü etkiler.",
            "Interface appearance: presentation preferences like theme, colours and language. Affects only look, not behaviour."),
        ["privacy"] = (
            "Gizlilik tercihleri: telemetri, veri paylaşımı ve yerel-öncelik. Sıkılaştırmak dışarı giden veriyi azaltır; bazı bulut özellikleri kısıtlanabilir.",
            "Privacy preferences: telemetry, data sharing and local-first behaviour. Tightening reduces outbound data; some cloud features may be limited."),

        // ── system / logging ─────────────────────────────────────────────
        ["logging"] = (
            "Günlük kaydı düzeyi ve hedefi. Ayrıntılı düzey hata ayıklamaya yardımcı olur ama disk kullanımını ve gürültüyü artırır; üretimde daha sessiz bir düzey önerilir.",
            "Log verbosity and destination. A verbose level helps debugging but increases disk use and noise; a quieter level is recommended in production."),
        ["updates"] = (
            "Otomatik güncelleme kontrolü ve kanalı. Açık tutmak seni güvenlik düzeltmeleriyle güncel tutar; kapatmak sürüm sabitliği isteyen ortamlar içindir.",
            "Automatic update checks and channel. Keeping it on keeps you current with security fixes; turning it off is for environments that need version stability."),
    };
}
