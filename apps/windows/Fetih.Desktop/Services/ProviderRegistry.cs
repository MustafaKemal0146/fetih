using System.Collections.Generic;

namespace Fetih.Desktop.Services;

/// <summary>
/// Bir sağlayıcının kurulum sırasında hangi akışı gerektirdiği. Sihirbaz her
/// sağlayıcıya aynı "API anahtarını yapıştır" adımını göstermek yerine bu
/// türe bakarak davranır.
/// </summary>
public enum ProviderKind
{
    /// <summary>Bulut sağlayıcı: API anahtarı istenir (Groq, OpenAI, Anthropic…).</summary>
    CloudApiKey,

    /// <summary>Bu makinede çalışan yerel sunucu: anahtar YOK, uç nokta yoklanır.</summary>
    LocalServer,

    /// <summary>Tarayıcı tabanlı OAuth akışı (cihaz kodu / geri çağırma).</summary>
    OAuthBrowser,

    /// <summary>Yerel bir CLI aracının kendi oturum akışı tetiklenir (gemini, codex…).</summary>
    CliLogin,

    /// <summary>AWS SDK kimlik zinciri (profil / IAM rolü).</summary>
    AwsSdk,
}

/// <summary>
/// Bir model sağlayıcısının kimliği.
///
/// <para><b>Id, FETİH CLI'nin KANONİK sağlayıcı kimliğidir.</b> Bu alan
/// <c>config.yaml</c>'daki <c>model.provider</c> değerine birebir yazılır ve
/// çalışma zamanında <c>fetih_cli/auth.py</c> içindeki
/// <c>resolve_provider()</c> tarafından çözülür. Buradaki kimlikler CLI'nin
/// kanonik listesinden saparsa kurulum sihirbazı "çalışıyor" görünen ama ilk
/// mesajda <c>Unknown provider</c> hatası veren bir yapılandırma üretir —
/// bu dosya bir zamanlar tam olarak bu hatayı barındırıyordu.</para>
/// </summary>
public sealed record ProviderEntry(
    string Id,
    string DisplayName,
    string Transport,
    string AuthType,
    IReadOnlyList<string> ApiKeyEnvVars,
    string BaseUrlEnvVar = "",
    bool IsAggregator = false,
    bool IsLocal = false,
    ProviderKind Kind = ProviderKind.CloudApiKey,
    string DefaultBaseUrl = "",
    string SignupUrl = "",
    string CliCommand = "");

/// <summary>
/// FETİH'in gerçekten desteklediği sağlayıcı kataloğu.
///
/// <para>Kimlikler <c>fetih_cli/models.py</c> içindeki
/// <c>CANONICAL_PROVIDERS</c> listesiyle ve <c>fetih_cli/auth.py</c>
/// içindeki <c>PROVIDER_REGISTRY</c> ile hizalıdır. Köprü ayaktayken
/// <see cref="ProviderCatalog"/> bu listeyi <c>providers.catalog</c>
/// RPC'sinden gelen CANLI listeyle değiştirir; buradaki tablo yalnızca köprü
/// henüz başlamadığındaki yedektir.</para>
/// </summary>
public static class ProviderRegistry
{
    /// <summary>Taşıma katmanının Türkçe etiketi.</summary>
    public static string TransportLabel(string transport) => transport switch
    {
        "openai_chat" => "OpenAI uyumlu sohbet",
        "chat_completions" => "OpenAI uyumlu sohbet",
        "anthropic_messages" => "Anthropic Messages",
        "codex_responses" => "Codex Responses",
        "bedrock_converse" => "Bedrock Converse",
        _ => transport,
    };

    /// <summary>Kimlik doğrulama türünün Türkçe etiketi.</summary>
    public static string AuthLabel(string authType) => authType switch
    {
        "api_key" => "API anahtarı",
        "oauth_device_code" => "OAuth (cihaz kodu)",
        "oauth_external" => "OAuth (harici akış)",
        "oauth_minimax" => "OAuth (harici akış)",
        "external_process" => "Harici süreç",
        "aws_sdk" => "AWS kimlik bilgileri",
        "none" => "Kimlik doğrulama yok",
        _ => authType,
    };

    /// <summary>Katalog. Sıra: yaygın kullanılanlar önce.</summary>
    public static IReadOnlyList<ProviderEntry> All { get; } = new List<ProviderEntry>
    {
        new("groq", "Groq", "openai_chat", "api_key",
            new[] { "GROQ_API_KEY" }, "GROQ_BASE_URL",
            DefaultBaseUrl: "https://api.groq.com/openai/v1",
            SignupUrl: "https://console.groq.com/keys"),

        new("anthropic", "Anthropic (Claude)", "anthropic_messages", "api_key",
            new[] { "ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN" },
            "ANTHROPIC_BASE_URL",
            SignupUrl: "https://console.anthropic.com/settings/keys"),

        new("openrouter", "OpenRouter", "openai_chat", "api_key",
            new[] { "OPENROUTER_API_KEY", "OPENAI_API_KEY" }, "OPENROUTER_BASE_URL",
            IsAggregator: true, SignupUrl: "https://openrouter.ai/keys"),

        // CLI kanonik kimliği "gemini" — "google" DEĞİL.
        new("gemini", "Google AI Studio (Gemini)", "openai_chat", "api_key",
            new[] { "GOOGLE_API_KEY", "GEMINI_API_KEY" }, "GEMINI_BASE_URL",
            SignupUrl: "https://aistudio.google.com/apikey"),

        new("google-gemini-cli", "Gemini CLI (Code Assist)", "openai_chat", "oauth_external",
            new string[0], Kind: ProviderKind.CliLogin, CliCommand: "gemini"),

        new("openai-codex", "OpenAI Codex (ChatGPT girişi)", "codex_responses", "oauth_external",
            new string[0], Kind: ProviderKind.CliLogin, CliCommand: "codex"),

        // CLI kanonik kimliği "copilot" — "github-copilot" DEĞİL.
        new("copilot", "GitHub Copilot", "openai_chat", "api_key",
            new[] { "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN" }),

        new("copilot-acp", "GitHub Copilot ACP", "codex_responses", "external_process",
            new string[0], "COPILOT_ACP_BASE_URL", Kind: ProviderKind.CliLogin,
            CliCommand: "copilot"),

        new("xai", "xAI (Grok)", "codex_responses", "api_key",
            new[] { "XAI_API_KEY" }, "XAI_BASE_URL"),

        new("xai-oauth", "xAI (OAuth)", "codex_responses", "oauth_external",
            new string[0], "XAI_BASE_URL", Kind: ProviderKind.OAuthBrowser),

        new("deepseek", "DeepSeek", "openai_chat", "api_key",
            new[] { "DEEPSEEK_API_KEY" }, "DEEPSEEK_BASE_URL"),

        new("zai", "Z.AI / GLM", "openai_chat", "api_key",
            new[] { "GLM_API_KEY", "ZAI_API_KEY", "Z_AI_API_KEY" }, "GLM_BASE_URL"),

        // CLI kanonik kimliği "kimi-coding".
        new("kimi-coding", "Kimi (Moonshot)", "openai_chat", "api_key",
            new[] { "KIMI_API_KEY", "KIMI_CODING_API_KEY" }, "KIMI_BASE_URL"),

        new("kimi-coding-cn", "Kimi (Çin)", "openai_chat", "api_key",
            new[] { "KIMI_CN_API_KEY" }),

        new("minimax", "MiniMax", "anthropic_messages", "api_key",
            new[] { "MINIMAX_API_KEY" }, "MINIMAX_BASE_URL"),

        new("minimax-cn", "MiniMax (Çin)", "anthropic_messages", "api_key",
            new[] { "MINIMAX_CN_API_KEY" }, "MINIMAX_CN_BASE_URL"),

        new("alibaba", "Alibaba DashScope (Qwen)", "openai_chat", "api_key",
            new[] { "DASHSCOPE_API_KEY" }, "DASHSCOPE_BASE_URL"),

        // Alibaba'nın kendi Qwen portalı (portal.qwen.ai) — yerel Qwen CLI
        // oturumunu yeniden kullanır.
        new("qwen-oauth", "Qwen Portal (OAuth)", "openai_chat", "oauth_external",
            new string[0], "FETIH_QWEN_BASE_URL", Kind: ProviderKind.CliLogin,
            CliCommand: "qwen"),

        new("stepfun", "StepFun Step Plan", "openai_chat", "api_key",
            new[] { "STEPFUN_API_KEY" }, "STEPFUN_BASE_URL"),

        new("nvidia", "NVIDIA NIM", "openai_chat", "api_key",
            new[] { "NVIDIA_API_KEY" }, "NVIDIA_BASE_URL"),

        new("bedrock", "AWS Bedrock", "bedrock_converse", "aws_sdk",
            new[] { "AWS_REGION", "AWS_PROFILE" }, Kind: ProviderKind.AwsSdk),

        new("azure-foundry", "Azure AI Foundry", "openai_chat", "api_key",
            new[] { "AZURE_FOUNDRY_API_KEY" }, "AZURE_FOUNDRY_BASE_URL"),

        // Not: bu sağlayıcının resmi adında geçen "gateway" kelimesi FETİH'te
        // mesajlaşma köprüsüne ayrılmıştır (bkz. docs/windows-app-plani.md, (b)),
        // bu yüzden arayüzde model yönlendirici olarak adlandırılır.
        // CLI kanonik kimliği "ai-gateway".
        new("ai-gateway", "Vercel AI (model yönlendirici)", "openai_chat", "api_key",
            new[] { "AI_GATEWAY_API_KEY" }, "AI_GATEWAY_BASE_URL", IsAggregator: true),

        // CLI kanonik kimliği "opencode-zen".
        new("opencode-zen", "OpenCode Zen", "openai_chat", "api_key",
            new[] { "OPENCODE_ZEN_API_KEY" }, "OPENCODE_ZEN_BASE_URL", IsAggregator: true),

        new("opencode-go", "OpenCode Go", "openai_chat", "api_key",
            new[] { "OPENCODE_GO_API_KEY" }, "OPENCODE_GO_BASE_URL", IsAggregator: true),

        // CLI kanonik kimliği "kilocode".
        new("kilocode", "KiloCode", "openai_chat", "api_key",
            new[] { "KILOCODE_API_KEY" }, "KILOCODE_BASE_URL", IsAggregator: true),

        new("huggingface", "Hugging Face", "openai_chat", "api_key",
            new[] { "HF_TOKEN" }, "HF_BASE_URL", IsAggregator: true),

        new("novita", "Novita AI", "openai_chat", "api_key",
            new[] { "NOVITA_API_KEY" }, "NOVITA_BASE_URL", IsAggregator: true),

        new("arcee", "Arcee AI", "openai_chat", "api_key",
            new[] { "ARCEEAI_API_KEY" }, "ARCEE_BASE_URL"),

        new("gmi", "GMI Cloud", "openai_chat", "api_key",
            new[] { "GMI_API_KEY" }, "GMI_BASE_URL"),

        new("xiaomi", "Xiaomi MiMo", "openai_chat", "api_key",
            new[] { "XIAOMI_API_KEY" }, "XIAOMI_BASE_URL"),

        new("tencent-tokenhub", "Tencent TokenHub", "openai_chat", "api_key",
            new[] { "TOKENHUB_API_KEY" }, "TOKENHUB_BASE_URL"),

        // ── Yerel / kendi barındırdığın uçlar ────────────────────────────
        // Hassas hedeflerde veri makineden çıkmasın isteyen kullanıcı için
        // öne çıkarılır (bkz. docs/windows-app-plani.md, (f) bölümü).
        //
        // Bunlar API anahtarı İSTEMEZ: sihirbaz uç noktayı yoklar ve o
        // makinede İNDİRİLMİŞ modelleri listeler.
        new("ollama", "Ollama (yerel)", "openai_chat", "none",
            new string[0], "OLLAMA_BASE_URL", IsLocal: true,
            Kind: ProviderKind.LocalServer,
            DefaultBaseUrl: "http://localhost:11434/v1",
            SignupUrl: "https://ollama.com/download"),

        new("lmstudio", "LM Studio (yerel)", "openai_chat", "api_key",
            new[] { "LM_API_KEY" }, "LM_BASE_URL", IsLocal: true,
            Kind: ProviderKind.LocalServer,
            DefaultBaseUrl: "http://127.0.0.1:1234/v1",
            SignupUrl: "https://lmstudio.ai/"),

        // Ollama Cloud yerel DEĞİL — barındırılan servis, anahtar ister.
        new("ollama-cloud", "Ollama Cloud", "openai_chat", "api_key",
            new[] { "OLLAMA_API_KEY" }, "OLLAMA_BASE_URL",
            SignupUrl: "https://ollama.com/settings/keys"),

        new("custom", "Özel yerel uç (vLLM / llama.cpp)", "openai_chat", "none",
            new string[0], IsLocal: true, Kind: ProviderKind.LocalServer,
            DefaultBaseUrl: "http://localhost:8000/v1"),
    };

    /// <summary>Kimliğe göre katalog kaydını döndürür (yoksa <c>null</c>).</summary>
    public static ProviderEntry? ById(string id)
    {
        foreach (var p in All)
        {
            if (p.Id == id)
            {
                return p;
            }
        }
        return null;
    }
}
