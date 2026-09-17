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
    string CliCommand = "",
    string DisplayNameKey = "")
{
    /// <summary>
    /// Arayüzde gösterilecek ad. <see cref="DisplayName"/> her zaman kanonik
    /// (marka) addır — katalogdaki adların çoğu çevrilmez. Yalnızca Türkçe/
    /// İngilizce ayrımı olan adlar <see cref="DisplayNameKey"/> taşır ve
    /// kullanıcıya dönük her yer bu özelliği okur, böylece dil değişince
    /// liste kendiliğinden güncellenir.
    /// </summary>
    public string Label => DisplayNameKey.Length > 0 ? Loc.T(DisplayNameKey) : DisplayName;
}

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
    /// <summary>Taşıma katmanının etiketi (etkin dile göre).</summary>
    public static string TransportLabel(string transport) => transport switch
    {
        "openai_chat" => Loc.T("provider.transport.openai_chat"),
        "chat_completions" => Loc.T("provider.transport.openai_chat"),
        "anthropic_messages" => "Anthropic Messages",
        "codex_responses" => "Codex Responses",
        "bedrock_converse" => "Bedrock Converse",
        _ => transport,
    };

    /// <summary>Kimlik doğrulama türünün etiketi (etkin dile göre).</summary>
    public static string AuthLabel(string authType) => authType switch
    {
        "api_key" => Loc.T("provider.auth.api_key"),
        "oauth_device_code" => Loc.T("provider.auth.oauth_device_code"),
        "oauth_external" => Loc.T("provider.auth.oauth_external"),
        "oauth_minimax" => Loc.T("provider.auth.oauth_external"),
        "external_process" => Loc.T("provider.auth.external_process"),
        "aws_sdk" => Loc.T("provider.auth.aws_sdk"),
        "none" => Loc.T("provider.auth.none"),
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

        new("openai-codex", "OpenAI Codex", "codex_responses", "oauth_external",
            new string[0], Kind: ProviderKind.CliLogin, CliCommand: "codex", DisplayNameKey: "provider.name.codex"),

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

        new("openai", "OpenAI", "openai_chat", "api_key",
            new[] { "OPENAI_API_KEY" }, "OPENAI_BASE_URL",
            DefaultBaseUrl: "https://api.openai.com/v1",
            SignupUrl: "https://platform.openai.com/api-keys"),

        new("deepseek", "DeepSeek", "openai_chat", "api_key",
            new[] { "DEEPSEEK_API_KEY" }, "DEEPSEEK_BASE_URL",
            DefaultBaseUrl: "https://api.deepseek.com/v1",
            SignupUrl: "https://platform.deepseek.com/api_keys"),

        new("zai", "Z.AI / GLM", "openai_chat", "api_key",
            new[] { "GLM_API_KEY", "ZAI_API_KEY", "Z_AI_API_KEY" }, "GLM_BASE_URL"),

        // CLI kanonik kimliği "kimi-coding".
        new("kimi-coding", "Kimi (Moonshot)", "openai_chat", "api_key",
            new[] { "KIMI_API_KEY", "KIMI_CODING_API_KEY" }, "KIMI_BASE_URL"),

        new("kimi-coding-cn", "Kimi CN", "openai_chat", "api_key",
            new[] { "KIMI_CN_API_KEY" }, DisplayNameKey: "provider.name.kimi_cn"),

        new("minimax", "MiniMax", "anthropic_messages", "api_key",
            new[] { "MINIMAX_API_KEY" }, "MINIMAX_BASE_URL"),

        new("minimax-cn", "MiniMax CN", "anthropic_messages", "api_key",
            new[] { "MINIMAX_CN_API_KEY" }, "MINIMAX_CN_BASE_URL",
            DisplayNameKey: "provider.name.minimax_cn"),

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
        new("ai-gateway", "Vercel AI", "openai_chat", "api_key",
            new[] { "AI_GATEWAY_API_KEY" }, "AI_GATEWAY_BASE_URL", IsAggregator: true,
            DisplayNameKey: "provider.name.ai_gateway"),

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
        new("ollama", "Ollama", "openai_chat", "none",
            new string[0], "OLLAMA_BASE_URL", IsLocal: true,
            Kind: ProviderKind.LocalServer,
            DefaultBaseUrl: "http://localhost:11434/v1",
            SignupUrl: "https://ollama.com/download",
            DisplayNameKey: "provider.name.ollama"),

        new("lmstudio", "LM Studio", "openai_chat", "api_key",
            new[] { "LM_API_KEY" }, "LM_BASE_URL", IsLocal: true,
            Kind: ProviderKind.LocalServer,
            DefaultBaseUrl: "http://127.0.0.1:1234/v1",
            SignupUrl: "https://lmstudio.ai/",
            DisplayNameKey: "provider.name.lmstudio"),

        // Ollama Cloud yerel DEĞİL — barındırılan servis, anahtar ister.
        new("ollama-cloud", "Ollama Cloud", "openai_chat", "api_key",
            new[] { "OLLAMA_API_KEY" }, "OLLAMA_BASE_URL",
            SignupUrl: "https://ollama.com/settings/keys"),

        new("custom", "Custom Local Endpoint", "openai_chat", "none",
            new string[0], IsLocal: true, Kind: ProviderKind.LocalServer,
            DefaultBaseUrl: "http://localhost:8000/v1",
            DisplayNameKey: "provider.name.custom"),
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

    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> CuratedModelsMap =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["deepseek"] = new[]
            {
                "deepseek-chat",
                "deepseek-reasoner",
                "deepseek-v4-pro",
                "deepseek-v4-flash",
            },
            ["groq"] = new[]
            {
                "openai/gpt-oss-120b",
                "openai/gpt-oss-20b",
                "qwen/qwen3.8-27b",
                "qwen/qwen3.6-27b",
            },
            ["openai"] = new[]
            {
                "gpt-5.4",
                "gpt-5.4-mini",
                "gpt-5-mini",
                "gpt-5.3-codex",
                "gpt-5.2-codex",
                "gpt-4.1",
                "gpt-4o",
                "gpt-4o-mini",
            },
            ["openai-codex"] = new[]
            {
                "gpt-5.4",
                "gpt-5.4-mini",
                "gpt-5.3-codex",
                "gpt-5.2-codex",
            },
            ["anthropic"] = new[]
            {
                "claude-opus-4-7",
                "claude-opus-4-6",
                "claude-sonnet-4-6",
                "claude-opus-4-5-20251101",
                "claude-sonnet-4-5-20250929",
                "claude-haiku-4-5-20251001",
            },
            ["gemini"] = new[]
            {
                "gemini-3.1-pro-preview",
                "gemini-3-pro-preview",
                "gemini-3-flash-preview",
                "gemini-3.1-flash-lite-preview",
            },
            ["google-gemini-cli"] = new[]
            {
                "gemini-3.1-pro-preview",
                "gemini-3-pro-preview",
                "gemini-3-flash-preview",
            },
            ["openrouter"] = new[]
            {
                "anthropic/claude-opus-4.7",
                "anthropic/claude-sonnet-4.6",
                "moonshotai/kimi-k2.6",
                "deepseek/deepseek-v4-pro",
                "openai/gpt-5.4",
                "google/gemini-3-flash-preview",
            },
            ["copilot"] = new[]
            {
                "gpt-5.4",
                "gpt-5.4-mini",
                "claude-sonnet-4.6",
                "gemini-3.1-pro-preview",
            },
            ["copilot-acp"] = new[]
            {
                "copilot-acp",
            },
            ["xai"] = new[]
            {
                "grok-4.3",
                "grok-4.20-0309-reasoning",
                "grok-4.20-0309-non-reasoning",
                "grok-4.20-multi-agent-0309",
            },
            ["xai-oauth"] = new[]
            {
                "grok-4.3",
                "grok-4.20-0309-reasoning",
                "grok-4.20-0309-non-reasoning",
            },
            ["zai"] = new[]
            {
                "glm-5.1",
                "glm-5",
                "glm-5v-turbo",
                "glm-5-turbo",
                "glm-4.7",
                "glm-4.5",
                "glm-4.5-flash",
            },
            ["kimi-coding"] = new[]
            {
                "kimi-k2.6",
                "kimi-k2.5",
                "kimi-for-coding",
                "kimi-k2-thinking",
                "kimi-k2-turbo-preview",
            },
            ["kimi-coding-cn"] = new[]
            {
                "kimi-k2.6",
                "kimi-k2.5",
                "kimi-k2-thinking",
            },
            ["minimax"] = new[]
            {
                "MiniMax-M2.7",
                "MiniMax-M2.5",
                "MiniMax-M2.1",
                "MiniMax-M2",
            },
            ["minimax-cn"] = new[]
            {
                "MiniMax-M2.7",
                "MiniMax-M2.5",
                "MiniMax-M2.1",
            },
            ["alibaba"] = new[]
            {
                "qwen3.6-plus",
                "kimi-k2.5",
                "qwen3.5-plus",
                "qwen3-coder-plus",
                "glm-5",
            },
            ["qwen-oauth"] = new[]
            {
                "qwen3.6-plus",
                "qwen3.5-plus",
                "qwen3-coder-plus",
            },
            ["nvidia"] = new[]
            {
                "nvidia/nemotron-3-super-120b-a12b",
                "nvidia/nemotron-3-nano-30b-a3b",
                "qwen/qwen3.5-397b-a17b",
                "deepseek-ai/deepseek-v3.2",
            },
            ["ollama"] = new[]
            {
                "llama3.3",
                "qwen2.5-coder",
                "deepseek-r1",
                "mistral",
                "phi4",
            },
            ["lmstudio"] = new[]
            {
                "local-model",
            },
            ["custom"] = new[]
            {
                "default",
            },
            ["ai-gateway"] = new[]
            {
                "moonshotai/kimi-k2.6",
                "alibaba/qwen3.6-plus",
                "zai/glm-5.1",
                "anthropic/claude-sonnet-4.6",
                "openai/gpt-5.4",
            },
            ["opencode-zen"] = new[]
            {
                "kimi-k2.5",
                "gpt-5.4-pro",
                "gpt-5.4",
                "claude-sonnet-4.6",
                "gemini-3.1-pro",
            },
            ["opencode-go"] = new[]
            {
                "kimi-k2.6",
                "kimi-k2.5",
                "glm-5.1",
                "qwen3.6-plus",
            },
            ["kilocode"] = new[]
            {
                "anthropic/claude-sonnet-4.6",
                "openai/gpt-5.4",
                "google/gemini-3-flash-preview",
            },
            ["huggingface"] = new[]
            {
                "moonshotai/Kimi-K2.5",
                "Qwen/Qwen3.5-397B-A17B",
                "deepseek-ai/DeepSeek-V3.2",
            },
            ["novita"] = new[]
            {
                "moonshotai/kimi-k2.5",
                "minimax/minimax-m2.7",
                "deepseek/deepseek-v3-0324",
                "deepseek/deepseek-r1-0528",
            },
            ["bedrock"] = new[]
            {
                "us.anthropic.claude-sonnet-4-6",
                "us.anthropic.claude-opus-4-6-v1",
                "deepseek.v3.2",
            },
            ["stepfun"] = new[]
            {
                "step-3.5-flash",
                "step-3.5-flash-2603",
            },
        };

    /// <summary>
    /// Bir sağlayıcının çevrimdışı / statik model listesini döndürür.
    /// Köprü çevrimdışıyken veya canlı sorgu yanıt vermediğinde bu liste sunulur.
    /// </summary>
    public static IReadOnlyList<string> GetCuratedModels(string providerId)
    {
        if (string.IsNullOrWhiteSpace(providerId))
        {
            return Array.Empty<string>();
        }

        if (CuratedModelsMap.TryGetValue(providerId.Trim(), out var models))
        {
            return models;
        }

        return Array.Empty<string>();
    }
}
