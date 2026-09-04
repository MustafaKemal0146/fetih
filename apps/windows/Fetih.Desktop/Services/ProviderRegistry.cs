using System.Collections.Generic;

namespace Fetih.Desktop.Services;

/// <summary>
/// Bir model sağlayıcısının kimliği. Kaynak: <c>fetih_cli/providers.py</c>
/// içindeki <c>FETIH_OVERLAYS</c> ve <c>_LABEL_OVERRIDES</c> tabloları,
/// artı <c>fetih_cli/config.py</c>'deki <c>OPTIONAL_ENV_VARS</c> anahtar adları.
/// </summary>
public sealed record ProviderEntry(
    string Id,
    string DisplayName,
    string Transport,
    string AuthType,
    IReadOnlyList<string> ApiKeyEnvVars,
    string BaseUrlEnvVar = "",
    bool IsAggregator = false,
    bool IsLocal = false);

/// <summary>
/// FETİH'in gerçekten desteklediği sağlayıcı kataloğu.
/// Python tarafında bu liste models.dev kataloğu + FETİH kaplaması (overlay)
/// birleştirilerek üretilir; Faz 1'de masaüstü uygulaması canlı Python'a
/// bağlanmadığı için kaplama tablosu burada birebir yansıtılır.
/// </summary>
public static class ProviderRegistry
{
    /// <summary>Taşıma katmanının Türkçe etiketi.</summary>
    public static string TransportLabel(string transport) => transport switch
    {
        "openai_chat" => "OpenAI uyumlu sohbet",
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
        "external_process" => "Harici süreç",
        "aws_sdk" => "AWS kimlik bilgileri",
        _ => authType,
    };

    /// <summary>Katalog. Sıra: yaygın kullanılanlar önce.</summary>
    public static IReadOnlyList<ProviderEntry> All { get; } = new List<ProviderEntry>
    {
        new("anthropic", "Anthropic (Claude)", "anthropic_messages", "api_key",
            new[] { "ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN" }),

        new("groq", "Groq", "openai_chat", "api_key",
            new[] { "GROQ_API_KEY" }, "GROQ_BASE_URL"),

        new("openrouter", "OpenRouter", "openai_chat", "api_key",
            new[] { "OPENROUTER_API_KEY", "OPENAI_API_KEY" }, "OPENROUTER_BASE_URL", IsAggregator: true),

        new("google", "Google AI Studio (Gemini)", "openai_chat", "api_key",
            new[] { "GOOGLE_API_KEY", "GEMINI_API_KEY" }, "GEMINI_BASE_URL"),

        new("google-gemini-cli", "Gemini CLI (Code Assist)", "openai_chat", "oauth_external",
            new[] { "FETIH_GEMINI_CLIENT_ID", "FETIH_GEMINI_CLIENT_SECRET" }),

        new("nous", "FETİH Portal", "openai_chat", "oauth_device_code",
            new string[0]),

        new("openai-codex", "OpenAI Codex", "codex_responses", "oauth_external",
            new string[0]),

        new("github-copilot", "GitHub Copilot", "openai_chat", "api_key",
            new[] { "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN" }),

        new("copilot-acp", "GitHub Copilot ACP", "codex_responses", "external_process",
            new string[0], "COPILOT_ACP_BASE_URL"),

        new("xai", "xAI (Grok)", "codex_responses", "api_key",
            new[] { "XAI_API_KEY" }, "XAI_BASE_URL"),

        new("xai-oauth", "xAI (OAuth)", "codex_responses", "oauth_external",
            new string[0], "XAI_BASE_URL"),

        new("deepseek", "DeepSeek", "openai_chat", "api_key",
            new[] { "DEEPSEEK_API_KEY" }, "DEEPSEEK_BASE_URL"),

        new("zai", "Z.AI / GLM", "openai_chat", "api_key",
            new[] { "GLM_API_KEY", "ZAI_API_KEY", "Z_AI_API_KEY" }, "GLM_BASE_URL"),

        new("kimi-for-coding", "Kimi (Moonshot)", "openai_chat", "api_key",
            new[] { "KIMI_API_KEY", "KIMI_CN_API_KEY" }, "KIMI_BASE_URL"),

        new("minimax", "MiniMax", "anthropic_messages", "api_key",
            new[] { "MINIMAX_API_KEY" }, "MINIMAX_BASE_URL"),

        new("minimax-cn", "MiniMax (Çin)", "anthropic_messages", "api_key",
            new[] { "MINIMAX_CN_API_KEY" }, "MINIMAX_CN_BASE_URL"),

        new("alibaba", "Alibaba DashScope (Qwen)", "openai_chat", "api_key",
            new[] { "DASHSCOPE_API_KEY" }, "DASHSCOPE_BASE_URL"),

        new("qwen-oauth", "Qwen Portal (OAuth)", "openai_chat", "oauth_external",
            new string[0], "FETIH_QWEN_BASE_URL"),

        new("stepfun", "StepFun Step Plan", "openai_chat", "api_key",
            new[] { "STEPFUN_API_KEY" }, "STEPFUN_BASE_URL"),

        new("nvidia", "NVIDIA NIM", "openai_chat", "api_key",
            new[] { "NVIDIA_API_KEY" }, "NVIDIA_BASE_URL"),

        new("bedrock", "AWS Bedrock", "bedrock_converse", "aws_sdk",
            new[] { "AWS_REGION", "AWS_PROFILE" }),

        new("azure-foundry", "Azure AI Foundry", "openai_chat", "api_key",
            new[] { "AZURE_FOUNDRY_API_KEY" }, "AZURE_FOUNDRY_BASE_URL"),

        // Not: bu sağlayıcının resmi adında geçen "gateway" kelimesi FETİH'te
        // mesajlaşma köprüsüne ayrılmıştır (bkz. docs/windows-app-plani.md, (b)),
        // bu yüzden arayüzde model yönlendirici olarak adlandırılır.
        new("vercel", "Vercel AI (model yönlendirici)", "openai_chat", "api_key",
            new[] { "VERCEL_OIDC_TOKEN", "VERCEL_TOKEN" }, IsAggregator: true),

        new("opencode", "OpenCode Zen", "openai_chat", "api_key",
            new[] { "OPENCODE_ZEN_API_KEY" }, "OPENCODE_ZEN_BASE_URL", IsAggregator: true),

        new("opencode-go", "OpenCode Go", "openai_chat", "api_key",
            new[] { "OPENCODE_GO_API_KEY" }, "OPENCODE_GO_BASE_URL", IsAggregator: true),

        new("kilo", "KiloCode", "openai_chat", "api_key",
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
        new("lmstudio", "LM Studio (yerel)", "openai_chat", "api_key",
            new[] { "LM_API_KEY" }, "LM_BASE_URL", IsLocal: true),

        new("ollama", "Ollama (yerel)", "openai_chat", "api_key",
            new[] { "OLLAMA_API_KEY" }, "OLLAMA_BASE_URL", IsLocal: true),

        new("ollama-cloud", "Ollama Cloud", "openai_chat", "api_key",
            new[] { "OLLAMA_API_KEY" }, "OLLAMA_BASE_URL"),

        new("local", "Özel yerel uç (vLLM / llama.cpp)", "openai_chat", "api_key",
            new string[0], IsLocal: true),
    };
}
