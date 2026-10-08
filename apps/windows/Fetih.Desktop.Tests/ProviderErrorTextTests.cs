using Fetih.Desktop.Services;
using Xunit;

namespace Fetih.Desktop.Tests;

/// <summary>
/// Ham sağlayıcı hatalarının sınıflandırılması. Örnek metinler kullanıcının
/// kurulum/sohbet ekranlarında gerçekten gördüğü gövdelerden alındı.
/// </summary>
public class ProviderErrorTextTests
{
    private const string AnthropicExtraUsage =
        "Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', " +
        "'message': 'Third-party apps now draw from your extra usage, not your plan limits. " +
        "Add more at claude.ai/settings/usage and keep going.'}, 'request_id': 'req_011CfqGK1hy1Tz9vWoAqrig'}";

    private const string GeminiQuota =
        "Code Assist HTTP 429: {\n  \"error\": {\n    \"code\": 429,\n" +
        "    \"message\": \"Resource has been exhausted (e.g. check quota).\",\n" +
        "    \"errors\": [ { \"domain\": \"global\", \"reason\": \"rateLimitExceeded\" } ],\n" +
        "    \"status\": \"RESOURCE_EXHAUSTED\"\n  }\n}";

    private const string CodeAssistDeprecated =
        "Code Assist HTTP 403: { \"error\": { \"code\": 403, \"message\": \"This client is no longer " +
        "supported for Gemini Code Assist for individuals. To continue using Gemini, please migrate " +
        "to the Antigravity suite of products: https://antigravity.google\" } }";

    [Fact]
    public void AnthropicThirdPartyBilling_IsExtraUsage()
        => Assert.Equal(ProviderErrorKind.AnthropicExtraUsage, ProviderErrorText.Classify(AnthropicExtraUsage));

    [Fact]
    public void GeminiResourceExhausted_IsQuota()
        => Assert.Equal(ProviderErrorKind.QuotaExhausted, ProviderErrorText.Classify(GeminiQuota));

    [Fact]
    public void CodeAssistShutdown_IsDeprecated_NotQuota()
        => Assert.Equal(ProviderErrorKind.CodeAssistDeprecated, ProviderErrorText.Classify(CodeAssistDeprecated));

    [Fact]
    public void InvalidModel_IsRecognised()
        => Assert.Equal(ProviderErrorKind.InvalidModel,
            ProviderErrorText.Classify("HTTP 400: Error code: 400 - Invalid model specified."));

    [Fact]
    public void ApiKeyRejected_IsUnauthorized()
        => Assert.Equal(ProviderErrorKind.Unauthorized,
            ProviderErrorText.Classify("Error code: 401 - {'type': 'error', 'error': {'type': 'authentication_error', 'message': 'invalid x-api-key'}}"));

    [Fact]
    public void RequestIdContainingStatusDigits_IsNotMisclassified()
    {
        // İstek kimliği tesadüfen "429" içeriyor; bu bir kota hatası değil.
        const string raw = "Error code: 500 - {'type': 'error', 'error': {'type': 'api_error', " +
                           "'message': 'Internal server error'}, 'request_id': 'req_011Cfq429xYz'}";
        Assert.Equal(ProviderErrorKind.Unknown, ProviderErrorText.Classify(raw));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("something unexpected happened")]
    public void UnknownOrEmpty_HasNoFriendlyText(string? raw)
        => Assert.Null(ProviderErrorText.Friendly(raw));

    [Fact]
    public void KnownError_FriendlyTextHidesRawJson()
    {
        var text = ProviderErrorText.Friendly(GeminiQuota);
        Assert.False(string.IsNullOrWhiteSpace(text));
        Assert.DoesNotContain("{", text);
        Assert.DoesNotContain("RESOURCE_EXHAUSTED", text);
    }

    [Fact]
    public void Humanize_UnknownError_IsSingleLineAndCapped()
    {
        var raw = "line one\n\n   line two\t\tthree " + new string('x', 500);
        var text = ProviderErrorText.Humanize(raw, max: 40);
        Assert.DoesNotContain("\n", text);
        Assert.DoesNotContain("\t", text);
        Assert.StartsWith("line one line two three", text);
        Assert.True(text.Length <= 41); // 40 + "…"
    }
}
