using System;
using System.Text.RegularExpressions;

namespace Fetih.Desktop.Services;

/// <summary>Sağlayıcıdan dönen bir hatanın kullanıcıya anlatılabilir türü.</summary>
public enum ProviderErrorKind
{
    /// <summary>Tanınmadı — ham (kısaltılmış) metin gösterilir.</summary>
    Unknown,

    /// <summary>
    /// Anthropic: Claude aboneliği üçüncü taraf uygulamada plan limitinden
    /// değil, ek kullanım (extra usage) bakiyesinden düşer; bakiye yok.
    /// </summary>
    AnthropicExtraUsage,

    /// <summary>Hesabın kotası / hız sınırı dolu (429, RESOURCE_EXHAUSTED).</summary>
    QuotaExhausted,

    /// <summary>Gemini Code Assist (bireysel) Google tarafından kapatıldı.</summary>
    CodeAssistDeprecated,

    /// <summary>Seçilen model sağlayıcıda yok.</summary>
    InvalidModel,

    /// <summary>Kimlik bilgisi reddedildi (geçersiz/süresi dolmuş anahtar ya da oturum).</summary>
    Unauthorized,
}

/// <summary>
/// Sağlayıcı hatalarını tek yerde sınıflandırıp insan diline çevirir.
///
/// <para>Ham hata gövdeleri (çok satırlı JSON, istek kimlikleri, iç içe
/// <c>errors</c> dizileri) sohbet kartına, durum rozetine ve kurulum
/// sihirbazına doğrudan basılıyordu. Kullanıcı bunu okuyup ne yapacağını
/// çıkaramaz. Bu sınıf bilinen durumları tanır ve ne yapılacağını söyleyen
/// tek bir cümle döndürür. Tanınmayan hatalar kısaltılıp tek satıra indirilir
/// (tanı için kaybolmaz).</para>
/// </summary>
public static class ProviderErrorText
{
    /// <summary>Ham hata metnini türüne ayırır. Sıra önemli: en özgül eşleşme önce.</summary>
    public static ProviderErrorKind Classify(string? raw)
    {
        var m = raw ?? "";
        if (m.Length == 0)
        {
            return ProviderErrorKind.Unknown;
        }

        if (Has(m, "draw from your extra usage") ||
            (Has(m, "extra usage") && Has(m, "third-party")))
        {
            return ProviderErrorKind.AnthropicExtraUsage;
        }

        if (Has(m, "no longer supported for Gemini Code Assist") ||
            Has(m, "antigravity.google") ||
            (Has(m, "Code Assist") && Code(m, "403")))
        {
            return ProviderErrorKind.CodeAssistDeprecated;
        }

        if (Code(m, "429") ||
            Has(m, "RESOURCE_EXHAUSTED") ||
            Has(m, "Resource has been exhausted") ||
            Has(m, "rateLimitExceeded") ||
            Has(m, "rate limit") ||
            Has(m, "rate-limit") ||
            Has(m, "too many requests") ||
            Has(m, "quota"))
        {
            return ProviderErrorKind.QuotaExhausted;
        }

        if (Has(m, "model_not_found") ||
            Has(m, "Invalid model") ||
            Has(m, "model not found") ||
            Has(m, "does not exist or you do not have access"))
        {
            return ProviderErrorKind.InvalidModel;
        }

        if (Has(m, "authentication_error") ||
            Has(m, "invalid x-api-key") ||
            Has(m, "invalid_api_key") ||
            Has(m, "Incorrect API key") ||
            Has(m, "HTTP 401") ||
            Has(m, "Error code: 401"))
        {
            return ProviderErrorKind.Unauthorized;
        }

        return ProviderErrorKind.Unknown;
    }

    /// <summary>Bilinen bir durumsa ne yapılacağını söyleyen cümle; değilse <c>null</c>.</summary>
    public static string? Friendly(string? raw) => Classify(raw) switch
    {
        ProviderErrorKind.AnthropicExtraUsage => Loc.T("provider.err.extra_usage"),
        ProviderErrorKind.QuotaExhausted => Loc.T("provider.err.quota"),
        ProviderErrorKind.CodeAssistDeprecated => Loc.T("provider.err.code_assist"),
        ProviderErrorKind.InvalidModel => Loc.T("provider.err.invalid_model"),
        ProviderErrorKind.Unauthorized => Loc.T("provider.err.unauthorized"),
        _ => null,
    };

    /// <summary>Her zaman gösterilebilir metin: bilinen durumsa açıklama, değilse kısaltılmış ham metin.</summary>
    public static string Humanize(string? raw, int max = 220) => Friendly(raw) ?? Shorten(raw, max);

    /// <summary>Çok satırlı/JSON ham metni tek satıra indirip kısaltır.</summary>
    public static string Shorten(string? raw, int max = 220)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "";
        }
        var flat = Regex.Replace(raw, @"\s+", " ").Trim();
        return flat.Length <= max ? flat : flat[..max] + "…";
    }

    private static bool Has(string haystack, string needle)
        => haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// HTTP durum kodunu tek başına bir sayı olarak arar. Ham hatalardaki
    /// istek kimlikleri (<c>req_011Cfq429x…</c>) tesadüfen aynı rakamları
    /// içerebilir; kelime sınırı onları dışarıda bırakır.
    /// </summary>
    private static bool Code(string haystack, string code)
        => Regex.IsMatch(haystack, $@"\b{code}\b");
}
