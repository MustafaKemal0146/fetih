using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Fetih.Desktop.Models;

/// <summary>
/// Düşünce metninden Claude tarzı tek satırlık özet etiket üreten saf (UI'dan bağımsız) yardımcı sınıf.
/// </summary>
public static class ActivityLabelBuilder
{
    private static readonly Regex MarkdownPatterns = new(
        @"(^\s*[-*>]+\s+)|(^\s*\d+\.\s+)|(\*\*|__)|(`+)|(^#+\s*)",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private static readonly Regex MultiWhitespace = new(
        @"\s+",
        RegexOptions.Compiled);

    private static readonly string[] ThoughtLeakPrefixes =
    [
        "the user",
        "user wants",
        "okay",
        "ok,",
        "ok.",
        "let me",
        "let's",
        "lets",
        "i need",
        "i should",
        "i will",
        "i must",
        "i have to",
        "i am going to",
        "i'm going to"
    ];

    private static readonly string[] ThoughtLeakPhrases =
    [
        "the user wants",
        "the user is asking",
        "the user asked",
        "kullan\u0131c\u0131 istiyor",
        "kullan\u0131c\u0131 benden",
        "kullan\u0131c\u0131 bizden",
        "kullan\u0131c\u0131n\u0131n iste\u011Fi",
        "kullan\u0131c\u0131 istedi",
        "kullan\u0131c\u0131 sordu"
    ];

    public static bool IsThoughtLeak(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        var trimmed = text.Trim();
        foreach (var prefix in ThoughtLeakPrefixes)
        {
            if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        foreach (var phrase in ThoughtLeakPhrases)
        {
            if (trimmed.IndexOf(phrase, StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        }
        return false;
    }

    /// <summary>
    /// Verilen düşünce metninden tek satırlık özet üretir.
    /// </summary>
    public static string? BuildLabel(string? thoughtText, CultureInfo? culture = null)
    {
        if (string.IsNullOrWhiteSpace(thoughtText)) return null;

        culture ??= CultureInfo.CurrentCulture;

        // 1. Baştaki/sondaki boşlukları at, Markdown süslerini temizle
        var text = thoughtText.Trim();
        text = MarkdownPatterns.Replace(text, "");

        // 2. İlk cümleyi veya ilk satırı bul (3.14, v1.2, örn., vs., e.g. gibi durumları bölmeden)
        text = ExtractFirstSentence(text);

        // 3. Çoklu boşluk dizilerini tek boşluğa indir
        text = MultiWhitespace.Replace(text, " ").Trim();
        if (string.IsNullOrWhiteSpace(text)) return null;

        // Sızıntı kontrolü
        if (IsThoughtLeak(text)) return null;

        // 4. Cümle sonundaki noktalama işaretlerini ve boşlukları temizle
        text = TrimTrailingPunctuation(text);

        // 5. En fazla 60 görünen karakter (grapheme cluster bazlı) - aşarsa kelime sınırında kesip '…' ekler
        text = TruncateToGraphemes(text, 60);

        if (string.IsNullOrWhiteSpace(text)) return null;

        return text;
    }

    /// <summary>
    /// Metindeki ilk cümleyi ayıklar.
    /// Sonlandırıcılar: '!', '?', '…', ':', '\n', '\r' veya kurala uyan '.'.
    /// Nokta için 'nokta + boşluk + büyük harf/rakam dışı' kuralı uygulanır;
    /// 3.14, v1.2, örn., vs., e.g. gibi durumlar bölünmez.
    /// </summary>
    public static string ExtractFirstSentence(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        // Üç nokta (...) dizilerini tekil '…' ile normalize et
        var normalized = text.Replace("...", "…");
        int cutIndex = -1;

        for (int i = 0; i < normalized.Length; i++)
        {
            char c = normalized[i];

            if (c is '!' or '?' or '…' or ':' or '\r' or '\n')
            {
                cutIndex = i;
                break;
            }

            if (c == '.')
            {
                // Son karakterse sonlandırıcıdır
                if (i == normalized.Length - 1)
                {
                    cutIndex = i;
                    break;
                }

                char next = normalized[i + 1];

                // 3.14 veya v1.2 gibi doğrudan rakam geliyorsa sonlandırıcı değildir
                if (char.IsDigit(next))
                {
                    continue;
                }

                // Boşluk geliyorsa, sonrasındaki harfi kontrol et
                if (char.IsWhiteSpace(next))
                {
                    // Boşluktan sonraki ilk yazdırılabilir karaktere bak
                    int j = i + 1;
                    while (j < normalized.Length && char.IsWhiteSpace(normalized[j]))
                    {
                        j++;
                    }

                    if (j >= normalized.Length)
                    {
                        cutIndex = i;
                        break;
                    }

                    char afterSpace = normalized[j];

                    // "örn. dosya", "e.g. file", "vs. diğer" gibi küçük harfle devam ediyorsa bölme
                    if (char.IsLower(afterSpace))
                    {
                        continue;
                    }

                    // "3.14" gibi rakamla devam eden durumlar
                    if (char.IsDigit(afterSpace))
                    {
                        continue;
                    }

                    // Büyük harfle veya yeni bir sembolle başlıyorsa cümle bitmiştir
                    cutIndex = i;
                    break;
                }
            }
        }

        if (cutIndex >= 0)
        {
            return normalized.Substring(0, cutIndex);
        }

        return normalized;
    }

    /// <summary>
    /// Metni grapheme cluster (görünen karakter) bazlı en fazla maxGraphemes uzunluğunda tutar.
    /// Aşarsa son tam kelimede kesip sonuna '…' ekler.
    /// </summary>
    public static string TruncateToGraphemes(string text, int maxGraphemes)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        var si = new StringInfo(text);
        if (si.LengthInTextElements <= maxGraphemes)
        {
            return text;
        }

        // İlk maxGraphemes karakteri topla
        var sb = new StringBuilder();
        int lastSpaceIndex = -1;

        for (int i = 0; i < maxGraphemes; i++)
        {
            string elem = si.SubstringByTextElements(i, 1);
            if (elem == " ")
            {
                lastSpaceIndex = sb.Length;
            }
            sb.Append(elem);
        }

        string result;
        if (lastSpaceIndex > 0)
        {
            result = sb.ToString(0, lastSpaceIndex);
        }
        else
        {
            result = sb.ToString();
        }

        result = TrimTrailingPunctuation(result);
        if (!result.EndsWith("…"))
        {
            result += "…";
        }

        return result;
    }

    /// <summary>
    /// Metnin sonundaki boşlukları ve '.', ':', ',', ';', '…' noktalama işaretlerini siler.
    /// </summary>
    public static string TrimTrailingPunctuation(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        int len = text.Length;
        while (len > 0)
        {
            char c = text[len - 1];
            if (char.IsWhiteSpace(c) || c is '.' or ':' or ',' or ';' or '…')
            {
                len--;
            }
            else
            {
                break;
            }
        }

        return text.Substring(0, len);
    }
}
