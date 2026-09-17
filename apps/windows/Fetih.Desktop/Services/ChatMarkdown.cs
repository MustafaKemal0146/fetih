using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;

namespace Fetih.Desktop.Services;

// ─────────────────────────────────────────────────────────────────────────────
//  Sohbet yanıtları için bağımlılıksız markdown katmanı.
//
//  Bu dosya iki parçadan oluşur:
//    1) ChatMarkdown        — satır tabanlı, bağımlılıksız ayrıştırıcı
//    2) ChatMarkdownView    — ayrıştırılan blokları WinUI öğelerine çeviren
//                             kapsayıcı denetim
//
//  GÜVENLİK İLKESİ — "inşa gereği etkisiz" (inert by construction):
//    · Bağlantılar TIKLANABİLİR DEĞİLDİR. Hiperlink üretilmez; adres yalnızca
//      düz metin olarak yazılır. `Hyperlink` türü bu dosyada hiç kullanılmaz.
//    · Görsel YÜKLENMEZ. `![alt](kaynak)` yalnızca alt metne indirgenir; ağa
//      çıkan hiçbir yol yoktur.
//    · HTML etiketleri yorumlanmaz. Metin her zaman `Run`/`Span` içine düz
//      metin olarak konur; hiçbir yerde ayrıştırıcıya verilmez, komut olarak
//      çalıştırılmaz.
//    · Dışarıdan gelen metin asla kod olarak yürütülmez; yalnızca çizilir.
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>Ayrıştırılmış markdown bloğunun türü.</summary>
public enum MdBlockKind
{
    /// <summary>Düz paragraf (satır sonları korunur).</summary>
    Paragraph,

    /// <summary>Başlık (#, ##, ###).</summary>
    Heading,

    /// <summary>Kod bloğu (üç ters tırnak).</summary>
    Code,

    /// <summary>Madde işaretli liste öğesi.</summary>
    Bullet,

    /// <summary>Numaralı liste öğesi.</summary>
    Numbered,

    /// <summary>Alıntı (&gt;).</summary>
    Quote,

    /// <summary>Yatay çizgi (---).</summary>
    Rule,

    /// <summary>Basit tablo (| ile).</summary>
    Table,
}

/// <summary>
/// Ayrıştırılmış tek bir markdown bloğu. Aynı blok listesinin art arda gelen
/// sürümlerini karşılaştırıp yalnızca değişen kuyruğu yeniden çizebilmek için
/// <see cref="Signature"/> ile ucuz bir içerik imzası sunar.
/// </summary>
public sealed class MdBlock
{
    private string? _signature;

    /// <summary>Bloğun türü.</summary>
    public MdBlockKind Kind { get; init; }

    /// <summary>Paragraf/başlık/alıntı metni veya liste öğesi gövdesi.</summary>
    public string Text { get; set; } = string.Empty;

    /// <summary>Başlık seviyesi ya da numaralı liste öğesinin numarası.</summary>
    public int Level { get; set; }

    /// <summary>Liste öğesinin iç girintisi (iç içe listeler).</summary>
    public int Indent { get; set; }

    /// <summary>Kod çitinin dil etiketi (opsiyonel).</summary>
    public string Language { get; set; } = string.Empty;

    /// <summary>Kod bloğunun satırları.</summary>
    public List<string> Lines { get; } = new();

    /// <summary>Tablo başlık hücreleri.</summary>
    public List<string> Header { get; } = new();

    /// <summary>Tablo gövde satırları.</summary>
    public List<List<string>> Rows { get; } = new();

    /// <summary>Alıntının içindeki bloklar.</summary>
    public List<MdBlock> Children { get; } = new();

    /// <summary>
    /// Bloğun içeriğini temsil eden kararlı imza. İki blok aynı imzaya sahipse
    /// çizilmiş hâlleri de aynıdır; böylece akış sırasında yalnızca değişen
    /// kuyruk yeniden kurulur.
    /// </summary>
    public string Signature => _signature ??= ComputeSignature();

    private string ComputeSignature()
    {
        var sb = new StringBuilder(96);
        sb.Append((int)Kind).Append('')
          .Append(Level).Append('')
          .Append(Indent).Append('')
          .Append(Language).Append('')
          .Append(Text);

        foreach (var line in Lines)
        {
            sb.Append('').Append(line);
        }

        foreach (var head in Header)
        {
            sb.Append('').Append(head);
        }

        foreach (var row in Rows)
        {
            foreach (var cell in row)
            {
                sb.Append('').Append(cell);
            }
            sb.Append('');
        }

        foreach (var child in Children)
        {
            sb.Append('').Append(child.Signature);
        }

        return sb.ToString();
    }
}

/// <summary>
/// Satır içi bir parçanın türü. Bilinçli olarak SINIRLI tutulur: burada
/// "bağlantı" diye tıklanabilir bir tür YOKTUR, yalnızca <see cref="LinkText"/>
/// ve <see cref="LinkUrl"/> vardır — ikisi de düz metin olarak çizilir.
/// </summary>
public enum MdRunKind
{
    /// <summary>Düz metin.</summary>
    Text,

    /// <summary>Kalın vurgu; içeriği <see cref="MdRun.Children"/> içindedir.</summary>
    Bold,

    /// <summary>Eğik vurgu; içeriği <see cref="MdRun.Children"/> içindedir.</summary>
    Italic,

    /// <summary>Satır içi kod (eş aralıklı yazı tipi).</summary>
    Code,

    /// <summary>Bağlantının görünen metni.</summary>
    LinkText,

    /// <summary>Bağlantının adresi — yalnızca metin; gezinme üretilmez.</summary>
    LinkUrl,

    /// <summary>Görselin alt metni — kaynak yüklenmez.</summary>
    ImageAlt,
}

/// <summary>
/// Ayrıştırılmış satır içi bir parça. Vurgular iç içe olabildiği için ağaç
/// biçimindedir; çizici yalnızca bu tipleri WinUI satır içi öğelerine çevirir.
/// </summary>
public sealed class MdRun
{
    /// <summary>Parçanın türü.</summary>
    public MdRunKind Kind { get; init; }

    /// <summary>Metin taşıyan türler için içerik.</summary>
    public string Text { get; init; } = string.Empty;

    /// <summary>Kalın/eğik vurguların iç parçaları.</summary>
    public List<MdRun> Children { get; } = new();
}

/// <summary>
/// Bağımlılıksız markdown ayrıştırıcısı. Desteklenen öğeler: başlıklar, kalın
/// ve eğik satır içi biçim, satır içi kod, kod blokları, madde işaretli ve
/// numaralı listeler, alıntılar, yatay çizgi ve basit tablolar.
///
/// <para>Akış (streaming) sırasında yarım gelen yapılar makul biçimde kapatılır:
/// kapanmamış bir kod çiti dosyanın sonunda biter, kapanmamış bir vurgu düz
/// metin olarak kalır, eksik tablo ayırıcısı satırı paragraf olarak çizilir.
/// Ayrıştırıcı hiçbir durumda dış girdiyi yürütmez.</para>
/// </summary>
public static class ChatMarkdown
{
    /// <summary>Metni blok listesine çevirir. Boş girdi boş liste döner.</summary>
    public static List<MdBlock> Parse(string? text)
    {
        var blocks = new List<MdBlock>();
        if (string.IsNullOrEmpty(text))
        {
            return blocks;
        }

        var lines = text!.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        var i = 0;

        while (i < lines.Length)
        {
            var line = lines[i];

            // ── Kod çiti ────────────────────────────────────────────────────
            if (TryFenceOpen(line, out var markerChar, out var markerLen, out var language))
            {
                var block = new MdBlock { Kind = MdBlockKind.Code, Language = language };
                i++;
                while (i < lines.Length)
                {
                    if (IsFenceClose(lines[i], markerChar, markerLen))
                    {
                        i++;
                        break;
                    }
                    block.Lines.Add(lines[i]);
                    i++;
                }
                blocks.Add(block);
                continue;
            }

            // ── Yatay çizgi (başlık ayırıcısından ÖNCE bakılır) ─────────────
            if (IsRule(line))
            {
                blocks.Add(new MdBlock { Kind = MdBlockKind.Rule });
                i++;
                continue;
            }

            // ── Başlık ──────────────────────────────────────────────────────
            if (TryHeading(line, out var level, out var headingText))
            {
                blocks.Add(new MdBlock { Kind = MdBlockKind.Heading, Level = level, Text = headingText });
                i++;
                continue;
            }

            // ── Alıntı ──────────────────────────────────────────────────────
            if (TryQuote(line, out var quoted))
            {
                var inner = new StringBuilder();
                while (i < lines.Length && TryQuote(lines[i], out var part))
                {
                    inner.Append(part).Append('\n');
                    i++;
                }
                var quote = new MdBlock { Kind = MdBlockKind.Quote };
                quote.Children.AddRange(Parse(inner.ToString()));
                blocks.Add(quote);
                continue;
            }

            // ── Tablo ───────────────────────────────────────────────────────
            if (LooksLikeTableStart(lines, i))
            {
                var table = new MdBlock { Kind = MdBlockKind.Table };
                table.Header.AddRange(SplitRow(lines[i]));
                i += 2;
                while (i < lines.Length && lines[i].Trim().Length > 0 && lines[i].Contains('|'))
                {
                    table.Rows.Add(SplitRow(lines[i]));
                    i++;
                }
                blocks.Add(table);
                continue;
            }

            // ── Madde işaretli liste ────────────────────────────────────────
            if (TryBullet(line, out var bulletIndent, out var bulletText))
            {
                blocks.Add(new MdBlock
                {
                    Kind = MdBlockKind.Bullet,
                    Indent = bulletIndent,
                    Text = bulletText,
                });
                i++;
                continue;
            }

            // ── Numaralı liste ──────────────────────────────────────────────
            if (TryNumbered(line, out var numberIndent, out var number, out var numberText))
            {
                blocks.Add(new MdBlock
                {
                    Kind = MdBlockKind.Numbered,
                    Indent = numberIndent,
                    Level = number,
                    Text = numberText,
                });
                i++;
                continue;
            }

            // ── Paragraf ────────────────────────────────────────────────────
            var paragraph = new StringBuilder();
            while (i < lines.Length &&
                   lines[i].Trim().Length > 0 &&
                   !IsBlockStart(lines[i]))
            {
                if (paragraph.Length > 0)
                {
                    paragraph.Append('\n');
                }
                paragraph.Append(lines[i].TrimEnd());
                i++;
            }

            if (paragraph.Length > 0)
            {
                blocks.Add(new MdBlock { Kind = MdBlockKind.Paragraph, Text = paragraph.ToString() });
            }
            else
            {
                // Güvenlik: hiçbir dal ilerlemediyse sonsuz döngüye düşme.
                i++;
            }
        }

        return blocks;
    }

    // ── Satır içi ayrıştırma ────────────────────────────────────────────────

    /// <summary>
    /// Bir satırın satır içi biçimini çözer. Dönen ağaç yalnızca metin, vurgu,
    /// satır içi kod, bağlantı metni/adresi ve görsel alt metni içerir;
    /// tıklanabilir ya da yüklenebilir hiçbir öğe üretilmez.
    /// </summary>
    public static List<MdRun> ParseInline(string? text)
    {
        var runs = new List<MdRun>();
        if (!string.IsNullOrEmpty(text))
        {
            ScanInline(text!, 0, runs);
        }
        return runs;
    }

    private static void ScanInline(string source, int depth, List<MdRun> target)
    {
        // Aşırı iç içe vurgu, çizim derinliğini sınırlı tutmak için düz metne iner.
        if (depth > 4)
        {
            AddText(target, source);
            return;
        }

        var buffer = new StringBuilder(source.Length);

        void Flush()
        {
            if (buffer.Length > 0)
            {
                AddText(target, buffer.ToString());
                buffer.Clear();
            }
        }

        var i = 0;
        while (i < source.Length)
        {
            var c = source[i];

            // Kaçış: bir sonraki karakter düz metindir.
            if (c == '\\' && i + 1 < source.Length && IsEscapable(source[i + 1]))
            {
                buffer.Append(source[i + 1]);
                i += 2;
                continue;
            }

            // Görsel: kaynak YÜKLENMEZ; yalnızca alt metin gösterilir. Adres
            // hiçbir yere yazılmaz, dolayısıyla yüklenebilecek bir yol kalmaz.
            if (c == '!' && i + 1 < source.Length && source[i + 1] == '[')
            {
                if (TryReadLink(source, i + 1, out var alt, out _, out var imageEnd))
                {
                    Flush();
                    target.Add(new MdRun { Kind = MdRunKind.ImageAlt, Text = alt });
                    i = imageEnd;
                    continue;
                }
            }

            // Bağlantı: yalnızca metin ve adres; tıklanabilir öğe üretilmez.
            if (c == '[')
            {
                if (TryReadLink(source, i, out var label, out var url, out var linkEnd))
                {
                    Flush();
                    target.Add(new MdRun
                    {
                        Kind = MdRunKind.LinkText,
                        Text = label.Length > 0 ? label : url,
                    });
                    if (url.Length > 0 && !string.Equals(url, label, StringComparison.Ordinal))
                    {
                        target.Add(new MdRun { Kind = MdRunKind.LinkUrl, Text = " <" + url + ">" });
                    }
                    i = linkEnd;
                    continue;
                }
            }

            // Satır içi kod.
            if (c == '`')
            {
                var close = source.IndexOf('`', i + 1);
                if (close > i + 1)
                {
                    Flush();
                    target.Add(new MdRun
                    {
                        Kind = MdRunKind.Code,
                        Text = source.Substring(i + 1, close - i - 1).Trim(),
                    });
                    i = close + 1;
                    continue;
                }
            }

            // Kalın ve eğik vurgu.
            if (c == '*' || c == '_')
            {
                var doubled = i + 1 < source.Length && source[i + 1] == c;
                if (doubled)
                {
                    var close = source.IndexOf(new string(c, 2), i + 2, StringComparison.Ordinal);
                    if (close > i + 2 &&
                        !char.IsWhiteSpace(source[i + 2]) &&
                        !char.IsWhiteSpace(source[close - 1]))
                    {
                        Flush();
                        var bold = new MdRun { Kind = MdRunKind.Bold };
                        ScanInline(source.Substring(i + 2, close - i - 2), depth + 1, bold.Children);
                        target.Add(bold);
                        i = close + 2;
                        continue;
                    }
                }
                else if (!(c == '_' && i > 0 && (char.IsLetterOrDigit(source[i - 1]) || source[i - 1] == '_')))
                {
                    // snake_case korunur: kelime içindeki alt çizgi eğik yapmaz.
                    var close = source.IndexOf(c, i + 1);
                    if (close > i + 1 &&
                        !char.IsWhiteSpace(source[i + 1]) &&
                        !char.IsWhiteSpace(source[close - 1]))
                    {
                        Flush();
                        var italic = new MdRun { Kind = MdRunKind.Italic };
                        ScanInline(source.Substring(i + 1, close - i - 1), depth + 1, italic.Children);
                        target.Add(italic);
                        i = close + 1;
                        continue;
                    }
                }
            }

            buffer.Append(c);
            i++;
        }

        Flush();
    }

    private static void AddText(List<MdRun> target, string text)
    {
        if (text.Length > 0)
        {
            target.Add(new MdRun { Kind = MdRunKind.Text, Text = text });
        }
    }

    private static bool IsEscapable(char c)
        => c is '*' or '_' or '`' or '[' or ']' or '(' or ')' or '!' or '#' or '>' or '\\' or '|' or '-' or '+';

    /// <summary>
    /// <c>[metin](adres)</c> kalıbını okur. Adres hiçbir zaman gezinme amacıyla
    /// kullanılmaz; yalnızca metin olarak gösterilir.
    /// </summary>
    private static bool TryReadLink(string source, int open, out string text, out string url, out int end)
    {
        text = string.Empty;
        url = string.Empty;
        end = open;

        if (open >= source.Length || source[open] != '[')
        {
            return false;
        }

        var close = source.IndexOf(']', open + 1);
        if (close < 0 || close + 1 >= source.Length || source[close + 1] != '(')
        {
            return false;
        }

        // Adres içindeki dengeli parantezler adresin parçası sayılır
        // (ör. .../wiki/Foo_(bar)); kapanmamışsa kalıp geçersizdir ve düz
        // metin olarak kalır — akış sırasında yarım gelen bağlantı bozulmaz.
        var depth = 1;
        var p = close + 2;
        while (p < source.Length)
        {
            var ch = source[p];
            if (ch == '(')
            {
                depth++;
            }
            else if (ch == ')')
            {
                depth--;
                if (depth == 0)
                {
                    break;
                }
            }
            p++;
        }

        if (p >= source.Length || depth != 0)
        {
            return false;
        }

        text = source.Substring(open + 1, close - open - 1);
        url = source.Substring(close + 2, p - close - 2).Trim();
        end = p + 1;
        return true;
    }

    // ── Satır sınıflandırma ─────────────────────────────────────────────────

    private static bool IsBlockStart(string line)
        => TryFenceOpen(line, out _, out _, out _)
           || IsRule(line)
           || TryHeading(line, out _, out _)
           || TryQuote(line, out _)
           || TryBullet(line, out _, out _)
           || TryNumbered(line, out _, out _, out _);

    private static int LeadingSpaces(string line)
    {
        var n = 0;
        while (n < line.Length && (line[n] == ' ' || line[n] == '\t'))
        {
            n++;
        }
        return n;
    }

    private static bool TryFenceOpen(string line, out char markerChar, out int markerLen, out string language)
    {
        markerChar = '\0';
        markerLen = 0;
        language = string.Empty;

        var start = LeadingSpaces(line);
        if (start >= 4 || start >= line.Length)
        {
            return false;
        }

        var c = line[start];
        if (c != '`' && c != '~')
        {
            return false;
        }

        var n = 0;
        while (start + n < line.Length && line[start + n] == c)
        {
            n++;
        }
        if (n < 3)
        {
            return false;
        }

        markerChar = c;
        markerLen = n;
        language = line[(start + n)..].Trim();
        var space = language.IndexOf(' ');
        if (space > 0)
        {
            language = language[..space];
        }
        // Dil etiketi yalnızca kısa bir simge olur; uzun serbest metin çizilmez.
        if (language.Length > 24)
        {
            language = language[..24];
        }
        return true;
    }

    private static bool IsFenceClose(string line, char markerChar, int minLen)
    {
        var t = line.Trim();
        if (t.Length < minLen)
        {
            return false;
        }
        foreach (var ch in t)
        {
            if (ch != markerChar)
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsRule(string line)
    {
        var start = LeadingSpaces(line);
        if (start >= 4 || start >= line.Length)
        {
            return false;
        }

        var c = '\0';
        var count = 0;
        for (var i = start; i < line.Length; i++)
        {
            var ch = line[i];
            if (ch == ' ' || ch == '\t')
            {
                continue;
            }
            if (c == '\0')
            {
                if (ch != '-' && ch != '*' && ch != '_')
                {
                    return false;
                }
                c = ch;
            }
            else if (ch != c)
            {
                return false;
            }
            count++;
        }

        return c != '\0' && count >= 3;
    }

    private static bool TryHeading(string line, out int level, out string content)
    {
        level = 0;
        content = string.Empty;

        var start = LeadingSpaces(line);
        if (start >= 4)
        {
            return false;
        }

        var h = start;
        while (h < line.Length && line[h] == '#')
        {
            h++;
        }
        var count = h - start;
        if (count is < 1 or > 6)
        {
            return false;
        }
        if (h < line.Length && line[h] != ' ' && line[h] != '\t')
        {
            return false;
        }

        content = line[h..].Trim().TrimEnd('#').TrimEnd();
        level = Math.Min(count, 3);
        return true;
    }

    private static bool TryQuote(string line, out string inner)
    {
        inner = string.Empty;
        var start = LeadingSpaces(line);
        if (start >= 4 || start >= line.Length || line[start] != '>')
        {
            return false;
        }

        var rest = line[(start + 1)..];
        if (rest.StartsWith(' '))
        {
            rest = rest[1..];
        }
        inner = rest;
        return true;
    }

    private static bool TryBullet(string line, out int indent, out string content)
    {
        indent = 0;
        content = string.Empty;

        var start = LeadingSpaces(line);
        if (start >= line.Length)
        {
            return false;
        }

        var c = line[start];
        if (c != '-' && c != '*' && c != '+')
        {
            return false;
        }
        if (start + 1 >= line.Length || line[start + 1] != ' ')
        {
            return false;
        }

        indent = start / 2;
        content = line[(start + 2)..].Trim();
        return true;
    }

    private static bool TryNumbered(string line, out int indent, out int number, out string content)
    {
        indent = 0;
        number = 0;
        content = string.Empty;

        var start = LeadingSpaces(line);
        var d = start;
        while (d < line.Length && char.IsAsciiDigit(line[d]))
        {
            d++;
        }
        if (d == start || d - start > 9)
        {
            return false;
        }
        if (d >= line.Length || (line[d] != '.' && line[d] != ')'))
        {
            return false;
        }
        if (d + 1 >= line.Length || line[d + 1] != ' ')
        {
            return false;
        }

        if (!int.TryParse(line.AsSpan(start, d - start), out number))
        {
            return false;
        }

        indent = start / 2;
        content = line[(d + 2)..].Trim();
        return true;
    }

    private static bool LooksLikeTableStart(string[] lines, int index)
    {
        if (index + 1 >= lines.Length)
        {
            return false;
        }

        var head = lines[index];
        if (!head.Contains('|'))
        {
            return false;
        }

        var separator = lines[index + 1].Trim();
        if (!separator.Contains('|') || !separator.Contains('-'))
        {
            return false;
        }

        // Ayırıcı satır yalnızca | - : ve boşluk içerebilir.
        foreach (var ch in separator)
        {
            if (ch != '|' && ch != '-' && ch != ':' && ch != ' ' && ch != '\t')
            {
                return false;
            }
        }

        return true;
    }

    private static List<string> SplitRow(string line)
    {
        var t = line.Trim();
        if (t.StartsWith('|'))
        {
            t = t[1..];
        }
        if (t.EndsWith('|'))
        {
            t = t[..^1];
        }

        var parts = t.Split('|');
        var cells = new List<string>(parts.Length);
        foreach (var part in parts)
        {
            cells.Add(part.Trim());
        }
        return cells;
    }
}

/// <summary>
/// Tema fırçalarını anahtarla çözer. Denetim ağacı elle kurulduğu için
/// <c>{ThemeResource}</c> işaretlemesi kullanılamaz; anahtar çözümü uygulama
/// kaynak sözlüğünden yapılır ve tema değişiminde ağaç yeniden kurulur.
/// </summary>
internal static class MdTheme
{
    private static readonly SolidColorBrush Fallback = new(Microsoft.UI.Colors.Transparent);

    /// <summary>Anahtarı fırçaya çevirir; bulunamazsa şeffaf döner.</summary>
    public static Brush Brush(string key) => BrushOrNull(key) ?? Fallback;

    /// <summary>
    /// Anahtarı fırçaya çevirir; kaynak bulunamazsa <c>null</c> döner. Gövde
    /// metni gibi görünür kalması gereken yerler bunu kullanıp kendi yedek
    /// rengine düşer; şeffaf fırça metni görünmez bırakırdı.
    /// </summary>
    public static Brush? BrushOrNull(string key)
    {
        try
        {
            if (Application.Current?.Resources is { } resources &&
                resources.TryGetValue(key, out var value) &&
                value is Brush brush)
            {
                return brush;
            }
        }
        catch
        {
            // Çağıran kendi yedek rengine düşer.
        }

        return null;
    }
}

/// <summary>
/// Bir <see cref="MdBlock"/> listesini WinUI öğelerine çeviren ve akış
/// sırasında yalnızca değişen kuyruğu yeniden kuran kapsayıcı denetim.
///
/// <para><b>Akış uyumu:</b> her delta için ağacın tamamı kurulmaz. Yeni blok
/// listesi öncekiyle karşılaştırılır, ortak ön ek korunur ve yalnızca değişen
/// bloklar yeniden çizilir. Bir kod bloğu yalnızca büyüyorsa metni yerinde
/// güncellenir; böylece kopyala düğmesi ve kaydırma konumu korunur, titreme
/// olmaz. Çizim ayrıca ~40 ms'lik bir pencerede birleştirilir; uzun yanıtlarda
/// UI iş parçacığı kilitlenmez.</para>
/// </summary>
public sealed class ChatMarkdownView : Grid
{
    /// <summary>İki çizim arasındaki en küçük süre (ms) — akış birleştirme.</summary>
    private const int MinRenderIntervalMs = 40;

    /// <summary>Vurgu ve kod için kullanılan eş aralıklı yazı tipi.</summary>
    private static readonly FontFamily MonoFont = new("Consolas");

    private readonly StackPanel _root;
    private readonly List<MdBlock> _blocks = new();
    private readonly List<FrameworkElement> _elements = new();
    private readonly DispatcherQueueTimer _throttle;
    private readonly HashSet<DispatcherQueueTimer> _liveTimers = new();

    private string _rendered = string.Empty;
    private bool _hasRendered;
    private bool _forceRebuild;
    private long _lastRenderTicks;

    public ChatMarkdownView()
    {
        _root = new StackPanel { Spacing = 4, HorizontalAlignment = HorizontalAlignment.Stretch };
        Children.Add(_root);

        HorizontalAlignment = HorizontalAlignment.Stretch;

        _throttle = DispatcherQueue.CreateTimer();
        _throttle.Interval = TimeSpan.FromMilliseconds(MinRenderIntervalMs);
        _throttle.IsRepeating = false;
        _throttle.Tick += (_, _) =>
        {
            _throttle.Stop();
            RenderNow();
        };

        ActualThemeChanged += (_, _) => RebuildAll();

        Unloaded += (_, _) => _throttle.Stop();
    }

    // ── Bağımlılık özellikleri ──────────────────────────────────────────────

    /// <summary>Çizilecek markdown metni.</summary>
    public static readonly DependencyProperty MarkdownProperty = DependencyProperty.Register(
        nameof(Markdown),
        typeof(string),
        typeof(ChatMarkdownView),
        new PropertyMetadata(string.Empty, OnMarkdownChanged));

    /// <summary>Gövde metni fırçası. Verilmezse tema varsayılanı kullanılır.</summary>
    public static readonly DependencyProperty TextBrushProperty = DependencyProperty.Register(
        nameof(TextBrush),
        typeof(Brush),
        typeof(ChatMarkdownView),
        new PropertyMetadata(null, OnTextBrushChanged));

    /// <summary>Çizilecek markdown metni.</summary>
    public string Markdown
    {
        get => GetValue(MarkdownProperty) as string ?? string.Empty;
        set => SetValue(MarkdownProperty, value ?? string.Empty);
    }

    /// <summary>Gövde metni fırçası (balon rengine uyum için).</summary>
    public Brush? TextBrush
    {
        get => GetValue(TextBrushProperty) as Brush;
        set => SetValue(TextBrushProperty, value);
    }

    private static void OnMarkdownChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ChatMarkdownView view)
        {
            view.ScheduleRender();
        }
    }

    private static void OnTextBrushChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ChatMarkdownView view)
        {
            // Balon rengi değiştiyse gövde metni de yeniden boyanmalı.
            view.RebuildAll();
        }
    }

    // ── Çizim akışı ─────────────────────────────────────────────────────────

    /// <summary>
    /// Ağacın tamamını yeniden kurar.
    ///
    /// <para>Tema ya da balon fırçası değiştiğinde metin aynı kaldığı için blok
    /// imzaları da aynı kalır; artımlı yol bu durumda hiçbir şeyi yeniden
    /// çizmez ve eski renkler ekranda kalır. Renklerin tazelenmesi ancak
    /// kurulumun zorlanmasıyla olur.</para>
    /// </summary>
    private void RebuildAll()
    {
        _forceRebuild = true;
        _hasRendered = false;
        _rendered = string.Empty;
        RenderNow();
    }

    private void ScheduleRender()
    {
        var text = Markdown;
        if (_hasRendered && string.Equals(text, _rendered, StringComparison.Ordinal))
        {
            return;
        }

        if (!_hasRendered || Environment.TickCount64 - _lastRenderTicks >= MinRenderIntervalMs)
        {
            RenderNow();
        }
        else if (!_throttle.IsRunning)
        {
            // Aynı pencereye düşen deltalar tek çizimde birleşir.
            _throttle.Start();
        }
    }

    private void RenderNow()
    {
        _lastRenderTicks = Environment.TickCount64;
        var source = Markdown;
        if (_hasRendered && string.Equals(source, _rendered, StringComparison.Ordinal))
        {
            return;
        }

        _rendered = source;
        _hasRendered = true;

        try
        {
            BuildTree(source);
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatMarkdownView.Render", ex, ex.Message);
        }
    }

    private void BuildTree(string source)
    {
        var blocks = ChatMarkdown.Parse(source);

        var force = _forceRebuild;
        _forceRebuild = false;

        var prefix = 0;
        if (!force)
        {
            while (prefix < _blocks.Count &&
                   prefix < blocks.Count &&
                   string.Equals(_blocks[prefix].Signature, blocks[prefix].Signature, StringComparison.Ordinal))
            {
                prefix++;
            }
        }

        // Hızlı yol: yalnızca son blok değişti ve ikisi de aynı dildeki kod
        // bloğu ise metni yerinde güncelle — kaydırma ve kopyala düğmesi korunur.
        if (!force &&
            prefix == _blocks.Count - 1 &&
            prefix == blocks.Count - 1 &&
            _elements.Count == _blocks.Count &&
            _blocks[prefix].Kind == MdBlockKind.Code &&
            blocks[prefix].Kind == MdBlockKind.Code &&
            string.Equals(_blocks[prefix].Language, blocks[prefix].Language, StringComparison.Ordinal))
        {
            if (_elements[prefix].Tag is TextBlock code)
            {
                code.Text = string.Join('\n', blocks[prefix].Lines);
                _blocks.Clear();
                _blocks.AddRange(blocks);
                return;
            }
        }

        var textBrush = TextBrush ?? MdTheme.Brush("TextFillColorPrimaryBrush");

        // İkincil renk çözülemezse gövde rengine düşülür: alıntı, bağlantı
        // adresi ve tablo gövdesi görünmez kalmasın.
        var mutedBrush = MdTheme.BrushOrNull("TextFillColorSecondaryBrush") ?? textBrush;

        for (var i = _elements.Count - 1; i >= prefix; i--)
        {
            _root.Children.Remove(_elements[i]);
            _elements.RemoveAt(i);
        }

        for (var i = prefix; i < blocks.Count; i++)
        {
            var element = BuildBlock(blocks[i], textBrush, mutedBrush, 0);
            _elements.Add(element);
            _root.Children.Add(element);
        }

        _blocks.Clear();
        _blocks.AddRange(blocks);
    }

    // ── Blok çizimi ─────────────────────────────────────────────────────────

    private FrameworkElement BuildBlock(MdBlock block, Brush text, Brush muted, int depth)
    {
        switch (block.Kind)
        {
            case MdBlockKind.Heading:
                return BuildHeading(block, text);

            case MdBlockKind.Code:
                return BuildCodeBlock(block, text, muted);

            case MdBlockKind.Bullet:
                return BuildListItem(block, text, muted, numbered: false);

            case MdBlockKind.Numbered:
                return BuildListItem(block, text, muted, numbered: true);

            case MdBlockKind.Rule:
                return BuildRule();

            case MdBlockKind.Quote:
                return BuildQuote(block, muted, depth);

            case MdBlockKind.Table:
                return BuildTable(block, text, muted);

            default:
                return BuildParagraph(block, text);
        }
    }

    private FrameworkElement BuildParagraph(MdBlock block, Brush text)
    {
        var paragraph = new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
            Foreground = text,
        };
        AppendRuns(paragraph.Inlines, ChatMarkdown.ParseInline(block.Text), null);
        return paragraph;
    }

    private FrameworkElement BuildHeading(MdBlock block, Brush text)
    {
        var heading = new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
            Foreground = text,
            FontWeight = FontWeights.SemiBold,
            FontSize = block.Level switch { 1 => 19, 2 => 16.5, _ => 14.5 },
            Margin = new Thickness(0, 6, 0, 0),
        };
        AppendRuns(heading.Inlines, ChatMarkdown.ParseInline(block.Text), null);
        return heading;
    }

    private FrameworkElement BuildRule()
    {
        return new Border
        {
            Height = 1,
            Margin = new Thickness(0, 6, 0, 6),
            Background = MdTheme.Brush("CardStrokeColorDefaultBrush"),
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
    }

    private FrameworkElement BuildQuote(MdBlock block, Brush muted, int depth)
    {
        var inner = new StackPanel { Spacing = 4 };
        foreach (var child in block.Children)
        {
            inner.Children.Add(BuildBlock(child, muted, muted, depth + 1));
        }

        // Çok derin iç içe alıntıda yeni çerçeve çizilmez; içerik korunur.
        if (depth >= 3)
        {
            return inner;
        }

        return new Border
        {
            Margin = new Thickness(0, 2, 0, 2),
            Padding = new Thickness(12, 2, 0, 2),
            BorderThickness = new Thickness(3, 0, 0, 0),
            BorderBrush = MdTheme.Brush("AccentFillColorDefaultBrush"),
            Child = inner,
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
    }

    private FrameworkElement BuildListItem(MdBlock block, Brush text, Brush muted, bool numbered)
    {
        var row = new Grid { Margin = new Thickness(2 + (block.Indent * 16), 0, 0, 0) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var marker = new TextBlock
        {
            Text = numbered ? block.Level + "." : "•",
            FontSize = 13,
            Foreground = muted,
            Margin = new Thickness(0, 0, 8, 0),
            MinWidth = numbered ? 20 : 0,
            TextAlignment = numbered ? TextAlignment.Right : TextAlignment.Left,
            VerticalAlignment = VerticalAlignment.Top,
        };
        Grid.SetColumn(marker, 0);
        row.Children.Add(marker);

        var body = new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
            Foreground = text,
        };
        AppendRuns(body.Inlines, ChatMarkdown.ParseInline(block.Text), muted);
        Grid.SetColumn(body, 1);
        row.Children.Add(body);

        return row;
    }

    private FrameworkElement BuildTable(MdBlock block, Brush text, Brush muted)
    {
        var columns = Math.Max(1, block.Header.Count);
        var grid = new Grid { Margin = new Thickness(0, 2, 0, 4) };

        for (var c = 0; c < columns; c++)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        }
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        for (var r = 0; r < block.Rows.Count; r++)
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        }

        AddTableCells(grid, block.Header, 0, columns, isHeader: true, text, muted);
        for (var r = 0; r < block.Rows.Count; r++)
        {
            AddTableCells(grid, block.Rows[r], r + 1, columns, isHeader: false, text, muted);
        }

        return grid;
    }

    private void AddTableCells(
        Grid grid,
        List<string> cells,
        int rowIndex,
        int columns,
        bool isHeader,
        Brush text,
        Brush muted)
    {
        for (var c = 0; c < columns; c++)
        {
            var content = c < cells.Count ? cells[c] : string.Empty;
            var cell = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true,
                Foreground = isHeader ? text : muted,
                FontWeight = isHeader ? FontWeights.SemiBold : FontWeights.Normal,
            };
            if (!isHeader)
            {
                AppendRuns(cell.Inlines, ChatMarkdown.ParseInline(content), muted);
            }
            else
            {
                cell.Text = content;
            }

            var holder = new Border
            {
                Padding = new Thickness(8, 4, 8, 4),
                BorderThickness = new Thickness(0, 0, 0, 1),
                BorderBrush = MdTheme.Brush("CardStrokeColorDefaultBrush"),
                Child = cell,
            };
            Grid.SetRow(holder, rowIndex);
            Grid.SetColumn(holder, c);
            grid.Children.Add(holder);
        }
    }

    // ── Kod bloğu ───────────────────────────────────────────────────────────

    private FrameworkElement BuildCodeBlock(MdBlock block, Brush text, Brush muted)
    {
        var code = new TextBlock
        {
            Text = string.Join('\n', block.Lines),
            FontFamily = MonoFont,
            FontSize = 12.5,
            TextWrapping = TextWrapping.NoWrap,
            IsTextSelectionEnabled = true,
            Foreground = text,
            Margin = new Thickness(12, 2, 12, 10),
        };

        // Yatay kaydırma: uzun satırlar kırpılmaz, kaydırılır.
        var scroller = new ScrollViewer
        {
            Content = code,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollMode = ScrollMode.Enabled,
            VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
            VerticalScrollMode = ScrollMode.Disabled,
        };

        var header = new Grid { Padding = new Thickness(12, 6, 6, 0) };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var language = new TextBlock
        {
            Text = block.Language,
            FontSize = 11,
            Foreground = muted,
            Opacity = 0.75,
            TextTrimming = TextTrimming.CharacterEllipsis,
            VerticalAlignment = VerticalAlignment.Center,
        };
        Grid.SetColumn(language, 0);
        header.Children.Add(language);

        var copy = new Button
        {
            Content = CopyLabel,
            FontSize = 11,
            MinHeight = 0,
            MinWidth = 84,
            Padding = new Thickness(10, 3, 10, 3),
            VerticalAlignment = VerticalAlignment.Center,
        };
        copy.Click += (_, _) => CopyCode(code.Text, copy);
        Grid.SetColumn(copy, 1);
        header.Children.Add(copy);

        var layout = new Grid();
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        Grid.SetRow(header, 0);
        layout.Children.Add(header);
        Grid.SetRow(scroller, 1);
        layout.Children.Add(scroller);

        var border = new Border
        {
            Margin = new Thickness(0, 4, 0, 4),
            Background = MdTheme.Brush("CardBackgroundFillColorSecondaryBrush"),
            BorderBrush = MdTheme.Brush("CardStrokeColorDefaultBrush"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Child = layout,
        };

        // Hızlı yol için kod metni düğümü taşınır.
        border.Tag = code;
        return border;
    }

    private void CopyCode(string code, Button button)
    {
        try
        {
            var package = new DataPackage();
            package.SetText(code ?? string.Empty);
            Clipboard.SetContent(package);
            button.Content = CopiedLabel;
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatMarkdownView.CopyCode", ex, ex.Message);
            return;
        }

        // Kısa süreli onay: düğme eski etiketine döner.
        var timer = DispatcherQueue.CreateTimer();
        timer.Interval = TimeSpan.FromMilliseconds(1600);
        timer.IsRepeating = false;
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            _liveTimers.Remove(timer);
            try
            {
                button.Content = CopyLabel;
            }
            catch (Exception ex)
            {
                App.LogCrash("ChatMarkdownView.CopyReset", ex, ex.Message);
            }
        };
        _liveTimers.Add(timer);
        timer.Start();
    }

    private static string CopyLabel
        => Loc.T("chat.md.copy");

    private static string CopiedLabel
        => Loc.T("chat.md.copied");

    // ── Satır içi çizim ─────────────────────────────────────────────────────

    /// <summary>
    /// Ayrıştırılmış satır içi parçaları WinUI satır içi öğelerine çevirir.
    ///
    /// <para>GÜVENLİK: burada üretilebilecek tek öğe türleri <see cref="Run"/>,
    /// <see cref="Bold"/> ve <see cref="Italic"/>'tir. Hiperlink üretilmez,
    /// görsel yüklenmez, HTML yorumlanmaz; tüm metin düz karakter olarak
    /// yerleştirilir.</para>
    /// </summary>
    private void AppendRuns(InlineCollection target, List<MdRun> runs, Brush? muted)
    {
        foreach (var run in runs)
        {
            switch (run.Kind)
            {
                case MdRunKind.Bold:
                {
                    var bold = new Bold();
                    AppendRuns(bold.Inlines, run.Children, muted);
                    target.Add(bold);
                    break;
                }

                case MdRunKind.Italic:
                {
                    var italic = new Italic();
                    AppendRuns(italic.Inlines, run.Children, muted);
                    target.Add(italic);
                    break;
                }

                case MdRunKind.Code:
                    target.Add(new Run
                    {
                        Text = run.Text,
                        FontFamily = MonoFont,
                        Foreground = MdTheme.Brush("AccentTextFillColorPrimaryBrush"),
                    });
                    break;

                case MdRunKind.LinkText:
                    target.Add(new Run { Text = run.Text });
                    break;

                case MdRunKind.LinkUrl:
                    target.Add(new Run { Text = run.Text, Foreground = muted });
                    break;

                case MdRunKind.ImageAlt:
                {
                    var image = new Italic();
                    image.Inlines.Add(new Run { Text = run.Text, Foreground = muted });
                    target.Add(image);
                    break;
                }

                default:
                    target.Add(new Run { Text = run.Text });
                    break;
            }
        }
    }
}
