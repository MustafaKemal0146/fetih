using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace Fetih.Desktop.Services;

/// <summary>Bir YAML düğümünün türü.</summary>
public enum YamlKind
{
    Scalar,
    Map,
    List,
}

/// <summary>
/// Girinti tabanlı, bağımlılıksız küçük bir YAML okuyucusunun ürettiği düğüm.
/// FETİH'in <c>~/.fetih/config.yaml</c> dosyası PyYAML'ın <c>safe_dump</c>
/// çıktısıdır (blok stili, akış stili yalnızca boş <c>{}</c> / <c>[]</c> için);
/// bu okuyucu tam bir YAML uygulaması değil, o alt kümeyi güvenle okur.
/// Ayarlar sayfaları salt okunurdur — geri yazma yoktur.
/// </summary>
public sealed class YamlNode
{
    private static readonly Dictionary<string, YamlNode> EmptyMap = new(StringComparer.Ordinal);
    private static readonly List<YamlNode> EmptyList = new();

    private YamlNode(YamlKind kind, string? scalar, Dictionary<string, YamlNode>? map, List<YamlNode>? items)
    {
        Kind = kind;
        Scalar = scalar;
        Map = map ?? EmptyMap;
        Items = items ?? EmptyList;
    }

    public YamlKind Kind { get; }

    /// <summary>Skaler değer (yalnızca <see cref="YamlKind.Scalar"/> için anlamlı).</summary>
    public string? Scalar { get; }

    public Dictionary<string, YamlNode> Map { get; }

    public List<YamlNode> Items { get; }

    public static YamlNode NullScalar { get; } = new(YamlKind.Scalar, null, null, null);

    public static YamlNode FromScalar(string? value) => new(YamlKind.Scalar, value, null, null);

    public static YamlNode FromMap(Dictionary<string, YamlNode> map) => new(YamlKind.Map, null, map, null);

    public static YamlNode FromList(List<YamlNode> items) => new(YamlKind.List, null, null, items);

    /// <summary>Noktalı yol ile alt düğüm getirir; yoksa <c>null</c>.</summary>
    public YamlNode? Get(string dottedPath)
    {
        if (string.IsNullOrEmpty(dottedPath))
        {
            return null;
        }

        var node = this;
        foreach (var part in dottedPath.Split('.'))
        {
            if (node is null || node.Kind != YamlKind.Map || !node.Map.TryGetValue(part, out var next))
            {
                return null;
            }

            node = next;
        }

        return node;
    }

    /// <summary>Noktalı yoldaki skaler değeri metin olarak döndürür.</summary>
    public string? GetString(string dottedPath) => Get(dottedPath)?.Scalar;

    /// <summary>
    /// Noktalı yoldaki değeri kullanıcıya gösterilebilir bir metne çevirir.
    /// Boş/eksik değerler için <paramref name="fallback"/> döner.
    /// </summary>
    public string GetDisplay(string dottedPath, string fallback = "—")
    {
        var node = Get(dottedPath);
        if (node is null)
        {
            return fallback;
        }

        switch (node.Kind)
        {
            case YamlKind.Scalar:
                return string.IsNullOrWhiteSpace(node.Scalar) ? fallback : node.Scalar!;
            case YamlKind.List:
                if (node.Items.Count == 0)
                {
                    return "(boş liste)";
                }

                var parts = new List<string>(node.Items.Count);
                foreach (var item in node.Items)
                {
                    parts.Add(item.Kind == YamlKind.Scalar ? item.Scalar ?? "" : "(…)");
                }

                return string.Join(", ", parts);
            case YamlKind.Map:
                return node.Map.Count == 0 ? "(boş)" : $"({node.Map.Count} alt anahtar)";
            default:
                return fallback;
        }
    }

    /// <summary>Noktalı yoldaki listeyi metin listesi olarak döndürür.</summary>
    public List<string> GetStringList(string dottedPath)
    {
        var result = new List<string>();
        var node = Get(dottedPath);
        if (node?.Kind != YamlKind.List)
        {
            return result;
        }

        foreach (var item in node.Items)
        {
            if (item.Kind == YamlKind.Scalar && item.Scalar is not null)
            {
                result.Add(item.Scalar);
            }
        }

        return result;
    }

    /// <summary>Noktalı yoldaki değeri bool olarak yorumlar.</summary>
    public bool? GetBool(string dottedPath)
    {
        var raw = GetString(dottedPath);
        if (raw is null)
        {
            return null;
        }

        return raw.Trim().ToLowerInvariant() switch
        {
            "true" or "yes" or "on" or "1" => true,
            "false" or "no" or "off" or "0" => false,
            _ => null,
        };
    }

    /// <summary>Noktalı yoldaki değeri tam sayı olarak yorumlar.</summary>
    public int? GetInt(string dottedPath)
    {
        var raw = GetString(dottedPath);
        return int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }
}

/// <summary>
/// Bağımlılıksız, hataya dayanıklı YAML alt kümesi okuyucusu.
/// Hiçbir koşulda istisna fırlatmaz; ayrıştırılamayan girdi için boş bir
/// eşleme döner (çağıran sayfa "okunamadı" mesajı gösterir).
/// </summary>
public static class YamlLite
{
    private const int MaxDepth = 32;

    /// <summary>Dosyayı okuyup ayrıştırır. Dosya yoksa/okunamıyorsa boş eşleme döner.</summary>
    public static YamlNode LoadFile(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return YamlNode.FromMap(new Dictionary<string, YamlNode>(StringComparer.Ordinal));
            }

            return Parse(File.ReadAllText(path));
        }
        catch
        {
            return YamlNode.FromMap(new Dictionary<string, YamlNode>(StringComparer.Ordinal));
        }
    }

    /// <summary>Metni ayrıştırır.</summary>
    public static YamlNode Parse(string text)
    {
        try
        {
            var lines = Tokenize(text);
            var index = 0;
            var node = ParseBlock(lines, ref index, lines.Count > 0 ? lines[0].Indent : 0, 0);
            return node.Kind == YamlKind.Map || node.Kind == YamlKind.List
                ? node
                : YamlNode.FromMap(new Dictionary<string, YamlNode>(StringComparer.Ordinal));
        }
        catch
        {
            return YamlNode.FromMap(new Dictionary<string, YamlNode>(StringComparer.Ordinal));
        }
    }

    private readonly record struct Line(int Indent, string Content);

    private static List<Line> Tokenize(string text)
    {
        var result = new List<Line>();
        foreach (var raw in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            var indent = 0;
            while (indent < raw.Length && raw[indent] == ' ')
            {
                indent++;
            }

            var content = raw[indent..].TrimEnd();
            if (content.Length == 0 || content[0] == '#' || content == "---" || content == "...")
            {
                continue;
            }

            result.Add(new Line(indent, content));
        }

        return result;
    }

    private static YamlNode ParseBlock(List<Line> lines, ref int index, int indent, int depth)
    {
        if (depth > MaxDepth || index >= lines.Count)
        {
            return YamlNode.NullScalar;
        }

        return lines[index].Content.StartsWith('-')
            ? ParseList(lines, ref index, indent, depth)
            : ParseMap(lines, ref index, indent, depth);
    }

    private static YamlNode ParseMap(List<Line> lines, ref int index, int indent, int depth)
    {
        var map = new Dictionary<string, YamlNode>(StringComparer.Ordinal);

        while (index < lines.Count)
        {
            var line = lines[index];
            if (line.Indent < indent)
            {
                break;
            }

            if (line.Indent > indent)
            {
                // Beklenmeyen fazla girinti: sarkan bloğu atla (bozuk dosyada takılmamak için).
                index++;
                continue;
            }

            if (line.Content.StartsWith('-'))
            {
                break;
            }

            if (!SplitKey(line.Content, out var key, out var inlineValue))
            {
                index++;
                continue;
            }

            index++;

            if (!string.IsNullOrEmpty(inlineValue))
            {
                map[key] = ParseInlineValue(inlineValue!);
                continue;
            }

            // Değer bir sonraki satırlarda: daha derin girinti ya da aynı girintide "- " dizisi.
            if (index < lines.Count &&
                (lines[index].Indent > indent ||
                 (lines[index].Indent == indent && lines[index].Content.StartsWith('-'))))
            {
                map[key] = ParseBlock(lines, ref index, lines[index].Indent, depth + 1);
            }
            else
            {
                map[key] = YamlNode.NullScalar;
            }
        }

        return YamlNode.FromMap(map);
    }

    private static YamlNode ParseList(List<Line> lines, ref int index, int indent, int depth)
    {
        var items = new List<YamlNode>();

        while (index < lines.Count)
        {
            var line = lines[index];
            if (line.Indent != indent || !line.Content.StartsWith('-'))
            {
                break;
            }

            var body = line.Content.Length > 1 ? line.Content[1..].TrimStart() : string.Empty;
            index++;

            if (body.Length == 0)
            {
                items.Add(index < lines.Count && lines[index].Indent > indent
                    ? ParseBlock(lines, ref index, lines[index].Indent, depth + 1)
                    : YamlNode.NullScalar);
                continue;
            }

            if (SplitKey(body, out var key, out var inlineValue))
            {
                // Satır içi eşleme öğesi: "- key: value" ve devamındaki daha derin satırlar.
                var map = new Dictionary<string, YamlNode>(StringComparer.Ordinal)
                {
                    [key] = string.IsNullOrEmpty(inlineValue)
                        ? YamlNode.NullScalar
                        : ParseInlineValue(inlineValue!),
                };

                if (index < lines.Count && lines[index].Indent > indent)
                {
                    var nested = ParseBlock(lines, ref index, lines[index].Indent, depth + 1);
                    if (nested.Kind == YamlKind.Map)
                    {
                        foreach (var pair in nested.Map)
                        {
                            map[pair.Key] = pair.Value;
                        }
                    }
                }

                items.Add(YamlNode.FromMap(map));
                continue;
            }

            items.Add(ParseInlineValue(body));
        }

        return YamlNode.FromList(items);
    }

    /// <summary>
    /// "key: value" / "key:" ayrıştırması. Değerin içindeki iki nokta
    /// (ör. <c>url: https://…</c>, <c>docker_image: repo:tag</c>) korunur:
    /// yalnızca "iki nokta + boşluk" ya da satır sonundaki iki nokta ayırıcıdır.
    /// </summary>
    private static bool SplitKey(string content, out string key, out string? value)
    {
        key = string.Empty;
        value = null;

        if (content.Length == 0 || content[0] is '{' or '[')
        {
            return false;
        }

        var inSingle = false;
        var inDouble = false;

        for (var i = 0; i < content.Length; i++)
        {
            var c = content[i];
            if (c == '\'' && !inDouble)
            {
                inSingle = !inSingle;
            }
            else if (c == '"' && !inSingle)
            {
                inDouble = !inDouble;
            }
            else if (c == ':' && !inSingle && !inDouble)
            {
                if (i == content.Length - 1)
                {
                    key = Unquote(content[..i].Trim());
                    value = null;
                    return key.Length > 0;
                }

                if (content[i + 1] == ' ')
                {
                    key = Unquote(content[..i].Trim());
                    value = content[(i + 2)..].Trim();
                    return key.Length > 0;
                }
            }
        }

        return false;
    }

    private static YamlNode ParseInlineValue(string raw)
    {
        var value = StripTrailingComment(raw);

        if (value == "{}")
        {
            return YamlNode.FromMap(new Dictionary<string, YamlNode>(StringComparer.Ordinal));
        }

        if (value == "[]")
        {
            return YamlNode.FromList(new List<YamlNode>());
        }

        if (value.Length > 1 && value[0] == '[' && value[^1] == ']')
        {
            var items = new List<YamlNode>();
            foreach (var part in value[1..^1].Split(','))
            {
                var trimmed = part.Trim();
                if (trimmed.Length > 0)
                {
                    items.Add(YamlNode.FromScalar(Unquote(trimmed)));
                }
            }

            return YamlNode.FromList(items);
        }

        if (value is "null" or "~" or "")
        {
            return YamlNode.NullScalar;
        }

        // Blok skaler göstergeleri (">", "|"): devam satırları burada okunmaz,
        // gösterim için göstergenin kendisini saklamak yanıltıcı olur.
        if (value is ">" or "|" or ">-" or "|-")
        {
            return YamlNode.NullScalar;
        }

        return YamlNode.FromScalar(Unquote(value));
    }

    private static string StripTrailingComment(string value)
    {
        if (value.Length == 0 || value[0] is '\'' or '"')
        {
            return value;
        }

        var idx = value.IndexOf(" #", StringComparison.Ordinal);
        return idx >= 0 ? value[..idx].TrimEnd() : value;
    }

    private static string Unquote(string value)
    {
        if (value.Length >= 2 &&
            ((value[0] == '\'' && value[^1] == '\'') || (value[0] == '"' && value[^1] == '"')))
        {
            return value[1..^1];
        }

        return value;
    }
}
