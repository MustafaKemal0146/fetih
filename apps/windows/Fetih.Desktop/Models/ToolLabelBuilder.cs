using System;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Models;

/// <summary>
/// Araç çağrılarından Claude tarzı canlı etiketler üreten saf (UI'dan bağımsız) yardımcı sınıf.
/// </summary>
public static class ToolLabelBuilder
{
    private static readonly Regex SecretPatterns = new(
        @"(?i)(token|password|passwd|secret|api[_-]?key)\s*([=:])\s*\S+",
        RegexOptions.Compiled);

    private static readonly Regex BearerPattern = new(
        @"(?i)bearer\s+[A-Za-z0-9_\-\.]+",
        RegexOptions.Compiled);

    public static string BuildLabel(string? toolName, string? argumentsJson)
    {
        if (string.IsNullOrWhiteSpace(toolName))
        {
            return Loc.T("Activity_Thinking") ?? "Düşünülüyor…";
        }

        var normalizedName = toolName.Trim().ToLowerInvariant();

        try
        {
            switch (normalizedName)
            {
                case "terminal":
                case "execute_command":
                case "bash":
                case "shell":
                {
                    var cmd = ExtractJsonField(argumentsJson, "command", "cmd");
                    if (string.IsNullOrWhiteSpace(cmd))
                    {
                        return Loc.Format("Activity_Tool_Default", toolName) ?? $"{toolName} çalıştırılıyor";
                    }

                    // İlk satırı al
                    var firstLine = GetFirstLine(cmd);
                    firstLine = MaskSecrets(firstLine);
                    firstLine = ActivityLabelBuilder.TruncateToGraphemes(firstLine, 40);
                    firstLine = ActivityLabelBuilder.TrimTrailingPunctuation(firstLine);

                    return Loc.Format("Activity_Tool_terminal", firstLine) ?? $"Komut çalıştırılıyor: {firstLine}";
                }

                case "read_file":
                case "view_file":
                case "read":
                {
                    var path = ExtractJsonField(argumentsJson, "path", "AbsolutePath", "file_path", "filename");
                    var fileName = GetFileName(path);
                    if (string.IsNullOrWhiteSpace(fileName))
                    {
                        return Loc.Format("Activity_Tool_Default", toolName) ?? $"{toolName} çalıştırılıyor";
                    }

                    fileName = ActivityLabelBuilder.TruncateToGraphemes(fileName, 40);
                    return Loc.Format("Activity_Tool_read_file", fileName) ?? $"{fileName} okunuyor";
                }

                case "write_file":
                case "write_to_file":
                case "write":
                {
                    var path = ExtractJsonField(argumentsJson, "path", "TargetFile", "file_path", "filename");
                    var fileName = GetFileName(path);
                    if (string.IsNullOrWhiteSpace(fileName))
                    {
                        return Loc.Format("Activity_Tool_Default", toolName) ?? $"{toolName} çalıştırılıyor";
                    }

                    fileName = ActivityLabelBuilder.TruncateToGraphemes(fileName, 40);
                    return Loc.Format("Activity_Tool_write_file", fileName) ?? $"{fileName} yazılıyor";
                }

                case "edit_file":
                case "patch":
                case "replace_file_content":
                case "edit":
                {
                    var path = ExtractJsonField(argumentsJson, "path", "TargetFile", "file_path", "filename");
                    var fileName = GetFileName(path);
                    if (string.IsNullOrWhiteSpace(fileName))
                    {
                        return Loc.Format("Activity_Tool_Default", toolName) ?? $"{toolName} çalıştırılıyor";
                    }

                    fileName = ActivityLabelBuilder.TruncateToGraphemes(fileName, 40);
                    return Loc.Format("Activity_Tool_edit_file", fileName) ?? $"{fileName} düzenleniyor";
                }

                case "search_web":
                case "web_search":
                {
                    var query = ExtractJsonField(argumentsJson, "query", "q", "search_term");
                    if (string.IsNullOrWhiteSpace(query))
                    {
                        return Loc.Format("Activity_Tool_Default", toolName) ?? $"{toolName} çalıştırılıyor";
                    }

                    query = MaskSecrets(query);
                    query = ActivityLabelBuilder.TruncateToGraphemes(query, 40);
                    query = ActivityLabelBuilder.TrimTrailingPunctuation(query);
                    return Loc.Format("Activity_Tool_search_web", query) ?? $"Web'de aranıyor: {query}";
                }

                case "read_url_content":
                case "fetch_web_page":
                case "web_fetch":
                {
                    var url = ExtractJsonField(argumentsJson, "url", "Url", "uri");
                    var host = ExtractHost(url);
                    if (string.IsNullOrWhiteSpace(host))
                    {
                        return Loc.Format("Activity_Tool_Default", toolName) ?? $"{toolName} çalıştırılıyor";
                    }

                    host = ActivityLabelBuilder.TruncateToGraphemes(host, 40);
                    return Loc.Format("Activity_Tool_fetch_url", host) ?? $"{host} getiriliyor";
                }

                default:
                    return Loc.Format("Activity_Tool_Default", toolName) ?? $"{toolName} çalıştırılıyor";
            }
        }
        catch
        {
            return Loc.Format("Activity_Tool_Default", toolName) ?? $"{toolName} çalıştırılıyor";
        }
    }

    /// <summary>
    /// Komut ve arama metinlerindeki gizli anahtar/parolaları maskeler.
    /// </summary>
    public static string MaskSecrets(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        // token=..., password: ..., api_key=... kalıpları
        var masked = SecretPatterns.Replace(text, m =>
        {
            var keyGroup = m.Groups[1].Value;
            var sepGroup = m.Groups[2].Value;
            return $"{keyGroup}{sepGroup}***";
        });

        // Bearer token kalıbı
        masked = BearerPattern.Replace(masked, "Bearer ***");

        return masked;
    }

    private static string GetFirstLine(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var idx = text.IndexOfAny(new[] { '\r', '\n' });
        return (idx >= 0 ? text.Substring(0, idx) : text).Trim();
    }

    private static string GetFileName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        var clean = path.Trim().Replace('\\', '/');
        var idx = clean.LastIndexOf('/');
        return idx >= 0 ? clean.Substring(idx + 1) : clean;
    }

    private static string ExtractHost(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return string.Empty;
        if (Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
        {
            return uri.Host;
        }
        var clean = url.Trim();
        if (clean.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) clean = clean.Substring(7);
        else if (clean.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) clean = clean.Substring(8);
        var slash = clean.IndexOfAny(new[] { '/', '?', ':' });
        return slash >= 0 ? clean.Substring(0, slash) : clean;
    }

    private static string? ExtractJsonField(string? json, params string[] fieldNames)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;

            foreach (var fn in fieldNames)
            {
                if (doc.RootElement.TryGetProperty(fn, out var prop))
                {
                    return prop.ValueKind == JsonValueKind.String ? prop.GetString() : prop.ToString();
                }
                // Case-insensitive fallback
                foreach (var p in doc.RootElement.EnumerateObject())
                {
                    if (string.Equals(p.Name, fn, StringComparison.OrdinalIgnoreCase))
                    {
                        return p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.ToString();
                    }
                }
            }
        }
        catch
        {
            // JSON ayrıştırma başarısızsa regex ile dene
            foreach (var fn in fieldNames)
            {
                var match = Regex.Match(json, $@"""{fn}""\s*:\s*""([^""]+)""", RegexOptions.IgnoreCase);
                if (match.Success) return match.Groups[1].Value;
            }
        }

        return null;
    }
}
