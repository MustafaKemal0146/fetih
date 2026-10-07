using System;
using System.Text;
using System.Text.Json;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Views;

public static class ToolFormatter
{
    public static (string Title, string Input) FormatInput(string toolName, string? rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
        {
            return (toolName, "");
        }

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return (toolName, rawJson);
            }

            switch (toolName)
            {
                case "terminal":
                case "execute_command":
                {
                    var cmd = Str(root, "command", "cmd");
                    if (cmd != null)
                    {
                        return ("Terminal", "$ " + cmd);
                    }
                    break;
                }
                case "write_file":
                case "write_to_file":
                {
                    var path = Str(root, "path", "file_path", "target_file");
                    var content = Str(root, "content", "code_content");
                    if (path != null)
                    {
                        return (Loc.Format("tool.format.write_file", path), content ?? "");
                    }
                    break;
                }
                case "read_file":
                case "view_file":
                {
                    var path = Str(root, "path", "file_path", "target_file");
                    if (path != null)
                    {
                        return (Loc.Format("tool.format.read_file", path), "");
                    }
                    break;
                }
            }

            // Genel nesne gösterimi
            var sb = new StringBuilder();
            foreach (var p in root.EnumerateObject())
            {
                var v = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.GetRawText();
                if (v != null && v.Contains('\n'))
                {
                    sb.AppendLine($"{p.Name}:").AppendLine(v);
                }
                else
                {
                    sb.AppendLine($"{p.Name}: {v}");
                }
            }
            return (toolName, sb.ToString().TrimEnd());
        }
        catch (JsonException)
        {
            return (toolName, rawJson);
        }
    }

    public static (ToolStatus Status, string Output) FormatResult(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return (ToolStatus.Success, "");
        }

        try
        {
            using var doc = JsonDocument.Parse(raw);
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object)
            {
                return (ToolStatus.Success, raw);
            }

            var error = Str(r, "error");
            if (!string.IsNullOrEmpty(error) && error != "null")
            {
                var low = error.ToLowerInvariant();
                bool denied = low.Contains("approval") || low.Contains("denied") ||
                              low.Contains("guard") || low.Contains("izin") || low.Contains("permission");
                return denied
                    ? (ToolStatus.Denied, Loc.T("tool.format.denied") + error)
                    : (ToolStatus.Error, error);
            }

            var stdout = Str(r, "stdout", "output");
            var stderr = Str(r, "stderr");
            int? exit = r.TryGetProperty("exit_code", out var ec) && ec.ValueKind == JsonValueKind.Number ? ec.GetInt32() : null;

            var sb = new StringBuilder();
            if (!string.IsNullOrEmpty(stdout))
            {
                sb.AppendLine(stdout.TrimEnd());
            }
            if (!string.IsNullOrEmpty(stderr))
            {
                if (sb.Length > 0) sb.AppendLine();
                sb.AppendLine("── stderr ──").AppendLine(stderr.TrimEnd());
            }
            if (exit is int code && code != 0)
            {
                if (sb.Length > 0) sb.AppendLine();
                sb.Append(Loc.Format("tool.format.exit_code", code));
            }

            if (sb.Length == 0)
            {
                sb.Append(Str(r, "message", "result", "content") ?? "");
            }

            return (exit is int c && c != 0 ? ToolStatus.Error : ToolStatus.Success, sb.ToString().TrimEnd());
        }
        catch (JsonException)
        {
            return (ToolStatus.Success, raw);
        }
    }

    private static string? Str(JsonElement obj, params string[] keys)
    {
        foreach (var k in keys)
        {
            if (obj.TryGetProperty(k, out var v))
            {
                if (v.ValueKind == JsonValueKind.Null) return null;
                return v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText();
            }
        }
        return null;
    }
}
