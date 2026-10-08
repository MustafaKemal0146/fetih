using System;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Models;

/// <summary>Zaman çizelgesindeki bir araç yürütmesinin durumu (issue #35).</summary>
public enum TimelineStatus
{
    Running,
    Done,
    Error,
}

/// <summary>
/// Operasyon zaman çizelgesindeki tek bir araç çağrısı: ad, argüman özeti,
/// başlangıç, süre ve (mümkünse) çıkış kodu. tool_call/tool_result
/// kayıtlarından/olaylarından türetilir.
/// </summary>
public sealed class TimelineEntry
{
    public required string CallId { get; init; }
    public required string Name { get; init; }
    public string ArgsSummary { get; set; } = "";
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.Now;
    public double? DurationMs { get; set; }
    public int? ExitCode { get; set; }
    public TimelineStatus Status { get; set; } = TimelineStatus.Running;

    public string TimeLabel => StartedAt.ToString("HH:mm:ss");

    public string DurationLabel => DurationMs is double d
        ? (d >= 1000 ? $"{d / 1000.0:0.0} s" : $"{(int)d} ms")
        : "…";

    public string StatusLabel => Status switch
    {
        TimelineStatus.Running => Loc.T("timeline.status.running"),
        TimelineStatus.Error => Loc.T("timeline.status.error"),
        _ => Loc.T("timeline.status.done"),
    };

    public string StatusBrushKey => Status switch
    {
        TimelineStatus.Running => "SystemFillColorAttentionBrush",
        TimelineStatus.Error => "SystemFillColorCriticalBrush",
        _ => "SystemFillColorSuccessBrush",
    };

    public bool HasExit => ExitCode is not null;
    public string ExitLabel => ExitCode is int c ? $"exit {c}" : "";

    /// <summary>İkon: araç adına göre kaba sınıflama.</summary>
    public string Glyph
    {
        get
        {
            var n = Name.ToLowerInvariant();
            if (n.Contains("terminal") || n.Contains("shell") || n.Contains("exec") || n.Contains("command")) return "\uE756";
            if (n.Contains("search") || n.Contains("grep") || n.Contains("find")) return "\uE721";
            if (n.Contains("read") || n.Contains("file") || n.Contains("write") || n.Contains("patch")) return "\uE8A5";
            if (n.Contains("browser") || n.Contains("web") || n.Contains("http")) return "\uE774";
            if (n.Contains("delegate") || n.Contains("agent")) return "\uE716";
            return "\uE9F5";
        }
    }
}
