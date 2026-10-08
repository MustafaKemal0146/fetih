using System;
using System.Collections.Generic;
using System.Linq;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Models;

/// <summary>
/// Bir hedefe (host/URL/dosya) ait bulguların kümesi (issue #34). Bulgular
/// hedef alanına göre gruplanır; URL'lerde host'a indirgenir.
/// </summary>
public sealed class TargetGroup
{
    public required string Target { get; init; }

    public List<Finding> Findings { get; } = new();

    public int Count => Findings.Count;

    public string CountLabel => string.Format(Loc.T("targets.count"), Count);

    public FindingSeverity MaxSeverity =>
        Findings.Count == 0 ? FindingSeverity.Info : Findings.Max(f => f.Severity);

    public string SeverityLabel => MaxSeverity switch
    {
        FindingSeverity.Critical => Loc.T("findings.severity.critical"),
        FindingSeverity.High => Loc.T("findings.severity.high"),
        FindingSeverity.Medium => Loc.T("findings.severity.medium"),
        FindingSeverity.Low => Loc.T("findings.severity.low"),
        _ => Loc.T("findings.severity.info"),
    };

    public string SeverityBrushKey => MaxSeverity switch
    {
        FindingSeverity.Critical or FindingSeverity.High => "SystemFillColorCriticalBrush",
        FindingSeverity.Medium => "SystemFillColorCautionBrush",
        FindingSeverity.Low => "SystemFillColorSuccessBrush",
        _ => "SystemFillColorNeutralBrush",
    };

    public string Glyph
    {
        get
        {
            if (Target.StartsWith("http", StringComparison.OrdinalIgnoreCase)) return "\uE774";
            if (Target.StartsWith("tool:", StringComparison.OrdinalIgnoreCase)) return "\uE756";
            if (Target.IndexOf((char)47) >= 0 || Target.IndexOf((char)58) >= 0 || Target.IndexOf((char)92) >= 0) return "";
            return "\uE968"; // globe/host
        }
    }

    /// <summary>Bir bulgunun hedefini grup anahtarına indirger (URL → host).</summary>
    public static string KeyFor(string? target)
    {
        var t = (target ?? "").Trim();
        if (t.Length == 0) return "—";
        if (Uri.TryCreate(t, UriKind.Absolute, out var u) && !string.IsNullOrEmpty(u.Host))
        {
            return u.Host;
        }
        return t;
    }
}
