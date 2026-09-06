using System;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Models;

/// <summary>Bir bulgunun ciddiyet seviyesi.</summary>
public enum FindingSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// <summary>
/// Bir tarama/görev sonucunda ortaya çıkan tek bir güvenlik bulgusu.
/// Faz 1'de koleksiyon boştur; Masaüstü Köprüsü bağlandığında ajan olayları
/// buraya akacak (bkz. docs/windows-app-plani.md, (f) bölümü).
/// </summary>
public sealed class Finding
{
    public Finding(
        string title,
        string target,
        FindingSeverity severity,
        string evidence = "",
        string recommendation = "",
        string reference = "")
    {
        Title = title;
        Target = target;
        Severity = severity;
        Evidence = evidence;
        Recommendation = recommendation;
        Reference = reference;
        DiscoveredAt = DateTimeOffset.Now;
    }

    /// <summary>Bulgunun başlığı.</summary>
    public string Title { get; }

    /// <summary>Hedef host / URL / dosya.</summary>
    public string Target { get; }

    public FindingSeverity Severity { get; }

    /// <summary>Kanıt (çıktı parçası, istek/yanıt, dosya yolu).</summary>
    public string Evidence { get; }

    /// <summary>Öneri / düzeltme adımı.</summary>
    public string Recommendation { get; }

    /// <summary>Referans (CVE / CWE / MITRE ATT&amp;CK tekniği).</summary>
    public string Reference { get; }

    public DateTimeOffset DiscoveredAt { get; }

    /// <summary>Rozette gösterilen ciddiyet etiketi.</summary>
    public string SeverityLabel => Severity switch
    {
        FindingSeverity.Critical => Loc.T("findings.severity.critical"),
        FindingSeverity.High => Loc.T("findings.severity.high"),
        FindingSeverity.Medium => Loc.T("findings.severity.medium"),
        FindingSeverity.Low => Loc.T("findings.severity.low"),
        _ => Loc.T("findings.severity.info"),
    };

    /// <summary>Ciddiyete göre tema kaynağı adı (XAML tarafında çözümlenir).</summary>
    public string SeverityBrushKey => Severity switch
    {
        FindingSeverity.Critical or FindingSeverity.High => "SystemFillColorCriticalBrush",
        FindingSeverity.Medium => "SystemFillColorCautionBrush",
        FindingSeverity.Low => "SystemFillColorSuccessBrush",
        _ => "SystemFillColorNeutralBrush",
    };

    public string TimeLabel => DiscoveredAt.ToString("dd.MM.yyyy HH:mm");

    public bool HasReference => !string.IsNullOrWhiteSpace(Reference);
}
