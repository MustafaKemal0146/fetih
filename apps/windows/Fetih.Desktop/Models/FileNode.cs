namespace Fetih.Desktop.Models;

/// <summary>
/// Dosya ağacındaki bir düğüm (issue #43). Köprünün <c>file.tree</c> çıktısından
/// kurulur; TreeViewNode.Content olarak taşınır.
/// </summary>
public sealed class FileNode
{
    public required string Name { get; init; }

    /// <summary>Çalışma alanı köküne göre ileri eğik çizgili yol.</summary>
    public required string Path { get; init; }

    public required bool IsDir { get; init; }

    /// <summary>Boyut (bayt); dizinlerde 0.</summary>
    public long Size { get; init; }

    /// <summary>Segoe MDL2 simgesi: klasör ya da belge.</summary>
    public string Glyph => IsDir ? "" : "";
}
