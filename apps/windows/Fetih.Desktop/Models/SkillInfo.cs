namespace Fetih.Desktop.Models;

/// <summary>
/// Bir <c>SKILL.md</c> dosyasının YAML ön bilgisinden (frontmatter) okunan yetenek kaydı.
/// </summary>
public sealed class SkillInfo
{
    public SkillInfo(string name, string description, string category, string source, string relativePath, string fullPath)
    {
        Name = name;
        Description = description;
        Category = category;
        Source = source;
        RelativePath = relativePath;
        FullPath = fullPath;
        SearchBlob = $"{name}\n{description}\n{category}\n{relativePath}".ToLowerInvariant();
    }

    /// <summary>Ön bilgideki <c>name</c> alanı (yoksa klasör adı).</summary>
    public string Name { get; }

    /// <summary>Ön bilgideki <c>description</c> alanı.</summary>
    public string Description { get; }

    /// <summary>Üst klasör adı (ör. <c>cybersecurity</c>, <c>ctf</c>, <c>red-teaming</c>).</summary>
    public string Category { get; }

    /// <summary>Kaynak ağaç: <c>skills</c>, <c>optional-skills</c> ya da <c>kullanıcı</c>.</summary>
    public string Source { get; }

    /// <summary>Kaynak ağacın köküne göre yol.</summary>
    public string RelativePath { get; }

    /// <summary>Diskteki tam yol.</summary>
    public string FullPath { get; }

    /// <summary>Arama için önceden küçük harfe çevrilmiş birleşik metin.</summary>
    public string SearchBlob { get; }

    /// <summary>Liste öğesinin altında gösterilen ikincil satır.</summary>
    public string SubtitleLabel => $"{Source} · {Category}";
}
