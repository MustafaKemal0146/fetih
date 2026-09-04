using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Models;

namespace Fetih.Desktop.Services;

/// <summary>Yetenek taramasının sonucu.</summary>
/// <param name="Skills">Tekilleştirilmiş yetenek listesi.</param>
/// <param name="Categories">"kaynak · kategori" biçiminde süzgeç seçenekleri.</param>
/// <param name="Error">Tarama sırasında oluşan hata (varsa).</param>
/// <param name="ElapsedMilliseconds">Tarama süresi.</param>
/// <param name="DuplicatesSkipped">
/// Aynı göreli yola sahip olduğu için atlanan kopya sayısı. FETİH kurulumu
/// depo <c>skills/</c> ağacını <c>~/.fetih/skills/</c> altına kopyalar; aynı
/// yeteneği iki kez listelemek yanıltıcı olurdu.
/// </param>
public sealed record SkillScanResult(
    IReadOnlyList<SkillInfo> Skills,
    IReadOnlyList<string> Categories,
    string? Error,
    long ElapsedMilliseconds,
    int DuplicatesSkipped);

/// <summary>
/// <c>skills/</c> ve <c>optional-skills/</c> ağaçlarındaki <c>SKILL.md</c>
/// dosyalarının YAML ön bilgisini okuyup kataloğa çevirir.
/// Depoda ~1000 dosya var; tarama her zaman arka planda yapılır ve her
/// dosyanın yalnızca ön bilgi bloğu (ilk satırları) okunur.
/// </summary>
public static class SkillCatalog
{
    /// <summary>Ön bilgi ararken okunacak azami satır sayısı.</summary>
    private const int MaxFrontMatterLines = 80;

    /// <summary>Kataloğu arka planda tarar. Hiçbir koşulda istisna fırlatmaz.</summary>
    public static Task<SkillScanResult> LoadAsync(CancellationToken cancellationToken = default)
        => Task.Run(() => Scan(cancellationToken), cancellationToken);

    private static SkillScanResult Scan(CancellationToken cancellationToken)
    {
        var started = Environment.TickCount64;
        var skills = new List<SkillInfo>(1024);
        var categories = new SortedSet<string>(StringComparer.CurrentCulture);
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var duplicates = 0;
        string? error = null;

        var roots = new List<(string Path, string Source)>();
        if (FetihPaths.SkillsRoot is { } skillsRoot)
        {
            roots.Add((skillsRoot, "skills"));
        }

        if (FetihPaths.OptionalSkillsRoot is { } optionalRoot)
        {
            roots.Add((optionalRoot, "optional-skills"));
        }

        roots.Add((FetihPaths.UserSkillsDir, "kullanıcı"));

        foreach (var (root, source) in roots)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                if (!Directory.Exists(root))
                {
                    continue;
                }

                var options = new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = true,
                    MaxRecursionDepth = 12,
                };

                foreach (var file in Directory.EnumerateFiles(root, "SKILL.md", options))
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    var relative = GetRelativePath(root, file);

                    // Kurulum, depo skills/ ağacını ~/.fetih/skills/ altına kopyalar.
                    // Aynı göreli yol daha önce görüldüyse ikinci kopya atlanır.
                    if (!seenPaths.Add(relative))
                    {
                        duplicates++;
                        continue;
                    }

                    var category = FirstSegment(relative);
                    var skill = ReadSkill(file, relative, category, source);
                    if (skill is not null)
                    {
                        skills.Add(skill);
                        categories.Add($"{source} · {category}");
                    }
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
        }

        skills.Sort(static (a, b) =>
        {
            var bySource = string.Compare(a.Source, b.Source, StringComparison.Ordinal);
            if (bySource != 0)
            {
                return bySource;
            }

            var byCategory = string.Compare(a.Category, b.Category, StringComparison.CurrentCultureIgnoreCase);
            return byCategory != 0
                ? byCategory
                : string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase);
        });

        return new SkillScanResult(
            skills,
            new List<string>(categories),
            error,
            Environment.TickCount64 - started,
            duplicates);
    }

    private static string GetRelativePath(string root, string file)
    {
        try
        {
            return Path.GetRelativePath(root, file).Replace('\\', '/');
        }
        catch
        {
            return file;
        }
    }

    private static string FirstSegment(string relativePath)
    {
        var slash = relativePath.IndexOf('/');
        return slash > 0 ? relativePath[..slash] : "(kök)";
    }

    private static SkillInfo? ReadSkill(string file, string relativePath, string category, string source)
    {
        try
        {
            string? name = null;
            string? description = null;

            using var reader = new StreamReader(file);
            var first = reader.ReadLine();
            if (first is null)
            {
                return null;
            }

            if (first.Trim() != "---")
            {
                // Ön bilgisi olmayan SKILL.md: klasör adıyla yine de listelenir.
                return Build(file, relativePath, category, source, null, null);
            }

            for (var i = 0; i < MaxFrontMatterLines; i++)
            {
                var line = reader.ReadLine();
                if (line is null || line.Trim() == "---")
                {
                    break;
                }

                if (TryReadField(line, "name", out var nameValue))
                {
                    name ??= nameValue;
                    continue;
                }

                if (TryReadField(line, "description", out var descValue))
                {
                    if (description is not null)
                    {
                        continue;
                    }

                    if (descValue.Length > 0 && descValue is not (">" or "|" or ">-" or "|-"))
                    {
                        description = descValue;
                        continue;
                    }

                    // Katlanmış blok (">" / "|"): girintili devam satırlarını topla.
                    var folded = new List<string>();
                    for (var j = 0; j < MaxFrontMatterLines; j++)
                    {
                        var next = reader.ReadLine();
                        if (next is null || next.Trim() == "---")
                        {
                            break;
                        }

                        if (next.Length == 0 || (next[0] != ' ' && next[0] != '\t'))
                        {
                            // Blok bitti; bu satır bir sonraki alan olabilir ama
                            // ön bilgi taramasında kaybı önemsiz.
                            break;
                        }

                        folded.Add(next.Trim());
                    }

                    description = string.Join(' ', folded);
                }
            }

            return Build(file, relativePath, category, source, name, description);
        }
        catch
        {
            return null;
        }
    }

    private static SkillInfo Build(
        string file, string relativePath, string category, string source, string? name, string? description)
    {
        var fallbackName = Path.GetFileName(Path.GetDirectoryName(file) ?? string.Empty);
        return new SkillInfo(
            string.IsNullOrWhiteSpace(name) ? (fallbackName.Length > 0 ? fallbackName : "(adsız)") : name!.Trim(),
            string.IsNullOrWhiteSpace(description) ? "(açıklama yok)" : Collapse(description!),
            category,
            source,
            relativePath,
            file);
    }

    private static string Collapse(string text)
    {
        var trimmed = text.Trim();
        return trimmed.Length > 400 ? trimmed[..400] + "…" : trimmed;
    }

    private static bool TryReadField(string line, string field, out string value)
    {
        value = string.Empty;
        if (line.Length == 0 || line[0] == ' ' || line[0] == '\t')
        {
            return false;
        }

        if (!line.StartsWith(field, StringComparison.Ordinal))
        {
            return false;
        }

        var rest = line[field.Length..];
        if (rest.Length == 0 || rest[0] != ':')
        {
            return false;
        }

        value = rest[1..].Trim();
        if (value.Length >= 2 &&
            ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
        {
            value = value[1..^1];
        }

        return true;
    }
}
