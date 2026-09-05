using System;
using System.IO;

namespace Fetih.Desktop.Services;

/// <summary>
/// FETİH'in gerçek dosya düzenini .NET tarafında çözümler.
/// Python karşılığı <c>fetih_constants.get_fetih_home()</c> ve
/// <c>fetih_cli/config.py</c> içindeki <c>get_config_path()</c> / <c>get_env_path()</c>:
/// FETIH_HOME ortam değişkeni varsa o, yoksa <c>~/.fetih</c>.
/// </summary>
public static class FetihPaths
{
    private static readonly Lazy<string> HomeLazy = new(ResolveFetihHome);
    private static readonly Lazy<string?> RepoLazy = new(ResolveRepositoryRoot);

    /// <summary>FETIH_HOME (varsayılan <c>~/.fetih</c>).</summary>
    public static string FetihHome => HomeLazy.Value;

    /// <summary><c>~/.fetih/config.yaml</c> — tüm ayarlar burada.</summary>
    public static string ConfigYamlPath => Path.Combine(FetihHome, "config.yaml");

    /// <summary><c>~/.fetih/.env</c> — API anahtarları ve gizli değerler.</summary>
    public static string EnvFilePath => Path.Combine(FetihHome, ".env");

    /// <summary><c>~/.fetih/sandboxes</c> — yerel çalışma alanı kopyaları.</summary>
    public static string SandboxesDir => Path.Combine(FetihHome, "sandboxes");

    /// <summary><c>~/.fetih/skills</c> — kullanıcının kendi eklediği yetenekler.</summary>
    public static string UserSkillsDir => Path.Combine(FetihHome, "skills");

    /// <summary><c>~/.fetih/logs</c>.</summary>
    public static string LogsDir => Path.Combine(FetihHome, "logs");

    /// <summary>
    /// %LOCALAPPDATA%\Fetih\Desktop\crash.log — App.xaml.cs'teki çökme günlüğü.
    /// Tanılama sayfası bu dosyayı okur.
    /// </summary>
    public static string CrashLogPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Fetih", "Desktop", "crash.log");

    /// <summary>
    /// FETİH deposunun kökü (bulunabildiyse). Geliştirme derlemesinde
    /// <c>apps/windows/Fetih.Desktop/bin/...</c> altından yukarı yürüyerek bulunur.
    /// </summary>
    public static string? RepositoryRoot => RepoLazy.Value;

    /// <summary>
    /// Alt süreç başlatmak için çalışma dizini: depo kökü bulunduysa o,
    /// bulunamadıysa uygulamanın kendi klasörü. Kurulan (depo dışı) bir
    /// dağıtımda <c>python -m fetih_cli</c> yine site-packages'tan çözülür.
    /// </summary>
    public static string RepoRootOrCurrent => RepositoryRoot ?? AppContext.BaseDirectory;

    /// <summary>Depo içindeki <c>skills/</c> klasörü.</summary>
    public static string? SkillsRoot =>
        RepositoryRoot is null ? null : Path.Combine(RepositoryRoot, "skills");

    /// <summary>Depo içindeki <c>optional-skills/</c> klasörü.</summary>
    public static string? OptionalSkillsRoot =>
        RepositoryRoot is null ? null : Path.Combine(RepositoryRoot, "optional-skills");

    /// <summary>Bir yolun var olup olmadığını güvenli biçimde döndürür.</summary>
    public static bool SafeExists(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            return File.Exists(path) || Directory.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    private static string ResolveFetihHome()
    {
        try
        {
            var overridden = Environment.GetEnvironmentVariable("FETIH_HOME");
            if (!string.IsNullOrWhiteSpace(overridden))
            {
                return overridden.Trim();
            }
        }
        catch
        {
            // Ortam değişkeni okunamazsa varsayılana düş.
        }

        try
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".fetih");
        }
        catch
        {
            return ".fetih";
        }
    }

    /// <summary>
    /// Uygulamanın çalıştığı klasörden yukarı doğru yürüyüp hem <c>skills/</c>
    /// hem <c>fetih_cli/</c> içeren ilk klasörü depo kökü kabul eder.
    /// </summary>
    private static string? ResolveRepositoryRoot()
    {
        try
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            for (var depth = 0; dir is not null && depth < 12; depth++, dir = dir.Parent)
            {
                if (Directory.Exists(Path.Combine(dir.FullName, "skills")) &&
                    Directory.Exists(Path.Combine(dir.FullName, "fetih_cli")))
                {
                    return dir.FullName;
                }
            }
        }
        catch
        {
            // Erişim hatası: depo kökü yok sayılır, çağıran null'ı işler.
        }

        return null;
    }
}
