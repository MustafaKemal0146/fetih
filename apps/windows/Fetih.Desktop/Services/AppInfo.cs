using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Fetih.Desktop.Services;

/// <summary>
/// Uygulamanın kendi kimliği ve çalışma zamanı bilgisi. Hakkında ve Tanılama
/// sayfaları bu değerleri gösterir — destek istenen ilk şey bunlar olur
/// (bkz. docs/windows-app-plani.md, (d) bölümü).
/// </summary>
public static class AppInfo
{
    /// <summary>Ürün adı (etkin dile göre — "Masaüstü"/"Desktop" sözcüğü çevrilir).</summary>
    public static string ProductName => Loc.T("app.product_name");

    /// <summary>Proje deposu.</summary>
    public const string RepositoryUrl = "https://github.com/MustafaKemal0146/fetih";

    /// <summary>Sürüm notları / yayınlar.</summary>
    public const string ReleasesUrl = "https://github.com/MustafaKemal0146/fetih/releases";

    /// <summary>Masaüstü uygulaması tasarım belgesi (depo içi).</summary>
    public const string PlanDocumentPath = "docs/windows-app-plani.md";

    /// <summary>Uygulama sürümü (csproj'daki <c>Version</c>).</summary>
    public static string Version => ReadInformationalVersion();

    /// <summary>Windows App SDK paket sürümü (csproj'dan gömülür).</summary>
    public static string WindowsAppSdkVersion => ReadMetadata("WindowsAppSdkVersion", Loc.T("about.unknown"));

    /// <summary>Hedef çatı (TFM).</summary>
    public static string TargetFramework => ReadMetadata("TargetFramework", Loc.T("about.unknown"));

    /// <summary>Çalışan .NET sürümü.</summary>
    public static string RuntimeDescription => SafeGet(() => RuntimeInformation.FrameworkDescription, Loc.T("about.unknown"));

    /// <summary>Süreç mimarisi (x64 / arm64 …).</summary>
    public static string Architecture => SafeGet(
        () => RuntimeInformation.ProcessArchitecture.ToString(), Loc.T("about.unknown"));

    /// <summary>İşletim sistemi mimarisi.</summary>
    public static string OsArchitecture => SafeGet(
        () => RuntimeInformation.OSArchitecture.ToString(), Loc.T("about.unknown"));

    /// <summary>Windows sürümü.</summary>
    public static string OsDescription => SafeGet(
        () => $"{RuntimeInformation.OSDescription} ({Environment.OSVersion.Version})", Loc.T("about.unknown"));

    /// <summary>
    /// Kurulum tipi. Derleme MSIX kimliği olmadan çalışır
    /// (<c>WindowsPackageType=None</c>), yani "paketlenmemiş / geliştirici".
    /// </summary>
    public static string InstallType => DetectInstallType();

    /// <summary>UI çatısı etiketi.</summary>
    public static string UiFramework => $"WinUI 3 · Windows App SDK {WindowsAppSdkVersion}";

    /// <summary>Uygulamanın çalıştığı klasör.</summary>
    public static string BaseDirectory => SafeGet(() => AppContext.BaseDirectory, Loc.T("about.unknown"));

    /// <summary>Derleme tarihi — çalıştırılabilir dosyanın son yazılma zamanı.</summary>
    public static string BuildDate => ReadBuildDate();

    private static string DetectInstallType()
    {
        try
        {
            // Paketli (MSIX) bir uygulamada paket ailesi adı okunabilir;
            // paketlenmemiş derlemede bu çağrı başarısız olur.
            var packagePath = Environment.GetEnvironmentVariable("MSIX_PACKAGE_FAMILY_NAME");
            if (!string.IsNullOrWhiteSpace(packagePath))
            {
                return Loc.T("about.install.packaged");
            }
        }
        catch
        {
            // Yoksayılır — aşağıdaki varsayılan doğru cevaptır.
        }

        return Loc.T("about.install.unpackaged");
    }

    private static string ReadBuildDate()
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            var location = assembly.Location;
            if (!string.IsNullOrEmpty(location) && File.Exists(location))
            {
                return File.GetLastWriteTime(location).ToString("dd.MM.yyyy HH:mm");
            }
        }
        catch
        {
            // Tek dosya / erişim kısıtı durumunda bilinmiyor döner.
        }

        return Loc.T("about.unknown");
    }

    private static string ReadInformationalVersion()
    {
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            var informational = assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            if (!string.IsNullOrWhiteSpace(informational))
            {
                // "1.0.0+abc123" biçimindeki derleme meta verisini kırp.
                var plus = informational.IndexOf('+');
                return plus > 0 ? informational[..plus] : informational;
            }

            return assembly.GetName().Version?.ToString() ?? Loc.T("about.unknown");
        }
        catch
        {
            return Loc.T("about.unknown");
        }
    }

    private static string ReadMetadata(string key, string fallback)
    {
        try
        {
            foreach (var attribute in Assembly.GetExecutingAssembly()
                         .GetCustomAttributes<AssemblyMetadataAttribute>())
            {
                if (string.Equals(attribute.Key, key, StringComparison.Ordinal) &&
                    !string.IsNullOrWhiteSpace(attribute.Value))
                {
                    return attribute.Value!;
                }
            }
        }
        catch
        {
            // Meta veri okunamazsa varsayılan döner.
        }

        return fallback;
    }

    private static string SafeGet(Func<string> getter, string fallback)
    {
        try
        {
            return getter();
        }
        catch
        {
            return fallback;
        }
    }
}
