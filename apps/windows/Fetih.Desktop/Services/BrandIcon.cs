using System;
using System.IO;
using Microsoft.UI.Windowing;

namespace Fetih.Desktop.Services;

/// <summary>
/// Pencere ikonunu FETİH markasına ayarlar.
///
/// <para>Uygulama MSIX'siz ("unpackaged") çalıştığı için Windows ikonu
/// paket manifestinden okuyamaz; her pencere kendi ikonunu
/// <see cref="AppWindow.SetIcon(string)"/> ile bildirmek zorunda. Bu olmadan
/// görev çubuğunda ve Alt+Tab'de jenerik .NET ikonu görünüyordu.</para>
///
/// <para>İkon <c>assets/fetih.ico</c>: aynı işaretin 16–256 piksel arası
/// ölçekleri (bkz. assets/Branding.xaml'daki monogram — küçük boyutta
/// "FETİH" okunmadığı için kalkan üstünde köşeli F'ye sadeleşir).</para>
/// </summary>
public static class BrandIcon
{
    private static readonly Lazy<string?> PathLazy = new(Resolve);

    /// <summary>Bulunabildiyse .ico dosyasının tam yolu.</summary>
    public static string? IconPath => PathLazy.Value;

    /// <summary>İkonu uygula. Dosya yoksa sessizce geç — pencere yine açılsın.</summary>
    public static void Apply(AppWindow? window)
    {
        if (window is null || IconPath is null)
        {
            return;
        }

        try
        {
            window.SetIcon(IconPath);
        }
        catch
        {
            // İkon yüklenemezse varsayılanla devam; bu bir çökme sebebi değil.
        }
    }

    private static string? Resolve()
    {
        try
        {
            var candidate = Path.Combine(AppContext.BaseDirectory, "assets", "fetih.ico");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        catch
        {
            // Erişim hatası: ikonsuz devam.
        }
        return null;
    }
}
