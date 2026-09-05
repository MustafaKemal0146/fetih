using System;

namespace Fetih.Desktop.Services;

/// <summary>
/// Bir sayfanın kabuktan (sol menüden) gezinme istemesini sağlayan ince köprü.
/// Sadeleştirilmiş ayar sayfalarındaki "Detaylı Mod'da aç" bağlantısı bunu
/// kullanır; sayfa <c>MainWindow</c>'a doğrudan bağımlı olmaz.
/// </summary>
public static class ShellNavigation
{
    /// <summary>Kabuk bu olaya abone olur; parametre bir <c>NavTags</c> değeridir.</summary>
    public static event Action<string>? Requested;

    /// <summary>Verilen etiketli sayfaya gezinilmesini ister.</summary>
    public static void Request(string tag)
    {
        try
        {
            Requested?.Invoke(tag);
        }
        catch
        {
            // Kabuk yoksa ya da dinleyici hata verirse sayfa çalışmaya devam etsin.
        }
    }
}
