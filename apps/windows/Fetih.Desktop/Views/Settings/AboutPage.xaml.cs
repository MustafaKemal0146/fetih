using System;
using System.Collections.Generic;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// Hakkında sayfası. Sürüm ve çalışma zamanı bilgisi uydurulmaz: csproj'a
/// gömülen meta veriden ve .NET çalışma zamanından okunur (bkz. Services/AppInfo.cs).
/// </summary>
public sealed partial class AboutPage : Page
{
    public AboutPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        Populate();
    }

    private void Populate()
    {
        try
        {
            ProductText.Text = AppInfo.ProductName;
            TaglineText.Text = AppInfo.Tagline;

            AppRows.ItemsSource = new List<SettingRow>
            {
                new("Uygulama adı", AppInfo.ProductName),
                new("Sürüm", AppInfo.Version),
                new("Derleme tarihi", AppInfo.BuildDate),
                new("Çalışma zamanı", $"{AppInfo.RuntimeDescription} · {AppInfo.UiFramework}"),
                new("Hedef çatı", AppInfo.TargetFramework),
                new("Mimari", AppInfo.Architecture),
                new("Windows", AppInfo.OsDescription),
                new("Kurulum tipi", AppInfo.InstallType,
                    "MSIX paketleme Faz 4'te eklenecek; şu anki derleme paket kimliği olmadan çalışır."),
                new("Uygulama klasörü", AppInfo.BaseDirectory),
            };

            SetLink(RepoLink, AppInfo.RepositoryUrl);
            SetLink(ReleasesLink, AppInfo.ReleasesUrl);
        }
        catch (Exception ex)
        {
            App.LogCrash("AboutPage.Populate", ex, ex.Message);
        }
    }

    private static void SetLink(HyperlinkButton button, string url)
    {
        try
        {
            button.NavigateUri = new Uri(url);
        }
        catch (Exception ex)
        {
            // Geçersiz bir URL yüzünden sayfa açılamamasın.
            App.LogCrash("AboutPage.SetLink", ex, url);
            button.IsEnabled = false;
        }
    }
}
