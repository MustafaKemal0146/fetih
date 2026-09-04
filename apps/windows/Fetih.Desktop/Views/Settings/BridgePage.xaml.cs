using System;
using System.Collections.Generic;
using System.IO;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// Masaüstü Köprüsü ayar sayfası: bağlantı durumu, taşıma yapılandırması ve
/// çözümlenen yollar. Faz 1'de salt okunur.
/// </summary>
public sealed partial class BridgePage : Page
{
    public BridgePage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    /// <summary>Kabukla ortak köprü durumu.</summary>
    public BridgeStatus Status => BridgeStatus.Shared;

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        Populate();
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        FetihConfigService.Current.Reload();
        Populate();
    }

    private void Populate()
    {
        try
        {
            var bridgeModulePath = FetihPaths.RepositoryRoot is null
                ? null
                : Path.Combine(FetihPaths.RepositoryRoot, "fetih_desktop_bridge");

            var moduleExists = FetihPaths.SafeExists(bridgeModulePath);

            TransportRows.ItemsSource = new List<SettingRow>
            {
                new("Varsayılan taşıma", "stdio",
                    "Uygulama Python sürecini kendi başlatır; açık port yoktur (en güvenli seçenek)."),
                new("Alternatif taşıma", "WebSocket — ws://127.0.0.1:<port>",
                    "Yalnızca yerel arayüze bağlanır; her oturumda üretilen tek kullanımlık bir belirteç ister."),
                new("Protokol", "Satır sonlu JSON-RPC (NDJSON)",
                    "Aynı sözleşme iki taşıma üzerinde de geçerlidir."),
                new("Bağlantı noktası değişkeni", "FETIH_BRIDGE_PORT",
                    Presence("FETIH_BRIDGE_PORT")),
                new("Belirteç değişkeni", "FETIH_BRIDGE_TOKEN",
                    Presence("FETIH_BRIDGE_TOKEN") +
                    " Değeri hiçbir zaman gösterilmez ve dosyaya yazılmaz; Python sürecine yalnızca ortam değişkeniyle geçirilir."),
                new("Python modülü", moduleExists ? "fetih_desktop_bridge (mevcut)" : "fetih_desktop_bridge (henüz yok)",
                    moduleExists
                        ? "python -m fetih_desktop_bridge ile başlatılır."
                        : "Faz 1'in Python tarafı henüz eklenmedi; bağlantı bu yüzden kurulmuyor."),
            };

            PathRows.ItemsSource = new List<SettingRow>
            {
                new("FETIH_HOME", FetihPaths.FetihHome, DirectoryNote(FetihPaths.FetihHome)),
                new("Yapılandırma", FetihPaths.ConfigYamlPath, FileNote(FetihPaths.ConfigYamlPath)),
                new("Ortam dosyası", FetihPaths.EnvFilePath, FileNote(FetihPaths.EnvFilePath)),
                new("Depo kökü", FetihPaths.RepositoryRoot ?? "(bulunamadı)",
                    FetihPaths.RepositoryRoot is null
                        ? "Uygulama depo ağacının dışından çalıştırılmış olabilir."
                        : "Yetenek kataloğu buradan okunur."),
                new("Uygulama klasörü", AppInfo.BaseDirectory),
            };
        }
        catch (Exception ex)
        {
            App.LogCrash("BridgePage.Populate", ex, ex.Message);
        }
    }

    private static string Presence(string variableName)
        => FetihConfigService.Current.GetKeyPresence(variableName) switch
        {
            EnvKeyPresence.Environment => "Şu an ortamda tanımlı.",
            EnvKeyPresence.EnvFile => ".env dosyasında tanımlı.",
            _ => "Tanımsız — köprü başlatılırken üretilecek.",
        };

    private static string FileNote(string path)
        => FetihPaths.SafeExists(path) ? "Dosya mevcut." : "Dosya yok.";

    private static string DirectoryNote(string path)
        => FetihPaths.SafeExists(path) ? "Klasör mevcut." : "Klasör yok.";
}
