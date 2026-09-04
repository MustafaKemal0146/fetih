using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// Tanılama sayfası. Sistem/çalışma zamanı bilgisi, çözümlenen yollar ve
/// App.xaml.cs'in yazdığı <c>%LOCALAPPDATA%\Fetih\Desktop\crash.log</c>
/// dosyasının içeriği. Bu sayfa yer tutucu değil — gerçek bir destek aracıdır.
/// </summary>
public sealed partial class DiagnosticsPage : Page
{
    /// <summary>Günlüğün gösterilen son parçasının azami boyutu.</summary>
    private const int MaxLogBytes = 256 * 1024;

    public DiagnosticsPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

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

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var package = new DataPackage { RequestedOperation = DataPackageOperation.Copy };
            package.SetText(BuildSupportReport());
            Clipboard.SetContent(package);
            ShowInfo("Tanılama raporu panoya kopyalandı.", InfoBarSeverity.Success);
        }
        catch (Exception ex)
        {
            App.LogCrash("DiagnosticsPage.Copy", ex, ex.Message);
            ShowInfo($"Panoya kopyalanamadı: {ex.Message}", InfoBarSeverity.Error);
        }
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (File.Exists(FetihPaths.CrashLogPath))
            {
                File.WriteAllText(FetihPaths.CrashLogPath, string.Empty);
                ShowInfo("Çökme günlüğü temizlendi.", InfoBarSeverity.Success);
            }
            else
            {
                ShowInfo("Temizlenecek günlük yok.", InfoBarSeverity.Informational);
            }

            Populate();
        }
        catch (Exception ex)
        {
            App.LogCrash("DiagnosticsPage.Clear", ex, ex.Message);
            ShowInfo($"Günlük temizlenemedi: {ex.Message}", InfoBarSeverity.Error);
        }
    }

    private void ShowInfo(string message, InfoBarSeverity severity)
    {
        ActionInfo.Message = message;
        ActionInfo.Severity = severity;
        ActionInfo.IsOpen = true;
    }

    private void Populate()
    {
        try
        {
            SystemRows.ItemsSource = BuildSystemRows();
            PathRows.ItemsSource = BuildPathRows();
            LoadCrashLog();
        }
        catch (Exception ex)
        {
            App.LogCrash("DiagnosticsPage.Populate", ex, ex.Message);
        }
    }

    private static List<SettingRow> BuildSystemRows() => new()
    {
        new("Uygulama", $"{AppInfo.ProductName} {AppInfo.Version}"),
        new("Derleme tarihi", AppInfo.BuildDate),
        new("Çalışma zamanı", AppInfo.RuntimeDescription),
        new("Hedef çatı", AppInfo.TargetFramework),
        new("Arayüz", AppInfo.UiFramework),
        new("Süreç mimarisi", AppInfo.Architecture),
        new("İşletim sistemi mimarisi", AppInfo.OsArchitecture),
        new("Windows", AppInfo.OsDescription),
        new("Kurulum tipi", AppInfo.InstallType),
        new("Makine", SafeMachineName()),
    };

    private static List<SettingRow> BuildPathRows()
    {
        var service = FetihConfigService.Current;

        return new List<SettingRow>
        {
            new("Uygulama klasörü", AppInfo.BaseDirectory),
            new("FETIH_HOME", FetihPaths.FetihHome, State(FetihPaths.FetihHome)),
            new("config.yaml", FetihPaths.ConfigYamlPath,
                service.ConfigError ?? (service.ConfigExists
                    ? $"{service.Config.Map.Count} kök anahtar okundu" + ModifiedNote(service)
                    : "Dosya yok")),
            new(".env", FetihPaths.EnvFilePath,
                service.EnvFileExists
                    ? $"{service.EnvFileKeys.Count} anahtar tanımlı (değerler okunmaz)"
                    : "Dosya yok"),
            new("Günlükler", FetihPaths.LogsDir, State(FetihPaths.LogsDir)),
            new("Sandbox klasörü", FetihPaths.SandboxesDir, State(FetihPaths.SandboxesDir)),
            new("Depo kökü", FetihPaths.RepositoryRoot ?? "(bulunamadı)",
                FetihPaths.RepositoryRoot is null ? "Yetenek kataloğu okunamaz" : "Mevcut"),
            new("Çökme günlüğü", FetihPaths.CrashLogPath, State(FetihPaths.CrashLogPath)),
        };
    }

    private static string ModifiedNote(FetihConfigService service)
        => service.ConfigModified is { } modified ? $" · son değişiklik {modified:dd.MM.yyyy HH:mm}" : string.Empty;

    private static string State(string path) => FetihPaths.SafeExists(path) ? "Mevcut" : "Yok";

    private static string SafeMachineName()
    {
        try
        {
            return Environment.MachineName;
        }
        catch
        {
            return "bilinmiyor";
        }
    }

    private void LoadCrashLog()
    {
        try
        {
            if (!File.Exists(FetihPaths.CrashLogPath))
            {
                CrashLogMeta.Text = $"{FetihPaths.CrashLogPath} — dosya yok (hiç çökme kaydedilmemiş).";
                CrashLogText.Text = "Kayıtlı çökme yok.";
                return;
            }

            var info = new FileInfo(FetihPaths.CrashLogPath);
            CrashLogMeta.Text =
                $"{FetihPaths.CrashLogPath} — {info.Length:N0} bayt · " +
                $"son yazma {info.LastWriteTime:dd.MM.yyyy HH:mm:ss}";

            var content = ReadTail(FetihPaths.CrashLogPath, MaxLogBytes);
            CrashLogText.Text = content.Length == 0 ? "Günlük boş." : content;
        }
        catch (Exception ex)
        {
            CrashLogMeta.Text = FetihPaths.CrashLogPath;
            CrashLogText.Text = $"Günlük okunamadı: {ex.Message}";
        }
    }

    /// <summary>Dosyanın son <paramref name="maxBytes"/> baytını okur.</summary>
    private static string ReadTail(string path, int maxBytes)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (stream.Length > maxBytes)
        {
            stream.Seek(-maxBytes, SeekOrigin.End);
        }

        using var reader = new StreamReader(stream);
        var text = reader.ReadToEnd();
        return stream.Length > maxBytes
            ? "… (günlüğün yalnızca son bölümü gösteriliyor) …\n" + text
            : text;
    }

    /// <summary>Panoya kopyalanan destek raporu.</summary>
    private string BuildSupportReport()
    {
        var builder = new StringBuilder();
        builder.AppendLine("FETİH Masaüstü — tanılama raporu");
        builder.AppendLine($"Oluşturma: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        builder.AppendLine(new string('-', 60));

        foreach (var row in BuildSystemRows())
        {
            builder.AppendLine($"{row.Label}: {row.Value}");
        }

        builder.AppendLine(new string('-', 60));
        foreach (var row in BuildPathRows())
        {
            builder.AppendLine($"{row.Label}: {row.Value} ({row.Note})");
        }

        builder.AppendLine(new string('-', 60));
        builder.AppendLine("Çökme günlüğü:");
        builder.AppendLine(CrashLogText.Text);
        return builder.ToString();
    }
}
