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
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged += OnLanguageChanged;
        Populate();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged -= OnLanguageChanged;
    }

    private void OnLanguageChanged()
    {
        ApplyLanguage();
        Populate();
    }

    private void ApplyLanguage()
    {
        PageTitleText.Text = Loc.T("diag.title");
        SubtitleText.Text = Loc.T("diag.subtitle");
        SystemHeader.Text = Loc.T("diag.section.system");
        PathsHeader.Text = Loc.T("diag.section.paths");
        CrashLogHeader.Text = Loc.T("diag.section.crash_log");
        RefreshButton.Content = Loc.T("diag.refresh");
        CopyButton.Content = Loc.T("diag.copy");
        ClearButton.Content = Loc.T("diag.clear");
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
            ShowInfo(Loc.T("diag.copied"), InfoBarSeverity.Success);
        }
        catch (Exception ex)
        {
            App.LogCrash("DiagnosticsPage.Copy", ex, ex.Message);
            ShowInfo(Loc.T("diag.copy_failed") + ex.Message, InfoBarSeverity.Error);
        }
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (File.Exists(FetihPaths.CrashLogPath))
            {
                File.WriteAllText(FetihPaths.CrashLogPath, string.Empty);
                ShowInfo(Loc.T("diag.cleared"), InfoBarSeverity.Success);
            }
            else
            {
                ShowInfo(Loc.T("diag.no_log"), InfoBarSeverity.Informational);
            }

            Populate();
        }
        catch (Exception ex)
        {
            App.LogCrash("DiagnosticsPage.Clear", ex, ex.Message);
            ShowInfo(Loc.T("diag.clear_failed") + ex.Message, InfoBarSeverity.Error);
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
        new(Loc.T("diag.row.app"), $"{AppInfo.ProductName} {AppInfo.Version}"),
        new(Loc.T("diag.row.build_date"), AppInfo.BuildDate),
        new(Loc.T("diag.row.runtime"), AppInfo.RuntimeDescription),
        new(Loc.T("diag.row.target_framework"), AppInfo.TargetFramework),
        new(Loc.T("diag.row.ui"), AppInfo.UiFramework),
        new(Loc.T("diag.row.proc_arch"), AppInfo.Architecture),
        new(Loc.T("diag.row.os_arch"), AppInfo.OsArchitecture),
        new(Loc.T("diag.row.windows"), AppInfo.OsDescription),
        new(Loc.T("diag.row.install_type"), AppInfo.InstallType),
        new(Loc.T("diag.row.machine"), SafeMachineName()),
    };

    private static List<SettingRow> BuildPathRows()
    {
        var service = FetihConfigService.Current;

        return new List<SettingRow>
        {
            new(Loc.T("diag.row.app_dir"), AppInfo.BaseDirectory),
            new("FETIH_HOME", FetihPaths.FetihHome, State(FetihPaths.FetihHome)),
            new("config.yaml", FetihPaths.ConfigYamlPath,
                service.ConfigError ?? (service.ConfigExists
                    ? $"{service.Config.Map.Count} " + Loc.T("diag.keys_read") + ModifiedNote(service)
                    : Loc.T("diag.file_missing"))),
            new(".env", FetihPaths.EnvFilePath,
                service.EnvFileExists
                    ? $"{service.EnvFileKeys.Count} " + Loc.T("diag.keys_defined")
                    : Loc.T("diag.file_missing")),
            new(Loc.T("diag.row.logs"), FetihPaths.LogsDir, State(FetihPaths.LogsDir)),
            new(Loc.T("diag.row.sandbox"), FetihPaths.SandboxesDir, State(FetihPaths.SandboxesDir)),
            new(Loc.T("diag.row.repo"), FetihPaths.RepositoryRoot ?? "(bulunamadı)",
                FetihPaths.RepositoryRoot is null ? Loc.T("diag.catalog_unreadable") : Loc.T("diag.present")),
            new(Loc.T("diag.row.crash_log"), FetihPaths.CrashLogPath, State(FetihPaths.CrashLogPath)),
        };
    }

    private static string ModifiedNote(FetihConfigService service)
        => service.ConfigModified is { } modified ? $" · {modified:dd.MM.yyyy HH:mm}" : string.Empty;

    private static string State(string path) => FetihPaths.SafeExists(path) ? Loc.T("diag.present") : Loc.T("diag.missing");

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
