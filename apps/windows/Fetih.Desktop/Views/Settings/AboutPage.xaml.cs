using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// Hakkında sayfası. Sürüm ve çalışma zamanı bilgisi uydurulmaz: csproj'a
/// gömülen meta veriden ve .NET çalışma zamanından okunur (bkz. Services/AppInfo.cs).
///
/// <para>Güncellemeler bölümü <see cref="UpdateService"/>'i sarar: elle
/// denetim, indirme ve (kurulum tipine göre) sessiz installer / taşınabilir
/// dosya değişimi. Ağ/kurulum hataları burada yutulmaz — kullanıcıya
/// <see cref="UpdateStatusText"/> üzerinden gösterilir.</para>
/// </summary>
public sealed partial class AboutPage : Page
{
    private UpdateInfo? _pendingUpdate;
    private bool _updateInProgress;

    public AboutPage()
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

        // Arka plan açılış denetimi bu sayfa açılmadan önce zaten bir sonuç
        // bulmuş olabilir — varsa doğrudan göster, kullanıcıyı tekrar
        // beklemeye zorlama.
        if (UpdateService.LastKnownUpdate is { } known)
        {
            ShowUpdateAvailable(known);
        }
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
        PageTitleText.Text = Loc.T("about.title");
        DescriptionText.Text = Loc.T("about.desc");
        AppInfoSectionHeader.Text = Loc.T("about.section.app_info");
        LinksSectionHeader.Text = Loc.T("about.section.links");
        RepoLink.Content = Loc.T("about.repo_link");
        ReleasesLink.Content = Loc.T("about.releases_link");
        DesignDocText.Text = Loc.T("about.design_doc");
        DisclaimerInfoBar.Title = Loc.T("about.disclaimer_title");
        DisclaimerInfoBar.Message = Loc.T("about.disclaimer_message");

        UpdateSectionHeader.Text = Loc.T("update.section.header");
        CheckUpdateButton.Content = Loc.T("update.check_button");
        DownloadInstallButton.Content = Loc.T("update.download_install");
        UpdateChannelText.Text = UpdateService.IsInstalledViaSetup()
            ? Loc.T("update.channel.setup")
            : Loc.T("update.channel.portable");

        if (_pendingUpdate is not null)
        {
            UpdateAvailableInfoBar.Title = $"{Loc.T("update.available")} — v{_pendingUpdate.Version}";
        }
    }

    private void Populate()
    {
        try
        {
            ProductText.Text = AppInfo.ProductName;
            TaglineText.Text = Loc.T("app.tagline");

            AppRows.ItemsSource = new List<SettingRow>
            {
                new(Loc.T("about.row.app_name"), AppInfo.ProductName),
                new(Loc.T("about.row.version"), AppInfo.Version),
                new(Loc.T("about.row.build_date"), AppInfo.BuildDate),
                new(Loc.T("about.row.runtime"), $"{AppInfo.RuntimeDescription} · {AppInfo.UiFramework}"),
                new(Loc.T("about.row.target_framework"), AppInfo.TargetFramework),
                new(Loc.T("about.row.architecture"), AppInfo.Architecture),
                new(Loc.T("about.row.windows"), AppInfo.OsDescription),
                new(Loc.T("about.row.install_type"), AppInfo.InstallType,
                    Loc.T("about.row.install_desc")),
                new(Loc.T("about.row.app_dir"), AppInfo.BaseDirectory),
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

    // ── Güncellemeler ───────────────────────────────────────────────────

    private async void CheckUpdateButton_Click(object sender, RoutedEventArgs e)
    {
        if (_updateInProgress)
        {
            return;
        }

        CheckUpdateButton.IsEnabled = false;
        UpdateProgressRing.IsActive = true;
        UpdateProgressRing.Visibility = Visibility.Visible;
        UpdateStatusText.Text = Loc.T("update.checking");
        UpdateAvailableInfoBar.IsOpen = false;

        try
        {
            var info = await UpdateService.CheckForUpdateAsync();
            if (info is null)
            {
                UpdateStatusText.Text = Loc.T("update.up_to_date");
            }
            else
            {
                UpdateStatusText.Text = "";
                ShowUpdateAvailable(info);
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("AboutPage.CheckUpdate", ex, ex.Message);
            UpdateStatusText.Text = Loc.T("update.check_failed");
        }
        finally
        {
            CheckUpdateButton.IsEnabled = true;
            UpdateProgressRing.IsActive = false;
            UpdateProgressRing.Visibility = Visibility.Collapsed;
        }
    }

    private void ShowUpdateAvailable(UpdateInfo info)
    {
        _pendingUpdate = info;
        UpdateAvailableInfoBar.Title = $"{Loc.T("update.available")} — v{info.Version}";
        UpdateAvailableInfoBar.Message = info.ReleaseNotesUrl;
        UpdateAvailableInfoBar.IsOpen = true;

        var hasAsset = UpdateService.IsInstalledViaSetup() ? info.InstallerUrl is not null : info.PortableZipUrl is not null;
        DownloadInstallButton.IsEnabled = hasAsset;
        if (!hasAsset)
        {
            UpdateStatusText.Text = Loc.T("update.no_asset_for_channel");
        }
    }

    private async void DownloadInstallButton_Click(object sender, RoutedEventArgs e)
    {
        if (_updateInProgress || _pendingUpdate is null)
        {
            return;
        }

        _updateInProgress = true;
        DownloadInstallButton.IsEnabled = false;
        CheckUpdateButton.IsEnabled = false;
        UpdateProgressRing.IsActive = true;
        UpdateProgressRing.Visibility = Visibility.Visible;

        try
        {
            var viaSetup = UpdateService.IsInstalledViaSetup();
            var assetUrl = viaSetup ? _pendingUpdate.InstallerUrl : _pendingUpdate.PortableZipUrl;
            if (assetUrl is null)
            {
                UpdateStatusText.Text = Loc.T("update.no_asset_for_channel");
                return;
            }

            var progress = new Progress<double>(p =>
            {
                UpdateStatusText.Text = $"{Loc.T("update.downloading")} {p * 100:0}%";
            });

            UpdateStatusText.Text = Loc.T("update.downloading");
            var downloadedPath = await UpdateService.DownloadAsync(assetUrl, progress);

            UpdateStatusText.Text = Loc.T("update.installing");
            await Task.Delay(400); // Kullanıcının mesajı görmesi için kısa duraklama.

            if (viaSetup)
            {
                UpdateService.RunInstallerSilentlyAndExit(downloadedPath);
            }
            else
            {
                var installDir = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                UpdateService.ApplyPortableUpdateAndExit(downloadedPath, installDir);
            }
            // Yukarıdaki çağrılar Environment.Exit(0) ile döner — buraya normalde ulaşılmaz.
        }
        catch (Exception ex)
        {
            App.LogCrash("AboutPage.DownloadInstall", ex, ex.Message);
            UpdateStatusText.Text = Loc.T("update.install_failed");
        }
        finally
        {
            _updateInProgress = false;
            DownloadInstallButton.IsEnabled = true;
            CheckUpdateButton.IsEnabled = true;
            UpdateProgressRing.IsActive = false;
            UpdateProgressRing.Visibility = Visibility.Collapsed;
        }
    }
}
