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
        PageTitleText.Text = Loc.T("about.title");
        DescriptionText.Text = Loc.T("about.desc");
        AppInfoSectionHeader.Text = Loc.T("about.section.app_info");
        LinksSectionHeader.Text = Loc.T("about.section.links");
        RepoLink.Content = Loc.T("about.repo_link");
        ReleasesLink.Content = Loc.T("about.releases_link");
        DesignDocText.Text = Loc.T("about.design_doc");
        DisclaimerInfoBar.Title = Loc.T("about.disclaimer_title");
        DisclaimerInfoBar.Message = Loc.T("about.disclaimer_message");
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
}
