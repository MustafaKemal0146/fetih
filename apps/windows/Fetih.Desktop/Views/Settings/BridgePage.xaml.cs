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
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    /// <summary>Kabukla ortak köprü durumu.</summary>
    public BridgeStatus Status => BridgeStatus.Shared;

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
        PageTitleText.Text = Loc.T("bridge.title");
        IntroText.Text = Loc.T("bridge.intro");
        TransportHeader.Text = Loc.T("bridge.section.transport");
        PathsHeader.Text = Loc.T("bridge.section.paths");
        PathsNoteText.Text = Loc.T("bridge.paths_note");
        PhaseInfo.Title = Loc.T("bridge.phase_title");
        PhaseInfo.Message = Loc.T("bridge.phase_desc");
        RefreshButton.Content = Loc.T("bridge.refresh");
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
                new(Loc.T("bridge.transport.default"), "stdio",
                    Loc.T("bridge.transport.default_note")),
                new(Loc.T("bridge.transport.alt"), Loc.T("bridge.transport.alt_val"),
                    Loc.T("bridge.transport.alt_note")),
                new(Loc.T("bridge.transport.proto"), Loc.T("bridge.transport.proto_val"),
                    Loc.T("bridge.transport.proto_note")),
                new(Loc.T("bridge.transport.port_var"), "FETIH_BRIDGE_PORT",
                    Presence("FETIH_BRIDGE_PORT")),
                new(Loc.T("bridge.transport.token_var"), "FETIH_BRIDGE_TOKEN",
                    Presence("FETIH_BRIDGE_TOKEN") + Loc.T("bridge.transport.token_note")),
                new(Loc.T("bridge.transport.python_mod"),
                    moduleExists ? Loc.T("bridge.transport.mod_avail") : Loc.T("bridge.transport.mod_missing"),
                    moduleExists
                        ? Loc.T("bridge.transport.mod_avail_note")
                        : Loc.T("bridge.transport.mod_missing_note")),
            };

            PathRows.ItemsSource = new List<SettingRow>
            {
                new("FETIH_HOME", FetihPaths.FetihHome, DirectoryNote(FetihPaths.FetihHome)),
                new(Loc.T("bridge.path.config"), FetihPaths.ConfigYamlPath, FileNote(FetihPaths.ConfigYamlPath)),
                new(Loc.T("bridge.path.env"), FetihPaths.EnvFilePath, FileNote(FetihPaths.EnvFilePath)),
                new(Loc.T("bridge.path.repo"), FetihPaths.RepositoryRoot ?? "(bulunamadı)",
                    FetihPaths.RepositoryRoot is null
                        ? Loc.T("bridge.repo.outside")
                        : Loc.T("bridge.repo.catalog")),
                new(Loc.T("bridge.path.app"), AppInfo.BaseDirectory),
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
            EnvKeyPresence.Environment => Loc.T("bridge.env.active"),
            EnvKeyPresence.EnvFile => Loc.T("bridge.env.file"),
            _ => Loc.T("bridge.env.none"),
        };

    private static string FileNote(string path)
        => FetihPaths.SafeExists(path) ? Loc.T("bridge.file.exists") : Loc.T("bridge.file.missing");

    private static string DirectoryNote(string path)
        => FetihPaths.SafeExists(path) ? Loc.T("bridge.dir.exists") : Loc.T("bridge.dir.missing");
}
