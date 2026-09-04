using System;
using System.Collections.ObjectModel;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Views;
using Fetih.Desktop.Views.Settings;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop;

/// <summary>Kabuğun sol menüsünün hangi kümeyi gösterdiği.</summary>
internal enum ShellMode
{
    /// <summary>Sohbet / Yetenekler / Bulgular + Tanılama + yerleşik Ayarlar.</summary>
    Normal,

    /// <summary>Ayarlar alt bölümleri (menünün tamamı değişmiş durumda).</summary>
    Settings,
}

/// <summary>
/// NavigationView kabuğu. Menü koleksiyonları XAML'de sabit değil, burada
/// <see cref="ObservableCollection{T}"/> olarak kurulur; "Ayarlar" seçildiğinde
/// sol menünün tamamı Ayarlar alt bölümleriyle değiştirilir ve geri tuşuyla
/// normal moda dönülür (bkz. docs/windows-app-plani.md).
/// </summary>
public sealed partial class MainWindow : Window
{
    private readonly ObservableCollection<object> _menuItems = new();
    private readonly ObservableCollection<object> _footerItems = new();

    /// <summary>Menü yeniden kurulurken tetiklenen seçim olaylarını bastırır.</summary>
    private bool _suppressSelection;

    private ShellMode _mode = ShellMode.Normal;

    /// <summary>İlk menü kurulumu yalnızca bir kez, kontrol yüklenince yapılır.</summary>
    private bool _shellInitialized;

    public MainWindow()
    {
        InitializeComponent();

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        // Köprü durumu güncellemeleri arka plandan gelir ama x:Bind'e bağlıdır;
        // UI iş parçacığına yönlendirebilmesi için kuyruğu ver.
        Bridge.BridgeStatus.Shared.Dispatcher = DispatcherQueue;

        RootNavigation.MenuItemsSource = _menuItems;
        RootNavigation.FooterMenuItemsSource = _footerItems;

        // İlk seçimi kurucuda yapmak WinUI'de kontrol henüz yüklenmediği için
        // "tutmuyor" ve yükleme sırasında yerleşik Ayarlar ögesi kendiliğinden
        // seçilip Ayarlar moduna geçebiliyor. Bu yüzden ilk menüyü NavigationView
        // Loaded olduğunda kuruyoruz.
        RootNavigation.Loaded += RootNavigation_Loaded;

        // Pencere kapanınca Masaüstü Köprüsü alt sürecini de sonlandır.
        Closed += (_, _) =>
        {
            try
            {
                Bridge.BridgeClient.Shared.Dispose();
            }
            catch
            {
                // Kapanış sırasında hata yut; süreç zaten sonlanıyor.
            }
        };

    }

    private void RootNavigation_Loaded(object sender, RoutedEventArgs e)
    {
        if (_shellInitialized)
        {
            return;
        }
        _shellInitialized = true;
        BuildNormalMenu();
    }

    /// <summary>Başlık çubuğundaki rozeti besleyen paylaşılan köprü durumu.</summary>
    public BridgeStatus Status => BridgeStatus.Shared;

    // ── Menü kurulumu ───────────────────────────────────────────────────────

    /// <summary>Normal mod: Sohbet / Yetenekler / Bulgular + Tanılama + Ayarlar.</summary>
    private void BuildNormalMenu()
    {
        _suppressSelection = true;
        try
        {
            RootNavigation.SelectedItem = null;
            _menuItems.Clear();
            _footerItems.Clear();

            _menuItems.Add(CreateItem("Sohbet", NavTags.Chat, Symbol.Message));
            _menuItems.Add(CreateItem("Yetenekler", NavTags.Skills, Symbol.Library));
            _menuItems.Add(CreateItem("Bulgular", NavTags.Findings, Symbol.Flag));

            _footerItems.Add(CreateItem("Tanılama", NavTags.Diagnostics, Symbol.Repair));
            _footerItems.Add(CreateItem("Ayarlar", NavTags.SettingsRoot, Symbol.Setting));

            // Yerleşik Ayarlar ögesi (cog) yükleme sırasında kendiliğinden
            // seçilip uygulamayı Ayarlar moduna atıyordu; kendi "Ayarlar"
            // öğemizi kullandığımız için tamamen kapatıyoruz.
            RootNavigation.IsSettingsVisible = false;
            RootNavigation.IsBackButtonVisible = NavigationViewBackButtonVisible.Collapsed;
            RootNavigation.IsBackEnabled = false;

            _mode = ShellMode.Normal;
            RootNavigation.SelectedItem = _menuItems[0];
        }
        finally
        {
            _suppressSelection = false;
        }

        NavigateTo(NavTags.Chat);
    }

    /// <summary>
    /// Ayarlar modu: sol menünün TAMAMI değişir. Kategori başlıkları
    /// <see cref="NavigationViewItemHeader"/> ile çizilir; yerleşik Ayarlar
    /// ögesi gizlenir ve yerini geri tuşu alır.
    /// </summary>
    private void BuildSettingsMenu()
    {
        _suppressSelection = true;
        try
        {
            RootNavigation.SelectedItem = null;
            RootNavigation.IsSettingsVisible = false;

            _menuItems.Clear();
            _footerItems.Clear();

            _menuItems.Add(new NavigationViewItemHeader { Content = "Bağlantı" });
            _menuItems.Add(CreateItem("Masaüstü Köprüsü", NavTags.SettingsBridge, Symbol.Link));

            _menuItems.Add(new NavigationViewItemHeader { Content = "Model ve Araçlar" });
            _menuItems.Add(CreateItem("Model ve Sağlayıcı", NavTags.SettingsProvider, Symbol.Target));
            _menuItems.Add(CreateItem("Araçlar", NavTags.SettingsTools, Symbol.AllApps));
            _menuItems.Add(CreateItem("Ajan", NavTags.SettingsAgent, Symbol.Play));
            _menuItems.Add(CreateItem("Ses", NavTags.SettingsVoice, Symbol.Microphone));

            _menuItems.Add(new NavigationViewItemHeader { Content = "Güvenlik ve Yürütme" });
            _menuItems.Add(CreateItem("İzinler", NavTags.SettingsPermissions, Symbol.Permissions));
            _menuItems.Add(CreateItem("Güvenlik", NavTags.SettingsSecurity, Symbol.ProtectedDocument));
            _menuItems.Add(CreateItem("Sandbox", NavTags.SettingsSandbox, Symbol.ProtectedDocument));

            _menuItems.Add(new NavigationViewItemHeader { Content = "Otomasyon ve Bağlam" });
            _menuItems.Add(CreateItem("Kanallar", NavTags.SettingsChannels, Symbol.Message));
            _menuItems.Add(CreateItem("Hafıza", NavTags.SettingsMemory, Symbol.Library));
            _menuItems.Add(CreateItem("Otomasyon", NavTags.SettingsAutomation, Symbol.Clock));
            _menuItems.Add(CreateItem("Görünüm", NavTags.SettingsAppearance, Symbol.View));

            _menuItems.Add(new NavigationViewItemHeader { Content = "Gelişmiş" });
            _menuItems.Add(CreateItem("Sistem", NavTags.SettingsSystem, Symbol.Setting));
            _menuItems.Add(CreateItem("Tüm Ayarlar", NavTags.SettingsAll, Symbol.List));

            _footerItems.Add(CreateItem("Tanılama", NavTags.Diagnostics, Symbol.Repair));
            _footerItems.Add(CreateItem("Hakkında", NavTags.SettingsAbout, Symbol.Help));

            RootNavigation.IsBackButtonVisible = NavigationViewBackButtonVisible.Visible;
            RootNavigation.IsBackEnabled = true;

            _mode = ShellMode.Settings;
            RootNavigation.SelectedItem = _menuItems[1];
        }
        finally
        {
            _suppressSelection = false;
        }

        NavigateTo(NavTags.SettingsBridge);
    }

    private static NavigationViewItem CreateItem(string content, string tag, Symbol symbol)
    {
        var item = new NavigationViewItem
        {
            Content = content,
            Tag = tag,
            Icon = new SymbolIcon(symbol),
        };

        // UI Automation ile programatik gezinme/testi mümkün kılar.
        AutomationProperties.SetAutomationId(item, tag);
        AutomationProperties.SetName(item, content);
        return item;
    }

    // ── Olaylar ─────────────────────────────────────────────────────────────

    private void RootNavigation_SelectionChanged(
        NavigationView sender,
        NavigationViewSelectionChangedEventArgs args)
    {
        if (_suppressSelection || !_shellInitialized)
        {
            return;
        }

        try
        {
            // Yerleşik Ayarlar ögesini kapattık; kendi "Ayarlar" öğemiz seçilince
            // Ayarlar moduna geçilir. (args.IsSettingsSelected artık tetiklenmez
            // ama olası bir kenar durum için güvenli tarafta kalıyoruz.)
            if (args.IsSettingsSelected ||
                (args.SelectedItem is NavigationViewItem { Tag: NavTags.SettingsRoot }))
            {
                // NavigationView'ın kendi seçim geçişi bitmeden koleksiyonları
                // değiştirmek kararsız davranışa yol açıyor; bir sonraki
                // dispatcher turuna erteliyoruz.
                EnqueueSafe(BuildSettingsMenu, nameof(BuildSettingsMenu));
                return;
            }

            if (args.SelectedItem is NavigationViewItem { Tag: string tag })
            {
                NavigateTo(tag);
            }
        }
        catch (Exception ex)
        {
            // Navigasyon sırasında beklenmeyen bir istisna tüm pencereyi (ve
            // süreci) kapatmasın diye burada bilerek yutuyoruz — App.xaml.cs'teki
            // ile aynı dosyaya (%LOCALAPPDATA%\Fetih\Desktop\crash.log) elle
            // yazıyoruz, çünkü burada yakalanan bir istisna artık "unhandled"
            // sayılmaz ve App'in global handler'ları tetiklenmez.
            App.LogCrash("MainWindow.RootNavigation_SelectionChanged", ex, ex.Message);
        }
    }

    /// <summary>
    /// Ayarlar modundayken geri tuşu normal moda döndürür ve Sohbet'i açar.
    /// </summary>
    private void RootNavigation_BackRequested(
        NavigationView sender,
        NavigationViewBackRequestedEventArgs args)
    {
        try
        {
            if (_mode == ShellMode.Settings)
            {
                EnqueueSafe(BuildNormalMenu, nameof(BuildNormalMenu));
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("MainWindow.RootNavigation_BackRequested", ex, ex.Message);
        }
    }

    private void EnqueueSafe(Action action, string label)
    {
        var queued = DispatcherQueue.TryEnqueue(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                App.LogCrash($"MainWindow.{label}", ex, ex.Message);
            }
        });

        if (!queued)
        {
            // Kuyruğa alınamadıysa doğrudan çalıştır; yine de korumalı.
            try
            {
                action();
            }
            catch (Exception ex)
            {
                App.LogCrash($"MainWindow.{label} (inline)", ex, ex.Message);
            }
        }
    }

    // ── Gezinme ─────────────────────────────────────────────────────────────

    private void NavigateTo(string tag)
    {
        try
        {
            var (pageType, parameter) = ResolvePage(tag);
            if (pageType is null)
            {
                return;
            }

            // Aynı sayfa türü ama farklı parametreyle (jenerik editör bölümleri)
            // yeniden gezinmek gerekir; bu yüzden parametreliyken tür eşitliğine
            // bakmadan her zaman gezin.
            if (parameter is null && ContentFrame.Content?.GetType() == pageType)
            {
                return;
            }

            if (parameter is null)
            {
                ContentFrame.Navigate(pageType);
            }
            else
            {
                ContentFrame.Navigate(pageType, parameter);
            }
        }
        catch (Exception ex)
        {
            App.LogCrash($"MainWindow.NavigateTo({tag})", ex, ex.Message);
        }
    }

    /// <summary>Etiketi (sayfa türü, gezinme parametresi) çiftine çözer.</summary>
    private static (Type? Page, object? Param) ResolvePage(string tag) => tag switch
    {
        NavTags.Chat => (typeof(ChatPage), null),
        NavTags.Skills => (typeof(SkillsPage), null),
        NavTags.Findings => (typeof(FindingsPage), null),
        NavTags.Diagnostics => (typeof(DiagnosticsPage), null),
        NavTags.SettingsBridge => (typeof(BridgePage), null),
        NavTags.SettingsProvider => (typeof(ProviderPage), null),
        NavTags.SettingsVoice => (typeof(VoicePage), null),
        NavTags.SettingsPermissions => (typeof(PermissionsPage), null),
        NavTags.SettingsSandbox => (typeof(SandboxPage), null),
        NavTags.SettingsAbout => (typeof(AboutPage), null),

        // Jenerik, düzenlenebilir config editörü bölümleri.
        NavTags.SettingsTools => (typeof(ConfigEditorPage),
            (object)"Araçlar|toolsets,agent"),
        NavTags.SettingsAgent => (typeof(ConfigEditorPage),
            (object)"Ajan|agent,browser,web"),
        NavTags.SettingsSecurity => (typeof(ConfigEditorPage),
            (object)"Güvenlik|security"),
        NavTags.SettingsChannels => (typeof(ConfigEditorPage),
            (object)"Kanallar|slack,discord,telegram,whatsapp,mattermost,matrix"),
        NavTags.SettingsMemory => (typeof(ConfigEditorPage),
            (object)"Hafıza ve Bağlam|memory,curator,honcho,context,compression,prompt_caching"),
        NavTags.SettingsAutomation => (typeof(ConfigEditorPage),
            (object)"Otomasyon|cron,kanban,goals,delegation"),
        NavTags.SettingsAppearance => (typeof(ConfigEditorPage),
            (object)"Görünüm|display,dashboard,privacy"),
        NavTags.SettingsSystem => (typeof(ConfigEditorPage),
            (object)"Sistem|logging,sessions,checkpoints,updates,network,lsp"),
        NavTags.SettingsAll => (typeof(ConfigEditorPage),
            (object)"Tüm Ayarlar|"),

        _ => (null, null),
    };
}

/// <summary>
/// Gezinme etiketleri. Aynı zamanda UI Automation kimliği (AutomationId)
/// olarak kullanılır, bu yüzden sabit ve kararlıdırlar.
/// </summary>
internal static class NavTags
{
    public const string Chat = "nav_chat";
    public const string Skills = "nav_skills";
    public const string Findings = "nav_findings";
    public const string Diagnostics = "nav_diagnostics";
    public const string SettingsRoot = "nav_settings_root";
    public const string SettingsBridge = "nav_settings_bridge";
    public const string SettingsProvider = "nav_settings_provider";
    public const string SettingsVoice = "nav_settings_voice";
    public const string SettingsPermissions = "nav_settings_permissions";
    public const string SettingsSandbox = "nav_settings_sandbox";
    public const string SettingsAbout = "nav_settings_about";

    // Jenerik config editörü bölümleri (envantere göre).
    public const string SettingsTools = "nav_settings_tools";
    public const string SettingsAgent = "nav_settings_agent";
    public const string SettingsSecurity = "nav_settings_security";
    public const string SettingsChannels = "nav_settings_channels";
    public const string SettingsMemory = "nav_settings_memory";
    public const string SettingsAutomation = "nav_settings_automation";
    public const string SettingsAppearance = "nav_settings_appearance";
    public const string SettingsSystem = "nav_settings_system";
    public const string SettingsAll = "nav_settings_all";
}
