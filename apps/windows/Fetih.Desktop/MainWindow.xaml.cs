using System;
using System.Collections.ObjectModel;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Services;
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

        // Görev çubuğu / Alt+Tab ikonu. MSIX'siz derlemede paket manifesti
        // yok, dolayısıyla ikon çalışma zamanında bildirilmek zorunda.
        ApplyBrandIcon();

        // Başlık çubuğundaki alt başlık da yerelleştirilir; aksi hâlde arayüz
        // İngilizceyken burada Türkçe bir metin kalıyordu.
        TaglineText.Text = Loc.T("app.tagline");

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

        // Dil değişince (Görünüm ayarından) sol menüyü yeniden kur.
        Loc.LanguageChanged += OnLanguageChanged;

        // Sadeleştirilmiş ayar sayfalarındaki "Detaylı Mod'da aç" bağlantısı.
        ShellNavigation.Requested += OnShellNavigationRequested;

        // Pencere kapanınca Masaüstü Köprüsü alt sürecini de sonlandır.
        Closed += (_, _) =>
        {
            try
            {
                Loc.LanguageChanged -= OnLanguageChanged;
                ShellNavigation.Requested -= OnShellNavigationRequested;
                Bridge.BridgeClient.Shared.Dispose();
            }
            catch
            {
                // Kapanış sırasında hata yut; süreç zaten sonlanıyor.
            }
        };

    }

    /// <summary>Pencere ikonunu marka işaretine ayarlar (bkz. Services/BrandIcon.cs).</summary>
    private void ApplyBrandIcon()
    {
        try
        {
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            var id = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
            BrandIcon.Apply(Microsoft.UI.Windowing.AppWindow.GetFromWindowId(id));
        }
        catch (Exception ex)
        {
            App.LogCrash("MainWindow.ApplyBrandIcon", ex, ex.Message);
        }
    }

    /// <summary>Dil değişiminde: mevcut moda göre menüyü baştan kur.</summary>
    private void OnLanguageChanged()
    {
        EnqueueSafe(() =>
        {
            TaglineText.Text = Loc.T("app.tagline");
            Bridge.BridgeStatus.Shared.RefreshLabels();
            if (_mode == ShellMode.Settings)
            {
                BuildSettingsMenu();
            }
            else
            {
                BuildNormalMenu();
            }
        }, nameof(OnLanguageChanged));
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

            _menuItems.Add(CreateItem(Loc.T("nav.chat"), NavTags.Chat, Symbol.Message));
            _menuItems.Add(CreateItem(Loc.T("nav.skills"), NavTags.Skills, Symbol.Library));
            _menuItems.Add(CreateItem(Loc.T("nav.findings"), NavTags.Findings, Symbol.Flag));

            _footerItems.Add(CreateItem(Loc.T("nav.diagnostics"), NavTags.Diagnostics, Symbol.Repair));
            _footerItems.Add(CreateItem(Loc.T("nav.settings"), NavTags.SettingsRoot, Symbol.Setting));

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

            _menuItems.Add(new NavigationViewItemHeader { Content = Loc.T("settings.header.connection") });
            _menuItems.Add(CreateItem(Loc.T("settings.bridge"), NavTags.SettingsBridge, Symbol.Link));

            _menuItems.Add(new NavigationViewItemHeader { Content = Loc.T("settings.header.model_tools") });
            _menuItems.Add(CreateItem(Loc.T("settings.provider"), NavTags.SettingsProvider, Symbol.Target));
            _menuItems.Add(CreateItem(Loc.T("settings.tools"), NavTags.SettingsTools, Symbol.AllApps));
            _menuItems.Add(CreateItem(Loc.T("settings.agent"), NavTags.SettingsAgent, Symbol.Play));
            _menuItems.Add(CreateItem(Loc.T("settings.voice"), NavTags.SettingsVoice, Symbol.Microphone));

            _menuItems.Add(new NavigationViewItemHeader { Content = Loc.T("settings.header.security_exec") });
            _menuItems.Add(CreateItem(Loc.T("settings.permissions"), NavTags.SettingsPermissions, Symbol.Permissions));
            _menuItems.Add(CreateItem(Loc.T("settings.security"), NavTags.SettingsSecurity, Symbol.ProtectedDocument));
            _menuItems.Add(CreateItem(Loc.T("settings.sandbox"), NavTags.SettingsSandbox, Symbol.ProtectedDocument));
            _menuItems.Add(CreateItem(Loc.T("settings.shell"), NavTags.SettingsShell, Symbol.Admin));

            _menuItems.Add(new NavigationViewItemHeader { Content = Loc.T("settings.header.automation") });
            _menuItems.Add(CreateItem(Loc.T("settings.channels"), NavTags.SettingsChannels, Symbol.Message));
            _menuItems.Add(CreateItem(Loc.T("settings.memory"), NavTags.SettingsMemory, Symbol.Library));
            _menuItems.Add(CreateItem(Loc.T("settings.automation"), NavTags.SettingsAutomation, Symbol.Clock));
            _menuItems.Add(CreateItem(Loc.T("settings.appearance"), NavTags.SettingsAppearance, Symbol.View));

            _menuItems.Add(new NavigationViewItemHeader { Content = Loc.T("settings.header.app") });
            _menuItems.Add(CreateItem(Loc.T("settings.system"), NavTags.SettingsSystem, Symbol.Setting));

            // "Detaylı Mod" ham config editörüdür ve yukarıdaki sadeleştirilmiş
            // sayfalarla aynı türden bir sayfa DEĞİLDİR; bu yüzden bir ayraçla
            // ayrılmış, kendi "Gelişmiş" başlığı altında, kendine ait bir
            // ikonla (kod/geliştirici) tek başına durur.
            _menuItems.Add(new NavigationViewItemSeparator());
            _menuItems.Add(new NavigationViewItemHeader { Content = Loc.T("settings.header.advanced") });
            _menuItems.Add(CreateGlyphItem(Loc.T("settings.all"), NavTags.SettingsAll, "\uE943"));

            _footerItems.Add(CreateItem(Loc.T("nav.diagnostics"), NavTags.Diagnostics, Symbol.Repair));
            _footerItems.Add(CreateItem(Loc.T("settings.about"), NavTags.SettingsAbout, Symbol.Help));

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
        => Decorate(new NavigationViewItem { Icon = new SymbolIcon(symbol) }, content, tag);

    /// <summary>Segoe Fluent Icons kod noktasıyla menü ögesi (Symbol yetmediğinde).</summary>
    private static NavigationViewItem CreateGlyphItem(string content, string tag, string glyph)
        => Decorate(new NavigationViewItem { Icon = new FontIcon { Glyph = glyph } }, content, tag);

    private static NavigationViewItem Decorate(NavigationViewItem item, string content, string tag)
    {
        item.Content = content;
        item.Tag = tag;

        // UI Automation ile programatik gezinme/testi mümkün kılar.
        AutomationProperties.SetAutomationId(item, tag);
        AutomationProperties.SetName(item, content);
        return item;
    }

    /// <summary>
    /// Bir sayfanın ("Detaylı Mod'da aç" bağlantısı gibi) istediği gezinme.
    /// Sol menüdeki ögeyi de seçili hâle getirir ki kullanıcı nerede olduğunu
    /// görsün.
    /// </summary>
    private void OnShellNavigationRequested(string tag)
    {
        EnqueueSafe(() =>
        {
            if (_mode != ShellMode.Settings && tag.StartsWith("nav_settings", StringComparison.Ordinal))
            {
                BuildSettingsMenu();
            }

            foreach (var candidate in _menuItems)
            {
                if (candidate is NavigationViewItem { Tag: string itemTag } item &&
                    string.Equals(itemTag, tag, StringComparison.Ordinal))
                {
                    RootNavigation.SelectedItem = item;
                    return;
                }
            }

            NavigateTo(tag);
        }, nameof(OnShellNavigationRequested));
    }

    /// <summary>
    /// Durum rozetine tıklandı. Yalnızca çözülebilir bir hata varsa gezinir:
    /// model hatasında Model/Sağlayıcı sayfasına, taşıma hatasında Masaüstü
    /// Köprüsü sayfasına. Sağlıklıyken tıklama sessizce yutulur.
    /// </summary>
    private void StatusBadge_Click(object sender, RoutedEventArgs e)
    {
        var status = Bridge.BridgeStatus.Shared;
        if (!status.IsActionable)
        {
            return;
        }
        ShellNavigation.Request(status.ActionNavTag);
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
        NavTags.SettingsShell => (typeof(ShellPage), null),
        NavTags.SettingsAbout => (typeof(AboutPage), null),

        // ── Sadeleştirilmiş ayar sayfaları ──────────────────────────────────
        // Bunların hepsi TEK bir motordan (SimpleSettingsPage) üretilir; içerik
        // SimpleSettingsCatalog'dadır. Ham config anahtarları burada değil,
        // yalnızca Detaylı Mod'da görünür.
        NavTags.SettingsPermissions => (typeof(SimpleSettingsPage), (object)"permissions"),
        NavTags.SettingsSecurity => (typeof(SimpleSettingsPage), (object)"security"),
        NavTags.SettingsSandbox => (typeof(SimpleSettingsPage), (object)"sandbox"),
        NavTags.SettingsTools => (typeof(SimpleSettingsPage), (object)"tools"),
        NavTags.SettingsAgent => (typeof(SimpleSettingsPage), (object)"agent"),
        NavTags.SettingsChannels => (typeof(SimpleSettingsPage), (object)"channels"),
        NavTags.SettingsMemory => (typeof(SimpleSettingsPage), (object)"memory"),
        NavTags.SettingsAutomation => (typeof(SimpleSettingsPage), (object)"automation"),
        NavTags.SettingsAppearance => (typeof(SimpleSettingsPage), (object)"appearance"),
        NavTags.SettingsSystem => (typeof(SimpleSettingsPage), (object)"system"),

        // ── Detaylı Mod ─────────────────────────────────────────────────────
        // Ham config editörünün TEK kullanım yeri: filtresiz, bütün kökleri
        // kendi bölüm başlığıyla gösterir.
        NavTags.SettingsAll => (typeof(ConfigEditorPage),
            (object)(Loc.T("settings.all") + "|")),

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
    public const string SettingsShell = "nav_settings_shell";
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
