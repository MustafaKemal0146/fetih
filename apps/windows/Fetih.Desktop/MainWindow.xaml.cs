using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Fetih.Desktop.Views;
using Fetih.Desktop.Views.Settings;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

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
    private NavigationViewItem? _chatItem;

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
        ChatSessionService.Shared.Dispatcher = DispatcherQueue;
        ChatSessionService.Shared.SessionsUpdated += OnChatSessionsUpdated;
        ChatSessionService.Shared.CurrentChanged += OnCurrentSessionChanged;

        RootNavigation.MenuItemsSource = _menuItems;
        RootNavigation.FooterMenuItemsSource = _footerItems;

        ToolTipService.SetToolTip(ActivityToggleButton, Loc.T("activity.toggle"));

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
                ChatSessionService.Shared.SessionsUpdated -= OnChatSessionsUpdated;
                ChatSessionService.Shared.CurrentChanged -= OnCurrentSessionChanged;
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

            _chatItem = CreateItem(Loc.T("nav.chat"), NavTags.Chat, Symbol.Message);
            _menuItems.Add(_chatItem);
            _menuItems.Add(CreateItem(Loc.T("nav.skills"), NavTags.Skills, Symbol.Library));
            _menuItems.Add(CreateItem(Loc.T("nav.findings"), NavTags.Findings, Symbol.Flag));
            _menuItems.Add(CreateItem(Loc.T("nav.files"), NavTags.Files, Symbol.Folder));

            _footerItems.Add(CreateItem(Loc.T("nav.diagnostics"), NavTags.Diagnostics, Symbol.Repair));
            _footerItems.Add(CreateItem(Loc.T("nav.settings"), NavTags.SettingsRoot, Symbol.Setting));

            // Yerleşik Ayarlar ögesi (cog) yükleme sırasında kendiliğinden
            // seçilip uygulamayı Ayarlar moduna atıyordu; kendi "Ayarlar"
            // öğemizi kullandığımız için tamamen kapatıyoruz.
            RootNavigation.IsSettingsVisible = false;
            RootNavigation.IsBackButtonVisible = NavigationViewBackButtonVisible.Collapsed;
            RootNavigation.IsBackEnabled = false;

            _mode = ShellMode.Normal;
            RebuildChatSubItems();
            RootNavigation.SelectedItem = _chatItem;
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

    // ── Sohbet Alt Menüsü Yönetimi ─────────────────────────────────────────

    private void OnChatSessionsUpdated()
    {
        EnqueueSafe(RebuildChatSubItems, nameof(RebuildChatSubItems));
    }

    private void OnCurrentSessionChanged(string? sid)
    {
        EnqueueSafe(SyncChatSelection, nameof(SyncChatSelection));
    }

    private void RebuildChatSubItems()
    {
        if (_chatItem is null || _mode != ShellMode.Normal) return;

        _chatItem.MenuItems.Clear();

        // 1. "＋ Yeni sohbet"
        var newChatItem = new NavigationViewItem
        {
            Content = Loc.T("chat.new_chat"),
            Tag = NavTags.ChatNew,
            Icon = new SymbolIcon(Symbol.Add)
        };
        AutomationProperties.SetAutomationId(newChatItem, NavTags.ChatNew);
        AutomationProperties.SetName(newChatItem, Loc.T("chat.new_chat"));
        _chatItem.MenuItems.Add(newChatItem);

        // 2. Kaydedilmiş oturumlar
        var sessions = ChatSessionService.Shared.Sessions;
        foreach (var session in sessions)
        {
            var sessionItem = CreateSessionMenuItem(session);
            _chatItem.MenuItems.Add(sessionItem);
        }

        // 3. Oturum varsa en altta "Tümünü sil"
        if (sessions.Count > 0)
        {
            var clearAllItem = new NavigationViewItem
            {
                Content = Loc.T("chat.delete_all"),
                Tag = NavTags.ChatClearAll,
                Icon = new SymbolIcon(Symbol.Delete)
            };
            AutomationProperties.SetAutomationId(clearAllItem, NavTags.ChatClearAll);
            AutomationProperties.SetName(clearAllItem, Loc.T("chat.delete_all"));
            _chatItem.MenuItems.Add(clearAllItem);
        }

        AttachChatParentFlyout(_chatItem);
        SyncChatSelection();
    }

    private NavigationViewItem CreateSessionMenuItem(ChatSessionInfo session)
    {
        var tb = new TextBlock
        {
            Text = session.Title,
            TextTrimming = TextTrimming.CharacterEllipsis,
            MaxLines = 1
        };
        var item = new NavigationViewItem
        {
            Content = tb,
            Tag = "session:" + session.Id,
            Icon = new SymbolIcon(Symbol.Message)
        };
        ToolTipService.SetToolTip(item, session.Title);
        AutomationProperties.SetAutomationId(item, "session_" + session.Id);
        AutomationProperties.SetName(item, session.Title);

        session.PropertyChanged += (s, e) =>
        {
            if (e.PropertyName == nameof(ChatSessionInfo.Title))
            {
                EnqueueSafe(() =>
                {
                    tb.Text = session.Title;
                    ToolTipService.SetToolTip(item, session.Title);
                    AutomationProperties.SetName(item, session.Title);
                }, "UpdateSessionTitle");
            }
        };

        var flyout = new MenuFlyout();
        var renameItem = new MenuFlyoutItem
        {
            Text = Loc.T("chat.rename"),
            Icon = new FontIcon { Glyph = "\uE8AC" }
        };
        renameItem.Click += async (_, _) => await PromptRenameSessionAsync(session);

        var deleteItem = new MenuFlyoutItem
        {
            Text = Loc.T("chat.delete"),
            Icon = new FontIcon { Glyph = "\uE74D" }
        };
        deleteItem.Click += async (_, _) => await PromptDeleteSessionAsync(session);

        flyout.Items.Add(renameItem);
        flyout.Items.Add(deleteItem);
        item.ContextFlyout = flyout;

        return item;
    }

    private void AttachChatParentFlyout(NavigationViewItem chatItem)
    {
        var flyout = new MenuFlyout();
        var newChatItem = new MenuFlyoutItem
        {
            Text = Loc.T("chat.new_chat"),
            Icon = new SymbolIcon(Symbol.Add)
        };
        newChatItem.Click += (_, _) =>
        {
            NavigateTo(NavTags.Chat);
            ChatSessionService.Shared.RequestNewChat();
        };
        flyout.Items.Add(newChatItem);

        if (ChatSessionService.Shared.Sessions.Count > 0)
        {
            var deleteAllItem = new MenuFlyoutItem
            {
                Text = Loc.T("chat.delete_all"),
                Icon = new FontIcon { Glyph = "\uE74D" }
            };
            deleteAllItem.Click += async (_, _) => await PromptDeleteAllSessionsAsync();
            flyout.Items.Add(deleteAllItem);
        }
        chatItem.ContextFlyout = flyout;
    }

    private void SyncChatSelection()
    {
        if (_suppressSelection || _mode != ShellMode.Normal || _chatItem is null) return;
        var curSid = ChatSessionService.Shared.CurrentSessionId;
        if (string.IsNullOrEmpty(curSid))
        {
            if (ContentFrame.Content is ChatPage)
            {
                _suppressSelection = true;
                RootNavigation.SelectedItem = _chatItem;
                _suppressSelection = false;
            }
            return;
        }

        foreach (var obj in _chatItem.MenuItems)
        {
            if (obj is NavigationViewItem nvi && nvi.Tag is string tag && tag == "session:" + curSid)
            {
                _suppressSelection = true;
                RootNavigation.SelectedItem = nvi;
                _suppressSelection = false;
                return;
            }
        }
    }

    private async Task PromptRenameSessionAsync(ChatSessionInfo session)
    {
        var input = new TextBox
        {
            Text = session.Title,
            Margin = new Thickness(0, 8, 0, 0)
        };
        input.Loaded += (_, _) =>
        {
            input.SelectAll();
            input.Focus(FocusState.Programmatic);
        };

        var dialog = new ContentDialog
        {
            Title = Loc.T("chat.rename"),
            Content = input,
            PrimaryButtonText = Loc.T("dialog.save"),
            CloseButtonText = Loc.T("dialog.cancel"),
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = Content.XamlRoot
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            var newTitle = input.Text.Trim();
            if (!string.IsNullOrEmpty(newTitle) && newTitle != session.Title)
            {
                await ChatSessionService.Shared.RenameAsync(session.Id, newTitle);
            }
        }
    }

    private async Task PromptDeleteSessionAsync(ChatSessionInfo session)
    {
        var dialog = new ContentDialog
        {
            Title = Loc.T("chat.delete_confirm_title"),
            Content = Loc.Format("chat.delete_confirm_body", session.Title),
            PrimaryButtonText = Loc.T("chat.delete"),
            CloseButtonText = Loc.T("dialog.cancel"),
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = Content.XamlRoot
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            await ChatSessionService.Shared.DeleteAsync(session.Id);
        }
    }

    private async Task PromptDeleteAllSessionsAsync()
    {
        var dialog = new ContentDialog
        {
            Title = Loc.T("chat.delete_all_confirm_title"),
            Content = Loc.T("chat.delete_all_confirm_body"),
            PrimaryButtonText = Loc.T("chat.delete_all"),
            CloseButtonText = Loc.T("dialog.cancel"),
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = Content.XamlRoot
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            await ChatSessionService.Shared.DeleteAllAsync();
        }
    }

    // ── Olaylar ─────────────────────────────────────────────────────────────

    private void NewChatAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        args.Handled = true;
        NavigateTo(NavTags.Chat);
        ChatSessionService.Shared.RequestNewChat();
    }

    // Sol menü (pane) genişliğini sürükleyerek ayarla — sol sohbet listesini
    // genişletip uzun adları tam görebilmek için. Üzerine gelmek bir şey
    // yapmaz; yalnızca sürükleme OpenPaneLength'i değiştirir (180–480 aralığı).
    private const double PaneMinWidth = 180;
    private const double PaneMaxWidth = 480;

    private void PaneSizer_DragDelta(object sender, Microsoft.UI.Xaml.Controls.Primitives.DragDeltaEventArgs e)
    {
        var newLen = Math.Clamp(RootNavigation.OpenPaneLength + e.HorizontalChange, PaneMinWidth, PaneMaxWidth);
        RootNavigation.OpenPaneLength = newLen;
        PaneSizer.Margin = new Thickness(newLen - PaneSizer.Width, 48, 0, 0);
    }

    // ── Sağ etkinlik paneli (issue #53): aç/kapat + genişlik sürükleme ──────────
    private const double ActivityMinWidth = 260;
    private const double ActivityMaxWidth = 640;
    private double _activityPanelWidth = 320;

    private bool ActivityPanelOpen => ActivityPanelColumn.Width.Value > 0;

    private void ActivityToggleButton_Click(object sender, RoutedEventArgs e)
    {
        if (ActivityPanelOpen)
        {
            ActivityPanelColumn.Width = new GridLength(0);
            ActivitySizer.Visibility = Visibility.Collapsed;
        }
        else
        {
            ActivityPanelColumn.Width = new GridLength(_activityPanelWidth);
            ActivitySizer.Visibility = Visibility.Visible;
        }
    }

    private void ActivitySizer_DragDelta(object sender, Microsoft.UI.Xaml.Controls.Primitives.DragDeltaEventArgs e)
    {
        // Tutamaç panelin SOL kenarında; sola sürükleyince panel genişler.
        var next = Math.Clamp(_activityPanelWidth - e.HorizontalChange, ActivityMinWidth, ActivityMaxWidth);
        _activityPanelWidth = next;
        ActivityPanelColumn.Width = new GridLength(next);
    }

    private async void RootNavigation_ItemInvoked(
        NavigationView sender,
        NavigationViewItemInvokedEventArgs args)
    {
        if (args.IsSettingsInvoked) return;

        if (args.InvokedItemContainer is NavigationViewItem nvi && nvi.Tag is string tag)
        {
            if (tag == NavTags.ChatNew)
            {
                NavigateTo(NavTags.Chat);
                ChatSessionService.Shared.RequestNewChat();
                _suppressSelection = true;
                RootNavigation.SelectedItem = _chatItem;
                _suppressSelection = false;
                return;
            }

            if (tag == NavTags.ChatClearAll)
            {
                await PromptDeleteAllSessionsAsync();
                return;
            }

            if (tag.StartsWith("session:", StringComparison.Ordinal))
            {
                var sid = tag["session:".Length..];
                var session = ChatSessionService.Shared.Sessions.FirstOrDefault(s => s.Id == sid);
                NavigateTo(NavTags.Chat);
                if (session is not null)
                {
                    ChatSessionService.Shared.RequestOpen(session);
                }
                return;
            }

            if (tag == NavTags.Chat)
            {
                NavigateTo(NavTags.Chat);
                return;
            }
        }
    }

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
                if (tag == NavTags.ChatNew)
                {
                    NavigateTo(NavTags.Chat);
                    ChatSessionService.Shared.RequestNewChat();
                    SyncChatSelection();
                    return;
                }

                if (tag == NavTags.ChatClearAll)
                {
                    SyncChatSelection();
                    _ = PromptDeleteAllSessionsAsync();
                    return;
                }

                if (tag.StartsWith("session:", StringComparison.Ordinal))
                {
                    var sid = tag["session:".Length..];
                    var session = ChatSessionService.Shared.Sessions.FirstOrDefault(s => s.Id == sid);
                    NavigateTo(NavTags.Chat);
                    if (session is not null)
                    {
                        ChatSessionService.Shared.RequestOpen(session);
                    }
                    return;
                }

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
        NavTags.Files => (typeof(FilesPage), null),
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
    public const string ChatNew = "nav_chat_new";
    public const string ChatClearAll = "nav_chat_clear_all";
    public const string Skills = "nav_skills";
    public const string Findings = "nav_findings";
    public const string Files = "nav_files";
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
