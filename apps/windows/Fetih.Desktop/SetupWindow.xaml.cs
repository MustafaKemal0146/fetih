using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Services;
using Fetih.Desktop.Setup;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Graphics;

namespace Fetih.Desktop;

/// <summary>
/// İlk kurulum sihirbazı.
///
/// <para>İki tasarım kararı bu dosyanın şeklini belirliyor:</para>
///
/// <para><b>1. Sağlayıcı listesi çalışma zamanından gelir.</b> Eskiden elle
/// tutulan C# tablosundan geliyordu; oradaki bir kimlik CLI'nin kayıt
/// defterinden saptığında sihirbaz "kurulum tamamlandı" diyor, ilk mesaj
/// <c>Unknown provider</c> ile ölüyordu. Artık liste
/// <see cref="ProviderCatalog"/> üzerinden <c>providers.catalog</c>
/// RPC'sinden gelir.</para>
///
/// <para><b>2. Her sağlayıcıya aynı soru sorulmaz.</b> Ollama'ya "API
/// anahtarın nedir" diye sormak anlamsız — sorulacak şey daemon'ın ayakta
/// olup olmadığıdır. Gemini/Codex'e anahtar sormak da yanlış: onlar tarayıcı
/// oturumu ister. Panel, seçilen sağlayıcının <see cref="ProviderKind"/>
/// değerine göre değişir.</para>
/// </summary>
public sealed partial class SetupWindow : Window
{
    private readonly ObservableCollection<StepRow> _rows = new();
    private readonly SetupContext _ctx = new();
    private CancellationTokenSource? _cts;
    private ProviderEntry? _selected;

    /// <summary>Sihirbazın kaç görsel adımı var (nokta göstergesi bunu çizer).</summary>
    private const int TotalPhases = 3;
    private int _phase = 1;

    private static readonly string JournalPath = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Fetih", "Desktop", "setup-journal.jsonl");

    public SetupWindow()
    {
        InitializeComponent();
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        // Kurulum sırasında köprü bağlanır; durum güncellemelerini UI'ya yönlendir.
        Bridge.BridgeStatus.Shared.Dispatcher = DispatcherQueue;

        StepList.ItemsSource = _rows;

        // Bütün sabit metinler tek yerden gelir; XAML'de metin yok.
        ApplyLanguage();

        // Ortalamayı kurucuda DEĞİL, ilk etkinleşmede yap: WinUI pencereyi
        // gösterirken kendi varsayılan yerleşimini uyguluyor ve kurucudaki
        // konumlandırmayı kısmen eziyordu (pencere ekranın solunda kalıyordu).
        Activated += OnFirstActivated;

        // Sihirbaz köprüyü BAŞLATIR (bkz. StartDesktopBridgeStep →
        // BridgeClient.Shared.EnsureConnectedAsync). Pencere kapanınca bu alt
        // süreç sonlandırılmazsa arkada yetim python süreci kalıyordu; her
        // aç-kapa döngüsü kalıcı bir sızıntı bırakıyordu.
        Closed += OnWindowClosed;

        RenderStepDots();
        PopulateProviders(ProviderRegistry.All);

        // Köprü ayağa kalktığında listeyi KANONİK katalogla değiştir.
        _ = RefreshCatalogAsync();
    }

    // ── Yerelleştirme ────────────────────────────────────────────────────────

    /// <summary>
    /// Penceredeki bütün görünür metni etkin dile göre yeniden yazar.
    ///
    /// <para>XAML'de sabit metin bırakılmadı: aynı cümle iki yerde durunca dil
    /// değişiminde biri güncellenip diğeri eski kalıyordu. Etiketlerin yanı sıra
    /// erişilebilirlik adları da burada kurulur, çünkü ekran okuyucu düğmeyi
    /// içeriğinden değil <c>AutomationProperties.Name</c>'den okur.</para>
    /// </summary>
    private void ApplyLanguage()
    {
        Title = Loc.T("setup.window_title");
        HeadingText.Text = Loc.T("setup.heading");

        // 1) Karşılama
        // Marka işareti görsel bir logodur; ekran okuyucuya ne olduğunu yazıyla
        // söyle, çünkü içindeki vektör metni okunamaz.
        AutomationProperties.SetName(Brandmark, Loc.T("setup.brandmark"));
        WelcomeTitle.Text = Loc.T("setup.welcome.title");
        WelcomeBody.Text = Loc.T("setup.welcome.body");
        SecurityTitle.Text = Loc.T("setup.security.title");
        SecurityBody.Text = Loc.T("setup.security.body");
        SetButton(WelcomeContinueButton, "setup.continue");

        // 2) Sağlayıcı
        ProviderTitle.Text = Loc.T("setup.provider.title");
        ProviderBody.Text = Loc.T("setup.provider.body");
        ProviderCombo.Header = Loc.T("setup.provider.header");
        AutomationProperties.SetName(ProviderCombo, Loc.T("setup.provider.header"));

        KeyBox.Header = Loc.T("setup.api_key.header");
        KeyBox.PlaceholderText = Loc.T("setup.api_key.placeholder");
        AutomationProperties.SetName(KeyBox, Loc.T("setup.api_key.header"));

        SignupLink.Content = Loc.T("setup.signup_link");

        SetButton(LocalReprobeButton, "setup.reprobe");
        LocalInstallLink.Content = Loc.T("setup.local_install_link");

        SetButton(CliLoginButton, "setup.cli_login");
        SetButton(CliLoginCheckButton, "setup.cli_check");

        AwsBar.Title = Loc.T("setup.aws.title");
        AwsBar.Message = Loc.T("setup.aws.message");

        ModelCombo.Header = Loc.T("setup.model.header");
        AutomationProperties.SetName(ModelCombo, Loc.T("setup.model.header"));

        SetButton(BackButton, "setup.back");
        SetButton(InstallButton, "setup.install");

        // 3) Kurulum ilerlemesi
        ProgressTitle.Text = Loc.T("setup.progress.title");
        SetButton(RetryButton, "setup.retry");
        SetButton(BackToProviderButton, "setup.back_to_provider");
        SetButton(GoToChatButton, "setup.go_to_chat");

        RenderStepDots();
    }

    /// <summary>Düğmenin hem görünen metnini hem erişilebilirlik adını tek anahtardan kurar.</summary>
    private static void SetButton(Button button, string key)
    {
        var text = Loc.T(key);
        button.Content = text;
        AutomationProperties.SetName(button, text);
    }

    /// <summary>
    /// Pencere kapanışı: abonelikleri geri çıkar ve Masaüstü Köprüsü alt
    /// sürecini sonlandır. <see cref="MainWindow"/> ile aynı desen; kapanış
    /// yolunda hata yutsun ki kapanma engellenmesin (süreç zaten sonlanıyor).
    /// </summary>
    private void OnWindowClosed(object sender, WindowEventArgs args)
    {
        try
        {
            Activated -= OnFirstActivated;
            Closed -= OnWindowClosed;
            _cts?.Cancel();

            // "Sohbete geç" akışında köprüyü YENİ pencere devralır
            // (bkz. GoToChat_Click); bu durumda kapatma işi ona aittir, aksi
            // hâlde yeni açılan sohbet penceresi köprüsüz kalırdı.
            if (ReferenceEquals(App.MainAppWindow, this))
            {
                Bridge.BridgeClient.Shared.Dispose();
            }
        }
        catch
        {
            // Kapanış sırasında hata yut.
        }
    }

    /// <summary>
    /// Pencereyi çalışma alanının ortasına al.
    ///
    /// <para>WinUI penceresi varsayılan olarak işletim sisteminin seçtiği
    /// kaskad konumunda açılır; ilk kurulum ekranının ekranın bir köşesinde
    /// belirmesi karşılama ekranı gibi durmuyordu.</para>
    /// </summary>
    private void OnFirstActivated(object sender, WindowActivatedEventArgs e)
    {
        Activated -= OnFirstActivated;
        CenterOnScreen();
    }

    private void CenterOnScreen()
    {
        try
        {
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            var id = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
            var appWindow = Microsoft.UI.Windowing.AppWindow.GetFromWindowId(id);
            if (appWindow is null)
            {
                return;
            }

            BrandIcon.Apply(appWindow);

            const int width = 900;
            const int height = 720;

            // Pencerenin bulunduğu ekranın ÇALIŞMA ALANI (görev çubuğu hariç).
            var area = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(
                id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
            var work = area?.WorkArea ?? new RectInt32(0, 0, width, height);

            // Küçük ekranlarda çalışma alanına sığdır, sonra ortala.
            var w = Math.Min(width, Math.Max(480, work.Width - 40));
            var h = Math.Min(height, Math.Max(400, work.Height - 40));

            appWindow.Resize(new SizeInt32(w, h));

            // Konumu, sistemin GERÇEKTEN verdiği boyuta göre hesapla: bazı
            // ölçek/DPI ayarlarında istenen boyut birebir uygulanmıyor ve
            // istenen boyutla ortalamak pencereyi merkezden kaydırıyordu.
            var actual = appWindow.Size;
            appWindow.Move(new PointInt32(
                work.X + ((work.Width - actual.Width) / 2),
                work.Y + ((work.Height - actual.Height) / 2)));
        }
        catch (Exception ex)
        {
            // Konumlandırma başarısızsa pencere yine de açılsın.
            App.LogCrash("SetupWindow.CenterOnScreen", ex, ex.Message);
        }
    }

    // ── Adım göstergesi (●●○○) ───────────────────────────────────────────────

    /// <summary>
    /// Nokta göstergesini çizer: tamamlanan ve içinde bulunulan adımlar dolu,
    /// kalanlar boş. Yüzdesiz bir ProgressBar "kaç adım kaldı" sorusunu
    /// yanıtlamıyordu.
    /// </summary>
    private void RenderStepDots()
    {
        StepDots.Children.Clear();
        for (var i = 1; i <= TotalPhases; i++)
        {
            var filled = i <= _phase;
            var dot = new Ellipse
            {
                Width = filled ? 9 : 8,
                Height = filled ? 9 : 8,
                VerticalAlignment = VerticalAlignment.Center,
                // Dolu nokta marka kırmızısı: sistem vurgu rengi kullanıcıya
                // göre değişiyor ve FETİH'in kırmızısıyla çakışabiliyordu.
                Fill = filled
                    ? Brush("FetihBloodBrush")
                    : Brush("ControlStrongFillColorDisabledBrush"),
            };
            AutomationProperties.SetAutomationId(dot, "setup_dot_" + i);
            AutomationProperties.SetName(
                dot,
                string.Format(Loc.T("setup.dot.name"), i, TotalPhases)
                    + (filled ? Loc.T("setup.dot.done") : ""));
            StepDots.Children.Add(dot);
        }
    }

    private static Brush Brush(string key)
    {
        try
        {
            if (Application.Current?.Resources is { } r && r.TryGetValue(key, out var v) && v is Brush b)
            {
                return b;
            }
        }
        catch { }
        return new SolidColorBrush(Microsoft.UI.Colors.Gray);
    }

    private void GoToPhase(int phase)
    {
        _phase = Math.Clamp(phase, 1, TotalPhases);
        WelcomePanel.Visibility = _phase == 1 ? Visibility.Visible : Visibility.Collapsed;
        ProviderPanel.Visibility = _phase == 2 ? Visibility.Visible : Visibility.Collapsed;
        ProgressPanel.Visibility = _phase == 3 ? Visibility.Visible : Visibility.Collapsed;
        RenderStepDots();
    }

    // ── Sağlayıcı listesi ────────────────────────────────────────────────────

    private async Task RefreshCatalogAsync()
    {
        try
        {
            var live = await ProviderCatalog.RefreshAsync().ConfigureAwait(false);
            DispatcherQueue.TryEnqueue(() =>
            {
                var keep = (ProviderCombo.SelectedItem as ComboBoxItem)?.Tag as string;
                PopulateProviders(live, keep);
            });
        }
        catch
        {
            // Köprü henüz yoksa gömülü yedek listeyle devam.
        }
    }

    private void PopulateProviders(IReadOnlyList<ProviderEntry> providers, string? preferId = null)
    {
        ProviderCombo.Items.Clear();
        foreach (var p in providers)
        {
            var suffix = p.IsLocal
                ? Loc.T("setup.provider.local")
                : p.IsAggregator ? Loc.T("setup.provider.aggregator") : "";
            ProviderCombo.Items.Add(new ComboBoxItem { Content = p.Label + suffix, Tag = p.Id });
        }

        // Varsayılan: kullanıcının zaten seçtiği, yoksa Groq (ücretsiz başlangıç).
        var want = preferId ?? "groq";
        for (var i = 0; i < ProviderCombo.Items.Count; i++)
        {
            if (ProviderCombo.Items[i] is ComboBoxItem item && (item.Tag as string) == want)
            {
                ProviderCombo.SelectedIndex = i;
                return;
            }
        }
        if (ProviderCombo.Items.Count > 0)
        {
            ProviderCombo.SelectedIndex = 0;
        }
    }

    private ProviderEntry? SelectedProvider()
        => ProviderCombo.SelectedItem is ComboBoxItem { Tag: string id } ? ProviderCatalog.ById(id) : null;

    /// <summary>
    /// Seçim değişti: paneli sağlayıcının TÜRÜNE göre yeniden kur ve model
    /// listesini canlı katalogdan doldur.
    /// </summary>
    private void ProviderCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var p = SelectedProvider();
        _selected = p;
        if (p is null)
        {
            return;
        }

        ApiKeySection.Visibility = Visibility.Collapsed;
        LocalSection.Visibility = Visibility.Collapsed;
        CliLoginSection.Visibility = Visibility.Collapsed;
        AwsSection.Visibility = Visibility.Collapsed;
        SignupLink.Visibility = Visibility.Collapsed;
        LocalInstallLink.Visibility = Visibility.Collapsed;

        switch (p.Kind)
        {
            case ProviderKind.LocalServer:
                LocalSection.Visibility = Visibility.Visible;
                KeyHint.Text = Loc.T("setup.provider.local.hint");
                _ = ProbeLocalAsync(p);
                break;

            case ProviderKind.CliLogin:
            case ProviderKind.OAuthBrowser:
                CliLoginSection.Visibility = Visibility.Visible;
                CliLoginBar.Severity = InfoBarSeverity.Informational;
                CliLoginBar.Title = Loc.T("setup.cli.title");
                CliLoginBar.Message = string.Format(Loc.T("setup.cli.message"), p.Label);
                KeyHint.Text = "";
                _ = CheckCliLoginAsync(p, announceOnly: true);
                break;

            case ProviderKind.AwsSdk:
                AwsSection.Visibility = Visibility.Visible;
                KeyHint.Text = "";
                break;

            default:
                ApiKeySection.Visibility = Visibility.Visible;
                KeyHint.Text = p.ApiKeyEnvVars.Count > 0
                    ? string.Format(Loc.T("setup.key.hint.env"), p.ApiKeyEnvVars[0])
                    : Loc.T("setup.key.hint.none");
                if (!string.IsNullOrWhiteSpace(p.SignupUrl))
                {
                    SignupLink.NavigateUri = new Uri(p.SignupUrl);
                    SignupLink.Content = string.Format(Loc.T("setup.signup_link.url"), p.SignupUrl);
                    SignupLink.Visibility = Visibility.Visible;
                }
                break;
        }

        _ = LoadModelsAsync(p);
    }

    // ── Yerel sunucu yoklaması ───────────────────────────────────────────────

    /// <summary>
    /// Yerel daemon ayakta mı, hangi modeller inik? Cevap köprüden gelir
    /// (<c>providers.probe_local</c>), yani gerçekten uç noktaya bakılır.
    /// </summary>
    private async Task ProbeLocalAsync(ProviderEntry p)
    {
        LocalStatusBar.Severity = InfoBarSeverity.Informational;
        LocalStatusBar.Title = Loc.T("setup.probing");
        LocalStatusBar.Message = p.DefaultBaseUrl;

        try
        {
            var res = await Bridge.BridgeClient.Shared
                .ProvidersProbeLocalAsync(p.Id, p.DefaultBaseUrl).ConfigureAwait(false);

            var running = res.TryGetProperty("running", out var r) && r.GetBoolean();
            var models = new List<string>();
            if (res.TryGetProperty("models", out var ms) &&
                ms.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var m in ms.EnumerateArray())
                {
                    if (m.ValueKind == System.Text.Json.JsonValueKind.String)
                    {
                        models.Add(m.GetString() ?? "");
                    }
                }
            }
            var endpoint = res.TryGetProperty("endpoint", out var ep) ? (ep.GetString() ?? "") : "";

            DispatcherQueue.TryEnqueue(() =>
            {
                if (!running)
                {
                    LocalStatusBar.Severity = InfoBarSeverity.Error;
                    LocalStatusBar.Title = string.Format(Loc.T("setup.local.not_found"), p.Label);
                    LocalStatusBar.Message = string.Format(Loc.T("setup.local.not_found.msg"), endpoint);
                    if (!string.IsNullOrWhiteSpace(p.SignupUrl))
                    {
                        LocalInstallLink.NavigateUri = new Uri(p.SignupUrl);
                        LocalInstallLink.Content =
                            string.Format(Loc.T("setup.local_install_link.url"), p.SignupUrl);
                        LocalInstallLink.Visibility = Visibility.Visible;
                    }
                    SetModels(new List<string>(), "");
                    ModelHint.Text = Loc.T("setup.local.no_models.hint");
                    return;
                }

                if (models.Count == 0)
                {
                    LocalStatusBar.Severity = InfoBarSeverity.Warning;
                    LocalStatusBar.Title = string.Format(
                        Loc.T("setup.local.running_no_models"), p.Label);
                    LocalStatusBar.Message = string.Format(
                        Loc.T("setup.local.running_no_models.msg"), endpoint);
                }
                else
                {
                    LocalStatusBar.Severity = InfoBarSeverity.Success;
                    LocalStatusBar.Title = string.Format(Loc.T("setup.local.running"), p.Label);
                    LocalStatusBar.Message = string.Format(
                        Loc.T("setup.local.found"), models.Count, endpoint);
                }
                SetModels(models, models.Count > 0 ? models[0] : "");
                ModelHint.Text = models.Count > 0 ? Loc.T("setup.local.installed_models") : "";
            });
        }
        catch (Exception ex)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                LocalStatusBar.Severity = InfoBarSeverity.Error;
                LocalStatusBar.Title = Loc.T("setup.probe_failed");
                LocalStatusBar.Message = ex.Message;
            });
        }
    }

    private void LocalReprobe_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is { Kind: ProviderKind.LocalServer } p)
        {
            _ = ProbeLocalAsync(p);
        }
    }

    // ── CLI / tarayıcı oturumu ───────────────────────────────────────────────

    /// <summary>
    /// FETİH'in GERÇEK giriş akışını başlatır.
    ///
    /// <para>Sahte bir "giriş yapıldı" ekranı göstermek yerine
    /// <c>fetih auth add &lt;sağlayıcı&gt;</c> komutunu GÖRÜNÜR bir konsol
    /// penceresinde çalıştırırız: cihaz kodu / tarayıcı yönlendirmesi orada
    /// akar (bu akışlar terminal etkileşimi ister, bir metin kutusuna
    /// sığmaz). Komut bitince oturumun gerçekten açıldığını
    /// <c>providers.auth_status</c> ile DOĞRULARIZ — düğmeye basılmış olması
    /// tek başına başarı sayılmaz.</para>
    /// </summary>
    private async void CliLogin_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is not ({ Kind: ProviderKind.CliLogin } or { Kind: ProviderKind.OAuthBrowser }))
        {
            return;
        }
        var p = _selected;

        if (!BridgeLauncherProbe.HasUsablePython(out var python))
        {
            CliLoginBar.Severity = InfoBarSeverity.Error;
            CliLoginBar.Title = Loc.T("setup.python_missing.title");
            CliLoginBar.Message = Loc.T("setup.python_missing.msg");
            return;
        }

        CliLoginButton.IsEnabled = false;
        CliLoginBar.Severity = InfoBarSeverity.Informational;
        CliLoginBar.Title = Loc.T("setup.login.opened.title");
        CliLoginBar.Message = Loc.T("setup.login.opened.msg");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = python,
                UseShellExecute = true,       // kendi konsol penceresini açsın
                WorkingDirectory = FetihPaths.RepoRootOrCurrent,
            };
            psi.ArgumentList.Add("-m");
            psi.ArgumentList.Add("fetih_cli");
            psi.ArgumentList.Add("auth");
            psi.ArgumentList.Add("add");
            psi.ArgumentList.Add(p.Id);

            var proc = Process.Start(psi);
            if (proc is not null)
            {
                await proc.WaitForExitAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                CliLoginBar.Severity = InfoBarSeverity.Error;
                CliLoginBar.Title = Loc.T("setup.login.failed.title");
                CliLoginBar.Message = ex.Message;
            });
        }

        DispatcherQueue.TryEnqueue(() => CliLoginButton.IsEnabled = true);
        await CheckCliLoginAsync(p, announceOnly: false).ConfigureAwait(false);
    }

    private void CliLoginCheck_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is { Kind: ProviderKind.CliLogin or ProviderKind.OAuthBrowser } p)
        {
            _ = CheckCliLoginAsync(p, announceOnly: false);
        }
    }

    /// <summary>Oturum durumunu köprüden okur; hiçbir şey istemez, hiçbir şey uydurmaz.</summary>
    private async Task CheckCliLoginAsync(ProviderEntry p, bool announceOnly)
    {
        try
        {
            var res = await Bridge.BridgeClient.Shared
                .ProvidersAuthStatusAsync(p.Id).ConfigureAwait(false);
            var loggedIn = res.TryGetProperty("logged_in", out var li) && li.GetBoolean();

            DispatcherQueue.TryEnqueue(() =>
            {
                if (loggedIn)
                {
                    CliLoginBar.Severity = InfoBarSeverity.Success;
                    CliLoginBar.Title = Loc.T("setup.login.ok.title");
                    CliLoginBar.Message = string.Format(Loc.T("setup.login.ok.msg"), p.Label);
                }
                else if (!announceOnly)
                {
                    CliLoginBar.Severity = InfoBarSeverity.Warning;
                    CliLoginBar.Title = Loc.T("setup.login.pending.title");
                    CliLoginBar.Message = Loc.T("setup.login.pending.msg");
                }
            });
        }
        catch
        {
            // Köprü yoksa durum bilinemez; kullanıcıyı yanlış bilgilendirme.
        }
    }

    // ── Model listesi ────────────────────────────────────────────────────────

    /// <summary>
    /// Model listesini SAĞLAYICIDAN çeker.
    ///
    /// <para>Sihirbaz eskiden gömülü bir örnek model kimliği öneriyordu.
    /// Sağlayıcılar model emekliye ayırır (Groq <c>llama-3.3-70b-versatile</c>'ı
    /// kaldırdı) ve gömülü kimlik bayatlayınca kurulum "başarılı" bitip ilk
    /// mesaj 404 alıyordu. Sağlayıcının kendisine sormak bayatlamaz.</para>
    /// </summary>
    private async Task LoadModelsAsync(ProviderEntry p)
    {
        if (p.Kind == ProviderKind.LocalServer)
        {
            return;   // ProbeLocalAsync zaten inik modelleri dolduruyor
        }

        DispatcherQueue.TryEnqueue(() => ModelHint.Text = Loc.T("setup.model.loading"));

        try
        {
            var res = await Bridge.BridgeClient.Shared.ProvidersModelsAsync(p.Id).ConfigureAwait(false);
            var models = new List<string>();
            if (res.TryGetProperty("models", out var ms) &&
                ms.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var m in ms.EnumerateArray())
                {
                    if (m.ValueKind == System.Text.Json.JsonValueKind.String)
                    {
                        models.Add(m.GetString() ?? "");
                    }
                }
            }
            var recommended = res.TryGetProperty("recommended", out var rc) ? (rc.GetString() ?? "") : "";
            var source = res.TryGetProperty("source", out var sv) ? (sv.GetString() ?? "") : "";

            DispatcherQueue.TryEnqueue(() =>
            {
                SetModels(models, recommended);
                ModelHint.Text = models.Count == 0
                    ? Loc.T("setup.model.unavailable")
                    : source == "live"
                        ? string.Format(Loc.T("setup.model.live"), models.Count)
                        : string.Format(Loc.T("setup.model.offline"), models.Count);
            });
        }
        catch (Exception ex)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                SetModels(new List<string>(), "");
                ModelHint.Text = Loc.T("setup.model.failed") + ex.Message;
            });
        }
    }

    private void SetModels(IReadOnlyList<string> models, string preferred)
    {
        ModelCombo.Items.Clear();
        foreach (var m in models)
        {
            ModelCombo.Items.Add(m);
        }
        if (ModelCombo.Items.Count == 0)
        {
            return;
        }
        var index = 0;
        for (var i = 0; i < models.Count; i++)
        {
            if (string.Equals(models[i], preferred, StringComparison.Ordinal))
            {
                index = i;
                break;
            }
        }
        ModelCombo.SelectedIndex = index;
    }

    // ── Adım geçişleri ───────────────────────────────────────────────────────

    private void WelcomeContinue_Click(object sender, RoutedEventArgs e) => GoToPhase(2);

    private void BackToWelcome_Click(object sender, RoutedEventArgs e) => GoToPhase(1);

    private void BackToProvider_Click(object sender, RoutedEventArgs e) => GoToPhase(2);

    private async void ProviderInstall_Click(object sender, RoutedEventArgs e)
    {
        var p = SelectedProvider();
        if (p is null)
        {
            return;
        }

        _ctx.ProviderId = p.Id;
        _ctx.KeyEnvVar = p.Kind == ProviderKind.CloudApiKey && p.ApiKeyEnvVars.Count > 0
            ? p.ApiKeyEnvVars[0]
            : "";
        _ctx.ApiKey = p.Kind == ProviderKind.CloudApiKey ? (KeyBox.Password ?? "") : "";
        _ctx.Model = ModelCombo.SelectedItem as string ?? "";

        // Yalnızca gerçekten anahtar isteyen sağlayıcıda anahtar zorunlu.
        if (p.Kind == ProviderKind.CloudApiKey && string.IsNullOrWhiteSpace(_ctx.ApiKey))
        {
            KeyHint.Text = Loc.T("setup.key.required");
            return;
        }

        // OAuth sağlayıcılarında ön denetim: Henüz oturum açılmamışsa kullanıcıyı uyar ve giriş akışını tetikle
        if (p.Kind is ProviderKind.CliLogin or ProviderKind.OAuthBrowser)
        {
            try
            {
                var res = await Bridge.BridgeClient.Shared.ProvidersAuthStatusAsync(p.Id).ConfigureAwait(true);
                var loggedIn = res.TryGetProperty("logged_in", out var li) && li.GetBoolean();
                if (!loggedIn)
                {
                    CliLoginBar.Severity = InfoBarSeverity.Warning;
                    CliLoginBar.Title = Loc.T("setup.needs_login.title");
                    CliLoginBar.Message = string.Format(Loc.T("setup.needs_login.msg"), p.Label);
                    CliLogin_Click(sender, e);
                    return;
                }
            }
            catch
            {
                // Köprü henüz ayakta değilse pipeline EnsureProviderAuthStep aşamasında ele alacaktır
            }
        }

        GoToPhase(3);
        _ = RunPipelineAsync();
    }

    private async Task RunPipelineAsync()
    {
        _rows.Clear();
        ResultBar.IsOpen = false;
        RetryButton.Visibility = Visibility.Collapsed;
        BackToProviderButton.Visibility = Visibility.Collapsed;
        GoToChatButton.Visibility = Visibility.Collapsed;
        OverallProgress.Value = 0;

        var steps = SetupStepFactory.BuildDefaultSteps();
        foreach (var s in steps)
        {
            _rows.Add(new StepRow
            {
                Id = s.Id,
                DisplayName = s.DisplayName,
                Message = Loc.T("setup.step.waiting"),
                Glyph = "•",
            });
        }

        var journal = new TransactionJournal(JournalPath);
        journal.Reset();
        var pipeline = new SetupPipeline(steps, journal);
        pipeline.Progress += OnProgress;

        _cts = new CancellationTokenSource();
        PipelineResult result;
        try
        {
            result = await pipeline.RunAsync(_ctx, _cts.Token);
        }
        catch (Exception ex)
        {
            result = new PipelineResult(PipelineOutcome.Failed, null, ex.Message);
        }

        pipeline.Progress -= OnProgress;

        if (result.Outcome == PipelineOutcome.Success)
        {
            ResultBar.Severity = InfoBarSeverity.Success;
            ResultBar.Title = Loc.T("setup.done.title");
            ResultBar.Message = Loc.T("setup.done.msg");
            ResultBar.IsOpen = true;
            GoToChatButton.Visibility = Visibility.Visible;
        }
        else
        {
            ResultBar.Severity = InfoBarSeverity.Error;
            ResultBar.Title = result.Outcome == PipelineOutcome.Cancelled
                ? Loc.T("setup.cancelled")
                : Loc.T("setup.failed");
            ResultBar.Message = result.Message + Loc.T("setup.log_suffix") + JournalPath;
            ResultBar.IsOpen = true;
            RetryButton.Visibility = Visibility.Visible;
            BackToProviderButton.Visibility = Visibility.Visible;
        }
    }

    private void OnProgress(StepProgress p)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            OverallProgress.Value = p.Total > 0 ? (double)p.Index / p.Total : 0;
            foreach (var row in _rows)
            {
                if (row.Id == p.StepId)
                {
                    row.Message = p.Message;
                    row.Glyph = p.Outcome switch
                    {
                        StepOutcome.Completed => "✓",
                        StepOutcome.Skipped => "»",
                        StepOutcome.Failed => "✗",
                        _ => "…",
                    };
                    break;
                }
            }
        });
    }

    private void Retry_Click(object sender, RoutedEventArgs e) => _ = RunPipelineAsync();

    private void GoToChat_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var main = new MainWindow();
            App.MainAppWindow = main;
            main.Activate();
            Close();
        }
        catch (Exception ex)
        {
            App.LogCrash("SetupWindow.GoToChat", ex, ex.Message);
        }
    }
}

/// <summary>İlerleme listesindeki tek bir adım satırı.</summary>
public sealed class StepRow : System.ComponentModel.INotifyPropertyChanged
{
    private string _message = "";
    private string _glyph = "•";

    public string Id { get; set; } = "";
    public string DisplayName { get; set; } = "";

    public string Message
    {
        get => _message;
        set { _message = value; Notify(nameof(Message)); }
    }

    public string Glyph
    {
        get => _glyph;
        set { _glyph = value; Notify(nameof(Glyph)); }
    }

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

    private void Notify(string n)
        => PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(n));
}
