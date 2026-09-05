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

        // Ortalamayı kurucuda DEĞİL, ilk etkinleşmede yap: WinUI pencereyi
        // gösterirken kendi varsayılan yerleşimini uyguluyor ve kurucudaki
        // konumlandırmayı kısmen eziyordu (pencere ekranın solunda kalıyordu).
        Activated += OnFirstActivated;

        RenderStepDots();
        PopulateProviders(ProviderRegistry.All);

        // Köprü ayağa kalktığında listeyi KANONİK katalogla değiştir.
        _ = RefreshCatalogAsync();
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
            AutomationProperties.SetName(dot, $"Adım {i}/{TotalPhases}" + (filled ? " (tamam)" : ""));
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
            var suffix = p.IsLocal ? " · yerel" : p.IsAggregator ? " · toplayıcı" : "";
            ProviderCombo.Items.Add(new ComboBoxItem { Content = p.DisplayName + suffix, Tag = p.Id });
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
                KeyHint.Text = "Bu sağlayıcı bu makinede çalışır; API anahtarı istemez. " +
                               "Veriler bilgisayardan çıkmaz.";
                _ = ProbeLocalAsync(p);
                break;

            case ProviderKind.CliLogin:
                CliLoginSection.Visibility = Visibility.Visible;
                CliLoginBar.Severity = InfoBarSeverity.Informational;
                CliLoginBar.Title = "Tarayıcı oturumu gerekiyor";
                CliLoginBar.Message =
                    $"{p.DisplayName} bir API anahtarı değil, hesabınla açtığınız bir oturum kullanır. " +
                    "\"Oturum aç\" düğmesi FETİH'in GERÇEK giriş akışını bir konsol penceresinde başlatır; " +
                    "tarayıcıda onayladıktan sonra buraya dön.";
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
                    ? $"Anahtar {p.ApiKeyEnvVars[0]} adıyla ~/.fetih/.env dosyasına kaydedilir."
                    : "Bu sağlayıcı için ortam değişkeni tanımlı değil.";
                if (!string.IsNullOrWhiteSpace(p.SignupUrl))
                {
                    SignupLink.NavigateUri = new Uri(p.SignupUrl);
                    SignupLink.Content = "Anahtar al — " + p.SignupUrl;
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
        LocalStatusBar.Title = "Yoklanıyor…";
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
                    LocalStatusBar.Title = p.DisplayName + " bulunamadı";
                    LocalStatusBar.Message =
                        $"{endpoint} adresinde çalışan bir sunucu yok. Kur ve başlat, sonra \"Yeniden yokla\"ya bas.";
                    if (!string.IsNullOrWhiteSpace(p.SignupUrl))
                    {
                        LocalInstallLink.NavigateUri = new Uri(p.SignupUrl);
                        LocalInstallLink.Content = "Kurulum sayfası — " + p.SignupUrl;
                        LocalInstallLink.Visibility = Visibility.Visible;
                    }
                    SetModels(new List<string>(), "");
                    ModelHint.Text = "Sunucu ayağa kalkınca modeller burada listelenir.";
                    return;
                }

                if (models.Count == 0)
                {
                    LocalStatusBar.Severity = InfoBarSeverity.Warning;
                    LocalStatusBar.Title = p.DisplayName + " çalışıyor, ama hiç model inik değil";
                    LocalStatusBar.Message = $"{endpoint} yanıt veriyor. Önce bir model indir (ör. `ollama pull`).";
                }
                else
                {
                    LocalStatusBar.Severity = InfoBarSeverity.Success;
                    LocalStatusBar.Title = p.DisplayName + " çalışıyor";
                    LocalStatusBar.Message = $"{models.Count} model bulundu · {endpoint}";
                }
                SetModels(models, models.Count > 0 ? models[0] : "");
                ModelHint.Text = models.Count > 0
                    ? "Bu makinede İNDİRİLMİŞ modeller listelendi."
                    : "";
            });
        }
        catch (Exception ex)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                LocalStatusBar.Severity = InfoBarSeverity.Error;
                LocalStatusBar.Title = "Yoklama yapılamadı";
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
        if (_selected is not { Kind: ProviderKind.CliLogin } p)
        {
            return;
        }

        if (!BridgeLauncherProbe.HasUsablePython(out var python))
        {
            CliLoginBar.Severity = InfoBarSeverity.Error;
            CliLoginBar.Title = "Python bulunamadı";
            CliLoginBar.Message = "Giriş akışı FETİH CLI üzerinden çalışır; Python 3.11+ gerekiyor.";
            return;
        }

        CliLoginButton.IsEnabled = false;
        CliLoginBar.Severity = InfoBarSeverity.Informational;
        CliLoginBar.Title = "Giriş penceresi açıldı";
        CliLoginBar.Message = "Konsol penceresindeki yönergeleri izle; bitince buraya dön.";

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
                CliLoginBar.Title = "Giriş akışı başlatılamadı";
                CliLoginBar.Message = ex.Message;
            });
        }

        DispatcherQueue.TryEnqueue(() => CliLoginButton.IsEnabled = true);
        await CheckCliLoginAsync(p, announceOnly: false).ConfigureAwait(false);
    }

    private void CliLoginCheck_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is { Kind: ProviderKind.CliLogin } p)
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
                    CliLoginBar.Title = "Oturum açık";
                    CliLoginBar.Message = p.DisplayName + " kimlik bilgileri FETİH kimlik deposunda bulundu.";
                }
                else if (!announceOnly)
                {
                    CliLoginBar.Severity = InfoBarSeverity.Warning;
                    CliLoginBar.Title = "Henüz oturum açılmadı";
                    CliLoginBar.Message = "Giriş akışı tamamlanmamış görünüyor. \"Oturum aç\"ı yeniden dene.";
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

        DispatcherQueue.TryEnqueue(() => ModelHint.Text = "Model listesi alınıyor…");

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
                    ? "Model listesi alınamadı. Kurulumu tamamlayıp Ayarlar › Model'den seçebilirsin."
                    : source == "live"
                        ? $"{models.Count} model sağlayıcıdan CANLI alındı."
                        : $"{models.Count} model (çevrimdışı yedek liste).";
            });
        }
        catch (Exception ex)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                SetModels(new List<string>(), "");
                ModelHint.Text = "Model listesi alınamadı: " + ex.Message;
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

    private void ProviderInstall_Click(object sender, RoutedEventArgs e)
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
            KeyHint.Text = "Bu sağlayıcı bir API anahtarı gerektirir; lütfen anahtarı gir.";
            return;
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
            _rows.Add(new StepRow { Id = s.Id, DisplayName = s.DisplayName, Message = "bekliyor", Glyph = "•" });
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
            ResultBar.Title = "Kurulum tamamlandı";
            ResultBar.Message = "Masaüstü Köprüsü hazır ve model gerçek bir yanıt döndürdü. Sohbete geçebilirsin.";
            ResultBar.IsOpen = true;
            GoToChatButton.Visibility = Visibility.Visible;
        }
        else
        {
            ResultBar.Severity = InfoBarSeverity.Error;
            ResultBar.Title = result.Outcome == PipelineOutcome.Cancelled ? "İptal edildi" : "Kurulum başarısız";
            ResultBar.Message = result.Message + "  ·  Günlük: " + JournalPath;
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
