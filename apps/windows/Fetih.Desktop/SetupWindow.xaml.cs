using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Services;
using Fetih.Desktop.Setup;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop;

/// <summary>
/// İlk kurulum sihirbazı. OpenClaw'ın <c>SetupEngine.UI</c> akışına esinlenir
/// (karşılama → sağlayıcı/anahtar → ilerleme); başsız motoru
/// (<see cref="SetupPipeline"/>) sürer ve <see cref="TransactionJournal"/> ile
/// çökme kurtarma günlüğü tutar. Kurulum başarılıysa ana pencereyi açar.
/// </summary>
public sealed partial class SetupWindow : Window
{
    private readonly ObservableCollection<StepRow> _rows = new();
    private readonly SetupContext _ctx = new();
    private CancellationTokenSource? _cts;

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
        PopulateProviders();
    }

    private void PopulateProviders()
    {
        foreach (var p in ProviderRegistry.All)
        {
            var suffix = p.IsLocal ? " · yerel" : p.IsAggregator ? " · toplayıcı" : "";
            ProviderCombo.Items.Add(new ComboBoxItem
            {
                Content = p.DisplayName + suffix,
                Tag = p.Id,
            });
        }
        // Varsayılan olarak Groq'u seç (ücretsiz başlangıç).
        for (var i = 0; i < ProviderCombo.Items.Count; i++)
        {
            if (ProviderCombo.Items[i] is ComboBoxItem { Tag: "groq" })
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
    {
        if (ProviderCombo.SelectedItem is ComboBoxItem { Tag: string id })
        {
            foreach (var p in ProviderRegistry.All)
            {
                if (p.Id == id)
                {
                    return p;
                }
            }
        }
        return null;
    }

    private void ProviderCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var p = SelectedProvider();
        if (p is null)
        {
            return;
        }

        var needsKey = p.ApiKeyEnvVars.Count > 0 && p.AuthType == "api_key";
        KeyBox.IsEnabled = needsKey;
        KeyHint.Text = needsKey
            ? $"Anahtar {p.ApiKeyEnvVars[0]} adıyla ~/.fetih/.env dosyasına kaydedilir."
            : "Bu sağlayıcı API anahtarı istemez (OAuth / yerel uç). Anahtar alanını boş bırak.";
    }

    // ── Adım 1 → 2 ───────────────────────────────────────────────────────────

    private void WelcomeContinue_Click(object sender, RoutedEventArgs e)
    {
        WelcomePanel.Visibility = Visibility.Collapsed;
        ProviderPanel.Visibility = Visibility.Visible;
        ProgressPanel.Visibility = Visibility.Collapsed;
    }

    private void ProviderBack_Click(object sender, RoutedEventArgs e)
    {
        ProviderPanel.Visibility = Visibility.Visible;
        ProgressPanel.Visibility = Visibility.Collapsed;
        WelcomePanel.Visibility = Visibility.Collapsed;
    }

    // ── Adım 2 → 3 (kurulum) ─────────────────────────────────────────────────

    private void ProviderInstall_Click(object sender, RoutedEventArgs e)
    {
        var p = SelectedProvider();
        if (p is null)
        {
            return;
        }

        _ctx.ProviderId = p.Id;
        _ctx.KeyEnvVar = p.ApiKeyEnvVars.Count > 0 ? p.ApiKeyEnvVars[0] : "";
        _ctx.ApiKey = KeyBox.Password ?? "";
        _ctx.Model = ModelBox.Text?.Trim() ?? "";

        var needsKey = p.ApiKeyEnvVars.Count > 0 && p.AuthType == "api_key";
        if (needsKey && string.IsNullOrWhiteSpace(_ctx.ApiKey))
        {
            KeyHint.Text = "Bu sağlayıcı bir API anahtarı gerektirir; lütfen anahtarı gir.";
            return;
        }

        ProviderPanel.Visibility = Visibility.Collapsed;
        ProgressPanel.Visibility = Visibility.Visible;
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
            ResultBar.Message = "Masaüstü Köprüsü hazır. Sohbete geçebilirsin.";
            ResultBar.IsOpen = true;
            GoToChatButton.Visibility = Visibility.Visible;
        }
        else
        {
            ResultBar.Severity = InfoBarSeverity.Error;
            ResultBar.Title = result.Outcome == PipelineOutcome.Cancelled ? "İptal edildi" : "Kurulum başarısız";
            ResultBar.Message = result.Message +
                $"  ·  Günlük: {JournalPath}";
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
