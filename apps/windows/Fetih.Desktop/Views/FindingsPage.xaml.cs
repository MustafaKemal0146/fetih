using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views;

/// <summary>
/// Bulgu listesi: Masaüstü Köprüsü üzerinden skills_guard tarayıcısına bağlıdır.
/// Bulgular gerçek zamanlı olaylarla akar veya kullanıcı isteğiyle taranır.
/// </summary>
public sealed partial class FindingsPage : Page
{
    /// <summary>
    /// Süreç genelinde paylaşılan bulgu deposu. Sayfa her açıldığında sıfırlanmasın
    /// diye statik tutulur; köprü katmanı buraya yazar.
    /// </summary>
    public static ObservableCollection<Finding> Findings { get; } = new();

    private bool _filterReady;

    public FindingsPage()
    {
        InitializeComponent();
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void ApplyLanguage()
    {
        PageTitleText.Text = Loc.T("findings.title");
        SummaryText.Text = Loc.T("findings.summary");
        ScanButton.Content = Loc.T("findings.scan_button");
        EmptyTitleText.Text = Loc.T("findings.empty_title");
        EmptyDescText.Text = Loc.T("findings.empty_desc");
        EmptyDisclaimerText.Text = Loc.T("findings.empty_disclaimer");

        _filterReady = false;
        var prevIndex = SeverityBox.SelectedIndex;
        SeverityBox.Items.Clear();
        SeverityBox.Items.Add(new ComboBoxItem { Content = Loc.T("findings.severity.all"), Tag = null });
        SeverityBox.Items.Add(new ComboBoxItem { Content = Loc.T("findings.severity.critical"), Tag = FindingSeverity.Critical });
        SeverityBox.Items.Add(new ComboBoxItem { Content = Loc.T("findings.severity.high"), Tag = FindingSeverity.High });
        SeverityBox.Items.Add(new ComboBoxItem { Content = Loc.T("findings.severity.medium"), Tag = FindingSeverity.Medium });
        SeverityBox.Items.Add(new ComboBoxItem { Content = Loc.T("findings.severity.low"), Tag = FindingSeverity.Low });
        SeverityBox.Items.Add(new ComboBoxItem { Content = Loc.T("findings.severity.info"), Tag = FindingSeverity.Info });
        SeverityBox.SelectedIndex = prevIndex >= 0 ? prevIndex : 0;
        _filterReady = true;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged += OnLanguageChanged;
        Findings.CollectionChanged += OnFindingsChanged;
        BridgeClient.Shared.FindingDiscovered += OnFindingDiscovered;
        ApplyFilter();
        _ = LoadFindingsAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged -= OnLanguageChanged;
        Findings.CollectionChanged -= OnFindingsChanged;
        BridgeClient.Shared.FindingDiscovered -= OnFindingDiscovered;
    }

    private void OnLanguageChanged()
    {
        ApplyLanguage();
        ApplyFilter();
    }

    private void OnFindingsChanged(object? sender, NotifyCollectionChangedEventArgs e) => ApplyFilter();

    private void OnFindingDiscovered(JsonElement el)
    {
        var f = ParseFinding(el);
        if (f is not null)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                if (!Findings.Any(existing => existing.Title == f.Title && existing.Target == f.Target))
                {
                    Findings.Insert(0, f);
                }
            });
        }
    }

    private async Task LoadFindingsAsync()
    {
        try
        {
            var res = await BridgeClient.Shared.FindingsListAsync().ConfigureAwait(true);
            if (res.TryGetProperty("findings", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    Findings.Clear();
                    foreach (var item in arr.EnumerateArray())
                    {
                        var f = ParseFinding(item);
                        if (f is not null) Findings.Add(f);
                    }
                });
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("FindingsPage.LoadFindings", ex, ex.Message);
        }
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        ScanButton.IsEnabled = false;
        ScanRing.Visibility = Visibility.Visible;
        ScanRing.IsActive = true;
        try
        {
            var res = await BridgeClient.Shared.FindingsScanAsync().ConfigureAwait(true);
            if (res.TryGetProperty("findings", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    foreach (var item in arr.EnumerateArray())
                    {
                        var f = ParseFinding(item);
                        if (f is not null && !Findings.Any(existing => existing.Title == f.Title && existing.Target == f.Target))
                        {
                            Findings.Add(f);
                        }
                    }
                });
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("FindingsPage.Scan", ex, ex.Message);
        }
        finally
        {
            ScanRing.IsActive = false;
            ScanRing.Visibility = Visibility.Collapsed;
            ScanButton.IsEnabled = true;
        }
    }

    private static Finding? ParseFinding(JsonElement el)
    {
        try
        {
            var title = el.TryGetProperty("title", out var t) ? t.GetString() ?? "Finding" : "Finding";
            var target = el.TryGetProperty("target", out var tg) ? tg.GetString() ?? "" : "";
            var sevStr = el.TryGetProperty("severity", out var s) ? s.GetString() ?? "Info" : "Info";
            var evidence = el.TryGetProperty("evidence", out var ev) ? ev.GetString() ?? "" : "";
            var rec = el.TryGetProperty("recommendation", out var rc) ? rc.GetString() ?? "" : "";
            var refStr = el.TryGetProperty("reference", out var rf) ? rf.GetString() ?? "" : "";

            var severity = sevStr.ToLowerInvariant() switch
            {
                "critical" => FindingSeverity.Critical,
                "high" => FindingSeverity.High,
                "medium" => FindingSeverity.Medium,
                "low" => FindingSeverity.Low,
                _ => FindingSeverity.Info,
            };
            return new Finding(title, target, severity, evidence, rec, refStr);
        }
        catch
        {
            return null;
        }
    }

    private void SeverityBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_filterReady)
        {
            ApplyFilter();
        }
    }

    private void ApplyFilter()
    {
        try
        {
            IEnumerable<Finding> query = Findings;

            if (SeverityBox.SelectedItem is ComboBoxItem { Tag: FindingSeverity sev })
            {
                query = query.Where(f => f.Severity == sev);
            }

            var filtered = query
                .OrderByDescending(f => f.Severity)
                .ThenByDescending(f => f.DiscoveredAt)
                .ToList();

            FindingList.ItemsSource = filtered;
            CountText.Text = Findings.Count == 0
                ? string.Empty
                : string.Format(Loc.T("findings.showing_count"), filtered.Count, Findings.Count);

            var hasItems = filtered.Count > 0;
            FindingList.Visibility = hasItems ? Visibility.Visible : Visibility.Collapsed;
            EmptyState.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
        }
        catch (Exception ex)
        {
            App.LogCrash("FindingsPage.ApplyFilter", ex, ex.Message);
        }
    }
}
