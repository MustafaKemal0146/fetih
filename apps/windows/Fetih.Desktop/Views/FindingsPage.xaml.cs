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
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

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
        ExportButton.Content = Loc.T("findings.export_button");
        ClearButton.Content = Loc.T("findings.clear_button");
        SearchBox.PlaceholderText = Loc.T("findings.search_placeholder");
        SessionOnlyBox.Content = Loc.T("findings.session_only");
        AutomationProperties.SetName(ClearButton, Loc.T("findings.clear_button"));
        AutomationProperties.SetName(SearchBox, Loc.T("findings.search_placeholder"));
        var prevSort = SortBox.SelectedIndex;
        SortBox.Items.Clear();
        SortBox.Items.Add(new ComboBoxItem { Content = Loc.T("findings.sort.severity"), Tag = "severity" });
        SortBox.Items.Add(new ComboBoxItem { Content = Loc.T("findings.sort.time"), Tag = "time" });
        SortBox.SelectedIndex = prevSort >= 0 ? prevSort : 0;
        AutomationProperties.SetName(ScanButton, Loc.T("findings.scan_button"));
        AutomationProperties.SetName(ExportButton, Loc.T("findings.export_button"));
        AutomationProperties.SetName(SeverityBox, Loc.T("findings.severity_label"));
        AutomationProperties.SetName(FindingList, Loc.T("findings.title"));
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

    private async void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        ExportButton.IsEnabled = false;
        try
        {
            var md = await BridgeClient.Shared.FindingsExportAsync("md").ConfigureAwait(true);
            var html = await BridgeClient.Shared.FindingsExportAsync("html").ConfigureAwait(true);
            var mdText = md.TryGetProperty("content", out var mc) ? mc.GetString() ?? "" : "";
            var htmlText = html.TryGetProperty("content", out var hc) ? hc.GetString() ?? "" : "";

            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "FETIH-Raporlar");
            System.IO.Directory.CreateDirectory(dir);
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var mdPath = System.IO.Path.Combine(dir, $"fetih-rapor-{stamp}.md");
            var htmlPath = System.IO.Path.Combine(dir, $"fetih-rapor-{stamp}.html");
            System.IO.File.WriteAllText(mdPath, mdText);
            System.IO.File.WriteAllText(htmlPath, htmlText);

            // Markdown'ı panoya da kopyala.
            try
            {
                var dp = new DataPackage { RequestedOperation = DataPackageOperation.Copy };
                dp.SetText(mdText);
                Clipboard.SetContent(dp);
            }
            catch { /* pano erişimi başarısızsa sorun değil */ }

            await new ContentDialog
            {
                Title = Loc.T("findings.export.done_title"),
                Content = string.Format(Loc.T("findings.export.done_body"), dir),
                CloseButtonText = Loc.T("dialog.ok"),
                XamlRoot = this.XamlRoot,
            }.ShowAsync();
        }
        catch (Exception ex)
        {
            App.LogCrash("FindingsPage.Export", ex, ex.Message);
        }
        finally
        {
            ExportButton.IsEnabled = true;
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
            var id = el.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "" : "";
            var sid = el.TryGetProperty("session_id", out var sidEl) ? sidEl.GetString() ?? "" : "";

            var severity = sevStr.ToLowerInvariant() switch
            {
                "critical" => FindingSeverity.Critical,
                "high" => FindingSeverity.High,
                "medium" => FindingSeverity.Medium,
                "low" => FindingSeverity.Low,
                _ => FindingSeverity.Info,
            };
            return new Finding(title, target, severity, evidence, rec, refStr, id, sid);
        }
        catch
        {
            return null;
        }
    }

    private void SeverityBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_filterReady) ApplyFilter();
    }

    private void SortBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_filterReady) ApplyFilter();
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void SessionOnly_Changed(object sender, RoutedEventArgs e) => ApplyFilter();

    private async void DeleteFinding_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string id } || string.IsNullOrEmpty(id)) return;
        try
        {
            await BridgeClient.Shared.FindingsDeleteAsync(id).ConfigureAwait(true);
            var row = Findings.FirstOrDefault(f => f.Id == id);
            if (row is not null) Findings.Remove(row);
        }
        catch (Exception ex)
        {
            App.LogCrash("FindingsPage.Delete", ex, ex.Message);
        }
    }

    private async void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        if (Findings.Count == 0) return;
        var confirm = new ContentDialog
        {
            Title = Loc.T("findings.clear_confirm_title"),
            Content = Loc.T("findings.clear_confirm_body"),
            PrimaryButtonText = Loc.T("findings.clear_button"),
            CloseButtonText = Loc.T("common.cancel"),
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot,
        };
        if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;
        try
        {
            await BridgeClient.Shared.FindingsClearAsync().ConfigureAwait(true);
            Findings.Clear();
        }
        catch (Exception ex)
        {
            App.LogCrash("FindingsPage.Clear", ex, ex.Message);
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

            if (SessionOnlyBox.IsChecked == true)
            {
                var sid = ChatConversationController.Shared.CurrentSessionId ?? "";
                query = query.Where(f => f.SessionId == sid);
            }

            var term = (SearchBox.Text ?? "").Trim();
            if (term.Length > 0)
            {
                query = query.Where(f =>
                    (f.Title?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
                    || (f.Target?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
                    || (f.Evidence?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
                    || (f.Reference?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false));
            }

            var byTime = SortBox.SelectedItem is ComboBoxItem { Tag: "time" };
            var filtered = (byTime
                ? query.OrderByDescending(f => f.DiscoveredAt).ThenByDescending(f => f.Severity)
                : query.OrderByDescending(f => f.Severity).ThenByDescending(f => f.DiscoveredAt))
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
