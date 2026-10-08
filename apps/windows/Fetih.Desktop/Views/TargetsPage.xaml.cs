using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views;

/// <summary>
/// Hedef paneli (issue #34): bulgular host/URL/dosya hedefine göre gruplanır.
/// Sol listeden bir hedef seçince sağda o hedefin tüm bulguları görünür.
/// Veriler kalıcı bulgu deposundan (findings.list) gelir, canlı günceller.
/// </summary>
public sealed partial class TargetsPage : Page
{
    private readonly BridgeClient _bridge = BridgeClient.Shared;
    private readonly ObservableCollection<TargetGroup> _targets = new();
    private string _selectedKey = "";

    public TargetsPage()
    {
        InitializeComponent();
        TargetList.ItemsSource = _targets;
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void ApplyLanguage()
    {
        PageTitleText.Text = Loc.T("targets.title");
        SubtitleText.Text = Loc.T("targets.subtitle");
        ReloadButton.Content = Loc.T("targets.reload");
        EmptyText.Text = Loc.T("targets.empty");
        SelectHintText.Text = Loc.T("targets.select_hint");
        AutomationProperties.SetName(TargetList, Loc.T("targets.title"));
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged += OnLanguageChanged;
        _bridge.FindingDiscovered += OnFindingDiscovered;
        _ = LoadAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged -= OnLanguageChanged;
        _bridge.FindingDiscovered -= OnFindingDiscovered;
    }

    private void OnLanguageChanged() => ApplyLanguage();

    private void ReloadButton_Click(object sender, RoutedEventArgs e) => _ = LoadAsync();

    private async Task LoadAsync()
    {
        try
        {
            var res = await _bridge.FindingsListAsync().ConfigureAwait(true);
            var findings = new List<Finding>();
            if (res.ValueKind == JsonValueKind.Object &&
                res.TryGetProperty("findings", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in arr.EnumerateArray())
                {
                    var f = ParseFinding(el);
                    if (f is not null) findings.Add(f);
                }
            }
            Rebuild(findings);
        }
        catch (Exception ex)
        {
            App.LogCrash("TargetsPage.Load", ex, ex.Message);
        }
    }

    private void Rebuild(IEnumerable<Finding> findings)
    {
        var groups = new Dictionary<string, TargetGroup>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings)
        {
            var key = TargetGroup.KeyFor(f.Target);
            if (!groups.TryGetValue(key, out var g))
            {
                g = new TargetGroup { Target = key };
                groups[key] = g;
            }
            g.Findings.Add(f);
        }

        // En yüksek ciddiyet önce, sonra bulgu sayısı.
        var ordered = groups.Values
            .OrderBy(g => (int)g.MaxSeverity == 0 ? 99 : 5 - (int)g.MaxSeverity)
            .ThenByDescending(g => g.Count)
            .ThenBy(g => g.Target, StringComparer.OrdinalIgnoreCase)
            .ToList();

        _targets.Clear();
        foreach (var g in ordered) _targets.Add(g);

        EmptyText.Visibility = _targets.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        TargetList.Visibility = _targets.Count == 0 ? Visibility.Collapsed : Visibility.Visible;

        // Seçimi koru; yoksa ilkini seç.
        var keep = _targets.FirstOrDefault(g => g.Target == _selectedKey);
        if (keep is not null)
        {
            TargetList.SelectedItem = keep;
            ShowFindings(keep);
        }
        else
        {
            ShowFindings(null);
        }
    }

    private void TargetList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var g = TargetList.SelectedItem as TargetGroup;
        _selectedKey = g?.Target ?? "";
        ShowFindings(g);
    }

    private void ShowFindings(TargetGroup? g)
    {
        if (g is null || g.Findings.Count == 0)
        {
            FindingList.ItemsSource = null;
            FindingList.Visibility = Visibility.Collapsed;
            SelectHintText.Visibility = Visibility.Visible;
            return;
        }
        FindingList.ItemsSource = g.Findings
            .OrderByDescending(f => f.Severity)
            .ThenByDescending(f => f.DiscoveredAt)
            .ToList();
        FindingList.Visibility = Visibility.Visible;
        SelectHintText.Visibility = Visibility.Collapsed;
    }

    private void OnFindingDiscovered(JsonElement el)
    {
        DispatcherQueue.TryEnqueue(() => _ = LoadAsync());
    }

    private static Finding? ParseFinding(JsonElement el)
    {
        try
        {
            string Get(string k) => el.TryGetProperty(k, out var v) ? v.GetString() ?? "" : "";
            var severity = Get("severity").ToLowerInvariant() switch
            {
                "critical" => FindingSeverity.Critical,
                "high" => FindingSeverity.High,
                "medium" => FindingSeverity.Medium,
                "low" => FindingSeverity.Low,
                _ => FindingSeverity.Info,
            };
            return new Finding(
                string.IsNullOrEmpty(Get("title")) ? "Finding" : Get("title"),
                Get("target"), severity, Get("evidence"), Get("recommendation"),
                Get("reference"), Get("id"), Get("session_id"));
        }
        catch
        {
            return null;
        }
    }
}
