using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views;

/// <summary>
/// Sağ panel (issue #53): aktif oturumun çalışan alt-ajanlarını
/// (<c>delegate_task</c>) ve arka plan süreçlerini (<c>terminal</c> background)
/// canlı gösterir. Köprünün var olan tool_call/tool_result olay akışından
/// beslenir — agent çekirdeğine dokunmaz. Yüksek frekanslı olaylar
/// dispatcher üzerinden UI iş parçacığına alınır.
/// </summary>
public sealed partial class ActivityPanel : UserControl
{
    private readonly BridgeClient _bridge = BridgeClient.Shared;
    private readonly ObservableCollection<ActivityItem> _items = new();
    private readonly DispatcherTimer _ticker = new() { Interval = TimeSpan.FromSeconds(1) };

    /// <summary>Panelin şu an yansıttığı oturum; değişince liste temizlenir.</summary>
    private string _currentSession = "";
    private bool _hooked;

    public ActivityPanel()
    {
        InitializeComponent();
        ActivityItems.ItemsSource = _items;
        _items.CollectionChanged += (_, _) => UpdateChrome();
        _ticker.Tick += (_, _) =>
        {
            foreach (var it in _items) it.TouchElapsed();
        };
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (!_hooked)
        {
            _bridge.SessionToolCall += OnToolCall;
            _bridge.SessionToolResult += OnToolResult;
            _bridge.SessionDone += OnSessionDone;
            _bridge.SessionError += OnSessionError;
            Loc.LanguageChanged += OnLanguageChanged;
            _hooked = true;
        }
        _ticker.Start();
        UpdateChrome();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        _ticker.Stop();
        if (_hooked)
        {
            _bridge.SessionToolCall -= OnToolCall;
            _bridge.SessionToolResult -= OnToolResult;
            _bridge.SessionDone -= OnSessionDone;
            _bridge.SessionError -= OnSessionError;
            Loc.LanguageChanged -= OnLanguageChanged;
            _hooked = false;
        }
    }

    private void OnLanguageChanged() => RunOnUi(ApplyLanguage);

    private void ApplyLanguage()
    {
        HeaderText.Text = Loc.T("activity.title");
        SubHeaderText.Text = Loc.T("activity.subtitle");
        StopAllButton.Content = Loc.T("activity.stop_all");
        EmptyText.Text = Loc.T("activity.empty");
        UpdateChrome();
    }

    // ── Olay işleyiciler (alım iş parçacığından → UI'a aktarılır) ──────────────

    private void OnToolCall(BridgeToolCall call) => RunOnUi(() =>
    {
        EnsureSession(call.SessionId);

        if (string.Equals(call.Name, "delegate_task", StringComparison.Ordinal))
        {
            AddSubAgents(call);
        }
        else if (string.Equals(call.Name, "terminal", StringComparison.Ordinal) && IsBackground(call.ArgumentsJson))
        {
            AddProcess(call);
        }
    });

    private void OnToolResult(BridgeToolResult result) => RunOnUi(() =>
    {
        var detail = Shorten(result.ResultText, 400);
        var isError = LooksLikeError(result.ResultText);
        foreach (var it in _items.Where(i => Matches(i.Key, result.Id)))
        {
            it.Status = isError ? ActivityStatus.Error : ActivityStatus.Done;
            it.EndedAt = DateTimeOffset.Now;
            if (!string.IsNullOrWhiteSpace(detail)) it.Detail = detail;
        }
    });

    private void OnSessionDone(BridgeDone done) => RunOnUi(() => FinishRunning(done.SessionId));
    private void OnSessionError(BridgeErrorEvent err) => RunOnUi(() => FinishRunning(err.SessionId));

    private void FinishRunning(string sessionId)
    {
        if (!string.Equals(sessionId, _currentSession, StringComparison.Ordinal)) return;
        foreach (var it in _items.Where(i => i.IsRunning))
        {
            it.Status = ActivityStatus.Done;
            it.EndedAt = DateTimeOffset.Now;
        }
        UpdateChrome();
    }

    // ── Eşleme yardımcıları ────────────────────────────────────────────────────

    private void EnsureSession(string sessionId)
    {
        if (string.IsNullOrEmpty(sessionId)) return;
        if (!string.Equals(sessionId, _currentSession, StringComparison.Ordinal))
        {
            _currentSession = sessionId;
            _items.Clear();
        }
    }

    private void AddSubAgents(BridgeToolCall call)
    {
        var tasks = ExtractTasks(call.ArgumentsJson);
        if (tasks.Count == 0)
        {
            _items.Add(new ActivityItem
            {
                Key = call.Id,
                SessionId = call.SessionId,
                Kind = ActivityKind.SubAgent,
                Title = Loc.T("activity.subagent"),
                Subtitle = Shorten(ExtractString(call.ArgumentsJson, "goal"), 160),
            });
            return;
        }
        for (var i = 0; i < tasks.Count; i++)
        {
            _items.Add(new ActivityItem
            {
                Key = tasks.Count == 1 ? call.Id : $"{call.Id}#{i}",
                SessionId = call.SessionId,
                Kind = ActivityKind.SubAgent,
                Title = Loc.T("activity.subagent") + (tasks.Count > 1 ? $" {i + 1}/{tasks.Count}" : ""),
                Subtitle = Shorten(tasks[i], 160),
            });
        }
    }

    private void AddProcess(BridgeToolCall call)
    {
        var cmd = ExtractString(call.ArgumentsJson, "command");
        _items.Add(new ActivityItem
        {
            Key = call.Id,
            SessionId = call.SessionId,
            Kind = ActivityKind.Process,
            Title = Loc.T("activity.process"),
            Subtitle = Shorten(cmd, 200),
        });
    }

    private static bool Matches(string itemKey, string toolId)
        => itemKey == toolId || itemKey.StartsWith(toolId + "#", StringComparison.Ordinal);

    // ── JSON ayrıştırma (savunmacı) ────────────────────────────────────────────

    private static bool IsBackground(string argsJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(argsJson) ? "{}" : argsJson);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("background", out var b)
                && b.ValueKind == JsonValueKind.True;
        }
        catch { return false; }
    }

    private static string ExtractString(string argsJson, string name)
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(argsJson) ? "{}" : argsJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty(name, out var v)
                && v.ValueKind == JsonValueKind.String)
            {
                return v.GetString() ?? "";
            }
        }
        catch { }
        return "";
    }

    /// <summary>delegate_task argümanlarından her alt-görevin özetini çıkarır.</summary>
    private static System.Collections.Generic.List<string> ExtractTasks(string argsJson)
    {
        var list = new System.Collections.Generic.List<string>();
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(argsJson) ? "{}" : argsJson);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("tasks", out var tasks)
                && tasks.ValueKind == JsonValueKind.Array)
            {
                foreach (var t in tasks.EnumerateArray())
                {
                    if (t.ValueKind == JsonValueKind.String)
                    {
                        list.Add(t.GetString() ?? "");
                    }
                    else if (t.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var field in new[] { "goal", "task", "description" })
                        {
                            if (t.TryGetProperty(field, out var fv) && fv.ValueKind == JsonValueKind.String)
                            {
                                list.Add(fv.GetString() ?? "");
                                break;
                            }
                        }
                    }
                }
            }
        }
        catch { }
        return list;
    }

    private static bool LooksLikeError(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        // tool sonuçları çoğu zaman JSON; "success": false / "error" ipucu arıyoruz.
        var head = text.Length > 300 ? text[..300] : text;
        return head.Contains("\"success\": false", StringComparison.OrdinalIgnoreCase)
            || head.Contains("\"error\"", StringComparison.OrdinalIgnoreCase);
    }

    private static string Shorten(string? text, int max)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        var t = text.Replace("\r", " ").Replace("\n", " ").Trim();
        return t.Length <= max ? t : t[..(max - 1)] + "…";
    }

    // ── Panel kromu ────────────────────────────────────────────────────────────

    private void UpdateChrome()
    {
        var anyRunning = _items.Any(i => i.IsRunning);
        EmptyText.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        StopAllButton.Visibility = anyRunning ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void StopAllButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_currentSession)) return;
        try
        {
            await _bridge.CancelAsync(_currentSession);
        }
        catch (Exception ex)
        {
            App.LogCrash("ActivityPanel.StopAll", ex, ex.Message);
        }
    }

    private void RunOnUi(Action action)
    {
        if (DispatcherQueue.HasThreadAccess) action();
        else DispatcherQueue.TryEnqueue(() => action());
    }
}
