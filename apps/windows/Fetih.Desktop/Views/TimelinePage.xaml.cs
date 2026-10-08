using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
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
/// Operasyon zaman çizelgesi (issue #35): seçili oturumda çalışan araçların
/// ad/süre/durum/çıkış-kodu dizilişi. Geçmiş session.load'dan, canlı güncelleme
/// tool_call/tool_result olaylarından gelir.
/// </summary>
public sealed partial class TimelinePage : Page
{
    private readonly BridgeClient _bridge = BridgeClient.Shared;
    private readonly ObservableCollection<TimelineEntry> _entries = new();
    private string _sessionId = "";
    private bool _ready;

    public TimelinePage()
    {
        InitializeComponent();
        TimelineItems.ItemsSource = _entries;
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void ApplyLanguage()
    {
        PageTitleText.Text = Loc.T("timeline.title");
        SubtitleText.Text = Loc.T("timeline.subtitle");
        ReloadButton.Content = Loc.T("timeline.reload");
        ExportButton.Content = Loc.T("timeline.export");
        EmptyText.Text = Loc.T("timeline.empty");
        AutomationProperties.SetName(SessionBox, Loc.T("nav.timeline"));
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged += OnLanguageChanged;
        _bridge.SessionToolCall += OnToolCall;
        _bridge.SessionToolResult += OnToolResult;
        _entries.CollectionChanged += (_, _) => UpdateChrome();
        _ = PopulateSessionsAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged -= OnLanguageChanged;
        _bridge.SessionToolCall -= OnToolCall;
        _bridge.SessionToolResult -= OnToolResult;
    }

    private void OnLanguageChanged() => ApplyLanguage();

    private async Task PopulateSessionsAsync()
    {
        _ready = false;
        try
        {
            SessionBox.Items.Clear();
            var sessions = await _bridge.ListSessionsAsync().ConfigureAwait(true);
            var current = ChatConversationController.Shared.CurrentSessionId ?? "";
            var chosen = -1;
            foreach (var sv in sessions)
            {
                var id = sv.SessionId;
                if (string.IsNullOrEmpty(id)) continue;
                var title = string.IsNullOrWhiteSpace(sv.Title) ? id : sv.Title;
                SessionBox.Items.Add(new ComboBoxItem { Content = title, Tag = id });
                if (id == current) chosen = SessionBox.Items.Count - 1;
            }
            _ready = true;
            if (SessionBox.Items.Count > 0)
            {
                SessionBox.SelectedIndex = chosen >= 0 ? chosen : 0;
            }
            else
            {
                UpdateChrome();
            }
        }
        catch (Exception ex)
        {
            _ready = true;
            App.LogCrash("TimelinePage.PopulateSessions", ex, ex.Message);
        }
    }

    private void SessionBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready) return;
        if (SessionBox.SelectedItem is ComboBoxItem { Tag: string id })
        {
            _sessionId = id;
            _ = LoadTimelineAsync();
        }
    }

    private void ReloadButton_Click(object sender, RoutedEventArgs e) => _ = LoadTimelineAsync();

    private async Task LoadTimelineAsync()
    {
        if (string.IsNullOrEmpty(_sessionId)) return;
        BusyRing.IsActive = true;
        try
        {
            var loaded = await _bridge.LoadSessionAsync(_sessionId).ConfigureAwait(true);
            var byId = new Dictionary<string, TimelineEntry>(StringComparer.Ordinal);
            var ordered = new List<TimelineEntry>();

            foreach (var it in loaded.Items)
            {
                if (it.Kind == "tool_call")
                {
                    var callId = it.CallId ?? Guid.NewGuid().ToString("N");
                    var entry = new TimelineEntry
                    {
                        CallId = callId,
                        Name = it.Name ?? "tool",
                        ArgsSummary = Shorten(it.Args),
                        Status = TimelineStatus.Running,
                    };
                    byId[callId] = entry;
                    ordered.Add(entry);
                }
                else if (it.Kind == "tool_result")
                {
                    var callId = it.CallId ?? "";
                    if (!string.IsNullOrEmpty(callId) && byId.TryGetValue(callId, out var entry))
                    {
                        ApplyResult(entry, it.Result, it.DurationMs);
                    }
                }
            }

            _entries.Clear();
            foreach (var en in ordered) _entries.Add(en);
            UpdateChrome();
        }
        catch (Exception ex)
        {
            App.LogCrash("TimelinePage.Load", ex, ex.Message);
        }
        finally
        {
            BusyRing.IsActive = false;
        }
    }

    // ── Canlı güncelleme ──────────────────────────────────────────────────────

    private void OnToolCall(BridgeToolCall call)
    {
        if (call.SessionId != _sessionId) return;
        DispatcherQueue.TryEnqueue(() =>
        {
            if (_entries.Any(en => en.CallId == call.Id)) return;
            _entries.Add(new TimelineEntry
            {
                CallId = call.Id,
                Name = call.Name,
                ArgsSummary = Shorten(call.ArgumentsJson),
                Status = TimelineStatus.Running,
            });
        });
    }

    private void OnToolResult(BridgeToolResult result)
    {
        if (result.SessionId != _sessionId) return;
        DispatcherQueue.TryEnqueue(() =>
        {
            var entry = _entries.FirstOrDefault(en => en.CallId == result.Id);
            if (entry is null) return;
            var durationMs = (DateTimeOffset.Now - entry.StartedAt).TotalMilliseconds;
            ApplyResult(entry, result.ResultText, durationMs);
            // ObservableCollection öğe içi değişimi yansıtmak için yenile.
            var idx = _entries.IndexOf(entry);
            if (idx >= 0) { _entries.RemoveAt(idx); _entries.Insert(idx, entry); }
        });
    }

    private static void ApplyResult(TimelineEntry entry, string? resultText, double? durationMs)
    {
        entry.DurationMs = durationMs;
        entry.ExitCode = ExtractExitCode(resultText);
        var isError = entry.ExitCode is int c and not 0
            || LooksLikeError(resultText);
        entry.Status = isError ? TimelineStatus.Error : TimelineStatus.Done;
    }

    // ── Dışa aktar ────────────────────────────────────────────────────────────

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("# FETİH — Operasyon zaman çizelgesi");
            sb.AppendLine();
            foreach (var en in _entries)
            {
                var exit = en.HasExit ? $" · {en.ExitLabel}" : "";
                sb.AppendLine($"- {en.TimeLabel}  **{en.Name}**  ({en.DurationLabel}{exit}) — {en.StatusLabel}");
                if (!string.IsNullOrWhiteSpace(en.ArgsSummary))
                    sb.AppendLine($"    `{en.ArgsSummary}`");
            }
            var dp = new DataPackage { RequestedOperation = DataPackageOperation.Copy };
            dp.SetText(sb.ToString());
            Clipboard.SetContent(dp);
        }
        catch (Exception ex)
        {
            App.LogCrash("TimelinePage.Export", ex, ex.Message);
        }
    }

    // ── Yardımcılar ───────────────────────────────────────────────────────────

    private void UpdateChrome()
    {
        var has = _entries.Count > 0;
        EmptyText.Visibility = has ? Visibility.Collapsed : Visibility.Visible;
        CountText.Text = has ? string.Format(Loc.T("timeline.count"), _entries.Count) : "";
    }

    private static string Shorten(string? text, int max = 160)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        var t = text.Replace("\r", " ").Replace("\n", " ").Trim();
        return t.Length <= max ? t : t[..(max - 1)] + "…";
    }

    private static int? ExtractExitCode(string? resultText)
    {
        if (string.IsNullOrWhiteSpace(resultText)) return null;
        var head = resultText.Length > 2000 ? resultText[..2000] : resultText;
        foreach (var key in new[] { "exit_code", "exitCode", "returncode", "return_code", "exit code" })
        {
            var i = head.IndexOf(key, StringComparison.OrdinalIgnoreCase);
            if (i < 0) continue;
            var j = i + key.Length;
            // "exit_code": 0  /  exit code 1
            while (j < head.Length && (head[j] == '"' || head[j] == ':' || head[j] == ' ' || head[j] == '=')) j++;
            var start = j;
            var neg = j < head.Length && head[j] == '-';
            if (neg) j++;
            while (j < head.Length && char.IsDigit(head[j])) j++;
            if (j > (neg ? start + 1 : start) && int.TryParse(head[start..j], out var code))
                return code;
        }
        return null;
    }

    private static bool LooksLikeError(string? text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        var head = text.Length > 300 ? text[..300] : text;
        return head.Contains("\"success\": false", StringComparison.OrdinalIgnoreCase)
            || head.Contains("\"error\"", StringComparison.OrdinalIgnoreCase)
            || head.Contains("Traceback", StringComparison.Ordinal);
    }
}
