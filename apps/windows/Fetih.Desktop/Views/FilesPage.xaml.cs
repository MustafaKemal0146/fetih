using System;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Fetih.Desktop.Views;

/// <summary>
/// Dosya ağacı + önizleme/diff (issue #43). Çalışma alanı ağacı köprünün
/// <c>file.tree</c>'siyle tembel yüklenir; seçilen dosya <c>file.read</c> ile
/// önizlenir, <c>file.diff</c> ile git değişikliği gösterilir. Tüm yollar
/// çalışma alanı köküne kısıtlıdır (köprü tarafında doğrulanır).
/// </summary>
public sealed partial class FilesPage : Page
{
    private readonly BridgeClient _bridge = BridgeClient.Shared;
    private string _selectedPath = "";
    private string _mode = "preview";

    public FilesPage()
    {
        InitializeComponent();
        ApplyLanguage();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        Loc.LanguageChanged += () => DispatcherQueue.TryEnqueue(ApplyLanguage);
        UpdateModeButtons();
        _ = LoadRootAsync();
    }

    private void ApplyLanguage()
    {
        TreeTitle.Text = Loc.T("files.title");
        ReloadButton.Content = Loc.T("files.reload");
        PreviewButton.Content = Loc.T("files.preview");
        DiffButton.Content = Loc.T("files.diff");
        EmptySelection.Text = Loc.T("files.empty_selection");
    }

    private void ReloadButton_Click(object sender, RoutedEventArgs e) => _ = LoadRootAsync();

    private async Task LoadRootAsync()
    {
        SetBusy(true);
        try
        {
            Tree.RootNodes.Clear();
            var res = await _bridge.FileTreeAsync("").ConfigureAwait(true);
            AddEntries(Tree.RootNodes, res);
        }
        catch (Exception ex)
        {
            App.LogCrash("FilesPage.LoadRoot", ex, ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private static void AddEntries(System.Collections.Generic.IList<TreeViewNode> into, JsonElement res)
    {
        if (res.ValueKind != JsonValueKind.Object ||
            !res.TryGetProperty("entries", out var entries) ||
            entries.ValueKind != JsonValueKind.Array)
        {
            return;
        }
        foreach (var e in entries.EnumerateArray())
        {
            var name = e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            var path = e.TryGetProperty("path", out var p) ? p.GetString() ?? "" : "";
            var isDir = e.TryGetProperty("is_dir", out var d) && d.ValueKind == JsonValueKind.True;
            var size = e.TryGetProperty("size", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt64() : 0;
            if (string.IsNullOrEmpty(name)) continue;
            into.Add(new TreeViewNode
            {
                Content = new FileNode { Name = name, Path = path, IsDir = isDir, Size = size },
                HasUnrealizedChildren = isDir,
            });
        }
    }

    private async void Tree_Expanding(TreeView sender, TreeViewExpandingEventArgs args)
    {
        var node = args.Node;
        if (!node.HasUnrealizedChildren) return;
        // Yeniden girişi önle: bu dizini yalnızca bir kez getir.
        node.HasUnrealizedChildren = false;
        if (node.Content is not FileNode fn || !fn.IsDir) return;
        try
        {
            var res = await _bridge.FileTreeAsync(fn.Path).ConfigureAwait(true);
            node.Children.Clear();
            AddEntries(node.Children, res);
        }
        catch (Exception ex)
        {
            App.LogCrash("FilesPage.Expand", ex, ex.Message);
        }
    }

    private void Tree_ItemInvoked(TreeView sender, TreeViewItemInvokedEventArgs args)
    {
        if (args.InvokedItem is FileNode fn && !fn.IsDir)
        {
            _selectedPath = fn.Path;
            PathText.Text = fn.Path;
            EmptySelection.Visibility = Visibility.Collapsed;
            _ = RenderAsync();
        }
    }

    private void PreviewButton_Click(object sender, RoutedEventArgs e) => SetMode("preview");
    private void DiffButton_Click(object sender, RoutedEventArgs e) => SetMode("diff");

    private void SetMode(string mode)
    {
        _mode = mode;
        UpdateModeButtons();
        if (!string.IsNullOrEmpty(_selectedPath)) _ = RenderAsync();
    }

    private void UpdateModeButtons()
    {
        var accent = (Style)Application.Current.Resources["AccentButtonStyle"];
        PreviewButton.Style = _mode == "preview" ? accent : null;
        DiffButton.Style = _mode == "diff" ? accent : null;
    }

    private async Task RenderAsync()
    {
        if (_mode == "diff") await ShowDiffAsync();
        else await ShowPreviewAsync();
    }

    private async Task ShowPreviewAsync()
    {
        DiffScroller.Visibility = Visibility.Collapsed;
        NoteText.Text = "";
        SetBusy(true);
        try
        {
            var res = await _bridge.FileReadAsync(_selectedPath).ConfigureAwait(true);
            var binary = res.TryGetProperty("binary", out var b) && b.ValueKind == JsonValueKind.True;
            if (binary)
            {
                PreviewBox.Text = "";
                PreviewBox.Visibility = Visibility.Collapsed;
                NoteText.Text = Loc.T("files.binary");
                return;
            }
            var content = res.TryGetProperty("content", out var c) ? c.GetString() ?? "" : "";
            PreviewBox.Text = content;
            PreviewBox.Visibility = Visibility.Visible;
            if (res.TryGetProperty("truncated", out var t) && t.ValueKind == JsonValueKind.True)
            {
                NoteText.Text = Loc.T("files.truncated");
            }
        }
        catch (Exception ex)
        {
            PreviewBox.Visibility = Visibility.Visible;
            PreviewBox.Text = ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task ShowDiffAsync()
    {
        PreviewBox.Visibility = Visibility.Collapsed;
        DiffHost.Children.Clear();
        NoteText.Text = "";
        SetBusy(true);
        try
        {
            var res = await _bridge.FileDiffAsync(_selectedPath).ConfigureAwait(true);
            var available = res.TryGetProperty("available", out var a) && a.ValueKind == JsonValueKind.True;
            if (!available)
            {
                var reason = res.TryGetProperty("reason", out var r) ? r.GetString() ?? "" : "";
                NoteText.Text = string.IsNullOrEmpty(reason) ? Loc.T("files.diff_unavailable") : reason;
                DiffScroller.Visibility = Visibility.Collapsed;
                return;
            }
            var diff = res.TryGetProperty("diff", out var dv) ? dv.GetString() ?? "" : "";
            if (string.IsNullOrWhiteSpace(diff))
            {
                NoteText.Text = Loc.T("files.no_diff");
                DiffScroller.Visibility = Visibility.Collapsed;
                return;
            }
            RenderDiff(diff);
            DiffScroller.Visibility = Visibility.Visible;
        }
        catch (Exception ex)
        {
            NoteText.Text = ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void RenderDiff(string diff)
    {
        var green = BrushFor("SystemFillColorSuccessBrush", Colors.SeaGreen);
        var red = BrushFor("SystemFillColorCriticalBrush", Colors.IndianRed);
        var accent = BrushFor("AccentTextFillColorPrimaryBrush", Colors.SteelBlue);

        var lines = diff.Replace("\r\n", "\n").Split('\n');
        var max = Math.Min(lines.Length, 4000);
        for (var i = 0; i < max; i++)
        {
            var line = lines[i];
            Brush? fg = null;
            double opacity = 1.0;
            if (line.StartsWith("+++", StringComparison.Ordinal) || line.StartsWith("---", StringComparison.Ordinal)
                || line.StartsWith("diff ", StringComparison.Ordinal) || line.StartsWith("index ", StringComparison.Ordinal)
                || line.StartsWith("new file", StringComparison.Ordinal) || line.StartsWith("deleted file", StringComparison.Ordinal)
                || line.StartsWith("similarity", StringComparison.Ordinal) || line.StartsWith("rename ", StringComparison.Ordinal))
            {
                opacity = 0.55;
            }
            else if (line.StartsWith("@@", StringComparison.Ordinal))
            {
                fg = accent;
            }
            else if (line.StartsWith("+", StringComparison.Ordinal))
            {
                fg = green;
            }
            else if (line.StartsWith("-", StringComparison.Ordinal))
            {
                fg = red;
            }

            var tb = new TextBlock
            {
                Text = line.Length == 0 ? " " : line,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12.5,
                TextWrapping = TextWrapping.NoWrap,
                IsTextSelectionEnabled = true,
                Opacity = opacity,
            };
            if (fg is not null) tb.Foreground = fg;
            DiffHost.Children.Add(tb);
        }

        if (lines.Length > max)
        {
            DiffHost.Children.Add(new TextBlock
            {
                Text = $"… +{lines.Length - max}",
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12.5,
                Opacity = 0.5,
                Margin = new Thickness(0, 6, 0, 0),
            });
        }
    }

    private static Brush BrushFor(string key, Windows.UI.Color fallback)
        => Application.Current.Resources.TryGetValue(key, out var b) && b is Brush brush
            ? brush
            : new SolidColorBrush(fallback);

    private void SetBusy(bool busy)
    {
        BusyRing.IsActive = busy;
        ReloadButton.IsEnabled = !busy;
    }
}
