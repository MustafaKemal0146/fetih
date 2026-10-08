using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;

namespace Fetih.Desktop.Views;

/// <summary>
/// Kanıt klasörü (issue #36): yerel kanıt dosyalarını (ekran görüntüsü, çıktı,
/// vb.) listeler ve native önizler (resim/metin). Kök: Belgeler\FETIH-Kanit.
/// Dosyalar kullanıcının makinesinde olduğundan doğrudan okunur (köprü yok).
/// </summary>
public sealed partial class EvidencePage : Page
{
    private static readonly string[] ImageExts =
        { ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tiff" };

    private static readonly string[] TextExts =
    {
        ".txt", ".log", ".md", ".json", ".xml", ".csv", ".yaml", ".yml", ".html", ".htm",
        ".py", ".cs", ".js", ".ts", ".sh", ".ps1", ".ini", ".cfg", ".conf", ".pcap-meta",
    };

    private readonly ObservableCollection<EvidenceFile> _files = new();

    private static string EvidenceRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "FETIH-Kanit");

    public EvidencePage()
    {
        InitializeComponent();
        FileList.ItemsSource = _files;
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void ApplyLanguage()
    {
        PageTitleText.Text = Loc.T("evidence.title");
        SubtitleText.Text = Loc.T("evidence.subtitle");
        AddButton.Content = Loc.T("evidence.add_file");
        OpenFolderButton.Content = Loc.T("evidence.open_folder");
        ReloadButton.Content = Loc.T("evidence.reload");
        EmptyText.Text = Loc.T("evidence.empty");
        SelectHintText.Text = Loc.T("evidence.select_hint");
        NoteText.Text = Loc.T("evidence.binary");
        AutomationProperties.SetName(FileList, Loc.T("evidence.title"));
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged += OnLanguageChanged;
        Reload();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged -= OnLanguageChanged;
    }

    private void OnLanguageChanged() => ApplyLanguage();

    private void ReloadButton_Click(object sender, RoutedEventArgs e) => Reload();

    private void Reload()
    {
        _files.Clear();
        try
        {
            Directory.CreateDirectory(EvidenceRoot);
            var infos = new DirectoryInfo(EvidenceRoot)
                .GetFiles()
                .OrderByDescending(fi => fi.LastWriteTime);
            foreach (var fi in infos)
            {
                _files.Add(new EvidenceFile(fi.Name, fi.FullName));
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("EvidencePage.Reload", ex, ex.Message);
        }

        var has = _files.Count > 0;
        EmptyText.Visibility = has ? Visibility.Collapsed : Visibility.Visible;
        CountText.Text = has ? string.Format(Loc.T("evidence.count"), _files.Count) : "";
        if (!has) ShowNone();
    }

    private void FileList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FileList.SelectedItem is EvidenceFile f)
        {
            _ = PreviewAsync(f.Path);
        }
    }

    private async Task PreviewAsync(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        SelectHintText.Visibility = Visibility.Collapsed;

        if (ImageExts.Contains(ext))
        {
            try
            {
                PreviewImage.Source = new BitmapImage(new Uri(path));
                ImageScroller.Visibility = Visibility.Visible;
                PreviewText.Visibility = Visibility.Collapsed;
                NoteText.Visibility = Visibility.Collapsed;
                return;
            }
            catch { /* düşer: not gösterilir */ }
        }

        if (TextExts.Contains(ext) || await LooksTextualAsync(path))
        {
            try
            {
                var content = await ReadCappedAsync(path);
                PreviewText.Text = content;
                PreviewText.Visibility = Visibility.Visible;
                ImageScroller.Visibility = Visibility.Collapsed;
                NoteText.Visibility = Visibility.Collapsed;
                return;
            }
            catch { /* düşer */ }
        }

        // Önizlenemeyen tür.
        ImageScroller.Visibility = Visibility.Collapsed;
        PreviewText.Visibility = Visibility.Collapsed;
        NoteText.Visibility = Visibility.Visible;
    }

    private void ShowNone()
    {
        ImageScroller.Visibility = Visibility.Collapsed;
        PreviewText.Visibility = Visibility.Collapsed;
        NoteText.Visibility = Visibility.Collapsed;
        SelectHintText.Visibility = Visibility.Visible;
    }

    private async void OpenFolderButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(EvidenceRoot);
            await Task.Run(() => Process.Start(new ProcessStartInfo
            {
                FileName = EvidenceRoot,
                UseShellExecute = true,
            }));
        }
        catch (Exception ex)
        {
            App.LogCrash("EvidencePage.OpenFolder", ex, ex.Message);
        }
    }

    private async void AddButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new Windows.Storage.Pickers.FileOpenPicker
            {
                SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.Desktop,
            };
            picker.FileTypeFilter.Add("*");

            if (App.MainAppWindow is { } win)
            {
                var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(win);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
            }

            var file = await picker.PickSingleFileAsync();
            if (file is null) return;

            Directory.CreateDirectory(EvidenceRoot);
            var dest = UniqueDest(EvidenceRoot, file.Name);
            File.Copy(file.Path, dest, overwrite: false);
            Reload();
            var added = _files.FirstOrDefault(f => f.Path == dest);
            if (added is not null) FileList.SelectedItem = added;
        }
        catch (Exception ex)
        {
            App.LogCrash("EvidencePage.Add", ex, ex.Message);
        }
    }

    // ── Yardımcılar ───────────────────────────────────────────────────────────

    private static string UniqueDest(string dir, string name)
    {
        var dest = Path.Combine(dir, name);
        if (!File.Exists(dest)) return dest;
        var stem = Path.GetFileNameWithoutExtension(name);
        var ext = Path.GetExtension(name);
        for (var i = 1; i < 1000; i++)
        {
            dest = Path.Combine(dir, $"{stem} ({i}){ext}");
            if (!File.Exists(dest)) return dest;
        }
        return Path.Combine(dir, $"{stem}-{Guid.NewGuid():N}{ext}");
    }

    private static async Task<string> ReadCappedAsync(string path)
    {
        const int max = 512 * 1024;
        await using var fs = File.OpenRead(path);
        var buf = new byte[Math.Min(max, (int)Math.Min(fs.Length, int.MaxValue))];
        var read = await fs.ReadAsync(buf.AsMemory(0, buf.Length));
        var text = System.Text.Encoding.UTF8.GetString(buf, 0, read);
        if (fs.Length > max) text += "\n\n… (kesildi / truncated)";
        return text;
    }

    private static async Task<bool> LooksTextualAsync(string path)
    {
        try
        {
            await using var fs = File.OpenRead(path);
            var buf = new byte[Math.Min(1024, (int)Math.Min(fs.Length, int.MaxValue))];
            var read = await fs.ReadAsync(buf.AsMemory(0, buf.Length));
            for (var i = 0; i < read; i++)
            {
                if (buf[i] == 0) return false; // NUL → ikili
            }
            return read > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Liste öğesi: dosya adı (görünür) + tam yol. ToString adı verir.</summary>
    private sealed record EvidenceFile(string Name, string Path)
    {
        public override string ToString() => Name;
    }
}
