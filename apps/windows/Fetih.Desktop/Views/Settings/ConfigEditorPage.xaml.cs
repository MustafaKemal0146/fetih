using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// Şema güdümlü jenerik yapılandırma editörü (OpenClaw'ın Config sayfası
/// desenine karşılık). <c>config.get</c> ile tüm config'i okur; bir
/// gezinme parametresiyle verilen kök anahtarın (ör. <c>agent</c>) altındaki
/// yaprakları TÜR'e göre (bool → ToggleSwitch, sayı → NumberBox, metin →
/// TextBox) düzenlenebilir satırlar olarak çizer ve her değişikliği
/// <c>config.set</c> ile DİSKE yazar.
///
/// <para>Gizli değerler (<c>&lt;redacted&gt;</c>) ve <c>${ENV}</c> referansları
/// salt okunur gösterilir — bu bir güvenlik aracı, anahtar değeri asla
/// düzenlenmez.</para>
/// </summary>
public sealed partial class ConfigEditorPage : Page
{
    private readonly BridgeClient _bridge = BridgeClient.Shared;

    /// <summary>Yalnızca bu kök anahtar(lar)ı göster. Boşsa tümü.</summary>
    private string[] _rootFilter = Array.Empty<string>();
    private string _title = "Ayarlar";

    public ConfigEditorPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);

        // Parametre: "başlık|kök1,kök2" ya da yalnızca "kök".
        if (e.Parameter is string spec && !string.IsNullOrWhiteSpace(spec))
        {
            var parts = spec.Split('|', 2);
            if (parts.Length == 2)
            {
                _title = parts[0];
                _rootFilter = parts[1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            }
            else
            {
                _rootFilter = new[] { spec.Trim() };
                _title = Humanize(spec.Trim());
            }
        }

        TitleText.Text = _title;
        _ = LoadAsync();
    }

    private void ReloadButton_Click(object sender, RoutedEventArgs e) => _ = LoadAsync();

    private async Task LoadAsync()
    {
        SetBusy(true);
        FieldsHost.Children.Clear();
        EmptyText.Visibility = Visibility.Collapsed;

        // Görev E: "Görünüm" bölümünde arayüz dili seçicisini en üste ekle.
        // Dil tercihi config.yaml'da değil yerel bir dosyada tutulduğundan
        // jenerik editör onu göstermez; bu yüzden özel bir kart çiziyoruz.
        if (Array.IndexOf(_rootFilter, "display") >= 0)
        {
            FieldsHost.Children.Add(BuildLanguageCard());
        }

        try
        {
            var res = await _bridge.ConfigGetAsync().ConfigureAwait(true);

            if (res.ValueKind != JsonValueKind.Object ||
                !res.TryGetProperty("config", out var config) ||
                config.ValueKind != JsonValueKind.Object)
            {
                ShowStatus("Yapılandırma okunamadı.", InfoBarSeverity.Error);
                return;
            }

            var any = false;
            foreach (var root in config.EnumerateObject())
            {
                if (_rootFilter.Length > 0 && Array.IndexOf(_rootFilter, root.Name) < 0)
                {
                    continue;
                }

                var sectionFields = new List<FrameworkElement>();
                BuildLeaves(root.Name, root.Value, sectionFields);

                if (sectionFields.Count == 0)
                {
                    continue;
                }

                any = true;
                FieldsHost.Children.Add(SectionHeader(Humanize(root.Name), root.Name));
                foreach (var f in sectionFields)
                {
                    FieldsHost.Children.Add(f);
                }
            }

            EmptyText.Visibility = any || FieldsHost.Children.Count > 0
                ? Visibility.Collapsed
                : Visibility.Visible;
            HideStatus();
        }
        catch (BridgeRpcException rpc)
        {
            ShowStatus($"Köprü hatası ({rpc.Code}): {rpc.Message}", InfoBarSeverity.Error);
        }
        catch (Exception ex)
        {
            ShowStatus("Yapılandırma yüklenemedi: " + ex.Message, InfoBarSeverity.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>Bir JSON alt ağacını düzenlenebilir yaprak satırlarına indirger.</summary>
    private void BuildLeaves(string keyPath, JsonElement value, List<FrameworkElement> into)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in value.EnumerateObject())
                {
                    BuildLeaves($"{keyPath}.{prop.Name}", prop.Value, into);
                }
                break;

            case JsonValueKind.Array:
                into.Add(ArrayRow(keyPath, value));
                break;

            case JsonValueKind.True:
            case JsonValueKind.False:
                into.Add(BoolRow(keyPath, value.GetBoolean()));
                break;

            case JsonValueKind.Number:
                into.Add(NumberRow(keyPath, value));
                break;

            case JsonValueKind.String:
                into.Add(StringRow(keyPath, value.GetString() ?? ""));
                break;

            case JsonValueKind.Null:
                into.Add(StringRow(keyPath, ""));
                break;
        }
    }

    // ── Satır kurucular ──────────────────────────────────────────────────────

    private Border BoolRow(string keyPath, bool current)
    {
        var toggle = new ToggleSwitch
        {
            IsOn = current,
            OnContent = "açık",
            OffContent = "kapalı",
        };
        SetAutoId(toggle, keyPath);
        var status = StatusText();

        toggle.Toggled += async (_, _) =>
            await SaveAsync(keyPath, toggle.IsOn, status, () => toggle.IsOn = current, v => current = (bool)v!);

        return RowShell(keyPath, toggle, status);
    }

    private Border NumberRow(string keyPath, JsonElement value)
    {
        var isInt = value.TryGetInt64(out _);
        double current = value.GetDouble();
        var box = new NumberBox
        {
            Value = current,
            SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Compact,
            SmallChange = 1,
            LargeChange = 10,
            Width = 220,
            HorizontalAlignment = HorizontalAlignment.Left,
        };
        SetAutoId(box, keyPath);
        var status = StatusText();

        box.ValueChanged += async (_, _) =>
        {
            if (double.IsNaN(box.Value))
            {
                return;
            }
            object payload = isInt && box.Value == Math.Floor(box.Value)
                ? (long)box.Value
                : box.Value;
            await SaveAsync(keyPath, payload, status, () => box.Value = current, v =>
                current = Convert.ToDouble(v, CultureInfo.InvariantCulture));
        };

        return RowShell(keyPath, box, status);
    }

    private Border StringRow(string keyPath, string current)
    {
        // Gizli / env-referans değerleri düzenlenemez.
        if (current == "<redacted>")
        {
            return ReadOnlyRow(keyPath, "•••••• (gizli — ~/.fetih/.env içinde)");
        }
        if (current.StartsWith("${", StringComparison.Ordinal) && current.EndsWith("}", StringComparison.Ordinal))
        {
            return ReadOnlyRow(keyPath, current + "  (ortam değişkeni referansı)");
        }

        var box = new TextBox
        {
            Text = current,
            Width = 360,
            HorizontalAlignment = HorizontalAlignment.Left,
            TextWrapping = TextWrapping.NoWrap,
        };
        SetAutoId(box, keyPath);
        var status = StatusText();

        // Enter veya odak kaybında kaydet.
        box.LostFocus += async (_, _) =>
        {
            if (box.Text != current)
            {
                await SaveAsync(keyPath, box.Text, status, () => box.Text = current, v => current = v?.ToString() ?? "");
            }
        };

        return RowShell(keyPath, box, status);
    }

    private Border ArrayRow(string keyPath, JsonElement arr)
    {
        // Düz string listeleri virgülle düzenlenebilir; karmaşık listeler salt okunur.
        var allStrings = true;
        var items = new List<string>();
        foreach (var el in arr.EnumerateArray())
        {
            if (el.ValueKind == JsonValueKind.String)
            {
                items.Add(el.GetString() ?? "");
            }
            else
            {
                allStrings = false;
                break;
            }
        }

        if (!allStrings)
        {
            return ReadOnlyRow(keyPath, arr.GetRawText() + "  (karmaşık liste — burada düzenlenmez)");
        }

        var current = string.Join(", ", items);
        var box = new TextBox
        {
            Text = current,
            Width = 360,
            HorizontalAlignment = HorizontalAlignment.Left,
            PlaceholderText = "virgülle ayrılmış liste",
        };
        SetAutoId(box, keyPath);
        var status = StatusText();

        box.LostFocus += async (_, _) =>
        {
            if (box.Text == current)
            {
                return;
            }
            var list = new List<string>();
            foreach (var piece in box.Text.Split(','))
            {
                var t = piece.Trim();
                if (t.Length > 0)
                {
                    list.Add(t);
                }
            }
            await SaveAsync(keyPath, list, status, () => box.Text = current, _ => current = box.Text);
        };

        return RowShell(keyPath, box, status);
    }

    private Border ReadOnlyRow(string keyPath, string display)
    {
        var tb = new TextBlock
        {
            Text = display,
            Opacity = 0.7,
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
            IsTextSelectionEnabled = true,
        };
        return RowShell(keyPath, tb, null);
    }

    // ── Kaydetme ─────────────────────────────────────────────────────────────

    private async Task SaveAsync(
        string keyPath, object? value, TextBlock status, Action revert, Action<object?> commit)
    {
        status.Text = "kaydediliyor…";
        try
        {
            await _bridge.ConfigSetAsync(keyPath, value).ConfigureAwait(true);
            commit(value);
            status.Text = "✓ kaydedildi";
        }
        catch (BridgeRpcException rpc)
        {
            revert();
            status.Text = "✗ " + (rpc.Code == -32004
                ? "reddedildi (gizli anahtar veya yönetilen kurulum)"
                : rpc.Message);
        }
        catch (Exception ex)
        {
            revert();
            status.Text = "✗ " + ex.Message;
        }
    }

    // ── Dil seçici kartı (Görev E) ─────────────────────────────────────────

    private static Border BuildLanguageCard()
    {
        var combo = new ComboBox
        {
            MinWidth = 240,
            HorizontalAlignment = HorizontalAlignment.Left,
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(combo, "ui_language");
        combo.Items.Add(new ComboBoxItem { Content = Services.Loc.T("appearance.language.auto"), Tag = "auto" });
        combo.Items.Add(new ComboBoxItem { Content = Services.Loc.T("appearance.language.tr"), Tag = "tr" });
        combo.Items.Add(new ComboBoxItem { Content = Services.Loc.T("appearance.language.en"), Tag = "en" });

        var pref = Services.Loc.Preference;
        combo.SelectedIndex = pref switch { "tr" => 1, "en" => 2, _ => 0 };

        var status = StatusText();
        combo.SelectionChanged += (_, _) =>
        {
            if (combo.SelectedItem is ComboBoxItem { Tag: string tag })
            {
                Services.Loc.SetPreference(tag);
                status.Text = Services.Loc.T("appearance.language.note");
            }
        };

        var panel = new StackPanel { Spacing = 6 };
        panel.Children.Add(new TextBlock
        {
            Text = Services.Loc.T("appearance.language"),
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            FontSize = 16,
        });
        panel.Children.Add(new TextBlock
        {
            Text = Services.Loc.T("appearance.language.note"),
            FontSize = 12,
            Opacity = 0.65,
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(combo);
        panel.Children.Add(status);

        return new Border
        {
            Padding = new Thickness(16),
            CornerRadius = new CornerRadius(8),
            Margin = new Thickness(0, 0, 0, 8),
            Background = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
            BorderThickness = new Thickness(1),
            BorderBrush = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"],
            Child = panel,
        };
    }

    // ── Görsel yardımcılar ───────────────────────────────────────────────────

    private static Border RowShell(string keyPath, FrameworkElement control, TextBlock? status)
    {
        var grid = new Grid { ColumnSpacing = 16, RowSpacing = 6 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(260) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var labelPanel = new StackPanel { Spacing = 2, VerticalAlignment = VerticalAlignment.Center };
        labelPanel.Children.Add(new TextBlock
        {
            Text = LeafLabel(keyPath),
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            FontSize = 13,
            TextWrapping = TextWrapping.Wrap,
        });
        labelPanel.Children.Add(new TextBlock
        {
            Text = keyPath,
            FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"),
            FontSize = 11,
            Opacity = 0.45,
            TextWrapping = TextWrapping.Wrap,
        });
        Grid.SetColumn(labelPanel, 0);
        Grid.SetRow(labelPanel, 0);
        grid.Children.Add(labelPanel);

        var right = new StackPanel { Spacing = 3, VerticalAlignment = VerticalAlignment.Center };
        right.Children.Add(control);
        if (status is not null)
        {
            right.Children.Add(status);
        }
        Grid.SetColumn(right, 1);
        Grid.SetRow(right, 0);
        grid.Children.Add(right);

        // Görev F: satırın altına, iki sütunu kaplayan bilgilendirici açıklama (varsa).
        var description = Services.SettingDescriptions.For(keyPath);
        if (!string.IsNullOrEmpty(description))
        {
            var desc = new TextBlock
            {
                Text = description,
                FontSize = 12,
                Opacity = 0.65,
                TextWrapping = TextWrapping.Wrap,
            };
            Grid.SetColumn(desc, 0);
            Grid.SetColumnSpan(desc, 2);
            Grid.SetRow(desc, 1);
            grid.Children.Add(desc);
        }

        return new Border
        {
            Padding = new Thickness(0, 8, 0, 8),
            Child = grid,
            BorderThickness = new Thickness(0, 0, 0, 1),
            BorderBrush = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"],
        };
    }

    private static TextBlock StatusText() => new()
    {
        Text = "",
        FontSize = 12,
        Opacity = 0.75,
    };

    private static Border SectionHeader(string title, string rootKey)
    {
        var panel = new StackPanel { Spacing = 1 };
        panel.Children.Add(new TextBlock
        {
            Text = title,
            FontSize = 16,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
        });
        panel.Children.Add(new TextBlock
        {
            Text = rootKey,
            FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"),
            FontSize = 11,
            Opacity = 0.4,
        });
        return new Border { Padding = new Thickness(0, 16, 0, 4), Child = panel };
    }

    private static void SetAutoId(FrameworkElement el, string keyPath)
        => Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(el, "cfg_" + keyPath.Replace('.', '_'));

    private static string LeafLabel(string keyPath)
    {
        var idx = keyPath.LastIndexOf('.');
        return Humanize(idx >= 0 ? keyPath[(idx + 1)..] : keyPath);
    }

    private static string Humanize(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return key;
        }
        var words = key.Replace('_', ' ').Replace('-', ' ');
        return char.ToUpper(words[0], CultureInfo.InvariantCulture) + words[1..];
    }

    private void SetBusy(bool busy)
    {
        BusyRing.IsActive = busy;
        ReloadButton.IsEnabled = !busy;
    }

    private void ShowStatus(string message, InfoBarSeverity severity)
    {
        StatusBar.Message = message;
        StatusBar.Severity = severity;
        StatusBar.IsOpen = true;
    }

    private void HideStatus() => StatusBar.IsOpen = false;
}
