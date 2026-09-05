using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Services;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
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
/// <para>Görsel dil, Windows 11 "SettingsCard" desenine yakındır: her bölüm
/// tek bir kart, kart içinde ayraçlarla bölünmüş satırlar; her satırda ikon,
/// yerelleştirilmiş etiket, ham config anahtarı, o anahtara ÖZGÜ açıklama
/// (bkz. <see cref="SettingDescriptions"/>), sağda kontrol ve değer
/// değiştiyse bir "yüklenen değere dön" düğmesi.</para>
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
                _title = SettingDescriptions.SectionTitle(spec.Trim());
            }
        }

        TitleText.Text = _title;

        // Filtresiz açıldığında sayfa "Detaylı Mod"dur: TÜM ham anahtarlar
        // görünür, bu yüzden kapatılamayan bir uyarı şeridi gösterilir.
        var isAdvancedMode = _rootFilter.Length == 0;
        SubtitleText.Text = isAdvancedMode
            ? Loc.T("config.advanced.subtitle")
            : Loc.T("config.subtitle");
        AdvancedWarning.Title = Loc.T("config.advanced.warn.title");
        AdvancedWarning.Message = Loc.T("config.advanced.warn.body");
        AdvancedWarning.IsOpen = isAdvancedMode;

        ReloadButton.Content = Loc.T("config.reload");
        EmptyText.Text = Loc.T("config.empty");
        _ = LoadAsync();
    }

    private void ReloadButton_Click(object sender, RoutedEventArgs e) => _ = LoadAsync();

    private async Task LoadAsync()
    {
        SetBusy(true);
        FieldsHost.Children.Clear();
        EmptyText.Visibility = Visibility.Collapsed;

        // Not: arayüz dili seçicisi artık burada değil, sadeleştirilmiş
        // "Görünüm" sayfasındadır (SimpleSettingsCatalog → appearance).
        // Detaylı Mod yalnızca config.yaml'daki ham anahtarları gösterir.

        try
        {
            var res = await _bridge.ConfigGetAsync().ConfigureAwait(true);

            if (res.ValueKind != JsonValueKind.Object ||
                !res.TryGetProperty("config", out var config) ||
                config.ValueKind != JsonValueKind.Object)
            {
                ShowStatus(Loc.T("config.read_failed"), InfoBarSeverity.Error);
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

                // Tek bölümlük bir sayfada bölüm başlığı, sayfa başlığının
                // aynısı olurdu; onun yerine kategori özetini alt başlığın
                // altına taşıyıp başlığı atlıyoruz.
                if (_rootFilter.Length == 1 &&
                    string.Equals(SettingDescriptions.SectionTitle(root.Name), _title, StringComparison.Ordinal))
                {
                    var summary = SettingDescriptions.SectionDescription(root.Name);
                    if (!string.IsNullOrEmpty(summary))
                    {
                        FieldsHost.Children.Add(new TextBlock
                        {
                            Text = summary,
                            FontSize = 13,
                            Opacity = 0.7,
                            MaxWidth = 820,
                            HorizontalAlignment = HorizontalAlignment.Left,
                            TextWrapping = TextWrapping.Wrap,
                            Margin = new Thickness(0, 0, 0, 10),
                        });
                    }
                }
                else
                {
                    FieldsHost.Children.Add(SectionHeader(root.Name));
                }

                FieldsHost.Children.Add(SectionCard(sectionFields));
            }

            EmptyText.Visibility = any || FieldsHost.Children.Count > 0
                ? Visibility.Collapsed
                : Visibility.Visible;
            HideStatus();
        }
        catch (BridgeRpcException rpc)
        {
            ShowStatus($"{Loc.T("config.bridge_error")} ({rpc.Code}): {rpc.Message}", InfoBarSeverity.Error);
        }
        catch (Exception ex)
        {
            ShowStatus(Loc.T("config.load_failed") + ex.Message, InfoBarSeverity.Error);
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
        var loaded = current;
        var toggle = new ToggleSwitch
        {
            IsOn = current,
            OnContent = Loc.T("common.on"),
            OffContent = Loc.T("common.off"),
            HorizontalAlignment = HorizontalAlignment.Right,
            MinWidth = 0,
        };
        SetAutoId(toggle, keyPath);
        var status = StatusText();
        var revert = RevertButton(keyPath);

        toggle.Toggled += async (_, _) =>
        {
            revert.Visibility = toggle.IsOn != loaded ? Visibility.Visible : Visibility.Collapsed;
            await SaveAsync(keyPath, toggle.IsOn, status, () => toggle.IsOn = current, v => current = (bool)v!);
        };

        revert.Click += (_, _) => toggle.IsOn = loaded;

        return RowShell(keyPath, toggle, status, revert);
    }

    private Border NumberRow(string keyPath, JsonElement value)
    {
        var isInt = value.TryGetInt64(out _);
        double current = value.GetDouble();
        var loaded = current;
        var box = new NumberBox
        {
            Value = current,
            SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Compact,
            SmallChange = 1,
            LargeChange = 10,
            Width = 200,
            HorizontalAlignment = HorizontalAlignment.Right,
        };
        SetAutoId(box, keyPath);
        var status = StatusText();
        var revert = RevertButton(keyPath);

        box.ValueChanged += async (_, _) =>
        {
            if (double.IsNaN(box.Value))
            {
                return;
            }
            revert.Visibility = Math.Abs(box.Value - loaded) > double.Epsilon
                ? Visibility.Visible
                : Visibility.Collapsed;
            object payload = isInt && box.Value == Math.Floor(box.Value)
                ? (long)box.Value
                : box.Value;
            await SaveAsync(keyPath, payload, status, () => box.Value = current, v =>
                current = Convert.ToDouble(v, CultureInfo.InvariantCulture));
        };

        revert.Click += (_, _) => box.Value = loaded;

        return RowShell(keyPath, box, status, revert);
    }

    private Border StringRow(string keyPath, string current)
    {
        // Gizli / env-referans değerleri düzenlenemez.
        if (current == "<redacted>")
        {
            return ReadOnlyRow(keyPath, Loc.T("config.secret"));
        }
        if (current.StartsWith("${", StringComparison.Ordinal) && current.EndsWith("}", StringComparison.Ordinal))
        {
            return ReadOnlyRow(keyPath, current + Loc.T("config.env_ref"));
        }

        var loaded = current;
        var box = new TextBox
        {
            Text = current,
            Width = 300,
            HorizontalAlignment = HorizontalAlignment.Right,
            TextWrapping = TextWrapping.NoWrap,
        };
        SetAutoId(box, keyPath);
        var status = StatusText();
        var revert = RevertButton(keyPath);

        box.TextChanged += (_, _) =>
            revert.Visibility = box.Text != loaded ? Visibility.Visible : Visibility.Collapsed;

        // Enter veya odak kaybında kaydet.
        box.LostFocus += async (_, _) =>
        {
            if (box.Text != current)
            {
                await SaveAsync(keyPath, box.Text, status, () => box.Text = current, v => current = v?.ToString() ?? "");
            }
        };

        revert.Click += async (_, _) =>
        {
            box.Text = loaded;
            if (loaded != current)
            {
                await SaveAsync(keyPath, loaded, status, () => box.Text = current, v => current = v?.ToString() ?? "");
            }
        };

        return RowShell(keyPath, box, status, revert);
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
            return ReadOnlyRow(keyPath, arr.GetRawText() + Loc.T("config.complex_list"));
        }

        var current = string.Join(", ", items);
        var loaded = current;
        var box = new TextBox
        {
            Text = current,
            Width = 300,
            HorizontalAlignment = HorizontalAlignment.Right,
            PlaceholderText = Loc.T("config.list_placeholder"),
        };
        SetAutoId(box, keyPath);
        var status = StatusText();
        var revert = RevertButton(keyPath);

        box.TextChanged += (_, _) =>
            revert.Visibility = box.Text != loaded ? Visibility.Visible : Visibility.Collapsed;

        box.LostFocus += async (_, _) =>
        {
            if (box.Text == current)
            {
                return;
            }
            await SaveAsync(keyPath, SplitList(box.Text), status, () => box.Text = current, _ => current = box.Text);
        };

        revert.Click += async (_, _) =>
        {
            box.Text = loaded;
            if (loaded != current)
            {
                await SaveAsync(keyPath, SplitList(loaded), status, () => box.Text = current, _ => current = loaded);
            }
        };

        return RowShell(keyPath, box, status, revert);
    }

    private static List<string> SplitList(string text)
    {
        var list = new List<string>();
        foreach (var piece in text.Split(','))
        {
            var t = piece.Trim();
            if (t.Length > 0)
            {
                list.Add(t);
            }
        }
        return list;
    }

    private static Border ReadOnlyRow(string keyPath, string display)
    {
        var tb = new TextBlock
        {
            Text = display,
            Opacity = 0.7,
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 300,
            HorizontalAlignment = HorizontalAlignment.Right,
            TextAlignment = TextAlignment.Right,
            VerticalAlignment = VerticalAlignment.Center,
            IsTextSelectionEnabled = true,
        };
        return RowShell(keyPath, tb, null, null);
    }

    // ── Kaydetme ─────────────────────────────────────────────────────────────

    private async Task SaveAsync(
        string keyPath, object? value, TextBlock status, Action revert, Action<object?> commit)
    {
        status.Text = Loc.T("config.saving");
        try
        {
            await _bridge.ConfigSetAsync(keyPath, value).ConfigureAwait(true);
            commit(value);
            status.Text = Loc.T("config.saved");
        }
        catch (BridgeRpcException rpc)
        {
            revert();
            status.Text = "✗ " + (rpc.Code == -32004 ? Loc.T("config.rejected") : rpc.Message);
        }
        catch (Exception ex)
        {
            revert();
            status.Text = "✗ " + ex.Message;
        }
    }

    // ── Görsel yardımcılar ───────────────────────────────────────────────────

    /// <summary>
    /// Tek bir ayar satırı. Soldan sağa: ikon · (etiket + ham anahtar +
    /// anahtara özgü açıklama) · kontrol + kaydetme durumu · geri al düğmesi.
    /// </summary>
    private static Border RowShell(
        string keyPath, FrameworkElement control, TextBlock? status, Button? revert)
    {
        var grid = new Grid { ColumnSpacing = 14 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var icon = new FontIcon
        {
            Glyph = SettingDescriptions.GlyphFor(keyPath),
            FontSize = 16,
            Opacity = 0.75,
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 3, 0, 0),
        };
        Grid.SetColumn(icon, 0);
        grid.Children.Add(icon);

        var labelPanel = new StackPanel { Spacing = 3, VerticalAlignment = VerticalAlignment.Center };
        labelPanel.Children.Add(new TextBlock
        {
            Text = SettingDescriptions.LabelFor(keyPath),
            FontWeight = FontWeights.SemiBold,
            FontSize = 14,
            TextWrapping = TextWrapping.Wrap,
        });
        labelPanel.Children.Add(new TextBlock
        {
            Text = keyPath,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 11,
            Opacity = 0.45,
            TextWrapping = TextWrapping.Wrap,
        });

        // Anahtara ÖZGÜ açıklama. Katalogda karşılığı yoksa hiçbir metin
        // gösterilmez — kategori-seviyesi metne düşülmez (bkz. SettingDescriptions).
        var description = SettingDescriptions.For(keyPath);
        if (!string.IsNullOrEmpty(description))
        {
            labelPanel.Children.Add(new TextBlock
            {
                Text = description,
                FontSize = 12.5,
                Opacity = 0.68,
                LineHeight = 18,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 3, 0, 0),
            });
        }

        Grid.SetColumn(labelPanel, 1);
        grid.Children.Add(labelPanel);

        var right = new StackPanel
        {
            Spacing = 4,
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Right,
            MinWidth = 120,
        };
        right.Children.Add(control);
        if (status is not null)
        {
            right.Children.Add(status);
        }
        Grid.SetColumn(right, 2);
        grid.Children.Add(right);

        if (revert is not null)
        {
            Grid.SetColumn(revert, 3);
            grid.Children.Add(revert);
        }

        return new Border
        {
            Padding = new Thickness(16, 13, 16, 13),
            Child = grid,
        };
    }

    /// <summary>Değer değiştiğinde beliren "yüklenen değere dön" düğmesi.</summary>
    private static Button RevertButton(string keyPath)
    {
        var button = new Button
        {
            Content = new FontIcon { Glyph = "", FontSize = 14 },
            Padding = new Thickness(7, 5, 7, 5),
            Visibility = Visibility.Collapsed,
            VerticalAlignment = VerticalAlignment.Center,
            Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent),
            BorderThickness = new Thickness(0),
        };
        ToolTipService.SetToolTip(button, Loc.T("config.revert"));
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(
            button, "revert_" + keyPath.Replace('.', '_'));
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(button, Loc.T("config.revert"));
        return button;
    }

    private static TextBlock StatusText() => new()
    {
        Text = "",
        FontSize = 12,
        Opacity = 0.75,
        HorizontalAlignment = HorizontalAlignment.Right,
    };

    /// <summary>Bölüm başlığı: yerelleştirilmiş ad, ham kök anahtar ve kategori özeti.</summary>
    private static Border SectionHeader(string rootKey)
    {
        var panel = new StackPanel { Spacing = 2 };

        var titleRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        titleRow.Children.Add(new FontIcon
        {
            Glyph = SettingDescriptions.GlyphFor(rootKey),
            FontSize = 16,
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = (Brush)Application.Current.Resources["AccentTextFillColorPrimaryBrush"],
        });
        titleRow.Children.Add(new TextBlock
        {
            Text = SettingDescriptions.SectionTitle(rootKey),
            FontSize = 18,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
        });
        titleRow.Children.Add(new TextBlock
        {
            Text = rootKey,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 11,
            Opacity = 0.4,
            VerticalAlignment = VerticalAlignment.Bottom,
            Margin = new Thickness(0, 0, 0, 3),
        });
        panel.Children.Add(titleRow);

        var summary = SettingDescriptions.SectionDescription(rootKey);
        if (!string.IsNullOrEmpty(summary))
        {
            panel.Children.Add(new TextBlock
            {
                Text = summary,
                FontSize = 12.5,
                Opacity = 0.65,
                TextWrapping = TextWrapping.Wrap,
            });
        }

        return new Border { Padding = new Thickness(2, 18, 0, 8), Child = panel };
    }

    /// <summary>Bir bölümün satırlarını tek bir kartta, ince ayraçlarla toplar.</summary>
    private static Border SectionCard(IReadOnlyList<FrameworkElement> rows)
    {
        var stroke = (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"];
        var stack = new StackPanel();

        for (var i = 0; i < rows.Count; i++)
        {
            if (i > 0)
            {
                stack.Children.Add(new Border
                {
                    Height = 1,
                    Background = stroke,
                    Opacity = 0.7,
                    Margin = new Thickness(16, 0, 16, 0),
                });
            }
            stack.Children.Add(rows[i]);
        }

        return new Border
        {
            CornerRadius = new CornerRadius(8),
            Background = (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
            BorderThickness = new Thickness(1),
            BorderBrush = stroke,
            Child = stack,
        };
    }

    private static void SetAutoId(FrameworkElement el, string keyPath)
        => Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(el, "cfg_" + keyPath.Replace('.', '_'));

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
