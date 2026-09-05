using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Services;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// <b>Sadeleştirilmiş</b> ayar sayfası motoru — normal (Detaylı Mod olmayan)
/// ayar sayfalarının tamamı bu tek sayfadan üretilir.
///
/// <para>Gezinme parametresi bir <see cref="SimpleSettingsCatalog"/> sayfa
/// kimliğidir (ör. <c>"security"</c>). Katalog, ham config anahtarlarını
/// gündelik dilde başlık + tek cümlelik açıklama + uygun kontrole
/// (aç/kapa, seçim, sayı) eşler. Nadiren değişen anahtarlar kart içindeki
/// "Gelişmiş" genişleticisine saklanır; sıradan kullanıcının hiç
/// ilgilenmeyeceği saf teknik anahtarlar buraya HİÇ konmaz — yalnızca
/// Detaylı Mod'da bulunur.</para>
///
/// <para><b>Fonksiyonellik korunur:</b> her kontrol gerçek config anahtarına
/// bağlıdır ve değişiklik <c>config.set</c> ile <c>~/.fetih/config.yaml</c>
/// dosyasına yazılır. Sadeleştirme yalnızca sunum katmanındadır.</para>
/// </summary>
public sealed partial class SimpleSettingsPage : Page
{
    private readonly BridgeClient _bridge = BridgeClient.Shared;

    private SimplePage? _spec;

    public SimpleSettingsPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);

        var id = e.Parameter as string ?? string.Empty;
        _spec = SimpleSettingsCatalog.Get(id);

        TitleText.Text = _spec?.Title.Value ?? id;
        IntroText.Text = _spec?.Intro.Value ?? string.Empty;
        ReloadButton.Content = Loc.T("simple.reload");
        AdvancedLink.Content = Loc.T("simple.open_advanced");
        AutomationProperties.SetAutomationId(this, "simple_page_" + id);

        _ = LoadAsync();
    }

    private void ReloadButton_Click(object sender, RoutedEventArgs e) => _ = LoadAsync();

    private void AdvancedLink_Click(object sender, RoutedEventArgs e)
        => ShellNavigation.Request(NavTags.SettingsAll);

    // ── Yükleme ──────────────────────────────────────────────────────────────

    private async Task LoadAsync()
    {
        SectionsHost.Children.Clear();
        if (_spec is null)
        {
            return;
        }

        SetBusy(true);
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

            foreach (var section in _spec.Sections)
            {
                var card = BuildSection(section, config);
                if (card is not null)
                {
                    SectionsHost.Children.Add(card);
                }
            }

            HideStatus();
        }
        catch (BridgeRpcException rpc)
        {
            ShowStatus($"{Loc.T("config.bridge_error")} ({rpc.Code}): {rpc.Message}", InfoBarSeverity.Error);
        }
        catch (Exception ex)
        {
            ShowStatus(Loc.T("config.load_failed") + ex.Message, InfoBarSeverity.Error);
            App.LogCrash("SimpleSettingsPage.LoadAsync", ex, ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    /// <summary>Bir kartı kurar. Kartta hiç görünür içerik yoksa <c>null</c> döner.</summary>
    private Border? BuildSection(SimpleSection section, JsonElement config)
    {
        var rows = new List<FrameworkElement>();
        foreach (var control in section.Controls)
        {
            var row = BuildControl(control, config);
            if (row is not null)
            {
                rows.Add(row);
            }
        }

        var advancedRows = new List<FrameworkElement>();
        foreach (var control in section.Advanced)
        {
            var row = BuildControl(control, config);
            if (row is not null)
            {
                advancedRows.Add(row);
            }
        }

        if (rows.Count == 0 && advancedRows.Count == 0 && section.Facts.Count == 0)
        {
            return null;
        }

        var stroke = (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"];
        var body = new StackPanel();

        // Kart başlığı
        var headerPanel = new StackPanel { Spacing = 3 };
        var titleRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        if (!string.IsNullOrEmpty(section.Glyph))
        {
            titleRow.Children.Add(new FontIcon
            {
                Glyph = section.Glyph,
                FontSize = 16,
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = (Brush)Application.Current.Resources["AccentTextFillColorPrimaryBrush"],
            });
        }
        titleRow.Children.Add(new TextBlock
        {
            Text = section.Title.Value,
            FontSize = 17,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
        });
        headerPanel.Children.Add(titleRow);

        if (!section.Description.IsEmpty)
        {
            headerPanel.Children.Add(new TextBlock
            {
                Text = section.Description.Value,
                FontSize = 12.5,
                Opacity = 0.68,
                TextWrapping = TextWrapping.Wrap,
            });
        }

        body.Children.Add(new Border
        {
            Padding = new Thickness(16, 14, 16, rows.Count > 0 ? 6 : 14),
            Child = headerPanel,
        });

        for (var i = 0; i < rows.Count; i++)
        {
            if (i > 0)
            {
                body.Children.Add(Divider(stroke));
            }
            body.Children.Add(rows[i]);
        }

        if (advancedRows.Count > 0)
        {
            body.Children.Add(Divider(stroke));
            body.Children.Add(BuildExpander(Loc.T("simple.advanced_group"), "", advancedRows));
        }

        if (section.Facts.Count > 0)
        {
            var factRows = new List<FrameworkElement>();
            foreach (var fact in section.Facts)
            {
                factRows.Add(FactRow(fact));
            }
            if (rows.Count > 0 || advancedRows.Count > 0)
            {
                body.Children.Add(Divider(stroke));
            }
            var factsTitle = section.FactsTitle.IsEmpty
                ? Loc.T("simple.reference")
                : section.FactsTitle.Value;
            body.Children.Add(BuildExpander(factsTitle, "", factRows));
        }

        return new Border
        {
            CornerRadius = new CornerRadius(8),
            Background = (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
            BorderThickness = new Thickness(1),
            BorderBrush = stroke,
            Child = body,
        };
    }

    private static Border Divider(Brush stroke) => new()
    {
        Height = 1,
        Background = stroke,
        Opacity = 0.7,
        Margin = new Thickness(16, 0, 16, 0),
    };

    private static Expander BuildExpander(string header, string glyph, IReadOnlyList<FrameworkElement> rows)
    {
        var content = new StackPanel();
        for (var i = 0; i < rows.Count; i++)
        {
            content.Children.Add(rows[i]);
        }

        var headerPanel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        if (!string.IsNullOrEmpty(glyph))
        {
            headerPanel.Children.Add(new FontIcon
            {
                Glyph = glyph,
                FontSize = 14,
                Opacity = 0.75,
                VerticalAlignment = VerticalAlignment.Center,
            });
        }
        headerPanel.Children.Add(new TextBlock
        {
            Text = header,
            FontSize = 13.5,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
        });

        var expander = new Expander
        {
            Header = headerPanel,
            Content = content,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(12, 8, 12, 12),
            Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent),
        };
        AutomationProperties.SetName(expander, header);
        return expander;
    }

    // ── Kontrol kurucuları ───────────────────────────────────────────────────

    private FrameworkElement? BuildControl(SimpleControl spec, JsonElement config)
    {
        if (spec.Kind == SimpleKind.Language)
        {
            return LanguageRow(spec);
        }

        // Anahtarı config'de bulunmayan kontrol hiç çizilmez: kullanıcıya
        // karşılığı olmayan bir kutu göstermektense sessizce atlanır.
        if (string.IsNullOrEmpty(spec.Key) || !TryPath(config, spec.Key, out var value))
        {
            return null;
        }

        try
        {
            return spec.Kind switch
            {
                SimpleKind.Toggle => ToggleRow(spec, value),
                SimpleKind.Choice => ChoiceRow(spec, value),
                SimpleKind.Select => SelectRow(spec, value),
                SimpleKind.Number => NumberRow(spec, value),
                SimpleKind.Text => TextRow(spec, value),
                SimpleKind.StringList => StringListRow(spec, value),
                _ => null,
            };
        }
        catch (Exception ex)
        {
            App.LogCrash($"SimpleSettingsPage.BuildControl({spec.Key})", ex, ex.Message);
            return null;
        }
    }

    private FrameworkElement ToggleRow(SimpleControl spec, JsonElement value)
    {
        var current = value.ValueKind == JsonValueKind.True;
        var toggle = new ToggleSwitch
        {
            IsOn = current,
            OnContent = Loc.T("common.on"),
            OffContent = Loc.T("common.off"),
            HorizontalAlignment = HorizontalAlignment.Right,
            MinWidth = 0,
        };
        SetAutoId(toggle, spec.Key);
        var status = StatusText();

        toggle.Toggled += async (_, _) =>
        {
            var desired = toggle.IsOn;
            await SaveAsync(spec.Key, desired, status, () => toggle.IsOn = current, () => current = desired);
        };

        return RowShell(spec, toggle, status);
    }

    private FrameworkElement ChoiceRow(SimpleControl spec, JsonElement value)
    {
        var current = value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ToString();
        var group = "grp_" + spec.Key.Replace('.', '_');

        var options = new StackPanel { Spacing = 10, Margin = new Thickness(0, 8, 0, 0) };
        var status = StatusText();
        var matched = false;

        foreach (var option in spec.Options)
        {
            var content = new StackPanel { Spacing = 2 };
            content.Children.Add(new TextBlock
            {
                Text = option.Title.Value,
                FontWeight = FontWeights.SemiBold,
                FontSize = 13.5,
                TextWrapping = TextWrapping.Wrap,
            });
            if (!option.Description.IsEmpty)
            {
                content.Children.Add(new TextBlock
                {
                    Text = option.Description.Value,
                    FontSize = 12.5,
                    Opacity = 0.68,
                    LineHeight = 18,
                    TextWrapping = TextWrapping.Wrap,
                    MaxWidth = 600,
                });
            }

            var radio = new RadioButton
            {
                GroupName = group,
                Content = content,
                IsChecked = string.Equals(option.Value, current, StringComparison.Ordinal),
                MinWidth = 0,
            };
            if (radio.IsChecked == true)
            {
                matched = true;
            }
            AutomationProperties.SetAutomationId(
                radio, "cfg_" + spec.Key.Replace('.', '_') + "_" + option.Value);
            AutomationProperties.SetName(radio, option.Title.Value);

            var optionValue = option.Value;
            radio.Checked += async (_, _) =>
            {
                if (string.Equals(optionValue, current, StringComparison.Ordinal))
                {
                    return;
                }
                await SaveAsync(spec.Key, optionValue, status, null, () => current = optionValue);
            };

            options.Children.Add(radio);
        }

        if (!matched && !string.IsNullOrEmpty(current))
        {
            options.Children.Add(new TextBlock
            {
                Text = string.Format(CultureInfo.CurrentCulture, Loc.T("simple.unknown_value"), current),
                FontSize = 12,
                Opacity = 0.6,
                TextWrapping = TextWrapping.Wrap,
            });
        }

        options.Children.Add(status);
        return StackedRowShell(spec, options);
    }

    private FrameworkElement SelectRow(SimpleControl spec, JsonElement value)
    {
        var current = value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ToString();
        var combo = new ComboBox { MinWidth = 280, HorizontalAlignment = HorizontalAlignment.Left };
        SetAutoId(combo, spec.Key);

        var descriptions = new List<string>();
        var selected = -1;
        foreach (var option in spec.Options)
        {
            combo.Items.Add(new ComboBoxItem { Content = option.Title.Value, Tag = option.Value });
            descriptions.Add(option.Description.Value);
            if (string.Equals(option.Value, current, StringComparison.Ordinal))
            {
                selected = combo.Items.Count - 1;
            }
        }

        // Config'deki değer katalogda yoksa kaybolmasın diye ham hâliyle eklenir.
        if (selected < 0 && !string.IsNullOrEmpty(current))
        {
            combo.Items.Add(new ComboBoxItem { Content = current, Tag = current });
            descriptions.Add(string.Empty);
            selected = combo.Items.Count - 1;
        }

        combo.SelectedIndex = selected;

        var optionNote = new TextBlock
        {
            Text = selected >= 0 && selected < descriptions.Count ? descriptions[selected] : string.Empty,
            FontSize = 12.5,
            Opacity = 0.68,
            LineHeight = 18,
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 600,
        };
        var status = StatusText();

        combo.SelectionChanged += async (_, _) =>
        {
            var index = combo.SelectedIndex;
            if (index < 0 || index >= descriptions.Count)
            {
                return;
            }
            optionNote.Text = descriptions[index];

            if (combo.SelectedItem is not ComboBoxItem { Tag: string tag } || tag == current)
            {
                return;
            }
            await SaveAsync(spec.Key, tag, status, null, () => current = tag);
        };

        var panel = new StackPanel { Spacing = 8, Margin = new Thickness(0, 8, 0, 0) };
        panel.Children.Add(combo);
        panel.Children.Add(optionNote);
        panel.Children.Add(status);
        return StackedRowShell(spec, panel);
    }

    private FrameworkElement NumberRow(SimpleControl spec, JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Number)
        {
            return RowShell(spec, ReadOnlyValue(value.ToString()), null);
        }

        var isInt = value.TryGetInt64(out _);
        var current = value.GetDouble();
        var box = new NumberBox
        {
            // Sınırlar Value'dan ÖNCE verilir; aksi hâlde aralık dışındaki bir
            // config değeri sessizce kırpılır ve ekranda diskteki değerden
            // farklı bir sayı görünür.
            Minimum = Math.Min(spec.Min, current),
            Maximum = Math.Max(spec.Max, current),
            Value = current,
            SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Compact,
            SmallChange = 1,
            LargeChange = 10,
            Width = 168,
            HorizontalAlignment = HorizontalAlignment.Right,
        };
        SetAutoId(box, spec.Key);
        var status = StatusText();

        box.ValueChanged += async (_, _) =>
        {
            if (double.IsNaN(box.Value) || Math.Abs(box.Value - current) < double.Epsilon)
            {
                return;
            }
            var desired = box.Value;
            object payload = isInt && desired == Math.Floor(desired) ? (long)desired : desired;
            await SaveAsync(spec.Key, payload, status, () => box.Value = current, () => current = desired);
        };

        FrameworkElement control = box;
        if (!spec.Unit.IsEmpty)
        {
            var row = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 8,
                HorizontalAlignment = HorizontalAlignment.Right,
            };
            row.Children.Add(box);
            row.Children.Add(new TextBlock
            {
                Text = spec.Unit.Value,
                FontSize = 12.5,
                Opacity = 0.7,
                VerticalAlignment = VerticalAlignment.Center,
            });
            control = row;
        }

        return RowShell(spec, control, status);
    }

    private FrameworkElement TextRow(SimpleControl spec, JsonElement value)
    {
        var current = value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ToString();
        if (current == "<redacted>")
        {
            return RowShell(spec, ReadOnlyValue(Loc.T("config.secret")), null);
        }

        var box = new TextBox
        {
            Text = current,
            Width = 280,
            HorizontalAlignment = HorizontalAlignment.Right,
        };
        SetAutoId(box, spec.Key);
        var status = StatusText();

        box.LostFocus += async (_, _) =>
        {
            if (box.Text == current)
            {
                return;
            }
            var desired = box.Text;
            await SaveAsync(spec.Key, desired, status, () => box.Text = current, () => current = desired);
        };

        return RowShell(spec, box, status);
    }

    private FrameworkElement StringListRow(SimpleControl spec, JsonElement value)
    {
        var items = new List<string>();
        if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var el in value.EnumerateArray())
            {
                items.Add(el.ValueKind == JsonValueKind.String ? el.GetString() ?? "" : el.ToString());
            }
        }

        var panel = new StackPanel { Spacing = 6, Margin = new Thickness(0, 8, 0, 0) };
        var status = StatusText();
        status.HorizontalAlignment = HorizontalAlignment.Left;

        if (items.Count == 0)
        {
            panel.Children.Add(new TextBlock
            {
                Text = spec.EmptyNote.IsEmpty ? Loc.T("simple.list_empty") : spec.EmptyNote.Value,
                FontSize = 12.5,
                Opacity = 0.68,
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 640,
            });
        }
        else
        {
            var chips = new StackPanel { Spacing = 4 };
            foreach (var item in items)
            {
                chips.Children.Add(new Border
                {
                    Padding = new Thickness(10, 6, 10, 6),
                    CornerRadius = new CornerRadius(4),
                    Background = (Brush)Application.Current.Resources["CardBackgroundFillColorSecondaryBrush"],
                    Child = new TextBlock
                    {
                        Text = item,
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 12,
                        TextWrapping = TextWrapping.Wrap,
                        IsTextSelectionEnabled = true,
                    },
                });
            }
            panel.Children.Add(chips);

            if (spec.AllowClear)
            {
                var clear = new Button
                {
                    Content = Loc.T("simple.list_clear"),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Margin = new Thickness(0, 4, 0, 0),
                };
                AutomationProperties.SetAutomationId(clear, "clear_" + spec.Key.Replace('.', '_'));
                clear.Click += async (_, _) =>
                {
                    clear.IsEnabled = false;
                    await SaveAsync(spec.Key, new List<string>(), status, () => clear.IsEnabled = true, () => { });
                    await LoadAsync();
                };
                panel.Children.Add(clear);
            }
        }

        panel.Children.Add(status);
        return StackedRowShell(spec, panel);
    }

    private static FrameworkElement LanguageRow(SimpleControl spec)
    {
        var combo = new ComboBox { MinWidth = 280, HorizontalAlignment = HorizontalAlignment.Left };
        AutomationProperties.SetAutomationId(combo, "ui_language");
        combo.Items.Add(new ComboBoxItem { Content = Loc.T("appearance.language.auto"), Tag = "auto" });
        combo.Items.Add(new ComboBoxItem { Content = Loc.T("appearance.language.tr"), Tag = "tr" });
        combo.Items.Add(new ComboBoxItem { Content = Loc.T("appearance.language.en"), Tag = "en" });
        combo.SelectedIndex = Loc.Preference switch { "tr" => 1, "en" => 2, _ => 0 };

        combo.SelectionChanged += (_, _) =>
        {
            if (combo.SelectedItem is ComboBoxItem { Tag: string tag })
            {
                Loc.SetPreference(tag);
            }
        };

        var panel = new StackPanel { Spacing = 8, Margin = new Thickness(0, 8, 0, 0) };
        panel.Children.Add(combo);
        return StackedRowShell(spec, panel);
    }

    private static FrameworkElement FactRow(SimpleFact fact)
    {
        var panel = new StackPanel { Spacing = 2, Margin = new Thickness(0, 6, 0, 6) };
        panel.Children.Add(new TextBlock
        {
            Text = fact.Title.Value,
            FontWeight = FontWeights.SemiBold,
            FontSize = 13,
            TextWrapping = TextWrapping.Wrap,
        });
        if (!fact.Detail.IsEmpty)
        {
            panel.Children.Add(new TextBlock
            {
                Text = fact.Detail.Value,
                FontSize = 12.5,
                Opacity = 0.68,
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 640,
            });
        }
        return panel;
    }

    // ── Kaydetme ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Değeri gerçek config anahtarına yazar. Başarısızlıkta kontrolü eski
    /// değerine döndürür — kullanıcı yazılmamış bir değeri yazılmış sanmaz.
    /// </summary>
    private async Task SaveAsync(
        string key, object? value, TextBlock status, Action? revert, Action commit)
    {
        status.Text = Loc.T("config.saving");
        try
        {
            await _bridge.ConfigSetAsync(key, value).ConfigureAwait(true);
            commit();
            status.Text = Loc.T("config.saved");
        }
        catch (BridgeRpcException rpc)
        {
            revert?.Invoke();
            status.Text = "✗ " + (rpc.Code == -32004 ? Loc.T("config.rejected") : rpc.Message);
        }
        catch (Exception ex)
        {
            revert?.Invoke();
            status.Text = "✗ " + ex.Message;
        }
    }

    // ── Görsel yardımcılar ───────────────────────────────────────────────────

    /// <summary>
    /// Kontrolün sağda durduğu satır: ikon · (başlık + açıklama) · kontrol.
    /// Ham config anahtarı BİLEREK gösterilmez — burası sadeleştirilmiş katman.
    /// </summary>
    private static Border RowShell(SimpleControl spec, FrameworkElement control, TextBlock? status)
    {
        var grid = new Grid { ColumnSpacing = 14 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var icon = LabelIcon(spec);
        Grid.SetColumn(icon, 0);
        grid.Children.Add(icon);

        var label = LabelPanel(spec);
        Grid.SetColumn(label, 1);
        grid.Children.Add(label);

        var right = new StackPanel
        {
            Spacing = 4,
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Right,
        };
        right.Children.Add(control);
        if (status is not null)
        {
            right.Children.Add(status);
        }
        Grid.SetColumn(right, 2);
        grid.Children.Add(right);

        return new Border { Padding = new Thickness(16, 13, 16, 13), Child = grid };
    }

    /// <summary>Kontrolün başlığın ALTINDA durduğu satır (seçim listeleri, radyolar).</summary>
    private static Border StackedRowShell(SimpleControl spec, FrameworkElement control)
    {
        var grid = new Grid { ColumnSpacing = 14 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var icon = LabelIcon(spec);
        Grid.SetColumn(icon, 0);
        grid.Children.Add(icon);

        var stack = new StackPanel();
        stack.Children.Add(LabelPanel(spec));
        stack.Children.Add(control);
        Grid.SetColumn(stack, 1);
        grid.Children.Add(stack);

        return new Border { Padding = new Thickness(16, 13, 16, 13), Child = grid };
    }

    private static FontIcon LabelIcon(SimpleControl spec) => new()
    {
        Glyph = string.IsNullOrEmpty(spec.Glyph) ? SettingDescriptions.GlyphFor(spec.Key) : spec.Glyph,
        FontSize = 16,
        Opacity = 0.75,
        VerticalAlignment = VerticalAlignment.Top,
        Margin = new Thickness(0, 3, 0, 0),
    };

    private static StackPanel LabelPanel(SimpleControl spec)
    {
        var panel = new StackPanel { Spacing = 3, VerticalAlignment = VerticalAlignment.Center };
        panel.Children.Add(new TextBlock
        {
            Text = spec.Title.Value,
            FontWeight = FontWeights.SemiBold,
            FontSize = 14,
            TextWrapping = TextWrapping.Wrap,
        });
        if (!spec.Description.IsEmpty)
        {
            panel.Children.Add(new TextBlock
            {
                Text = spec.Description.Value,
                FontSize = 12.5,
                Opacity = 0.68,
                LineHeight = 18,
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 560,
            });
        }
        return panel;
    }

    private static TextBlock ReadOnlyValue(string text) => new()
    {
        Text = text,
        Opacity = 0.7,
        FontSize = 12.5,
        TextWrapping = TextWrapping.Wrap,
        MaxWidth = 280,
        TextAlignment = TextAlignment.Right,
        HorizontalAlignment = HorizontalAlignment.Right,
        VerticalAlignment = VerticalAlignment.Center,
        IsTextSelectionEnabled = true,
    };

    private static TextBlock StatusText() => new()
    {
        Text = string.Empty,
        FontSize = 12,
        Opacity = 0.75,
        HorizontalAlignment = HorizontalAlignment.Right,
    };

    private static void SetAutoId(FrameworkElement element, string key)
        => AutomationProperties.SetAutomationId(element, "cfg_" + key.Replace('.', '_'));

    /// <summary>Noktalı bir yolu JSON ağacında çözer.</summary>
    private static bool TryPath(JsonElement root, string path, out JsonElement value)
    {
        value = default;
        var current = root;
        foreach (var segment in path.Split('.'))
        {
            if (current.ValueKind != JsonValueKind.Object ||
                !current.TryGetProperty(segment, out var next))
            {
                return false;
            }
            current = next;
        }
        value = current;
        return true;
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
