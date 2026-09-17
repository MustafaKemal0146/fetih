using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Fetih.Desktop.Setup;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// Model ve sağlayıcı ayarları. Sağlayıcı listesi <c>fetih_cli/providers.py</c>
/// kaplama tablosundan, etkin model/sağlayıcı <c>~/.fetih/config.yaml</c>'dan,
/// anahtar durumu ise süreç ortamı + <c>~/.fetih/.env</c>'den okunur.
/// <b>Anahtar değerleri hiçbir zaman okunmaz veya gösterilmez.</b>
/// </summary>
public sealed partial class ProviderPage : Page
{
    private List<ProviderRow> _all = new();

    private readonly BridgeClient _bridge = BridgeClient.Shared;

    /// <summary>Görev G: seçiciyi besleyen (etiket → id) sağlayıcı adayları.</summary>
    private List<(string Label, string Id)> _providerChoices = new();

    public ProviderPage()
    {
        InitializeComponent();
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void ApplyLanguage()
    {
        PageTitleText.Text = Loc.T("provider.title");
        SubtitleText.Text = Loc.T("provider.subtitle");
        ActiveConfigHeader.Text = Loc.T("provider.active_config");
        ChangeModelHeader.Text = Loc.T("provider.change_model");
        ChangeModelDesc.Text = Loc.T("provider.change_model_desc");
        ProviderLabel.Text = Loc.T("provider.label.provider");
        ModelLabel.Text = Loc.T("provider.label.model");
        ApiKeyLabel.Text = Loc.T("provider.label.api_key");
        ProviderSelectBox.PlaceholderText = Loc.T("provider.placeholder.provider");
        ModelCombo.PlaceholderText = Loc.T("provider.placeholder.model");
        ApiKeySignupLink.Content = Loc.T("provider.get_key");
        SaveModelButton.Content = Loc.T("provider.save");
        SlotsTitle.Text = Loc.T("provider.slots_title");
        SlotsIntro.Text = Loc.T("provider.slots_intro");
        SearchBox.PlaceholderText = Loc.T("provider.search_placeholder");
        OnlyConfiguredBox.Content = Loc.T("provider.only_configured");

        // Ekran okuyucu adları: yukarıdaki etiketler ayrı TextBlock'lar olduğu
        // için UIA bunları denetimlerle kendiliğinden eşleştiremiyor; adları
        // açıkça kurmazsak alanlar adsız kalıyordu.
        AutomationProperties.SetName(ProviderSelectBox, ProviderLabel.Text);
        AutomationProperties.SetName(ModelCombo, ModelLabel.Text);
        AutomationProperties.SetName(ApiKeyBox, ApiKeyLabel.Text);
        AutomationProperties.SetName(SaveModelButton, SaveModelButton.Content?.ToString() ?? "");
        AutomationProperties.SetName(SearchBox, Loc.T("provider.search_name"));
        AutomationProperties.SetName(OnlyConfiguredBox, OnlyConfiguredBox.Content?.ToString() ?? "");
        AutomationProperties.SetName(ApiKeySignupLink, ApiKeySignupLink.Content?.ToString() ?? "");
        AutomationProperties.SetName(
            ProviderList, Loc.T("provider.list_name"));
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged += OnLanguageChanged;
        Populate();
        _ = SeedSelectorAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged -= OnLanguageChanged;
    }

    private void OnLanguageChanged()
    {
        ApplyLanguage();
        Populate();
        _ = SeedSelectorAsync();
    }

    /// <summary>
    /// providers.list RPC'sinden etkin sağlayıcı/model ve kullanıcı tanımlı
    /// sağlayıcıları okur; seçiciyi ProviderRegistry kataloğuyla birleştirip
    /// doldurur. Köprüye bağlanamazsa yalnızca statik katalog kullanılır.
    /// </summary>
    private async Task SeedSelectorAsync()
    {
        // Statik katalog her zaman mevcuttur; seçici en azından bununla dolar.
        _providerChoices = ProviderRegistry.All
            .Select(p => ($"{p.Label}  ({p.Id})", p.Id))
            .ToList();

        try
        {
            var res = await _bridge.ProvidersListAsync().ConfigureAwait(true);
            if (res.ValueKind == JsonValueKind.Object)
            {
                // Kullanıcı tanımlı sağlayıcıları da adaylara ekle.
                if (res.TryGetProperty("providers", out var provs) && provs.ValueKind == JsonValueKind.Array)
                {
                    foreach (var p in provs.EnumerateArray())
                    {
                        var id = p.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "";
                        var name = p.TryGetProperty("name", out var n) ? n.GetString() ?? id : id;
                        if (!string.IsNullOrEmpty(id) &&
                            !_providerChoices.Any(c => c.Id == id))
                        {
                            _providerChoices.Add(($"{name}  ({id})", id));
                        }
                    }
                }

                // Etkin değerleri düzenleyiciye ön-doldur.
                string activeProv = "";
                string activeModel = "";
                if (res.TryGetProperty("active", out var active) && active.ValueKind == JsonValueKind.Object)
                {
                    activeProv = active.TryGetProperty("provider", out var pv) ? pv.GetString() ?? "" : "";
                    activeModel = active.TryGetProperty("model", out var mv) ? mv.GetString() ?? "" : "";
                }
                if (string.IsNullOrEmpty(activeProv))
                {
                    activeProv = FetihConfigService.Current.Config.GetString("model.provider") ?? "";
                    activeModel = FetihConfigService.Current.Config.GetString("model.default") ?? "";
                }

                if (!string.IsNullOrEmpty(activeProv))
                {
                    ProviderSelectBox.Text = activeProv;
                    await UpdateSelectedProviderStateAsync(activeProv, activeModel).ConfigureAwait(true);
                }
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("ProviderPage.SeedSelector", ex, ex.Message);
        }

        if (string.IsNullOrEmpty(ProviderSelectBox.Text))
        {
            var fallbackProv = FetihConfigService.Current.Config.GetString("model.provider") ?? "";
            var fallbackModel = FetihConfigService.Current.Config.GetString("model.default") ?? "";
            if (!string.IsNullOrEmpty(fallbackProv))
            {
                ProviderSelectBox.Text = fallbackProv;
                await UpdateSelectedProviderStateAsync(fallbackProv, fallbackModel).ConfigureAwait(true);
            }
        }

        // Yuva satırları sağlayıcı adaylarını kullanır; bu yüzden ADAYLAR
        // hazırlandıktan SONRA kurulur.
        try
        {
            await BuildModelSlotsAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            App.LogCrash("ProviderPage.BuildModelSlots", ex, ex.Message);
        }
    }

    // ── Diğer model yuvaları ────────────────────────────────────────────────
    //
    // Envanterdeki (docs/fetih-ozellik-envanteri.md §1) gerçek anahtarlar:
    //   * fallback_model            → birincil sağlayıcı 429/5xx verdiğinde
    //   * auxiliary.<görev>.provider / .model → 11 yan görev için ayrı model
    // Buraya UYDURMA yuva EKLENMEZ: her satırın karşılığı config.yaml'da
    // gerçekten bulunan bir anahtardır (fetih_cli/config.py DEFAULT_CONFIG).

    /// <summary>
    /// Bir yardımcı model yuvasının tanımı. Başlık ve açıklama yerelleştirme
    /// anahtarı olarak tutulur; metin <see cref="Loc.T"/> ile çözülür ki dil
    /// değişince yuva da yeni dilde kurulsun.
    /// </summary>
    private sealed record AuxSlot(string Task, string TitleKey, string DescriptionKey);

    private static readonly AuxSlot[] AuxSlots =
    {
        new("vision", "provider.aux.vision.title", "provider.aux.vision.desc"),
        new("web_extract", "provider.aux.web_extract.title", "provider.aux.web_extract.desc"),
        new("compression", "provider.aux.compression.title", "provider.aux.compression.desc"),
        new("skills_hub", "provider.aux.skills_hub.title", "provider.aux.skills_hub.desc"),
        new("approval", "provider.aux.approval.title", "provider.aux.approval.desc"),
        new("mcp", "provider.aux.mcp.title", "provider.aux.mcp.desc"),
        new("title_generation", "provider.aux.title_generation.title", "provider.aux.title_generation.desc"),
        new("triage_specifier", "provider.aux.triage_specifier.title", "provider.aux.triage_specifier.desc"),
        new("kanban_decomposer", "provider.aux.kanban_decomposer.title", "provider.aux.kanban_decomposer.desc"),
        new("profile_describer", "provider.aux.profile_describer.title", "provider.aux.profile_describer.desc"),
        new("curator", "provider.aux.curator.title", "provider.aux.curator.desc"),
    };

    /// <summary>
    /// Yuva kartını kurar: yedek model + 11 yardımcı model. Değerler
    /// <c>config.get</c>'ten okunur, kayıt <c>config.set</c> ile yapılır.
    /// </summary>
    private async Task BuildModelSlotsAsync()
    {
        SlotsHost.Children.Clear();

        JsonElement config;
        try
        {
            var res = await _bridge.ConfigGetAsync().ConfigureAwait(true);
            if (res.ValueKind != JsonValueKind.Object ||
                !res.TryGetProperty("config", out config) ||
                config.ValueKind != JsonValueKind.Object)
            {
                SlotsHost.Children.Add(new TextBlock
                {
                    Text = Loc.T("provider.config_unreadable"),
                    Opacity = 0.7,
                    FontSize = 12,
                });
                return;
            }
        }
        catch (Exception ex)
        {
            SlotsHost.Children.Add(new TextBlock
            {
                Text = Loc.T("provider.config_error") + ex.Message,
                Opacity = 0.7,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
            });
            return;
        }

        // ── Yedek model ─────────────────────────────────────────────────────
        var (fbProvider, fbModel, fbChainLength) = ReadFallback(config);
        var fallbackNote = fbChainLength > 1
            ? string.Format(Loc.T("provider.slots.chain_note"), fbChainLength)
            : Loc.T("provider.slots.fallback_desc");

        SlotsHost.Children.Add(SlotRow(
            "slot_fallback",
            Loc.T("provider.slots.fallback_title"),
            fallbackNote,
            fbProvider,
            fbModel,
            includeAuto: false,
            async (provider, model, status) =>
            {
                if (string.IsNullOrEmpty(provider) && string.IsNullOrEmpty(model))
                {
                    await _bridge.ConfigSetAsync("fallback_model", null).ConfigureAwait(true);
                    return;
                }
                await _bridge.ConfigSetAsync("fallback_model", new Dictionary<string, object?>
                {
                    ["provider"] = provider,
                    ["model"] = model,
                }).ConfigureAwait(true);
            }));

        // ── Yardımcı modeller ───────────────────────────────────────────────
        var auxHost = new StackPanel { Spacing = 4 };
        foreach (var slot in AuxSlots)
        {
            var provider = ReadString(config, "auxiliary", slot.Task, "provider");
            var model = ReadString(config, "auxiliary", slot.Task, "model");
            var task = slot.Task;
            auxHost.Children.Add(SlotRow(
                "slot_aux_" + task,
                Loc.T(slot.TitleKey),
                Loc.T(slot.DescriptionKey),
                string.IsNullOrEmpty(provider) ? "auto" : provider,
                model,
                includeAuto: true,
                async (p, m, status) =>
                {
                    await _bridge.ConfigSetAsync($"auxiliary.{task}.provider",
                        string.IsNullOrEmpty(p) ? "auto" : p).ConfigureAwait(true);
                    await _bridge.ConfigSetAsync($"auxiliary.{task}.model", m).ConfigureAwait(true);
                }));
        }

        var expander = new Expander
        {
            Header = new TextBlock
            {
                Text = string.Format(Loc.T("provider.slots.aux_header"), AuxSlots.Length),
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                FontSize = 13,
            },
            Content = auxHost,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(0, 8, 0, 0),
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(expander, "slot_aux_group");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(expander, Loc.T("provider.slots.aux_name"));
        SlotsHost.Children.Add(expander);
    }

    /// <summary>Tek bir yuva satırı: sağlayıcı seçici + model kutusu + Kaydet.</summary>
    private FrameworkElement SlotRow(
        string id,
        string title,
        string description,
        string currentProvider,
        string currentModel,
        bool includeAuto,
        Func<string, string, TextBlock, Task> save)
    {
        var panel = new StackPanel { Spacing = 4, Margin = new Thickness(0, 6, 0, 6) };
        panel.Children.Add(new TextBlock
        {
            Text = title,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            FontSize = 13.5,
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(new TextBlock
        {
            Text = description,
            FontSize = 12,
            Opacity = 0.65,
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 620,
        });

        var combo = new ComboBox { MinWidth = 220, IsEditable = false };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(combo, id + "_provider");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(combo, title);
        if (includeAuto)
        {
            combo.Items.Add(new ComboBoxItem { Content = Loc.T("provider.slots.auto"), Tag = "auto" });
        }
        else
        {
            combo.Items.Add(new ComboBoxItem { Content = Loc.T("provider.slots.none"), Tag = "" });
        }
        foreach (var choice in _providerChoices)
        {
            combo.Items.Add(new ComboBoxItem { Content = choice.Label, Tag = choice.Id });
        }

        var selected = -1;
        for (var i = 0; i < combo.Items.Count; i++)
        {
            if (combo.Items[i] is ComboBoxItem { Tag: string tag } &&
                string.Equals(tag, currentProvider, StringComparison.OrdinalIgnoreCase))
            {
                selected = i;
                break;
            }
        }
        // Katalogda olmayan bir sağlayıcı config'de yazıyorsa kaybolmasın.
        if (selected < 0 && !string.IsNullOrEmpty(currentProvider))
        {
            combo.Items.Add(new ComboBoxItem { Content = currentProvider, Tag = currentProvider });
            selected = combo.Items.Count - 1;
        }
        combo.SelectedIndex = selected < 0 ? 0 : selected;

        var modelBox = new TextBox
        {
            Text = currentModel,
            MinWidth = 240,
            PlaceholderText = Loc.T("provider.slots.model_placeholder"),
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(modelBox, id + "_model");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            modelBox, title + " — " + Loc.T("provider.label.model"));

        var status = new TextBlock { FontSize = 12, Opacity = 0.8, VerticalAlignment = VerticalAlignment.Center };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(status, id + "_status");

        var saveButton = new Button { Content = Loc.T("provider.slots.save") };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(saveButton, id + "_save");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            saveButton, string.Format(Loc.T("provider.slots.save_name"), title));
        saveButton.Click += async (_, _) =>
        {
            saveButton.IsEnabled = false;
            status.Text = Loc.T("provider.slots.saving");
            try
            {
                var provider = combo.SelectedItem is ComboBoxItem { Tag: string t } ? t : "";
                await save(provider, modelBox.Text?.Trim() ?? "", status);
                status.Text = Loc.T("provider.slots.saved");
            }
            catch (BridgeRpcException rpc)
            {
                status.Text = "✗ " + (rpc.Code == -32004 ? Loc.T("provider.slots.rejected") : rpc.Message);
            }
            catch (Exception ex)
            {
                status.Text = "✗ " + ex.Message;
                App.LogCrash("ProviderPage.SlotSave(" + id + ")", ex, ex.Message);
            }
            finally
            {
                saveButton.IsEnabled = true;
            }
        };

        var row = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            Margin = new Thickness(0, 4, 0, 0),
        };
        row.Children.Add(combo);
        row.Children.Add(modelBox);
        row.Children.Add(saveButton);
        row.Children.Add(status);
        panel.Children.Add(row);

        return panel;
    }

    /// <summary>
    /// <c>fallback_model</c> hem tek bir sözlük hem de bir zincir (liste)
    /// olabilir; ikisini de okur ve ilk basamağı döndürür.
    /// </summary>
    private static (string Provider, string Model, int ChainLength) ReadFallback(JsonElement config)
    {
        if (!config.TryGetProperty("fallback_model", out var fb))
        {
            return ("", "", 0);
        }

        if (fb.ValueKind == JsonValueKind.Array)
        {
            var length = fb.GetArrayLength();
            foreach (var entry in fb.EnumerateArray())
            {
                return (StringOf(entry, "provider"), StringOf(entry, "model"), length);
            }
            return ("", "", length);
        }

        if (fb.ValueKind == JsonValueKind.Object)
        {
            return (StringOf(fb, "provider"), StringOf(fb, "model"), 1);
        }

        return ("", "", 0);
    }

    private static string StringOf(JsonElement element, string name)
        => element.ValueKind == JsonValueKind.Object &&
           element.TryGetProperty(name, out var v) &&
           v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? ""
            : "";

    /// <summary>Noktalı olmayan çok parçalı bir yolu JSON ağacında çözer.</summary>
    private static string ReadString(JsonElement root, params string[] path)
    {
        var current = root;
        foreach (var segment in path)
        {
            if (current.ValueKind != JsonValueKind.Object ||
                !current.TryGetProperty(segment, out var next))
            {
                return "";
            }
            current = next;
        }
        return current.ValueKind == JsonValueKind.String ? current.GetString() ?? "" : "";
    }

    private async void ProviderSelectBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason != AutoSuggestionBoxTextChangeReason.UserInput)
        {
            return;
        }
        var needle = sender.Text?.Trim().ToLowerInvariant() ?? "";
        var matches = _providerChoices
            .Where(c => needle.Length == 0 ||
                        c.Label.ToLowerInvariant().Contains(needle, StringComparison.Ordinal) ||
                        c.Id.Contains(needle, StringComparison.Ordinal))
            .Select(c => c.Label)
            .Take(12)
            .ToList();
        sender.ItemsSource = matches;

        // Tam eşleşen bir sağlayıcı id'si veya etiketi yazıldıysa durumunu güncelle
        var exact = _providerChoices.FirstOrDefault(c =>
            string.Equals(c.Id, needle, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(c.Label, needle, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrEmpty(exact.Id))
        {
            await UpdateSelectedProviderStateAsync(exact.Id).ConfigureAwait(true);
        }
    }

    private async void ProviderSelectBox_SuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
    {
        // Seçilen etiketten id'yi çöz ve kutuya id'yi yaz (config.set id bekler).
        if (args.SelectedItem is string label)
        {
            var match = _providerChoices.FirstOrDefault(c => c.Label == label);
            var pid = !string.IsNullOrEmpty(match.Id) ? match.Id : label;
            sender.Text = pid;
            await UpdateSelectedProviderStateAsync(pid).ConfigureAwait(true);
        }
    }

    private async void SelectProviderFromList_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string providerId } && !string.IsNullOrWhiteSpace(providerId))
        {
            ProviderSelectBox.Text = providerId;
            await UpdateSelectedProviderStateAsync(providerId).ConfigureAwait(true);
            ProviderSelectBox.Focus(FocusState.Programmatic);
        }
    }

    private async void ApiKeySignupLink_Click(object sender, RoutedEventArgs e)
    {
        if (sender is HyperlinkButton { Tag: string url } && Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            await Windows.System.Launcher.LaunchUriAsync(uri);
        }
    }

    private async Task UpdateSelectedProviderStateAsync(string providerId, string? preferredModel = null)
    {
        if (string.IsNullOrWhiteSpace(providerId))
        {
            return;
        }

        var resolved = _providerChoices.FirstOrDefault(c =>
            string.Equals(c.Label, providerId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(c.Id, providerId, StringComparison.OrdinalIgnoreCase));
        var pid = !string.IsNullOrEmpty(resolved.Id) ? resolved.Id : providerId.Trim();

        var entry = ProviderRegistry.ById(pid);

        // ── 1. API Anahtarı Durumu ve Arayüzü ──────────────────────────────
        if (entry == null)
        {
            ApiKeyBox.Visibility = Visibility.Visible;
            ApiKeySignupLink.Visibility = Visibility.Collapsed;
            ApiKeyStatusDot.Visibility = Visibility.Collapsed;
            ApiKeyStatusText.Text = "";
            ApiKeyEnvVarText.Text = "";
            ProviderKindInfoBar.IsOpen = false;
        }
        else if (entry.Kind == ProviderKind.LocalServer)
        {
            ApiKeyBox.Visibility = Visibility.Collapsed;
            ApiKeyStatusDot.Visibility = Visibility.Collapsed;
            ApiKeyStatusText.Text = "";
            ApiKeyEnvVarText.Text = "";
            ProviderKindInfoBar.Severity = InfoBarSeverity.Informational;
            ProviderKindInfoBar.Title = entry.Label;
            ProviderKindInfoBar.Message = Loc.T("provider.local_no_key");
            ProviderKindInfoBar.IsOpen = true;

            if (!string.IsNullOrWhiteSpace(entry.SignupUrl))
            {
                ApiKeySignupLink.Visibility = Visibility.Visible;
                ApiKeySignupLink.Tag = entry.SignupUrl;
            }
            else
            {
                ApiKeySignupLink.Visibility = Visibility.Collapsed;
            }
        }
        else if (entry.Kind is ProviderKind.CliLogin or ProviderKind.OAuthBrowser or ProviderKind.AwsSdk)
        {
            ApiKeyBox.Visibility = Visibility.Collapsed;
            ApiKeyStatusDot.Visibility = Visibility.Collapsed;
            ApiKeyStatusText.Text = "";
            ApiKeyEnvVarText.Text = "";
            ProviderKindInfoBar.Severity = InfoBarSeverity.Informational;
            ProviderKindInfoBar.Title = entry.Label;
            ProviderKindInfoBar.Message = Loc.T("provider.cli_auth_required");
            ProviderKindInfoBar.IsOpen = true;
            ApiKeySignupLink.Visibility = Visibility.Collapsed;
        }
        else
        {
            ProviderKindInfoBar.IsOpen = false;
            ApiKeyBox.Visibility = Visibility.Visible;
            var envVar = entry.ApiKeyEnvVars.Count > 0 ? entry.ApiKeyEnvVars[0] : "";
            ApiKeyEnvVarText.Text = string.IsNullOrEmpty(envVar) ? "" : $"({envVar})";

            var presence = !string.IsNullOrEmpty(envVar)
                ? FetihConfigService.Current.GetKeyPresence(envVar)
                : EnvKeyPresence.Missing;

            ApiKeyStatusDot.Visibility = Visibility.Visible;
            if (presence != EnvKeyPresence.Missing)
            {
                if (Application.Current.Resources.TryGetValue("SystemFillColorSuccessBrush", out var successBrush))
                {
                    ApiKeyStatusDot.Fill = (Microsoft.UI.Xaml.Media.Brush)successBrush;
                    ApiKeyStatusText.Foreground = (Microsoft.UI.Xaml.Media.Brush)successBrush;
                }
                ApiKeyStatusText.Text = Loc.T("provider.status.key_configured");
                ApiKeyBox.PlaceholderText = Loc.T("provider.placeholder.api_key_configured");
            }
            else
            {
                if (Application.Current.Resources.TryGetValue("SystemFillColorCautionBrush", out var cautionBrush))
                {
                    ApiKeyStatusDot.Fill = (Microsoft.UI.Xaml.Media.Brush)cautionBrush;
                    ApiKeyStatusText.Foreground = (Microsoft.UI.Xaml.Media.Brush)cautionBrush;
                }
                ApiKeyStatusText.Text = Loc.T("provider.status.key_missing");
                ApiKeyBox.PlaceholderText = Loc.T("provider.placeholder.api_key_missing");
            }

            if (!string.IsNullOrWhiteSpace(entry.SignupUrl))
            {
                ApiKeySignupLink.Visibility = Visibility.Visible;
                ApiKeySignupLink.Tag = entry.SignupUrl;
            }
            else
            {
                ApiKeySignupLink.Visibility = Visibility.Collapsed;
            }
        }

        // ── 2. Model Listesi (Canlı + Çevrimdışı Katalog) ─────────────────────
        var curated = ProviderRegistry.GetCuratedModels(pid);
        var currentSelection = preferredModel ?? (ModelCombo.SelectedItem as string ?? ModelCombo.Text ?? "");

        if (curated.Count > 0)
        {
            ModelHintText.Text = string.Format(Loc.T("provider.models.curated"), curated.Count);
            PopulateModelCombo(curated, currentSelection);
        }
        else
        {
            ModelHintText.Text = "";
            PopulateModelCombo(Array.Empty<string>(), currentSelection);
        }

        try
        {
            var res = await _bridge.ProvidersModelsAsync(pid).ConfigureAwait(true);
            if (res.ValueKind == JsonValueKind.Object &&
                res.TryGetProperty("models", out var ms) &&
                ms.ValueKind == JsonValueKind.Array)
            {
                var liveModels = new List<string>();
                foreach (var m in ms.EnumerateArray())
                {
                    if (m.ValueKind == JsonValueKind.String)
                    {
                        var str = m.GetString() ?? "";
                        if (!string.IsNullOrWhiteSpace(str) && !liveModels.Contains(str))
                        {
                            liveModels.Add(str);
                        }
                    }
                }

                if (liveModels.Count > 0)
                {
                    var combined = new List<string>(curated.Where(c => liveModels.Contains(c)));
                    foreach (var m in liveModels)
                    {
                        if (!combined.Contains(m)) combined.Add(m);
                    }
                    var rec = res.TryGetProperty("recommended", out var rc) ? rc.GetString() ?? "" : "";
                    var source = res.TryGetProperty("source", out var sv) ? sv.GetString() ?? "" : "";
                    ModelHintText.Text = string.Format(
                        Loc.T(source == "live" ? "provider.models.live" : "provider.models.ready"),
                        combined.Count);

                    var targetModel = !string.IsNullOrEmpty(currentSelection) ? currentSelection : rec;
                    PopulateModelCombo(combined, targetModel);
                }
            }
        }
        catch
        {
            if (curated.Count == 0)
            {
                ModelHintText.Text = Loc.T("provider.models.failed");
            }
        }
    }

    private void PopulateModelCombo(IReadOnlyList<string> models, string? preferred)
    {
        ModelCombo.Items.Clear();
        foreach (var m in models)
        {
            ModelCombo.Items.Add(m);
        }

        if (!string.IsNullOrWhiteSpace(preferred))
        {
            var matched = models.FirstOrDefault(m => string.Equals(m, preferred, StringComparison.OrdinalIgnoreCase));
            if (matched != null)
            {
                ModelCombo.SelectedItem = matched;
            }
            else
            {
                ModelCombo.Text = preferred;
            }
        }
        else if (models.Count > 0 && string.IsNullOrEmpty(ModelCombo.Text))
        {
            ModelCombo.SelectedIndex = 0;
        }
    }

    private async void SaveModelButton_Click(object sender, RoutedEventArgs e)
    {
        // Girilen etiket bir öneri etiketiyse id'ye çevir; değilse olduğu gibi kullan.
        var providerInput = ProviderSelectBox.Text?.Trim() ?? "";
        var resolved = _providerChoices.FirstOrDefault(c =>
            c.Label == providerInput || c.Id == providerInput);
        var provider = string.IsNullOrEmpty(resolved.Id) ? providerInput : resolved.Id;
        var model = (ModelCombo.SelectedItem as string ?? ModelCombo.Text ?? "").Trim();
        var newKey = ApiKeyBox.Password?.Trim() ?? "";

        if (string.IsNullOrEmpty(provider) && string.IsNullOrEmpty(model))
        {
            SaveModelStatus.Text = Loc.T("provider.save.need_input");
            return;
        }

        SaveModelButton.IsEnabled = false;
        SaveModelStatus.Text = Loc.T("provider.save.saving");
        try
        {
            if (!string.IsNullOrEmpty(provider))
            {
                await _bridge.ConfigSetAsync("model.provider", provider).ConfigureAwait(true);
            }
            if (!string.IsNullOrEmpty(model))
            {
                await _bridge.ConfigSetAsync("model.default", model).ConfigureAwait(true);
            }

            var keySaved = false;
            var entry = ProviderRegistry.ById(provider);
            var envVar = entry?.ApiKeyEnvVars.Count > 0 ? entry.ApiKeyEnvVars[0] : "";
            if (!string.IsNullOrEmpty(newKey))
            {
                if (!string.IsNullOrEmpty(envVar))
                {
                    EnvFileWriter.SetValue(FetihPaths.EnvFilePath, envVar, newKey);
                    Environment.SetEnvironmentVariable(envVar, newKey);
                    keySaved = true;
                }
                ApiKeyBox.Password = "";
            }

            // Yazıldığını doğrula: config.get ile geri oku.
            var check = await _bridge.ConfigGetAsync("model").ConfigureAwait(true);
            SaveModelStatus.Text = Loc.T(keySaved
                ? "provider.save.model_and_key"
                : "provider.save.model_only");

            if (entry != null && entry.Kind == ProviderKind.CloudApiKey && !string.IsNullOrEmpty(envVar) &&
                FetihConfigService.Current.GetKeyPresence(envVar) == EnvKeyPresence.Missing && !keySaved)
            {
                SaveModelStatus.Text += Loc.T("provider.save.no_key_yet");
            }

            // Diskten okuyan salt-okunur listeyi de tazele.
            Populate();
            await UpdateSelectedProviderStateAsync(provider, model).ConfigureAwait(true);
        }
        catch (BridgeRpcException rpc)
        {
            SaveModelStatus.Text = "✗ " + (rpc.Code == -32004
                ? Loc.T("provider.save.rejected")
                : rpc.Message);
        }
        catch (Exception ex)
        {
            SaveModelStatus.Text = "✗ " + ex.Message;
            App.LogCrash("ProviderPage.SaveModel", ex, ex.Message);
        }
        finally
        {
            SaveModelButton.IsEnabled = true;
        }
    }

    private void Populate()
    {
        try
        {
            var service = FetihConfigService.Current;
            service.Reload();
            var config = service.Config;

            var activeProvider = config.GetString("model.provider") ?? string.Empty;
            var activeModel = config.GetString("model.default") ?? string.Empty;

            ActiveRows.ItemsSource = BuildActiveRows(config, activeProvider, activeModel);

            _all = ProviderRegistry.All
                .Select(entry => BuildRow(entry, service, activeProvider))
                .ToList();

            ApplyFilter();
        }
        catch (Exception ex)
        {
            App.LogCrash("ProviderPage.Populate", ex, ex.Message);
        }
    }

    private static List<SettingRow> BuildActiveRows(YamlNode config, string activeProvider, string activeModel)
    {
        var service = FetihConfigService.Current;

        var rows = new List<SettingRow>
        {
            new(SettingDescriptions.LabelFor("model.default"), string.IsNullOrWhiteSpace(activeModel) ? Loc.T("voice.undefined") : activeModel,
                SettingDescriptions.For("model.default") ?? "", "model.default"),
            new(SettingDescriptions.LabelFor("model.provider"), string.IsNullOrWhiteSpace(activeProvider) ? Loc.T("voice.undefined") : activeProvider,
                SettingDescriptions.For("model.provider") ?? "", "model.provider"),
            new(SettingDescriptions.LabelFor("fallback_model"), config.GetDisplay("fallback_model.model", Loc.T("voice.undefined")),
                SettingDescriptions.For("fallback_model") ?? Loc.T("provider.active.fallback_note"), "fallback_model"),
            new(SettingDescriptions.LabelFor("context.engine"), config.GetDisplay("context.engine"),
                SettingDescriptions.For("context.engine") ?? "", "context.engine"),
            new(SettingDescriptions.LabelFor("toolsets"), config.GetDisplay("toolsets"),
                SettingDescriptions.For("toolsets") ?? "", "toolsets"),
        };

        var customProviders = config.Get("providers");
        rows.Add(new SettingRow(
            Loc.T("provider.active.custom"),
            customProviders is null || customProviders.Kind != YamlKind.Map || customProviders.Map.Count == 0
                ? Loc.T("provider.active.custom_none")
                : string.Join(", ", customProviders.Map.Keys),
            Loc.T("provider.active.custom_note"),
            "providers"));

        rows.Add(new SettingRow(
            Loc.T("provider.active.config_file"),
            service.ConfigExists ? FetihPaths.ConfigYamlPath : $"{FetihPaths.ConfigYamlPath} ({Loc.T("diag.missing")})",
            service.ConfigError ?? (service.ConfigModified is { } modified
                ? string.Format(Loc.T("provider.active.last_modified"), modified.ToString("dd.MM.yyyy HH:mm"))
                : string.Empty)));

        return rows;
    }

    private static ProviderRow BuildRow(ProviderEntry entry, FetihConfigService service, string activeProvider)
    {
        var keys = new List<EnvKeyRow>(entry.ApiKeyEnvVars.Count);
        var anyDefined = false;

        foreach (var variable in entry.ApiKeyEnvVars)
        {
            var presence = service.GetKeyPresence(variable);
            var defined = presence != EnvKeyPresence.Missing;
            anyDefined |= defined;

            keys.Add(new EnvKeyRow(
                variable,
                Loc.T(defined ? "provider.key.defined" : "provider.key.undefined"),
                defined,
                presence switch
                {
                    EnvKeyPresence.Environment => Loc.T("provider.source.environment"),
                    EnvKeyPresence.EnvFile => Loc.T("provider.source.env_file"),
                    _ => Loc.T("provider.source.none"),
                }));
        }

        if (!string.IsNullOrEmpty(entry.BaseUrlEnvVar))
        {
            var presence = service.GetKeyPresence(entry.BaseUrlEnvVar);
            var defined = presence != EnvKeyPresence.Missing;
            keys.Add(new EnvKeyRow(
                entry.BaseUrlEnvVar,
                Loc.T(defined ? "provider.key.defined" : "provider.key.undefined"),
                defined,
                Loc.T(defined ? "provider.baseurl.overridden" : "provider.baseurl.default")));
        }

        // OAuth / harici süreç ile kimliklenen sağlayıcılarda API anahtarı
        // aranmaz; "tanımlı" göstermek yanıltıcı olurdu.
        var configured = entry.AuthType is "api_key" or "aws_sdk"
            ? anyDefined
            : false;

        var badges = new List<string>();
        if (entry.IsAggregator)
        {
            badges.Add(Loc.T("provider.badge.aggregator"));
        }

        if (entry.IsLocal)
        {
            badges.Add(Loc.T("provider.badge.local"));
        }

        if (entry.AuthType != "api_key")
        {
            badges.Add(ProviderRegistry.AuthLabel(entry.AuthType).ToLowerInvariant());
        }

        return new ProviderRow(
            entry.Label,
            entry.Id,
            ProviderRegistry.TransportLabel(entry.Transport),
            ProviderRegistry.AuthLabel(entry.AuthType),
            string.Join(" · ", badges),
            configured,
            IsActive(entry, activeProvider),
            keys);
    }

    /// <summary>
    /// config.yaml'daki <c>model.provider</c> değeri bu sağlayıcıyı mı gösteriyor?
    /// Python tarafındaki takma ad çözümlemesinin (ALIASES) yaygın karşılıkları
    /// burada da tanınır.
    /// </summary>
    private static bool IsActive(ProviderEntry entry, string activeProvider)
    {
        if (string.IsNullOrWhiteSpace(activeProvider))
        {
            return false;
        }

        var normalized = activeProvider.Trim().ToLowerInvariant();
        if (normalized == entry.Id)
        {
            return true;
        }

        return normalized switch
        {
            "claude" or "claude-code" => entry.Id == "anthropic",
            "openai" => entry.Id == "openrouter",
            "glm" or "z-ai" or "z.ai" or "zhipu" => entry.Id == "zai",
            "grok" or "x-ai" or "x.ai" => entry.Id == "xai",
            "gemini" => entry.Id == "google",
            "kimi" or "moonshot" => entry.Id == "kimi-for-coding",
            "qwen" or "dashscope" or "aliyun" => entry.Id == "alibaba",
            "copilot" or "github" => entry.Id == "github-copilot",
            "lmstudio" or "lm-studio" or "lm_studio" => entry.Id == "lmstudio",
            "aws" or "aws-bedrock" or "amazon-bedrock" => entry.Id == "bedrock",
            _ => false,
        };
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void Filter_Changed(object sender, RoutedEventArgs e) => ApplyFilter();

    private void ApplyFilter()
    {
        try
        {
            IEnumerable<ProviderRow> query = _all;

            if (OnlyConfiguredBox.IsChecked == true)
            {
                query = query.Where(p => p.IsConfigured);
            }

            var needle = SearchBox.Text?.Trim().ToLowerInvariant();
            if (!string.IsNullOrEmpty(needle))
            {
                query = query.Where(p =>
                    p.DisplayName.ToLowerInvariant().Contains(needle, StringComparison.Ordinal) ||
                    p.Id.Contains(needle, StringComparison.Ordinal));
            }

            var filtered = query.ToList();
            ProviderList.ItemsSource = filtered;
            CountText.Text = string.Format(Loc.T("provider.count"), filtered.Count, _all.Count);
        }
        catch (Exception ex)
        {
            App.LogCrash("ProviderPage.ApplyFilter", ex, ex.Message);
        }
    }
}
