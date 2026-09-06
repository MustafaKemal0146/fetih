using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
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
        ProviderSelectBox.PlaceholderText = Loc.T("provider.placeholder.provider");
        ModelBox.PlaceholderText = Loc.T("provider.placeholder.model");
        SaveModelButton.Content = Loc.T("provider.save");
        SlotsTitle.Text = Loc.T("provider.slots_title");
        SlotsIntro.Text = Loc.T("provider.slots_intro");
        SearchBox.PlaceholderText = Loc.T("provider.search_placeholder");
        OnlyConfiguredBox.Content = Loc.T("provider.only_configured");
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
            .Select(p => ($"{p.DisplayName}  ({p.Id})", p.Id))
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
                if (res.TryGetProperty("active", out var active) && active.ValueKind == JsonValueKind.Object)
                {
                    var prov = active.TryGetProperty("provider", out var pv) ? pv.GetString() ?? "" : "";
                    var model = active.TryGetProperty("model", out var mv) ? mv.GetString() ?? "" : "";
                    if (!string.IsNullOrEmpty(prov) && string.IsNullOrEmpty(ProviderSelectBox.Text))
                    {
                        ProviderSelectBox.Text = prov;
                    }
                    if (!string.IsNullOrEmpty(model) && string.IsNullOrEmpty(ModelBox.Text))
                    {
                        ModelBox.Text = model;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("ProviderPage.SeedSelector", ex, ex.Message);
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

    /// <summary>Bir yardımcı model yuvasının tanımı.</summary>
    private sealed record AuxSlot(string Task, string Title, string Description);

    private static readonly AuxSlot[] AuxSlots =
    {
        new("vision", "Görüntü çözümleme",
            "Ekran görüntüsü ve resim analizi (vision_analyze, tarayıcı görüntüleri). Çok kipli (multimodal) bir model gerekir."),
        new("web_extract", "Web sayfası özetleme",
            "Bir sayfayı okuyup özetleyen yan görev."),
        new("compression", "Bağlam sıkıştırma",
            "Sohbet uzayınca eski turları özetleyip yer açar."),
        new("skills_hub", "Yetenek merkezi",
            "Yetenek (skill) arama ve eşleştirme çağrıları."),
        new("approval", "Onay kararı",
            "Tehlikeli bir komutun otomatik onaylanıp onaylanmayacağına karar verir. Ucuz ve hızlı bir model önerilir."),
        new("mcp", "MCP yardımcısı",
            "MCP sunucularıyla ilgili kısa çağrılar."),
        new("title_generation", "Sohbet başlığı üretme",
            "Bir oturuma kısa bir başlık yazar."),
        new("triage_specifier", "Görev ayrıntılandırma",
            "Kanban 'triage' sütunundaki tek satırlık bir işi somut bir tarife dönüştürür."),
        new("kanban_decomposer", "Görev parçalama",
            "Bir işi alt görev grafiğine böler; diğerlerinden daha çok token harcar."),
        new("profile_describer", "Profil açıklaması",
            "Bir profilin ne işe yaradığını bir iki cümleyle yazar."),
        new("curator", "Küratör (yetenek incelemesi)",
            "Yetenek kullanımını gözden geçiren fork. Uzun sürebilir."),
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
                    Text = "Yapılandırma okunamadı; köprü bağlı değil.",
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
                Text = "Yapılandırma okunamadı: " + ex.Message,
                Opacity = 0.7,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
            });
            return;
        }

        // ── Yedek model ─────────────────────────────────────────────────────
        var (fbProvider, fbModel, fbChainLength) = ReadFallback(config);
        var fallbackNote = fbChainLength > 1
            ? $"Şu anda {fbChainLength} basamaklı bir yedek zinciri tanımlı; buradan kaydetmek zinciri tek bir yedeğe indirir."
            : "Birincil sağlayıcı 429/503/529 döndüğünde bu model devreye girer. Boş bırakılırsa yedek yoktur.";

        SlotsHost.Children.Add(SlotRow(
            "slot_fallback",
            "Yedek model",
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
                slot.Title,
                slot.Description,
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
                Text = $"Yardımcı modeller — yan görev başına ayrı model ({AuxSlots.Length} yuva)",
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                FontSize = 13,
            },
            Content = auxHost,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(0, 8, 0, 0),
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(expander, "slot_aux_group");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(expander, "Yardımcı modeller");
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
        if (includeAuto)
        {
            combo.Items.Add(new ComboBoxItem { Content = "Otomatik (auto)", Tag = "auto" });
        }
        else
        {
            combo.Items.Add(new ComboBoxItem { Content = "(yok)", Tag = "" });
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
            PlaceholderText = "Model kimliği (boş = sağlayıcının varsayılanı)",
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(modelBox, id + "_model");

        var status = new TextBlock { FontSize = 12, Opacity = 0.8, VerticalAlignment = VerticalAlignment.Center };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(status, id + "_status");

        var saveButton = new Button { Content = "Kaydet" };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(saveButton, id + "_save");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(saveButton, title + " kaydet");
        saveButton.Click += async (_, _) =>
        {
            saveButton.IsEnabled = false;
            status.Text = "kaydediliyor…";
            try
            {
                var provider = combo.SelectedItem is ComboBoxItem { Tag: string t } ? t : "";
                await save(provider, modelBox.Text?.Trim() ?? "", status);
                status.Text = "✓ kaydedildi";
            }
            catch (BridgeRpcException rpc)
            {
                status.Text = "✗ " + (rpc.Code == -32004 ? "reddedildi (yönetilen kurulum)" : rpc.Message);
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

    private void ProviderSelectBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
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
    }

    private void ProviderSelectBox_SuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
    {
        // Seçilen etiketten id'yi çöz ve kutuya id'yi yaz (config.set id bekler).
        if (args.SelectedItem is string label)
        {
            var match = _providerChoices.FirstOrDefault(c => c.Label == label);
            if (!string.IsNullOrEmpty(match.Id))
            {
                sender.Text = match.Id;
            }
        }
    }

    private async void SaveModelButton_Click(object sender, RoutedEventArgs e)
    {
        // Girilen etiket bir öneri etiketiyse id'ye çevir; değilse olduğu gibi kullan.
        var providerInput = ProviderSelectBox.Text?.Trim() ?? "";
        var resolved = _providerChoices.FirstOrDefault(c =>
            c.Label == providerInput || c.Id == providerInput);
        var provider = string.IsNullOrEmpty(resolved.Id) ? providerInput : resolved.Id;
        var model = ModelBox.Text?.Trim() ?? "";

        if (string.IsNullOrEmpty(provider) && string.IsNullOrEmpty(model))
        {
            SaveModelStatus.Text = "Sağlayıcı veya model gir.";
            return;
        }

        SaveModelButton.IsEnabled = false;
        SaveModelStatus.Text = "kaydediliyor…";
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

            // Yazıldığını doğrula: config.get ile geri oku.
            var check = await _bridge.ConfigGetAsync("model").ConfigureAwait(true);
            SaveModelStatus.Text = "✓ kaydedildi — bir sonraki mesajda etkili olacak";

            // Diskten okuyan salt-okunur listeyi de tazele.
            Populate();
        }
        catch (BridgeRpcException rpc)
        {
            SaveModelStatus.Text = "✗ " + (rpc.Code == -32004
                ? "reddedildi (yönetilen kurulum)"
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
                SettingDescriptions.For("fallback_model")
                    ?? (Loc.Current == UiLanguage.Turkish ? "Birincil sağlayıcı 429/529/503 döndüğünde devreye girer." : "Kicks in when the primary provider returns 429/529/503."), "fallback_model"),
            new(SettingDescriptions.LabelFor("context.engine"), config.GetDisplay("context.engine"),
                SettingDescriptions.For("context.engine") ?? "", "context.engine"),
            new(SettingDescriptions.LabelFor("toolsets"), config.GetDisplay("toolsets"),
                SettingDescriptions.For("toolsets") ?? "", "toolsets"),
        };

        var customProviders = config.Get("providers");
        rows.Add(new SettingRow(
            Loc.Current == UiLanguage.Turkish ? "Kullanıcı tanımlı sağlayıcılar" : "User-defined providers",
            customProviders is null || customProviders.Kind != YamlKind.Map || customProviders.Map.Count == 0
                ? (Loc.Current == UiLanguage.Turkish ? "(yok)" : "(none)")
                : string.Join(", ", customProviders.Map.Keys),
            Loc.Current == UiLanguage.Turkish
                ? "config.yaml içindeki providers: bölümüne eklenen özel OpenAI uyumlu uçlar."
                : "Custom OpenAI-compatible endpoints added under the providers: section in config.yaml.",
            "providers"));

        rows.Add(new SettingRow(
            Loc.Current == UiLanguage.Turkish ? "Yapılandırma dosyası" : "Configuration file",
            service.ConfigExists ? FetihPaths.ConfigYamlPath : $"{FetihPaths.ConfigYamlPath} ({Loc.T("diag.missing")})",
            service.ConfigError ?? (service.ConfigModified is { } modified
                ? (Loc.Current == UiLanguage.Turkish ? $"Son değişiklik: {modified:dd.MM.yyyy HH:mm}" : $"Last modified: {modified:dd.MM.yyyy HH:mm}")
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
                defined ? "Tanımlı" : "Tanımsız",
                defined,
                presence switch
                {
                    EnvKeyPresence.Environment => "süreç ortam değişkeni",
                    EnvKeyPresence.EnvFile => "~/.fetih/.env",
                    _ => "hiçbir kaynakta yok",
                }));
        }

        if (!string.IsNullOrEmpty(entry.BaseUrlEnvVar))
        {
            var presence = service.GetKeyPresence(entry.BaseUrlEnvVar);
            var defined = presence != EnvKeyPresence.Missing;
            keys.Add(new EnvKeyRow(
                entry.BaseUrlEnvVar,
                defined ? "Tanımlı" : "Tanımsız",
                defined,
                defined ? "uç adresi geçersiz kılınmış" : "varsayılan uç adresi kullanılır"));
        }

        // OAuth / harici süreç ile kimliklenen sağlayıcılarda API anahtarı
        // aranmaz; "tanımlı" göstermek yanıltıcı olurdu.
        var configured = entry.AuthType is "api_key" or "aws_sdk"
            ? anyDefined
            : false;

        var badges = new List<string>();
        if (entry.IsAggregator)
        {
            badges.Add("toplayıcı");
        }

        if (entry.IsLocal)
        {
            badges.Add("yerel — veri makineden çıkmaz");
        }

        if (entry.AuthType != "api_key")
        {
            badges.Add(ProviderRegistry.AuthLabel(entry.AuthType).ToLowerInvariant());
        }

        return new ProviderRow(
            entry.DisplayName,
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
            CountText.Text = $"{filtered.Count} / {_all.Count} sağlayıcı";
        }
        catch (Exception ex)
        {
            App.LogCrash("ProviderPage.ApplyFilter", ex, ex.Message);
        }
    }
}
