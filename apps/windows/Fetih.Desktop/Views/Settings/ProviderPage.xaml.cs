using System;
using System.Collections.Generic;
using System.Linq;
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

    public ProviderPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        Populate();
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
            new("Etkin model", string.IsNullOrWhiteSpace(activeModel) ? "(tanımsız)" : activeModel,
                configKey: "model.default"),
            new("Etkin sağlayıcı", string.IsNullOrWhiteSpace(activeProvider) ? "(tanımsız)" : activeProvider,
                configKey: "model.provider"),
            new("Yedek model", config.GetDisplay("fallback_model.model", "(tanımsız)"),
                "Birincil sağlayıcı 429/529/503 döndüğünde devreye girer.", "fallback_model"),
            new("Bağlam motoru", config.GetDisplay("context.engine"), configKey: "context.engine"),
            new("Etkin araç kümeleri", config.GetDisplay("toolsets"), configKey: "toolsets"),
        };

        var customProviders = config.Get("providers");
        rows.Add(new SettingRow(
            "Kullanıcı tanımlı sağlayıcılar",
            customProviders is null || customProviders.Kind != YamlKind.Map || customProviders.Map.Count == 0
                ? "(yok)"
                : string.Join(", ", customProviders.Map.Keys),
            "config.yaml içindeki providers: bölümüne eklenen özel OpenAI uyumlu uçlar.",
            "providers"));

        rows.Add(new SettingRow(
            "Yapılandırma dosyası",
            service.ConfigExists ? FetihPaths.ConfigYamlPath : $"{FetihPaths.ConfigYamlPath} (yok)",
            service.ConfigError ?? (service.ConfigModified is { } modified
                ? $"Son değişiklik: {modified:dd.MM.yyyy HH:mm}"
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
