using System;
using System.Collections.Generic;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// Sandbox (yürütme ortamı) ayarları. FETİH'te sandbox kavramının gerçek
/// karşılığı <c>config.yaml</c> içindeki <c>terminal.backend</c> anahtarı ve
/// ona bağlı konteyner ayarlarıdır (Python tarafı: <c>tools/environments/</c>).
/// </summary>
public sealed partial class SandboxPage : Page
{
    public SandboxPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        Populate();
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        FetihConfigService.Current.Reload();
        Populate();
    }

    private void Populate()
    {
        try
        {
            var config = FetihConfigService.Current.Config;
            var backend = (config.GetString("terminal.backend") ?? string.Empty).Trim();

            BackendInfo.Message = BackendMessage(backend);
            BackendInfo.Severity = backend is "local" or ""
                ? InfoBarSeverity.Warning
                : InfoBarSeverity.Success;

            var isContainer = backend is "docker" or "singularity" or "modal" or "daytona" or "vercel_sandbox";
            ContainerCard.Visibility = isContainer ? Visibility.Visible : Visibility.Collapsed;

            BackendRows.ItemsSource = new List<SettingRow>
            {
                new("Arka uç", string.IsNullOrEmpty(backend) ? "(tanımsız)" : backend,
                    "local · docker · ssh · singularity · modal · daytona · vercel_sandbox",
                    "terminal.backend"),
                new("Çalışma dizini", config.GetDisplay("terminal.cwd"), configKey: "terminal.cwd"),
                new("Komut zaman aşımı", $"{config.GetDisplay("terminal.timeout")} sn", configKey: "terminal.timeout"),
                new("Kalıcı kabuk", Bool(config.GetBool("terminal.persistent_shell")),
                    "Açıkken cwd/ortam değişkenleri komutlar arasında korunur.", "terminal.persistent_shell"),
                new("Kabuk başlangıç dosyaları", config.GetDisplay("terminal.shell_init_files", "(otomatik)"),
                    $"Kabuk rc dosyalarını otomatik yükle: {Bool(config.GetBool("terminal.auto_source_bashrc"))}",
                    "terminal.shell_init_files"),
                new("Yerel sandbox klasörü", FetihPaths.SandboxesDir,
                    FetihPaths.SafeExists(FetihPaths.SandboxesDir) ? "Klasör mevcut." : "Klasör yok."),
            };

            ContainerRows.ItemsSource = new List<SettingRow>
            {
                new("İmaj", config.GetDisplay(ImageKeyFor(backend)), configKey: ImageKeyFor(backend)),
                new("CPU", config.GetDisplay("terminal.container_cpu"), configKey: "terminal.container_cpu"),
                new("Bellek", $"{config.GetDisplay("terminal.container_memory")} MB", configKey: "terminal.container_memory"),
                new("Disk", $"{config.GetDisplay("terminal.container_disk")} MB", configKey: "terminal.container_disk"),
                new("Kalıcı dosya sistemi", Bool(config.GetBool("terminal.container_persistent")),
                    configKey: "terminal.container_persistent"),
            };

            var volumes = config.GetStringList("terminal.docker_volumes");
            var passthrough = config.GetStringList("terminal.env_passthrough");

            IsolationRows.ItemsSource = new List<SettingRow>
            {
                new("Host klasör bağlamaları", volumes.Count == 0 ? "(yok)" : string.Join("\n", volumes),
                    "Her bağlama izolasyonu zayıflatır: konteyner host dosyalarına erişebilir hale gelir.",
                    "terminal.docker_volumes"),
                new("Çalışma dizinini bağla", Bool(config.GetBool("terminal.docker_mount_cwd_to_workspace")),
                    "Varsayılan kapalı — host dizinini sandbox'a vermek izolasyonu zayıflatır.",
                    "terminal.docker_mount_cwd_to_workspace"),
                new("Host kullanıcısı olarak çalıştır", Bool(config.GetBool("terminal.docker_run_as_host_user")),
                    configKey: "terminal.docker_run_as_host_user"),
                new("Aktarılan ortam değişkenleri",
                    passthrough.Count == 0 ? "(yok)" : string.Join(", ", passthrough),
                    "Sandbox içine geçirilen değişken adları. Yetenek (skill) tanımlı olanlar otomatik aktarılır.",
                    "terminal.env_passthrough"),
                new("Ek docker bayrakları", config.GetDisplay("terminal.docker_extra_args", "(yok)"),
                    configKey: "terminal.docker_extra_args"),
            };

            ExecutionRows.ItemsSource = new List<SettingRow>
            {
                new("Kod çalıştırma kipi", config.GetDisplay("code_execution.mode"),
                    "Kod yürütme aracının kapsamı.", "code_execution.mode"),
                new("Azami dosya okuma", $"{config.GetDisplay("file_read_max_chars")} karakter",
                    configKey: "file_read_max_chars"),
                new("Araç çıktısı sınırı",
                    $"{config.GetDisplay("tool_output.max_bytes")} bayt · " +
                    $"{config.GetDisplay("tool_output.max_lines")} satır · " +
                    $"satır başına {config.GetDisplay("tool_output.max_line_length")}",
                    "Uzun süren tarama araçlarının UI'yi kilitlememesi için.", "tool_output"),
                new("Kontrol noktaları", Bool(config.GetBool("checkpoints.enabled")),
                    $"Azami {config.GetDisplay("checkpoints.max_total_size_mb")} MB · " +
                    $"{config.GetDisplay("checkpoints.retention_days")} gün saklanır",
                    "checkpoints.enabled"),
            };
        }
        catch (Exception ex)
        {
            App.LogCrash("SandboxPage.Populate", ex, ex.Message);
        }
    }

    private static string ImageKeyFor(string backend) => backend switch
    {
        "singularity" => "terminal.singularity_image",
        "modal" => "terminal.modal_image",
        "daytona" => "terminal.daytona_image",
        "vercel_sandbox" => "terminal.vercel_runtime",
        _ => "terminal.docker_image",
    };

    private static string BackendMessage(string backend) => backend switch
    {
        "local" => "local — araçlar doğrudan bu makinede, izolasyon olmadan çalışır. " +
                   "Bilinmeyen hedeflere karşı test yaparken konteyner arka uçlarından birini tercih edin.",
        "docker" => "docker — araçlar konteyner içinde çalışır; host dosya sistemi yalnızca " +
                    "açıkça bağlanan klasörlerle paylaşılır.",
        "ssh" => "ssh — araçlar uzak makinede çalışır; yerel makine etkilenmez.",
        "singularity" => "singularity — konteyner içinde, kök yetkisi gerektirmeyen izolasyon.",
        "modal" => "modal — bulut konteyneri.",
        "daytona" => "daytona — bulut geliştirme ortamı.",
        "vercel_sandbox" => "vercel_sandbox — bulut sandbox çalışma zamanı.",
        "" => "Arka uç config.yaml'da tanımlı değil; Python tarafı varsayılan olarak local kullanır.",
        _ => backend,
    };

    private static string Bool(bool? value) => value switch
    {
        true => "Açık",
        false => "Kapalı",
        _ => "(tanımsız)",
    };
}
