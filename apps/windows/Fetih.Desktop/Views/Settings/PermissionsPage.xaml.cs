using System;
using System.Collections.Generic;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// İzin / onay ayarları. Kaynaklar:
/// <c>~/.fetih/config.yaml</c> → <c>approvals</c>, <c>command_allowlist</c>, <c>security</c>;
/// komut sınıfları ise <c>tools/approval.py</c> içindeki tehlikeli komut
/// desenlerinin (DANGEROUS_PATTERNS) kategorileştirilmiş özetidir.
/// </summary>
public sealed partial class PermissionsPage : Page
{
    public PermissionsPage()
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

            ApprovalRows.ItemsSource = new List<SettingRow>
            {
                new("Onay kipi", ApprovalMode(config.GetString("approvals.mode")),
                    "manual: her zaman sor · smart: düşük riskli komutları yardımcı model onaylasın · off: hiç sorma.",
                    "approvals.mode"),
                new("Onay zaman aşımı", $"{config.GetDisplay("approvals.timeout")} sn",
                    "Bu süre içinde yanıt gelmezse istek düşer.", "approvals.timeout"),
                new("Zamanlanmış görev kipi", CronMode(config.GetString("approvals.cron_mode")),
                    "Zamanlanmış bir görev tehlikeli komuta çarparsa ne olacağı. Varsayılan güvenli seçenek: engelle.",
                    "approvals.cron_mode"),
                new("MCP yeniden yükleme onayı", Bool(config.GetBool("approvals.mcp_reload_confirm")),
                    "Araç şemaları sistem istemine gömülü olduğu için yeniden yükleme önbelleği geçersiz kılar.",
                    "approvals.mcp_reload_confirm"),
                new("Yıkıcı oturum komutu onayı", Bool(config.GetBool("approvals.destructive_slash_confirm")),
                    "/clear, /new, /reset, /undo çalıştırılmadan önce sorulur.",
                    "approvals.destructive_slash_confirm"),
                new("Alt ajan otomatik onayı", Bool(config.GetBool("delegation.subagent_auto_approve")),
                    "Devredilen alt ajanların onay istemeden çalışıp çalışmayacağı.",
                    "delegation.subagent_auto_approve"),
                new("Kabuk kancası otomatik kabulü", Bool(config.GetBool("hooks_auto_accept")),
                    "Yeni kabuk betiği kancaları TTY istemi olmadan kabul edilsin mi.",
                    "hooks_auto_accept"),
            };

            var allowlist = config.GetStringList("command_allowlist");
            AllowlistItems.ItemsSource = allowlist;
            AllowlistEmptyText.Text = "Liste boş — kalıcı olarak izin verilmiş tehlikeli komut deseni yok. " +
                                      "Bu, en sıkı ve önerilen durumdur.";
            AllowlistEmptyText.Visibility = allowlist.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            RiskRows.ItemsSource = BuildRiskRows();

            SecurityRows.ItemsSource = new List<SettingRow>
            {
                new("Özel/iç ağ adreslerine izin", Bool(config.GetBool("security.allow_private_urls")),
                    "Kapalıyken 127.0.0.1 / 192.168.x.x gibi hedeflere istek engellenir.",
                    "security.allow_private_urls"),
                new("Gizli değerleri maskele", Bool(config.GetBool("security.redact_secrets")),
                    configKey: "security.redact_secrets"),
                new("Çalıştırma öncesi tarama", Bool(config.GetBool("security.tirith_enabled")),
                    $"Tarayıcı: {config.GetDisplay("security.tirith_path")} · " +
                    $"zaman aşımı {config.GetDisplay("security.tirith_timeout")} sn · " +
                    $"hata durumunda geçir: {Bool(config.GetBool("security.tirith_fail_open"))}",
                    "security.tirith_enabled"),
                new("Web sitesi engel listesi", Bool(config.GetBool("security.website_blocklist.enabled")),
                    $"Alan adı sayısı: {config.GetStringList("security.website_blocklist.domains").Count}",
                    "security.website_blocklist"),
                new("Çalışma anında paket kurulumu", Bool(config.GetBool("security.allow_lazy_installs")),
                    "Kapalıyken hiçbir bileşen PyPI'dan kendiliğinden kurulmaz (denetimli/hava boşluklu ortamlar için).",
                    "security.allow_lazy_installs"),
                new("Tarayıcıda özel adreslere izin", Bool(config.GetBool("browser.allow_private_urls")),
                    configKey: "browser.allow_private_urls"),
            };
        }
        catch (Exception ex)
        {
            App.LogCrash("PermissionsPage.Populate", ex, ex.Message);
        }
    }

    /// <summary>
    /// <c>tools/approval.py</c> içindeki desen açıklamalarının sınıflara toplanmış hâli.
    /// Desenlerin kendisi Python tarafında tek kaynaktır; burada yalnızca kullanıcıya
    /// ne tür komutların onay isteyeceğini anlatan referans tablo tutulur.
    /// </summary>
    private static List<SettingRow> BuildRiskRows() => new()
    {
        new("Dosya silme",
            "rm -r, rm /…, find -delete, find -exec rm, xargs rm",
            "Onay ister."),
        new("Dosya sistemi / disk",
            "mkfs, dd if=…, > /dev/sd…",
            "Onay ister."),
        new("İzin ve sahiplik",
            "chmod 777 / 666 / o+w, chown -R root",
            "Onay ister."),
        new("Sistem yapılandırması",
            "/etc altına yazma (tee, >, cp, mv, sed -i), systemctl stop/restart/disable/mask",
            "Onay ister."),
        new("Proje gizli dosyaları",
            ".env / yapılandırma dosyalarının üzerine yazma",
            "Onay ister."),
        new("Uzak içerik çalıştırma",
            "curl|sh, wget|sh, bash <(curl …), heredoc ile python/perl/ruby/node",
            "Onay ister."),
        new("Kabuk / betik çalıştırma",
            "bash -c, sh -lc, python -c, node -e, chmod +x ardından ./…",
            "Onay ister."),
        new("Süreç sonlandırma",
            "kill -9 -1, pkill -9, killall -KILL, kill $(pgrep …)",
            "Onay ister — ajanın kendi sürecini öldürmesi ayrıca engellenir."),
        new("Veritabanı",
            "DROP TABLE/DATABASE, TRUNCATE, WHERE'siz DELETE",
            "Onay ister."),
        new("Git geçmişi",
            "git reset --hard, git push --force, git clean -f, git branch -D",
            "Onay ister."),
        new("Yetki yükseltme",
            "sudo -S / --stdin / -A / --askpass / -s / -a ve birleşik kısa bayraklar",
            "Onay ister; TTY'siz çalışan ajan için özellikle taranır."),
        new("Kendi altyapısını bozma",
            "fetih update, mesajlaşma köprüsünü durdurma/yeniden başlatma",
            "Onay ister — çalışan ajanları öldürür."),
        new("Fork bombası ve benzeri",
            ":(){ :|:& };:",
            "Kesin engellenir."),
    };

    private static string ApprovalMode(string? mode) => mode switch
    {
        "manual" => "manual — her tehlikeli komut için sor",
        "smart" => "smart — düşük riskli komutları yardımcı model onaylasın",
        "off" => "off — hiç sorma (yalnızca izole ortamlarda önerilir)",
        null or "" => "(tanımsız)",
        _ => mode,
    };

    private static string CronMode(string? mode) => mode switch
    {
        "deny" => "deny — engelle (varsayılan, güvenli)",
        "approve" => "approve — otomatik onayla",
        null or "" => "(tanımsız)",
        _ => mode,
    };

    private static string Bool(bool? value) => value switch
    {
        true => "Açık",
        false => "Kapalı",
        _ => "(tanımsız)",
    };
}
