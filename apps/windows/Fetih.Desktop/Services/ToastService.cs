using System;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;

namespace Fetih.Desktop.Services;

/// <summary>
/// Windows toast bildirimleri (issue #49): tur bitti, onay bekleniyor, bayrak,
/// hata. Yalnızca pencere ÖN PLANDA DEĞİLKEN gösterilir; tıklayınca uygulamayı
/// öne getirip ilgili sayfaya gider. Toast altyapısı yoksa (kayıt başarısız)
/// sessizce devre dışı kalır — uygulama normal çalışmaya devam eder.
/// </summary>
public static class ToastService
{
    private static bool _registered;

    /// <summary>Ana pencere şu an ön planda mı? Ön plandayken toast gösterilmez.</summary>
    public static bool IsForeground { get; set; } = true;

    public static void Register()
    {
        if (_registered) return;
        try
        {
            AppNotificationManager.Default.NotificationInvoked += OnInvoked;
            AppNotificationManager.Default.Register();
            _registered = true;
        }
        catch (Exception ex)
        {
            _registered = false;
            App.LogCrash("ToastService.Register", ex, ex.Message);
        }
    }

    public static void Unregister()
    {
        try
        {
            if (_registered) AppNotificationManager.Default.Unregister();
        }
        catch
        {
            // Kapanış yolunda yutulur.
        }
    }

    // ── Bildirimler ─────────────────────────────────────────────────────────

    public static void NotifyTurnDone(string? preview)
    {
        if (!ShouldNotify("desktop.notifications.turn_done")) return;
        Show(Loc.T("toast.turn_done.title"), Shorten(preview), "chat");
    }

    public static void NotifyApproval()
    {
        if (!ShouldNotify("desktop.notifications.approval")) return;
        Show(Loc.T("toast.approval.title"), Loc.T("toast.approval.body"), "chat");
    }

    public static void NotifyFlag(string flag)
    {
        if (!ShouldNotify("desktop.notifications.flag")) return;
        Show(Loc.T("toast.flag.title"), flag, "findings");
    }

    public static void NotifyError(string? message)
    {
        if (!ShouldNotify("desktop.notifications.error")) return;
        Show(Loc.T("toast.error.title"), Shorten(message), "chat");
    }

    // ── İç ─────────────────────────────────────────────────────────────────

    private static bool ShouldNotify(string categoryKey)
    {
        if (!_registered || IsForeground) return false;
        try
        {
            var cfg = FetihConfigService.Current.Config;
            if (!(cfg.GetBool("desktop.notifications.enabled") ?? true)) return false;
            return cfg.GetBool(categoryKey) ?? true;
        }
        catch
        {
            return false;
        }
    }

    private static void Show(string title, string body, string route)
    {
        try
        {
            var toast = new AppNotificationBuilder()
                .AddText(title)
                .AddText(body)
                .AddArgument("route", route)
                .BuildNotification();
            AppNotificationManager.Default.Show(toast);
        }
        catch (Exception ex)
        {
            App.LogCrash("ToastService.Show", ex, ex.Message);
        }
    }

    private static void OnInvoked(AppNotificationManager sender, AppNotificationActivatedEventArgs args)
    {
        var route = args.Arguments.TryGetValue("route", out var r) ? r : "chat";
        var win = App.MainAppWindow;
        win?.DispatcherQueue?.TryEnqueue(() =>
        {
            try
            {
                win.Activate();
                if (win.AppWindow is { } aw)
                {
                    aw.Show();
                    aw.MoveInZOrderAtTop();
                }
                if (win is MainWindow mw)
                {
                    mw.NavigateFromToast(route);
                }
            }
            catch (Exception ex)
            {
                App.LogCrash("ToastService.OnInvoked", ex, ex.Message);
            }
        });
    }

    private static string Shorten(string? s, int max = 120)
    {
        if (string.IsNullOrWhiteSpace(s)) return "";
        var t = s.Replace("\r", " ").Replace("\n", " ").Trim();
        return t.Length <= max ? t : t[..(max - 1)] + "…";
    }
}
