using System;
using System.IO;
using Microsoft.UI.Xaml;

namespace Fetih.Desktop;

/// <summary>
/// FETİH masaüstü kabuğunun uygulama giriş noktası: dil tercihini yükler,
/// ilk kurulum gerekiyorsa sihirbazı, aksi hâlde ana pencereyi açar.
/// </summary>
public partial class App : Application
{
    private Window? _window;

    /// <summary>
    /// %LOCALAPPDATA%\Fetih\Desktop\crash.log — yakalanmamış istisnalar buraya yazılır.
    /// Pencere sessizce kapanıyorsa (WinUI3 unpackaged uygulamalarda
    /// varsayılan davranış budur, WER genelde bir diyalog göstermez) kök nedeni
    /// bu dosyadan okuyabiliriz.
    /// </summary>
    private static readonly string CrashLogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Fetih", "Desktop", "crash.log");

    public App()
    {
        InitializeComponent();

        // Yapısal günlükleyiciyi erkenden başlat (crash.log'un yanında, döngüsel
        // uygulama logu). En iyi çaba — başlatılamazsa Write'lar sessizce düşer.
        Fetih.Desktop.Services.Logger.Initialize();
        Fetih.Desktop.Services.Logger.Info("FETİH Desktop başlatılıyor.");

        // Süreç kapanışında bekleyen log satırlarını diske akıt.
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            Fetih.Desktop.Services.ToastService.Unregister();
            Fetih.Desktop.Services.Logger.Shutdown();
        };

        // WinUI3/XAML dispatcher'ında yakalanmayan istisna: varsayılan davranış
        // pencereyi sessizce kapatmaktır. e.Handled = true YAPMIYORUZ (uygulamayı
        // sahte bir "iyi" durumda tutmak yanıltıcı olur) — sadece loglayıp
        // asıl davranışın (kapanma) neden olduğunu görünür kılıyoruz.
        UnhandledException += (_, e) =>
        {
            CleanupBridge();
            LogCrash("Application.UnhandledException", e.Exception, e.Message);
        };

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            CleanupBridge();
            LogCrash("AppDomain.UnhandledException", e.ExceptionObject as Exception, e.ExceptionObject?.ToString());
        };

        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            LogCrash("TaskScheduler.UnobservedTaskException", e.Exception, e.Exception.Message);
            e.SetObserved();
        };
    }

    /// <summary>
    /// Çökme yolunda en iyi çaba temizlik: Masaüstü Köprüsü alt sürecini
    /// sonlandırır. Bu yol her zaman çalışmayabilir (işletim sistemi süreci
    /// doğrudan öldürebilir), bu yüzden asıl güvence köprü sürecinin bir iş
    /// nesnesine alınmasıdır (bkz. <c>Bridge/BridgeProcess.cs</c>).
    ///
    /// <para>Burada fırlatılan bir istisna orijinal çökmeyi gizleyeceği için
    /// her şey yutulur; loglama da bozulmaz.</para>
    /// </summary>
    private static void CleanupBridge()
    {
        try
        {
            Bridge.BridgeClient.Shared.Dispose();
        }
        catch
        {
            // Çökme yolunda ikinci bir istisna fırlatmak yasak.
        }
    }

    /// <summary>Uygulamanın şu anda açık olan ana penceresi.</summary>
    public static Window? MainAppWindow { get; internal set; }

    /// <summary>
    /// Zaten çalışan bir FETİH örneği varsa aktivasyonu ona yönlendirir ve
    /// <c>true</c> döner (bu örnek kapanmalı). Biz birincil örneksek, ikinci
    /// bir örnek bizi uyandırdığında pencereyi öne getirmek için Activated'a
    /// abone olur ve <c>false</c> döneriz. Hata → <c>false</c> (fail-safe).
    /// </summary>
    private bool TryRedirectToPrimaryInstance()
    {
        try
        {
            var primary = Microsoft.Windows.AppLifecycle.AppInstance
                .FindOrRegisterForKey("FETIH.Desktop.Main");
            if (primary.IsCurrent)
            {
                primary.Activated += OnInstanceActivated;
                return false;
            }
            var activatedArgs = Microsoft.Windows.AppLifecycle.AppInstance
                .GetCurrent().GetActivatedEventArgs();
            primary.RedirectActivationToAsync(activatedArgs).AsTask().Wait(TimeSpan.FromSeconds(3));
            return true;
        }
        catch (Exception ex)
        {
            LogCrash("App.SingleInstance", ex, ex.Message);
            return false;
        }
    }

    private void OnInstanceActivated(object? sender, Microsoft.Windows.AppLifecycle.AppActivationArguments e)
    {
        // Activated arka plan iş parçacığından gelir; pencereyi UI iş
        // parçacığında öne getir.
        var window = MainAppWindow;
        window?.DispatcherQueue?.TryEnqueue(() =>
        {
            try
            {
                window.Activate();
                if (window.AppWindow is { } aw)
                {
                    aw.Show();
                    aw.MoveInZOrderAtTop();
                }
            }
            catch
            {
                // Öne getirme başarısızsa sorun değil.
            }
        });
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // Tek örnek: zaten bir FETİH açıksa onu öne getirip bu ikinci örneği
        // kapat (iki köprü süreci doğmasın). Fail-safe: herhangi bir hata
        // olursa normal açılışa devam edilir.
        if (TryRedirectToPrimaryInstance())
        {
            try { Exit(); } catch { }
            return;
        }

        // Açılışta, ÖNCEKİ oturumlardan (çökme, Görev Yöneticisi'nden
        // sonlandırma) yetim kalmış köprü süreçlerini topla. Arka planda ve
        // hatasız çalışır; açılışı hiçbir koşulda durdurmaz. Bu oturumun
        // başlattığı köprü, ebeveyni (biz) yaşadığı için zaten korunur.
        Fetih.Desktop.Services.OrphanBridgeSweeper.SweepInBackground();

        // Taze kullanıcı (config/anahtar yok) → ilk kurulum sihirbazı.
        // Zaten yapılandırılmışsa (bizim durumumuz: Groq ayarlı) → doğrudan Sohbet.
        var needsSetup = false;
        try
        {
            needsSetup = Fetih.Desktop.Setup.SetupDetector.NeedsSetup();
        }
        catch (Exception ex)
        {
            LogCrash("App.OnLaunched.SetupDetector", ex, ex.Message);
        }

        if (needsSetup)
        {
            _window = new SetupWindow();
        }
        else
        {
            _window = new MainWindow();
        }

        MainAppWindow = _window;
        _window.Activate();

        // Toast bildirim altyapısını kaydet (issue #49). Başarısızsa sessizce
        // devre dışı kalır; uygulama etkilenmez.
        Fetih.Desktop.Services.ToastService.Register();

        // Açılıştan hemen sonra, arka planda ve sessizce: günde en fazla bir
        // kez GitHub Releases'e bakar. Bulursa Hakkında sayfası bir sonraki
        // açılışında (veya LastKnownUpdate zaten set edildiyse hemen)
        // gösterir. Ağ hatası/gecikmesi açılışı ASLA bloklamaz — fire-and-forget.
        _ = Fetih.Desktop.Services.UpdateService.CheckInBackgroundAsync(TimeSpan.FromHours(24));
    }

    /// <summary>
    /// Diğer sınıfların (ör. MainWindow'un navigasyon try/catch'i) aynı log
    /// dosyasına yazabilmesi için genel erişimli tutulur.
    /// </summary>
    internal static void LogCrash(string source, Exception? ex, string? message)
    {
        try
        {
            var dir = Path.GetDirectoryName(CrashLogPath);
            if (dir is not null)
            {
                Directory.CreateDirectory(dir);
            }

            var entry =
                $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] {source}\n" +
                $"{message}\n" +
                $"{ex}\n" +
                new string('-', 80) + "\n";

            File.AppendAllText(CrashLogPath, entry);
        }
        catch
        {
            // Loglama sırasında ikinci bir istisna atarsak orijinal çökmeyi
            // gizlememesi için burada bilerek yutuyoruz.
        }

        // Yapısal loga da düş (gizli bilgiler orada redakte edilir). Ayrı
        // try: crash.log yazımını hiçbir koşulda etkilemesin.
        try
        {
            Fetih.Desktop.Services.Logger.Error(
                $"{source}: {message} {(ex is null ? "" : ex.GetType().Name)}");
        }
        catch
        {
            // yut
        }
    }
}
