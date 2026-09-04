using System;
using System.IO;
using Microsoft.UI.Xaml;

namespace Fetih.Desktop;

/// <summary>
/// FETİH masaüstü kabuğunun uygulama giriş noktası.
/// Faz 1: yalnızca ana pencereyi açar. Süreç yöneticisi ve Masaüstü Köprüsü
/// bağlantısı (bkz. docs/windows-app-plani.md, Faz 1) sonraki adımda eklenir.
/// </summary>
public partial class App : Application
{
    private Window? _window;

    /// <summary>
    /// %LOCALAPPDATA%\Fetih\Desktop\crash.log — yakalanmamış istisnalar buraya yazılır.
    /// Faz 1'de pencere sessizce kapanıyorsa (WinUI3 unpackaged uygulamalarda
    /// varsayılan davranış budur, WER genelde bir diyalog göstermez) kök nedeni
    /// bu dosyadan okuyabiliriz.
    /// </summary>
    private static readonly string CrashLogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Fetih", "Desktop", "crash.log");

    public App()
    {
        InitializeComponent();

        // WinUI3/XAML dispatcher'ında yakalanmayan istisna: varsayılan davranış
        // pencereyi sessizce kapatmaktır. e.Handled = true YAPMIYORUZ (uygulamayı
        // sahte bir "iyi" durumda tutmak yanıltıcı olur) — sadece loglayıp
        // asıl davranışın (kapanma) neden olduğunu görünür kılıyoruz.
        UnhandledException += (_, e) =>
            LogCrash("Application.UnhandledException", e.Exception, e.Message);

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            LogCrash("AppDomain.UnhandledException", e.ExceptionObject as Exception, e.ExceptionObject?.ToString());

        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            LogCrash("TaskScheduler.UnobservedTaskException", e.Exception, e.Exception.Message);
            e.SetObserved();
        };
    }

    /// <summary>Uygulamanın şu anda açık olan ana penceresi.</summary>
    public static Window? MainAppWindow { get; internal set; }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
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
    }
}
