using System;
using System.IO;
using System.Text;

namespace Fetih.Desktop.Setup;

/// <summary>
/// Dosya tabanlı tek-çalışma kilidi: aynı anda yalnızca bir kurulum
/// çalışmasına izin verir. İkinci bir örnek (ya da aynı örnekte ikinci bir
/// sihirbaz) kilidi alamaz ve kullanıcıya "zaten çalışıyor" denir — iki
/// sihirbazın <c>.env</c>/<c>config.yaml</c>'a aynı anda yazıp birbirini
/// ezmesi böylece engellenir.
///
/// <para>Mekanizma: <c>FileShare.None</c> ile açık tutulan bir
/// <c>setup.lock</c>. Dosya açıkken ikinci <c>FileStream</c> açılışı
/// <see cref="IOException"/> verir. <see cref="Dispose"/> akışı kapatıp
/// dosyayı siler.</para>
/// </summary>
public sealed class SetupRunLock : IDisposable
{
    private readonly string _path;
    private FileStream? _stream;

    private SetupRunLock(string path, FileStream stream)
    {
        _path = path;
        _stream = stream;
    }

    /// <summary>Kilit dosyasının yolu.</summary>
    public string Path => _path;

    /// <summary>
    /// Kilidi almayı dener. Alınırsa <paramref name="handle"/> dolar ve true
    /// döner; başkası tutuyorsa false döner (handle null). Kilit dosyasına
    /// tanılama için pid + başlangıç zamanı yazılır.
    /// </summary>
    public static bool TryAcquire(string dir, out SetupRunLock? handle)
    {
        handle = null;
        try
        {
            Directory.CreateDirectory(dir);
            var path = System.IO.Path.Combine(dir, "setup.lock");
            var fs = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            try
            {
                var info = Encoding.UTF8.GetBytes(
                    $"pid={Environment.ProcessId}\nstartedUtc={DateTimeOffset.UtcNow:o}\n");
                fs.SetLength(0);
                fs.Write(info, 0, info.Length);
                fs.Flush(flushToDisk: true);
            }
            catch
            {
                // Bilgi yazılamasa da kilit (açık FileStream) geçerlidir.
            }
            handle = new SetupRunLock(path, fs);
            return true;
        }
        catch (IOException)
        {
            // Başka bir çalışma kilidi tutuyor.
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        var s = _stream;
        _stream = null;
        try { s?.Dispose(); } catch { /* en iyi çaba */ }
        try { File.Delete(_path); } catch { /* başka örnek sildiyse sorun değil */ }
    }
}
