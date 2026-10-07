using System;
using System.IO;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Fetih.Desktop.Services;

/// <summary>
/// Uygulama düzeyinde yapısal günlükleyici. Çağıranı asla bloklamaz: satırlar
/// sınırlı (bounded) bir kanala yazılır, tek bir arka plan okuyucu bunları
/// toplu (batch) olarak dosyaya akıtır. Kanal dolarsa EN ESKİ satır düşürülür
/// (son bağlam önemli). 5 MB'ı aşınca tek bir yedeğe (.old) döndürülür.
///
/// <para>OpenClaw'ın Logger deseninden uyarlanmıştır. Biçimleme/redaksiyon/
/// rotasyon kararı saf <see cref="LogFormatting"/>'dedir (test edilebilir);
/// burada yalnızca IO + kanal yaşam döngüsü vardır.</para>
/// </summary>
public static class Logger
{
    private const int ChannelCapacity = 4096;
    private const int BatchMax = 256;
    private const long RotateThresholdBytes = 5 * 1024 * 1024;
    private const int RotateCheckInterval = 64;

    private static readonly object InitLock = new();
    private static Channel<string>? _channel;
    private static Task? _writerTask;
    private static string? _logPath;
    private static string? _oldPath;
    private static int _writesSinceRotateCheck;

    /// <summary>Aktif günlük dosyasının yolu (başlatılmadıysa null).</summary>
    public static string? LogFilePath => _logPath;

    /// <summary>Son yazım hatası (varsa) — tanılama için; Logger.* ÇAĞIRMAZ (özyineleme).</summary>
    public static string? LastWriteError { get; private set; }

    /// <summary>
    /// Günlükleyiciyi başlatır. Birden çok çağrıda yalnızca ilki iş yapar.
    /// <paramref name="dir"/> verilmezse %LOCALAPPDATA%\Fetih\Desktop\logs.
    /// </summary>
    public static void Initialize(string? dir = null)
    {
        lock (InitLock)
        {
            if (_channel is not null)
            {
                return;
            }
            try
            {
                dir ??= Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Fetih", "Desktop", "logs");
                Directory.CreateDirectory(dir);
                _logPath = Path.Combine(dir, "fetih-desktop.log");
                _oldPath = Path.Combine(dir, "fetih-desktop.log.old");

                _channel = Channel.CreateBounded<string>(new BoundedChannelOptions(ChannelCapacity)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = false,
                });

                TryRotate(); // başlangıçta zaten büyükse döndür
                var reader = _channel.Reader;
                _writerTask = Task.Run(() => WriterLoopAsync(reader));
            }
            catch (Exception ex)
            {
                LastWriteError = ex.Message;
                _channel = null; // başlatılamadı — Write'lar sessizce düşer
            }
        }
    }

    public static void Debug(string message) => Write(LogLevel.Debug, message);
    public static void Info(string message) => Write(LogLevel.Info, message);
    public static void Warn(string message) => Write(LogLevel.Warn, message);
    public static void Error(string message) => Write(LogLevel.Error, message);

    private static void Write(LogLevel level, string message)
    {
        var ch = _channel;
        if (ch is null)
        {
            return;
        }
        // Non-blocking; kanal doluysa en eski satır düşer (DropOldest).
        ch.Writer.TryWrite(LogFormatting.FormatLine(DateTimeOffset.Now, level, message));
    }

    private static async Task WriterLoopAsync(ChannelReader<string> reader)
    {
        while (await reader.WaitToReadAsync().ConfigureAwait(false))
        {
            var written = 0;
            try
            {
                // Batch başına TEK dosya açılışı.
                await using var fs = new FileStream(
                    _logPath!, FileMode.Append, FileAccess.Write, FileShare.Read);
                await using var sw = new StreamWriter(fs);
                while (written < BatchMax && reader.TryRead(out var line))
                {
                    await sw.WriteLineAsync(line).ConfigureAwait(false);
                    written++;
                }
                await sw.FlushAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Logger.* çağırma — özyineleme riski. Sadece son hatayı tut.
                LastWriteError = ex.Message;
            }

            _writesSinceRotateCheck += written;
            if (_writesSinceRotateCheck >= RotateCheckInterval)
            {
                _writesSinceRotateCheck = 0;
                TryRotate();
            }
        }
    }

    private static void TryRotate()
    {
        try
        {
            if (_logPath is null || !File.Exists(_logPath))
            {
                return;
            }
            var len = new FileInfo(_logPath).Length;
            if (!LogFormatting.ShouldRotate(len, RotateThresholdBytes))
            {
                return;
            }
            if (_oldPath is not null)
            {
                if (File.Exists(_oldPath))
                {
                    File.Delete(_oldPath);
                }
                File.Move(_logPath, _oldPath);
            }
        }
        catch (Exception ex)
        {
            LastWriteError = ex.Message;
        }
    }

    /// <summary>Kanalı kapatır ve bekleyen satırların en iyi çabayla yazılmasını bekler.</summary>
    public static void Shutdown()
    {
        try
        {
            _channel?.Writer.TryComplete();
            _writerTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
            // kapanışta en iyi çaba
        }
    }
}
