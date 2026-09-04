using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Bridge;

/// <summary>
/// Masaüstü Köprüsü Python sürecini (<c>fetih desktop-bridge</c> /
/// <c>python -m fetih_desktop_bridge</c>) başlatır ve el sıkışma satırından
/// (<c>{"event":"bridge.listening", ...}</c>) WebSocket URL'sini ve tek
/// kullanımlık token'ı okur.
///
/// <para>Token yalnızca sürecin stdout'una yazılan tek satırda görünür; bu
/// sınıf onu bellekte tutar, <b>asla</b> diske/loga yazmaz.</para>
/// </summary>
public sealed class BridgeProcess : IDisposable
{
    /// <summary>Sürecin ilan ettiği bağlantı bilgisi.</summary>
    public sealed record Handshake(string Url, string Token, int ProtocolVersion, int Pid);

    private Process? _process;
    private bool _ownsProcess;

    public Handshake? Info { get; private set; }

    /// <summary>Süreç şu an çalışıyor mu?</summary>
    public bool IsRunning => _ownsProcess && _process is { HasExited: false };

    /// <summary>
    /// Ortam değişkenleriyle önceden verilmiş bir köprü varsa (kurulum
    /// sihirbazı / test senaryoları) onu kullan; yoksa yeni süreç başlat.
    /// </summary>
    public async Task<Handshake> StartAsync(CancellationToken ct = default)
    {
        // Dışarıdan verilmiş köprü: süreç bizim değil, yalnızca bağlanırız.
        var envUrl = SafeEnv("FETIH_BRIDGE_URL");
        var envToken = SafeEnv("FETIH_BRIDGE_TOKEN");
        if (!string.IsNullOrWhiteSpace(envUrl) && !string.IsNullOrWhiteSpace(envToken))
        {
            _ownsProcess = false;
            Info = new Handshake(envUrl!.Trim(), envToken!.Trim(), 1, 0);
            return Info;
        }

        var (exe, prefixArgs) = ResolveLauncher();
        var repoRoot = FetihPaths.RepositoryRoot;

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = repoRoot ?? Environment.CurrentDirectory,
        };
        foreach (var a in prefixArgs)
        {
            psi.ArgumentList.Add(a);
        }
        // NOT: `python -m fetih_desktop_bridge` modülünün argparse'ı doğrudan
        // --port/--stdio bekler; "desktop-bridge" alt komutu YALNIZCA `fetih`
        // CLI sarmalayıcısına aittir ve modüle verilirse argparse hatası verir.
        // Argümansız çalıştırma = WebSocket, boş port, üretilen token.

        // Alt sürecin FETİH deposunu bulabilmesi için PYTHONPATH'i kökle güçlendir.
        if (repoRoot is not null)
        {
            var existing = psi.Environment.TryGetValue("PYTHONPATH", out var pp) ? pp : "";
            psi.Environment["PYTHONPATH"] = string.IsNullOrEmpty(existing)
                ? repoRoot
                : repoRoot + Path.PathSeparator + existing;
        }
        psi.Environment["PYTHONUNBUFFERED"] = "1";

        var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        try
        {
            if (!proc.Start())
            {
                throw new InvalidOperationException($"Köprü süreci başlatılamadı: {exe}");
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Köprü süreci başlatılamadı ({exe}): {ex.Message}", ex);
        }

        _process = proc;
        _ownsProcess = true;

        // stderr'i arka planda topla (tampon dolup süreci kilitlemesin).
        _ = Task.Run(() => DrainAsync(proc.StandardError));

        // stdout'un İLK satırı el sıkışmadır. Zaman aşımıyla oku.
        var handshakeLine = await ReadHandshakeLineAsync(proc, ct).ConfigureAwait(false);
        if (handshakeLine is null)
        {
            var err = _lastStderr;
            Stop();
            throw new InvalidOperationException(
                "Köprü el sıkışma satırı alınamadı (süreç beklenmedik şekilde sonlandı). " +
                (string.IsNullOrWhiteSpace(err) ? "" : "Ayrıntı: " + err));
        }

        Handshake parsed;
        try
        {
            parsed = ParseHandshake(handshakeLine);
        }
        catch (Exception ex)
        {
            Stop();
            throw new InvalidOperationException(
                "Köprü el sıkışma satırı çözümlenemedi: " + ex.Message, ex);
        }

        // Kalan stdout'u arka planda tüket; sunucu artık her şeyi WS üzerinden
        // yolluyor ama stdout'u yine de boşaltmak deadlock'u önler.
        _ = Task.Run(() => DrainAsync(proc.StandardOutput));

        Info = parsed;
        return parsed;
    }

    private volatile string _lastStderr = "";

    private async Task DrainAsync(StreamReader reader)
    {
        try
        {
            string? line;
            while ((line = await reader.ReadLineAsync().ConfigureAwait(false)) is not null)
            {
                // stderr tanı için faydalı olabilir ama token içerebilecek
                // stdout el sıkışması ASLA loglanmaz; burada yalnızca stderr
                // (token taşımaz) son satırı tutulur.
                if (reader.BaseStream is not null && !string.IsNullOrWhiteSpace(line))
                {
                    _lastStderr = line;
                }
            }
        }
        catch
        {
            // Süreç kapanınca okuma biter; sorun değil.
        }
    }

    private static async Task<string?> ReadHandshakeLineAsync(Process proc, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(30));

        var readTask = proc.StandardOutput.ReadLineAsync();
        var completed = await Task.WhenAny(
            readTask,
            Task.Delay(Timeout.Infinite, timeoutCts.Token)).ConfigureAwait(false);

        if (completed == readTask)
        {
            return await readTask.ConfigureAwait(false);
        }
        return null;
    }

    private static Handshake ParseHandshake(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        var ev = root.TryGetProperty("event", out var e) ? e.GetString() : null;
        if (ev != "bridge.listening")
        {
            throw new FormatException($"beklenen 'bridge.listening', gelen: {ev ?? "(yok)"}");
        }
        var url = root.GetProperty("url").GetString()
                  ?? throw new FormatException("url yok");
        var token = root.GetProperty("token").GetString()
                    ?? throw new FormatException("token yok");
        var proto = root.TryGetProperty("protocol_version", out var p) ? p.GetInt32() : 1;
        var pid = root.TryGetProperty("pid", out var pd) ? pd.GetInt32() : 0;
        return new Handshake(url, token, proto, pid);
    }

    /// <summary>
    /// Köprüyü başlatacak yürütülebiliri çözer. Sırasıyla:
    /// <c>FETIH_PYTHON</c> ortam değişkeni → bilinen pythoncore yolu →
    /// PATH'teki <c>py -3</c> → <c>python</c>. Hepsinde <c>-m
    /// fetih_desktop_bridge</c> ön argümanı kullanılır.
    /// </summary>
    private static (string Exe, IReadOnlyList<string> PrefixArgs) ResolveLauncher()
    {
        var moduleArgs = new[] { "-m", "fetih_desktop_bridge" };

        var explicitPy = SafeEnv("FETIH_PYTHON");
        if (!string.IsNullOrWhiteSpace(explicitPy) && File.Exists(explicitPy))
        {
            return (explicitPy!, moduleArgs);
        }

        // Bu makinede FETİH'in çalıştığı Python (bkz. proje notları).
        var known = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Python", "pythoncore-3.14-64", "python.exe");
        if (File.Exists(known))
        {
            return (known, moduleArgs);
        }

        // Windows Python başlatıcısı (py.exe) genellikle PATH'tedir.
        var pyLauncher = FindOnPath("py.exe");
        if (pyLauncher is not null)
        {
            return (pyLauncher, new[] { "-3", "-m", "fetih_desktop_bridge" });
        }

        var python = FindOnPath("python.exe") ?? "python";
        return (python, moduleArgs);
    }

    private static string? FindOnPath(string fileName)
    {
        try
        {
            var path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (var dir in path.Split(Path.PathSeparator))
            {
                if (string.IsNullOrWhiteSpace(dir))
                {
                    continue;
                }
                var candidate = Path.Combine(dir.Trim(), fileName);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }
        catch
        {
            // PATH okunamazsa çözümleme bir üst adıma düşer.
        }
        return null;
    }

    private static string? SafeEnv(string name)
    {
        try
        {
            return Environment.GetEnvironmentVariable(name);
        }
        catch
        {
            return null;
        }
    }

    public void Stop()
    {
        if (!_ownsProcess)
        {
            _process = null;
            return;
        }

        var proc = _process;
        _process = null;
        if (proc is null)
        {
            return;
        }

        try
        {
            if (!proc.HasExited)
            {
                proc.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Zaten kapanmış olabilir.
        }
        finally
        {
            try { proc.Dispose(); } catch { }
        }
    }

    public void Dispose() => Stop();
}
