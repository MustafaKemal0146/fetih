using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Fetih.Desktop.Bridge;

/// <summary>Bir JSON-RPC hata çerçevesinden doğan istisna.</summary>
public sealed class BridgeRpcException : Exception
{
    public BridgeRpcException(int code, string message, JsonElement? data)
        : base(message)
    {
        Code = code;
        Data2 = data;
    }

    /// <summary>Köprü hata kodu (bkz. docs/masaustu-koprusu-rpc.md).</summary>
    public int Code { get; }

    /// <summary>Sağlayıcının kendi mesajını taşıyabilen ek veri.</summary>
    public JsonElement? Data2 { get; }
}

/// <summary>Bir araç çağrısı olayının yükü.</summary>
public sealed record BridgeToolCall(string SessionId, string Id, string Name, string ArgumentsJson);

/// <summary>Bir araç sonucu olayının yükü.</summary>
public sealed record BridgeToolResult(string SessionId, string Id, string Name, string ResultText);

/// <summary>Bir turun başarıyla bitişi.</summary>
public sealed record BridgeDone(string SessionId, string Text, int? ApiCalls, long? ElapsedMs);

/// <summary>Bir turun başarısız bitişi.</summary>
public sealed record BridgeErrorEvent(string SessionId, string Error, string? Partial);

/// <summary>
/// Masaüstü Köprüsü'nün GERÇEK WebSocket / JSON-RPC 2.0 (NDJSON) istemcisi.
/// Süreci <see cref="BridgeProcess"/> başlatır, token'ı el sıkışmadan alır,
/// <c>bridge.authenticate</c> ile kimlik doğrular ve tüm RPC yüzeyini sunar.
///
/// <para>Olaylar (Delta/ToolCall/ToolResult/Done/ErrorEvent) alım döngüsü
/// iş parçacığında tetiklenir; UI tüketicileri kendi DispatcherQueue'larına
/// yönlendirmelidir.</para>
/// </summary>
public sealed class BridgeClient : IDisposable
{
    /// <summary>Kabuk, sohbet ve ayar sayfalarının paylaştığı tek örnek.</summary>
    public static BridgeClient Shared { get; } = new();

    private readonly SemaphoreSlim _connectLock = new(1, 1);
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonElement>> _pending = new();
    private readonly BridgeProcess _bridgeProcess = new();

    private ClientWebSocket? _ws;
    private CancellationTokenSource? _receiveCts;
    private long _nextId;
    private int _protocolVersion = 1;
    private volatile bool _authenticated;
    private volatile bool _disposed;

    // ── Durum + olaylar ─────────────────────────────────────────────────────

    public BridgeStatus Status => BridgeStatus.Shared;

    public bool IsConnected => _authenticated && _ws is { State: WebSocketState.Open };

    public int ProtocolVersion => _protocolVersion;

    public event Action<string /*sessionId*/, string /*text*/>? SessionDelta;
    public event Action<BridgeToolCall>? SessionToolCall;
    public event Action<BridgeToolResult>? SessionToolResult;
    public event Action<BridgeDone>? SessionDone;
    public event Action<BridgeErrorEvent>? SessionError;
    public event Action? ConnectionLost;

    // ── Bağlantı ────────────────────────────────────────────────────────────

    /// <summary>
    /// Bağlıysa hiçbir şey yapmaz; değilse süreci başlatıp bağlanır ve
    /// kimlik doğrular. Aynı anda birden çok çağrı gelirse yalnızca biri iş yapar.
    /// </summary>
    public async Task EnsureConnectedAsync(CancellationToken ct = default)
    {
        if (IsConnected)
        {
            return;
        }

        await _connectLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (IsConnected)
            {
                return;
            }

            Status.Update(BridgeConnectionState.Connecting, "Masaüstü Köprüsü başlatılıyor…");

            var handshake = await _bridgeProcess.StartAsync(ct).ConfigureAwait(false);
            _protocolVersion = handshake.ProtocolVersion;

            var ws = new ClientWebSocket();
            await ws.ConnectAsync(new Uri(handshake.Url), ct).ConfigureAwait(false);
            _ws = ws;
            _authenticated = false;

            _receiveCts = new CancellationTokenSource();
            _ = Task.Run(() => ReceiveLoopAsync(ws, _receiveCts.Token));

            // Sürüm aralığını doğrula (tam eşitlik değil — bkz. RPC belgesi §6).
            var caps = await CallAsync("bridge.capabilities", null, ct).ConfigureAwait(false);
            if (caps.TryGetProperty("min_supported_version", out var minV)
                && caps.TryGetProperty("max_supported_version", out var maxV))
            {
                var min = minV.GetInt32();
                var max = maxV.GetInt32();
                const int clientVersion = 1;
                if (clientVersion < min || clientVersion > max)
                {
                    Status.Update(BridgeConnectionState.Faulted,
                        $"Protokol uyumsuz: istemci {clientVersion}, sunucu {min}–{max}.");
                    throw new InvalidOperationException(
                        $"Köprü protokol sürümü uyumsuz (istemci 1, sunucu {min}–{max}).");
                }
            }

            // Kimlik doğrula.
            var authParams = new Dictionary<string, object?> { ["token"] = handshake.Token };
            var auth = await CallAsync("bridge.authenticate", authParams, ct).ConfigureAwait(false);
            _authenticated = auth.TryGetProperty("authenticated", out var ok) && ok.GetBoolean();

            if (!_authenticated)
            {
                Status.Update(BridgeConnectionState.Faulted, "Kimlik doğrulama reddedildi.");
                throw new InvalidOperationException("Köprü kimlik doğrulaması başarısız.");
            }

            Status.Update(BridgeConnectionState.Ready,
                $"Bağlı · protokol v{_protocolVersion} · pid {handshake.Pid}");
        }
        catch (Exception ex)
        {
            if (Status.State != BridgeConnectionState.Faulted)
            {
                Status.Update(BridgeConnectionState.Faulted, "Köprüye bağlanılamadı: " + ex.Message);
            }
            CleanupSocket();
            throw;
        }
        finally
        {
            _connectLock.Release();
        }
    }

    private async Task ReceiveLoopAsync(ClientWebSocket ws, CancellationToken ct)
    {
        var buffer = new byte[64 * 1024];
        var sb = new StringBuilder();
        try
        {
            while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
            {
                sb.Clear();
                WebSocketReceiveResult result;
                do
                {
                    result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), ct)
                        .ConfigureAwait(false);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        throw new WebSocketException("sunucu bağlantıyı kapattı");
                    }
                    sb.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                }
                while (!result.EndOfMessage);

                var frame = sb.ToString();
                if (frame.Length > 0)
                {
                    DispatchFrame(frame);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal kapanış.
        }
        catch (Exception)
        {
            OnConnectionDropped();
        }
    }

    private void OnConnectionDropped()
    {
        if (_disposed)
        {
            return;
        }
        _authenticated = false;
        // Bekleyen tüm çağrıları serbest bırak.
        foreach (var kv in _pending)
        {
            kv.Value.TrySetException(new InvalidOperationException("Köprü bağlantısı koptu."));
        }
        _pending.Clear();
        Status.Update(BridgeConnectionState.Reconnecting,
            "Bağlantı koptu; sonraki istekte yeniden bağlanılacak.");
        try { ConnectionLost?.Invoke(); } catch { }
    }

    private void DispatchFrame(string frame)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(frame);
        }
        catch
        {
            return;
        }

        using (doc)
        {
            var root = doc.RootElement;

            // Yanıt/hata: 'id' var.
            if (root.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.Number)
            {
                var id = idEl.GetInt64();
                if (_pending.TryRemove(id, out var tcs))
                {
                    if (root.TryGetProperty("error", out var errEl))
                    {
                        var code = errEl.TryGetProperty("code", out var c) ? c.GetInt32() : -1;
                        var msg = errEl.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
                        JsonElement? data = errEl.TryGetProperty("data", out var d)
                            ? d.Clone()
                            : null;
                        tcs.TrySetException(new BridgeRpcException(code, msg, data));
                    }
                    else if (root.TryGetProperty("result", out var resEl))
                    {
                        tcs.TrySetResult(resEl.Clone());
                    }
                    else
                    {
                        tcs.TrySetResult(default);
                    }
                }
                return;
            }

            // Olay (bildirim): 'method' var, 'id' yok.
            if (root.TryGetProperty("method", out var methodEl))
            {
                var method = methodEl.GetString() ?? "";
                var p = root.TryGetProperty("params", out var pe) ? pe : default;
                HandleEvent(method, p);
            }
        }
    }

    private void HandleEvent(string method, JsonElement p)
    {
        try
        {
            switch (method)
            {
                case "bridge.ready":
                    // Kabuk zaten Connecting/Ready gösteriyor; burada ekstra iş yok.
                    break;

                case "session.delta":
                    SessionDelta?.Invoke(Str(p, "session_id"), Str(p, "text"));
                    break;

                case "session.tool_call":
                    SessionToolCall?.Invoke(new BridgeToolCall(
                        Str(p, "session_id"), Str(p, "id"), Str(p, "name"),
                        RawOrString(p, "arguments")));
                    break;

                case "session.tool_result":
                    SessionToolResult?.Invoke(new BridgeToolResult(
                        Str(p, "session_id"), Str(p, "id"), Str(p, "name"),
                        RawOrString(p, "result")));
                    break;

                case "session.done":
                    SessionDone?.Invoke(new BridgeDone(
                        Str(p, "session_id"), Str(p, "text"),
                        IntOrNull(p, "api_calls"), LongOrNull(p, "elapsed_ms")));
                    break;

                case "session.error":
                    SessionError?.Invoke(new BridgeErrorEvent(
                        Str(p, "session_id"), Str(p, "error"),
                        p.TryGetProperty("partial", out var pt) ? pt.ToString() : null));
                    break;
            }
        }
        catch
        {
            // Bir olay tüketicisinin hatası alım döngüsünü çökertmesin.
        }
    }

    // ── Genel RPC çağrısı ────────────────────────────────────────────────────

    /// <summary>Bir RPC metodu çağırır; hata çerçevesi geldiğinde fırlatır.</summary>
    public async Task<JsonElement> CallAsync(
        string method, object? parameters, CancellationToken ct = default)
    {
        var ws = _ws;
        if (ws is null || ws.State != WebSocketState.Open)
        {
            throw new InvalidOperationException("Köprü bağlı değil.");
        }

        var id = Interlocked.Increment(ref _nextId);
        var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;

        var frame = new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["id"] = id,
            ["method"] = method,
            ["params"] = parameters ?? new Dictionary<string, object?>(),
        };
        var json = JsonSerializer.Serialize(frame, SerializerOptions);
        var bytes = Encoding.UTF8.GetBytes(json);

        await _sendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await ws.SendAsync(
                new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _pending.TryRemove(id, out _);
            throw new InvalidOperationException("Köprüye istek gönderilemedi: " + ex.Message, ex);
        }
        finally
        {
            _sendLock.Release();
        }

        using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
        return await tcs.Task.ConfigureAwait(false);
    }

    // ── Yüksek seviye RPC metotları ──────────────────────────────────────────

    public async Task<string> NewSessionAsync(
        string? model = null, string? provider = null, IEnumerable<string>? toolsets = null,
        bool skipContextFiles = false, bool skipMemory = false, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = SessionParams(model, provider, toolsets, skipContextFiles, skipMemory);
        var res = await CallAsync("session.new", p, ct).ConfigureAwait(false);
        return Str(res, "session_id");
    }

    /// <summary>
    /// <c>session.send</c> — ana metot. Tur boyunca olaylar akar; bu çağrı
    /// <c>session.done</c> sonucuyla döner. Hata → <see cref="BridgeRpcException"/>.
    /// </summary>
    public async Task<JsonElement> SendMessageAsync(
        string message, string? sessionId = null, bool stream = true,
        string? model = null, string? provider = null, IEnumerable<string>? toolsets = null,
        bool skipContextFiles = false, bool skipMemory = false, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = SessionParams(model, provider, toolsets, skipContextFiles, skipMemory);
        p["message"] = message;
        p["stream"] = stream;
        if (!string.IsNullOrEmpty(sessionId))
        {
            p["session_id"] = sessionId;
        }
        return await CallAsync("session.send", p, ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> CancelAsync(string sessionId, CancellationToken ct = default)
    {
        return await CallAsync("session.cancel",
            new Dictionary<string, object?> { ["session_id"] = sessionId }, ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> ConfigGetAsync(string? key = null, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?>();
        if (!string.IsNullOrEmpty(key))
        {
            p["key"] = key;
        }
        return await CallAsync("config.get", p, ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> ConfigSetAsync(string key, object? value, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("config.set",
            new Dictionary<string, object?> { ["key"] = key, ["value"] = value }, ct)
            .ConfigureAwait(false);
    }

    public async Task<JsonElement> ProvidersListAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("providers.list", null, ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> SkillsListAsync(
        string? category = null, string? search = null, int limit = 100, int offset = 0,
        CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?> { ["limit"] = limit, ["offset"] = offset };
        if (!string.IsNullOrEmpty(category)) p["category"] = category;
        if (!string.IsNullOrEmpty(search)) p["search"] = search;
        return await CallAsync("skills.list", p, ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> DiagnosticsInfoAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("diagnostics.info", null, ct).ConfigureAwait(false);
    }

    /// <summary><c>shell.status</c> — Windows kabuk backend'inin (Git Bash / WSL) durumu.</summary>
    public async Task<JsonElement> ShellStatusAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("shell.status", null, ct).ConfigureAwait(false);
    }

    /// <summary><c>shell.ensure_user</c> — WSL içinde ayrılmış FETİH kullanıcısını oluşturur.</summary>
    public async Task<JsonElement> ShellEnsureUserAsync(
        string? distro = null, string? user = null, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?>();
        if (!string.IsNullOrEmpty(distro)) p["distro"] = distro;
        if (!string.IsNullOrEmpty(user)) p["user"] = user;
        return await CallAsync("shell.ensure_user", p, ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> PingAsync(CancellationToken ct = default)
    {
        return await CallAsync("bridge.ping", null, ct).ConfigureAwait(false);
    }

    // ── Yardımcılar ──────────────────────────────────────────────────────────

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static Dictionary<string, object?> SessionParams(
        string? model, string? provider, IEnumerable<string>? toolsets,
        bool skipContextFiles, bool skipMemory)
    {
        var p = new Dictionary<string, object?>();
        if (!string.IsNullOrEmpty(model)) p["model"] = model;
        if (!string.IsNullOrEmpty(provider)) p["provider"] = provider;
        if (toolsets is not null)
        {
            var list = new List<string>(toolsets);
            if (list.Count > 0) p["toolsets"] = list;
        }
        if (skipContextFiles) p["skip_context_files"] = true;
        if (skipMemory) p["skip_memory"] = true;
        return p;
    }

    private static string Str(JsonElement e, string name)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v))
        {
            return v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString();
        }
        return "";
    }

    private static string RawOrString(JsonElement e, string name)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v))
        {
            return v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.GetRawText();
        }
        return "";
    }

    private static int? IntOrNull(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
           && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null;

    private static long? LongOrNull(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
           && v.ValueKind == JsonValueKind.Number ? v.GetInt64() : null;

    private void CleanupSocket()
    {
        try { _receiveCts?.Cancel(); } catch { }
        try { _ws?.Abort(); } catch { }
        try { _ws?.Dispose(); } catch { }
        _ws = null;
        _authenticated = false;
    }

    public void Dispose()
    {
        _disposed = true;
        CleanupSocket();
        _bridgeProcess.Dispose();
    }
}
