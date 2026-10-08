using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Services;

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

/// <summary>Bir turun başarıyla bitişi. Token alanları oturum boyunca kümülatiftir.</summary>
public sealed record BridgeDone(
    string SessionId, string Text, int? ApiCalls, long? ElapsedMs, string? Thought = null,
    int? TotalTokens = null, int? PromptTokens = null, int? CompletionTokens = null);

/// <summary>Bir turun başarısız bitişi.</summary>
public sealed record BridgeErrorEvent(string SessionId, string Error, string? Partial);

/// <summary>Oturum özeti.</summary>
public sealed record SessionSummary(string SessionId, string Title, double UpdatedAt);

/// <summary>Tehlikeli bir komut için kullanıcı onayı isteyen olayın yükü.</summary>
public sealed record BridgeApprovalRequest(
    string SessionId, string RequestId, string Command, string Description,
    IReadOnlyList<string> PatternKeys);

/// <summary>
/// Arka planda yürüyen bir OAuth/abonelik girişinin (xAI, Codex, Gemini CLI,
/// Qwen) konsol çıktısından gelen tek satır — cihaz kodu ya da yetkilendirme
/// bağlantısı burada akar. <c>RequestId</c> ile <see cref="BridgeAuthDone"/>'a
/// eşlenir.
/// </summary>
public sealed record BridgeAuthProgress(string RequestId, string Provider, string Line);

/// <summary>Bir OAuth/abonelik giriş akışının sonucu (başarı + tazelenmiş durum).</summary>
public sealed record BridgeAuthDone(
    string RequestId, string Provider, bool Ok, string Error, bool LoggedIn,
    string Email, string Plan, string ExpiresAt);

/// <summary>Oturum yükleme sonucu (geriye dönük deconstruct uyumlu).</summary>
public sealed record BridgeSessionLoadResult(
    string Title,
    List<StoredItem> Items,
    bool Running = false,
    StoredItem? Pending = null)
{
    public void Deconstruct(out string title, out List<StoredItem> items)
    {
        title = Title;
        items = Items;
    }

    public void Deconstruct(out string title, out List<StoredItem> items, out bool running, out StoredItem? pending)
    {
        title = Title;
        items = Items;
        running = Running;
        pending = Pending;
    }
}

/// <summary>
/// Masaüstü Köprüsü'nün GERÇEK WebSocket / JSON-RPC 2.0 (NDJSON) istemcisi.
/// Süreci <see cref="BridgeProcess"/> başlatır, token'ı el sıkışmadan alır,
/// <c>bridge.authenticate</c> ile kimlik doğrular ve tüm RPC yüzeyini sunar.
///
/// <para>Olaylar (Delta/Thought/ToolCall/ToolResult/Done/ErrorEvent) alım döngüsü
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
    private int _reconnecting;

    // ── Durum + olaylar ─────────────────────────────────────────────────────

    public BridgeStatus Status => BridgeStatus.Shared;

    public bool IsConnected => _authenticated && _ws is { State: WebSocketState.Open };

    public int ProtocolVersion => _protocolVersion;

    public event Action<string /*sessionId*/, string /*text*/>? SessionDelta;
    public event Action<string /*sessionId*/, string /*text*/>? SessionThought;
    public event Action<BridgeToolCall>? SessionToolCall;
    public event Action<BridgeToolResult>? SessionToolResult;
    public event Action<BridgeDone>? SessionDone;
    public event Action<BridgeErrorEvent>? SessionError;
    public event Action<string /*sessionId*/, string /*title*/, double /*updatedAt*/>? SessionUpdated;
    public event Action<string /*sessionId*/, string /*label*/>? ThoughtLabel;
    public event Action<JsonElement>? FindingDiscovered;
    public event Action<BridgeApprovalRequest>? ApprovalRequested;
    public event Action<string /*sessionId*/, string /*requestId*/>? ApprovalResolved;
    public event Action<BridgeAuthProgress>? AuthProgress;
    public event Action<BridgeAuthDone>? AuthDone;
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

            Status.Update(BridgeConnectionState.Connecting, Loc.T("bridge.detail.connecting"));

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
                        string.Format(Loc.T("bridge.detail.protocol_mismatch"), clientVersion, min, max));
                    throw new InvalidOperationException(
                        string.Format(Loc.T("bridge.detail.protocol_mismatch_ex"), min, max));
                }
            }

            // Kimlik doğrula.
            var authParams = new Dictionary<string, object?> { ["token"] = handshake.Token };
            var auth = await CallAsync("bridge.authenticate", authParams, ct).ConfigureAwait(false);
            _authenticated = auth.TryGetProperty("authenticated", out var ok) && ok.GetBoolean();

            if (!_authenticated)
            {
                Status.Update(BridgeConnectionState.Faulted, Loc.T("bridge.detail.auth_rejected"));
                throw new InvalidOperationException(Loc.T("bridge.detail.auth_failed"));
            }

            Status.Update(BridgeConnectionState.Ready,
                Loc.Format("bridge.detail.connected", _protocolVersion, handshake.Pid));
        }
        catch (Exception ex)
        {
            if (Status.State != BridgeConnectionState.Faulted)
            {
                Status.Update(BridgeConnectionState.Faulted, Loc.T("bridge.detail.connect_failed") + ex.Message);
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
        using var message = new MemoryStream();
        try
        {
            while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
            {
                message.SetLength(0);
                WebSocketReceiveResult result;
                do
                {
                    result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), ct)
                        .ConfigureAwait(false);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        throw new WebSocketException(Loc.T("bridge.detail.server_closed"));
                    }
                    message.Write(buffer, 0, result.Count);
                }
                while (!result.EndOfMessage);

                // Tüm mesaj biriktikten SONRA tek seferde çöz: çok baytlı bir
                // karakter (ş, ğ, İ, emoji) 64 KB'lık parça sınırına denk
                // gelirse parça parça çözmek onu U+FFFD'ye (�) çevirirdi.
                if (message.Length > 0)
                {
                    var frame = Encoding.UTF8.GetString(message.GetBuffer(), 0, (int)message.Length);
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
            kv.Value.TrySetException(new InvalidOperationException(Loc.T("bridge.detail.dropped")));
        }
        _pending.Clear();
        Status.Update(BridgeConnectionState.Reconnecting,
            Loc.T("bridge.detail.reconnecting"));
        try { ConnectionLost?.Invoke(); } catch { }

        // Proaktif yeniden bağlanma: eskiden durum yalnızca "Reconnecting"
        // etiketinde kalıyor, bağlantı ancak bir sonraki kullanıcı isteğinde
        // tembel kuruluyordu. Artık backoff ile otomatik denenir.
        if (!_disposed)
        {
            _ = ReconnectLoopAsync();
        }
    }

    /// <summary>
    /// Bağlantı koptuğunda arka planda çalışan yeniden bağlanma döngüsü.
    /// Backoff ile (1→60 sn, tavanlı) bağlanana veya süreç dispose edilene
    /// kadar dener. Aynı anda yalnızca bir döngü koşar.
    /// </summary>
    private async Task ReconnectLoopAsync()
    {
        if (Interlocked.Exchange(ref _reconnecting, 1) == 1)
        {
            return;
        }
        try
        {
            var attempt = 0;
            while (!_disposed && !IsConnected)
            {
                var delay = BridgeBackoff.ForAttempt(attempt);
                Status.Update(BridgeConnectionState.Reconnecting,
                    Loc.Format("bridge.detail.reconnecting_in", (int)delay.TotalSeconds));
                try
                {
                    await Task.Delay(delay).ConfigureAwait(false);
                }
                catch
                {
                    // yoksay
                }
                if (_disposed)
                {
                    break;
                }
                try
                {
                    await EnsureConnectedAsync().ConfigureAwait(false);
                    break; // bağlandı
                }
                catch
                {
                    attempt++;
                }
            }
        }
        finally
        {
            Interlocked.Exchange(ref _reconnecting, 0);
        }
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

                case "session.thought":
                case "session.reasoning":
                    SessionThought?.Invoke(Str(p, "session_id"), Str(p, "text"));
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
                    int? totTok = null, prmTok = null, cmpTok = null;
                    if (p.TryGetProperty("tokens", out var tk) && tk.ValueKind == JsonValueKind.Object)
                    {
                        totTok = IntOrNull(tk, "total");
                        prmTok = IntOrNull(tk, "prompt");
                        cmpTok = IntOrNull(tk, "completion");
                    }
                    SessionDone?.Invoke(new BridgeDone(
                        Str(p, "session_id"), Str(p, "text"),
                        IntOrNull(p, "api_calls"), LongOrNull(p, "elapsed_ms"),
                        Str(p, "thought"), totTok, prmTok, cmpTok));
                    break;

                case "session.error":
                    SessionError?.Invoke(new BridgeErrorEvent(
                        Str(p, "session_id"), Str(p, "error"),
                        p.TryGetProperty("partial", out var pt)
                            && pt.ValueKind is JsonValueKind.True or JsonValueKind.False
                            ? (pt.GetBoolean() ? "true" : "false")
                            : null));
                    break;

                case "session.updated":
                    SessionUpdated?.Invoke(
                        Str(p, "session_id"),
                        Str(p, "title"),
                        p.TryGetProperty("updated_at", out var ua) && ua.ValueKind == JsonValueKind.Number ? ua.GetDouble() : 0.0);
                    break;

                // Köprü aynı etiketi hem "thought.label" hem
                // "session.thought_label" olarak yayıyor; çift tetiklememek
                // için yalnızca ad-uzaylı olanı işliyoruz.
                case "session.thought_label":
                    ThoughtLabel?.Invoke(Str(p, "session_id"), Str(p, "label"));
                    break;

                case "findings.discovered":
                    if (p.TryGetProperty("finding", out var findingEl))
                    {
                        FindingDiscovered?.Invoke(findingEl);
                    }
                    break;

                case "session.approval_request":
                    ApprovalRequested?.Invoke(new BridgeApprovalRequest(
                        Str(p, "session_id"), Str(p, "request_id"),
                        Str(p, "command"), Str(p, "description"),
                        StrList(p, "pattern_keys")));
                    break;

                case "session.approval_resolved":
                    ApprovalResolved?.Invoke(Str(p, "session_id"), Str(p, "request_id"));
                    break;

                case "auth.progress":
                    AuthProgress?.Invoke(new BridgeAuthProgress(
                        Str(p, "request_id"), Str(p, "provider"), Str(p, "line")));
                    break;

                case "auth.done":
                    AuthDone?.Invoke(new BridgeAuthDone(
                        Str(p, "request_id"), Str(p, "provider"),
                        Bool(p, "ok"), Str(p, "error"), Bool(p, "logged_in"),
                        Str(p, "email"), Str(p, "plan"), Str(p, "expires_at")));
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
            throw new InvalidOperationException(Loc.T("bridge.detail.not_connected"));
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
            throw new InvalidOperationException(Loc.T("bridge.detail.send_failed") + ex.Message, ex);
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

    public async Task<string> CreateSessionAsync(string? sessionId = null, string title = "", CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?>();
        if (!string.IsNullOrEmpty(sessionId)) p["session_id"] = sessionId;
        if (!string.IsNullOrEmpty(title)) p["title"] = title;
        var res = await CallAsync("session.create", p, ct).ConfigureAwait(false);
        return Str(res, "session_id");
    }

    public async Task<List<SessionSummary>> ListSessionsAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var res = await CallAsync("session.list", null, ct).ConfigureAwait(false);
        var list = new List<SessionSummary>();
        if (res.TryGetProperty("sessions", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in arr.EnumerateArray())
            {
                var sid = Str(item, "session_id");
                var title = Str(item, "title");
                var updated = item.TryGetProperty("updated_at", out var ua) && ua.ValueKind == JsonValueKind.Number ? ua.GetDouble() : 0.0;
                list.Add(new SessionSummary(sid, string.IsNullOrWhiteSpace(title) ? "Yeni sohbet" : title, updated));
            }
        }
        return list;
    }

    public async Task<BridgeSessionLoadResult> LoadSessionAsync(string sessionId, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?> { ["session_id"] = sessionId };
        var res = await CallAsync("session.load", p, ct).ConfigureAwait(false);
        var title = Str(res, "title");
        var running = res.TryGetProperty("running", out var rEl) && rEl.ValueKind == JsonValueKind.True;
        StoredItem? pending = null;
        if (res.TryGetProperty("pending", out var pEl) && pEl.ValueKind == JsonValueKind.Object)
        {
            pending = ParseStoredItem(pEl);
        }

        var items = new List<StoredItem>();
        if (res.TryGetProperty("items", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var it in arr.EnumerateArray())
            {
                items.Add(ParseStoredItem(it));
            }
        }
        return new BridgeSessionLoadResult(title, items, running, pending);
    }

    private static StoredItem ParseStoredItem(JsonElement it)
    {
        var kind = Str(it, "kind");
        var text = it.TryGetProperty("text", out var t) ? t.GetString() : null;
        var callId = it.TryGetProperty("call_id", out var cid) ? cid.GetString() : null;
        var name = it.TryGetProperty("name", out var n) ? n.GetString() : null;
        var args = it.TryGetProperty("args", out var a) ? (a.ValueKind == JsonValueKind.String ? a.GetString() : a.GetRawText()) : null;
        var result = it.TryGetProperty("result", out var r) ? (r.ValueKind == JsonValueKind.String ? r.GetString() : r.GetRawText()) : null;
        var dur = it.TryGetProperty("duration_ms", out var d) && d.ValueKind == JsonValueKind.Number ? d.GetDouble() : (double?)null;
        var tsStart = it.TryGetProperty("ts_start", out var tss) && tss.ValueKind == JsonValueKind.Number ? tss.GetDouble() : (double?)null;
        var tsEnd = it.TryGetProperty("ts_end", out var tse) && tse.ValueKind == JsonValueKind.Number ? tse.GetDouble() : (double?)null;
        var label = it.TryGetProperty("label", out var l) ? l.GetString() : null;
        return new StoredItem(kind, text, callId, name, args, result, dur, tsStart, tsEnd, label);
    }

    public async Task RenameSessionAsync(string sessionId, string title, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?> { ["session_id"] = sessionId, ["title"] = title };
        await CallAsync("session.rename", p, ct).ConfigureAwait(false);
    }

    public async Task DeleteSessionAsync(string sessionId, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?> { ["session_id"] = sessionId };
        await CallAsync("session.delete", p, ct).ConfigureAwait(false);
    }

    public async Task DeleteAllSessionsAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        await CallAsync("session.delete_all", null, ct).ConfigureAwait(false);
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

        // Model sağlığını BURADA raporla, çağıranlarda değil: her sohbet yolu
        // bu metottan geçer, dolayısıyla rozet hiçbir çağrı yerinde unutulmaz.
        try
        {
            var result = await CallAsync("session.send", p, ct).ConfigureAwait(false);
            Status.ReportModelHealthy();
            return result;
        }
        catch (BridgeRpcException rpc) when (IsModelFault(rpc.Code))
        {
            Status.ReportModelFault(rpc.Code, rpc.Message);
            throw;
        }
    }

    /// <summary>
    /// Bu hata kodu "model/sağlayıcı yapılandırması bozuk" anlamına mı geliyor?
    ///
    /// <para>Yalnızca kullanıcının Ayarlar'dan düzeltebileceği hatalar rozeti
    /// kırmızıya çevirir. Oturum meşgul (-32002) ve iptal (-32005) geçicidir;
    /// bunlarda rozeti bozmak yanlış alarm olur.</para>
    /// </summary>
    private static bool IsModelFault(int code) => code is
        -32003 or   // AGENT_ERROR — sağlayıcı isteği reddetti (401/404/413…)
        -32004;     // CONFIG_ERROR — sağlayıcı çözümlemesi başarısız

    public async Task<JsonElement> CancelAsync(string sessionId, CancellationToken ct = default)
    {
        return await CallAsync("session.cancel",
            new Dictionary<string, object?> { ["session_id"] = sessionId }, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>session.approve</c> — tehlikeli komut onayını yanıtlar.
    /// <paramref name="choice"/>: <c>once</c> | <c>session</c> | <c>always</c> | <c>deny</c>.
    /// </summary>
    public async Task<JsonElement> ApproveAsync(
        string sessionId, string choice, bool all = false, CancellationToken ct = default)
    {
        var p = new Dictionary<string, object?>
        {
            ["session_id"] = sessionId,
            ["choice"] = choice,
        };
        if (all) p["all"] = true;
        return await CallAsync("session.approve", p, ct).ConfigureAwait(false);
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

    /// <summary>
    /// <c>providers.catalog</c> — CLI'nin KANONİK sağlayıcı listesi.
    ///
    /// <para><c>providers.list</c>'ten farkı: o, kullanıcının
    /// <c>config.yaml</c>'ında ne yapılandırdığını söyler (taze kurulumda
    /// boştur). Bu ise "bu çalışma zamanı hangi sağlayıcı kimliklerini kabul
    /// eder" sorusunu yanıtlar — sihirbazın sorması gereken soru budur.</para>
    /// </summary>
    public async Task<JsonElement> ProvidersCatalogAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("providers.catalog", null, ct).ConfigureAwait(false);
    }

    /// <summary><c>providers.models</c> — sağlayıcının ŞU AN sunduğu model kimlikleri.</summary>
    public async Task<JsonElement> ProvidersModelsAsync(string provider, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("providers.models",
            new Dictionary<string, object?> { ["provider"] = provider }, ct).ConfigureAwait(false);
    }

    /// <summary><c>providers.probe_local</c> — yerel sunucu ayakta mı, hangi modeller inik?</summary>
    public async Task<JsonElement> ProvidersProbeLocalAsync(
        string provider, string? baseUrl = null, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?> { ["provider"] = provider };
        if (!string.IsNullOrWhiteSpace(baseUrl)) p["base_url"] = baseUrl;
        return await CallAsync("providers.probe_local", p, ct).ConfigureAwait(false);
    }

    /// <summary><c>providers.auth_status</c> — OAuth sağlayıcısına giriş yapılmış mı (istem YOK).</summary>
    public async Task<JsonElement> ProvidersAuthStatusAsync(string provider, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("providers.auth_status",
            new Dictionary<string, object?> { ["provider"] = provider }, ct).ConfigureAwait(false);
    }

    /// <summary>OAuth/abonelik girişi destekleyen sağlayıcılar ve akış türleri.</summary>
    public async Task<JsonElement> AuthProvidersAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("auth.providers", null, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Anthropic (Claude Pro/Max) uygulama içi yapıştırma akışını başlatır:
    /// tarayıcıda açılacak yetkilendirme URL'si + opak <c>flow_token</c> döner.
    /// </summary>
    public async Task<JsonElement> AuthBeginAsync(string provider, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("auth.begin",
            new Dictionary<string, object?> { ["provider"] = provider }, ct).ConfigureAwait(false);
    }

    /// <summary>Yapıştırma akışını tamamlar: kodu takas edip jetonu saklar.</summary>
    public async Task<JsonElement> AuthCompleteAsync(
        string provider, string flowToken, string code, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("auth.complete", new Dictionary<string, object?>
        {
            ["provider"] = provider,
            ["flow_token"] = flowToken,
            ["code"] = code,
        }, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Tarayıcı/cihaz-kodu/CLI-oturumu akışını köprü sürecinde başlatır; ilerleme
    /// <see cref="AuthProgress"/>, sonuç <see cref="AuthDone"/> olaylarından gelir.
    /// </summary>
    public async Task<JsonElement> AuthLoginAsync(string provider, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("auth.login",
            new Dictionary<string, object?> { ["provider"] = provider }, ct).ConfigureAwait(false);
    }

    /// <summary>Bir sağlayıcının saklanan kimlik durumunu temizler.</summary>
    public async Task<JsonElement> AuthLogoutAsync(string provider, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("auth.logout",
            new Dictionary<string, object?> { ["provider"] = provider }, ct).ConfigureAwait(false);
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

    /// <summary><c>findings.list</c> — Kaydedilmiş güvenlik bulgularını listeler.</summary>
    public async Task<JsonElement> FindingsListAsync(string? severity = null, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?>();
        if (!string.IsNullOrEmpty(severity)) p["severity"] = severity;
        return await CallAsync("findings.list", p, ct).ConfigureAwait(false);
    }

    /// <summary><c>findings.export</c> — Bulguları Markdown (<c>md</c>) ya da <c>html</c> rapor olarak döndürür.</summary>
    public async Task<JsonElement> FindingsExportAsync(string format = "md", CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("findings.export",
            new Dictionary<string, object?> { ["format"] = format }, ct).ConfigureAwait(false);
    }

    /// <summary><c>findings.scan</c> — Yetenekleri veya hedef dizini güvenlik açıklarına karşı tarar.</summary>
    public async Task<JsonElement> FindingsScanAsync(string? target = null, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        var p = new Dictionary<string, object?>();
        if (!string.IsNullOrEmpty(target)) p["target"] = target;
        return await CallAsync("findings.scan", p, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>system.reset_configuration</c> — SADECE <c>config.yaml</c> ve
    /// <c>.env</c> silinir. Sohbet geçmişi, hafıza ve günlükler korunur; bir
    /// sonraki açılışta ilk kurulum sihirbazı çalışır.
    /// </summary>
    public async Task<JsonElement> SystemResetConfigurationAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("system.reset_configuration",
            new Dictionary<string, object?> { ["confirm"] = true }, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>system.wipe_all_data</c> — FETIH_HOME altındaki HER ŞEY silinir
    /// (yapılandırma, anahtarlar, sohbetler, hafıza, günlükler, çalışma
    /// alanları). Geri alınamaz.
    /// </summary>
    public async Task<JsonElement> SystemWipeAllDataAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);
        return await CallAsync("system.wipe_all_data",
            new Dictionary<string, object?> { ["confirm"] = true }, ct).ConfigureAwait(false);
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

    private static IReadOnlyList<string> StrList(JsonElement e, string name)
    {
        var list = new List<string>();
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var arr)
            && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in arr.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    var s = item.GetString();
                    if (!string.IsNullOrEmpty(s)) list.Add(s);
                }
            }
        }
        return list;
    }

    private static int? IntOrNull(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
           && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null;

    private static bool Bool(JsonElement e, string name)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
           && v.ValueKind == JsonValueKind.True;

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
