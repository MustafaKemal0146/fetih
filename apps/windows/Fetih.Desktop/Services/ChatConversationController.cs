using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Views;

namespace Fetih.Desktop.Services;

/// <summary>
/// Sayfa yaşam döngüsünden bağımsız, uygulama düzeyinde çalışan tekil sohbet ve tur yöneticisi.
/// Sayfalar arası geçişlerde (Chat -> Skills -> Settings -> Chat) tur durumunun, aktivite akışının
/// ve köprü olaylarının kaybolmasını engeller.
/// </summary>
public sealed class ChatConversationController
{
    private const int SessionNotFoundCode = -32001;

    private static ChatConversationController? _shared;
    public static ChatConversationController Shared => _shared ??= new ChatConversationController();

    /// <summary>
    /// Sayfa kurulumunda çağrılır. İLK çağrıda tekil controller'ı kurar;
    /// sonraki çağrılarda yalnızca UI dispatcher'ını yeniden bağlar.
    ///
    /// <para>Eskiden her çağrı yeni bir controller üretiyordu; bu, sayfalar
    /// arası her gezinmede (Sohbet → Yetenekler → Sohbet) süren turu, aktivite
    /// akışını ve köprü olay aboneliklerini sıfırlıyor, ayrıca eski örneğin
    /// abonelikleri hiç kaldırılmadığı için bellek sızdırıyordu.</para>
    /// </summary>
    public static void Initialize(IUiDispatcher dispatcher)
    {
        if (_shared is null)
        {
            _shared = new ChatConversationController(dispatcher);
        }
        else
        {
            _shared._dispatcher = dispatcher;
        }
    }

    private readonly BridgeClient _bridge;
    private IUiDispatcher _dispatcher;
    private readonly Dictionary<string, ChatMessage> _toolByCallId = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ChatMessage> _approvalByRequestId = new(StringComparer.Ordinal);
    private ChatMessage? _lastTool;

    private readonly StringBuilder _buffer = new();
    private ChatRole _bufferKind = ChatRole.Agent;

    private ActivityGroup? _activity;
    private ChatMessage? _thoughtStep;
    private ChatMessage? _streamingMessage;
    private Timer? _flushTimer;
    private Timer? _gapTimer;

    private bool _busy;
    private string? _currentSessionId;

    public ChatConversationController(IUiDispatcher? dispatcher = null, BridgeClient? bridge = null)
    {
        _bridge = bridge ?? BridgeClient.Shared;
        _dispatcher = dispatcher ?? (Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread() != null
            ? new WinUiDispatcher(Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread())
            : new NullDispatcher());

        HookBridgeEvents();
    }

    public ObservableCollection<ChatMessage> Messages { get; } = new();

    public string? CurrentSessionId
    {
        get => _currentSessionId;
        set => _currentSessionId = value;
    }

    public bool IsBusy => _busy;

    public ChatMessage? EditTarget { get; set; }

    public event Action<bool>? BusyChanged;
    public event Action? ScrollRequested;
    public event Action<string>? SystemMessageAdded;
    public event Action? MessagesChanged;

    /// <summary>Oturum boyunca kümülatif token toplamı değişince tetiklenir.</summary>
    public event Action<int /*total*/>? TokensUpdated;

    /// <summary>Son bilinen kümülatif token toplamı (oturum).</summary>
    public int LastTokenTotal { get; private set; }

    // ── Köprü Olayları (Kalıcı Abonelik) ─────────────────────────────────────

    private void HookBridgeEvents()
    {
        _bridge.SessionDelta += OnSessionDelta;
        _bridge.SessionThought += OnSessionThought;
        _bridge.SessionToolCall += OnToolCall;
        _bridge.SessionToolResult += OnToolResult;
        _bridge.SessionDone += OnSessionDone;
        _bridge.SessionError += OnSessionError;
        _bridge.ConnectionLost += OnConnectionLost;
        _bridge.ThoughtLabel += OnThoughtLabel;
        _bridge.ApprovalRequested += OnApprovalRequested;
        _bridge.ApprovalResolved += OnApprovalResolved;
    }

    private static string StripDsml(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var cleaned = Regex.Replace(
            text,
            @"<[｜|]DSML[｜|][^>]*>[\s\S]*?(?:</[｜|]DSML[｜|][^>]*>|$)|<tool_call>[\s\S]*?(?:</tool_call>|$)",
            "",
            RegexOptions.IgnoreCase);
        return cleaned;
    }

    private void OnSessionThought(string sessionId, string text)
    {
        if (!_busy || (!string.IsNullOrEmpty(_currentSessionId) && sessionId != _currentSessionId)) return;
        var clean = StripDsml(text);
        if (string.IsNullOrEmpty(clean)) return;

        CancelGapTimer();
        _dispatcher.Run(() =>
        {
            QueueText(ChatRole.Thought, clean);
        });
    }

    private void OnSessionDelta(string sessionId, string text)
    {
        if (!_busy || (!string.IsNullOrEmpty(_currentSessionId) && sessionId != _currentSessionId)) return;
        var clean = StripDsml(text);
        if (string.IsNullOrEmpty(clean)) return;

        CancelGapTimer();
        _dispatcher.Run(() =>
        {
            QueueText(ChatRole.Agent, clean);
        });
    }

    private void OnThoughtLabel(string sessionId, string label)
    {
        if (!_busy || (!string.IsNullOrEmpty(_currentSessionId) && sessionId != _currentSessionId)) return;
        if (string.IsNullOrWhiteSpace(label)) return;

        _dispatcher.Run(() =>
        {
            if (_activity != null)
            {
                _activity.SetThoughtLabel(label);
                _activity.Refresh();
            }
        });
    }

    private void OnToolCall(BridgeToolCall call)
    {
        if (!_busy || (!string.IsNullOrEmpty(_currentSessionId) && call.SessionId != _currentSessionId)) return;

        CancelGapTimer();
        _dispatcher.Run(() =>
        {
            FlushBuffer();
            CloseThoughtStep();

            var act = EnsureActivity();
            act.SetToolRunning(call.Name, call.ArgumentsJson);

            var (title, input) = ToolFormatter.FormatInput(call.Name, call.ArgumentsJson);
            var card = new ChatMessage(ChatRole.Tool)
            {
                ToolCallId = call.Id,
                ToolName = call.Name,
                ToolTitle = title,
                ToolInput = input,
                Status = ToolStatus.Running,
                ParentGroup = act,
                IsExpanded = false
            };

            act.Steps.Add(card);
            _lastTool = card;
            if (!string.IsNullOrEmpty(call.Id))
            {
                _toolByCallId[call.Id] = card;
            }

            act.Refresh();
            RequestScroll();
        });
    }

    private void OnToolResult(BridgeToolResult result)
    {
        if (!_busy || (!string.IsNullOrEmpty(_currentSessionId) && result.SessionId != _currentSessionId)) return;

        _dispatcher.Run(() =>
        {
            var card = (!string.IsNullOrEmpty(result.Id) && _toolByCallId.TryGetValue(result.Id, out var c))
                ? c
                : _lastTool;

            if (card != null)
            {
                var (status, output) = ToolFormatter.FormatResult(result.ResultText);
                card.ToolOutput = output;
                card.Status = status;
                card.Duration = ActivityGroup.FormatDuration(DateTime.Now - card.StartedAt);

                if (status is ToolStatus.Error or ToolStatus.Denied)
                {
                    card.IsExpanded = true;
                }
            }

            if (_activity != null)
            {
                _activity.EndedAt = DateTime.Now;
                _activity.Refresh();
            }
            RequestScroll();
        });
    }

    private void OnSessionDone(BridgeDone done)
    {
        if (!string.IsNullOrEmpty(_currentSessionId) && done.SessionId != _currentSessionId) return;

        _dispatcher.Run(() =>
        {
            if (done.TotalTokens is { } total)
            {
                LastTokenTotal = total;
                TokensUpdated?.Invoke(total);
            }
            EndTurn();
        });
    }

    private void OnSessionError(BridgeErrorEvent err)
    {
        if (!string.IsNullOrEmpty(_currentSessionId) && err.SessionId != _currentSessionId) return;

        _dispatcher.Run(() =>
        {
            EndTurn(error: err.Error);
        });
    }

    private void OnConnectionLost()
    {
        _dispatcher.Run(() =>
        {
            if (_busy)
            {
                EndTurn(error: Loc.T("bridge.detail.dropped") ?? "Köprü bağlantısı koptu.");
            }
        });
    }

    // ── Onay (approval) akışı ────────────────────────────────────────────────

    private void OnApprovalRequested(BridgeApprovalRequest req)
    {
        // Yalnızca aktif oturumun onayını göster; eşleşmeyen oturumlar tur
        // sonunda köprü tarafında zaten reddedilir.
        if (!string.IsNullOrEmpty(_currentSessionId) && req.SessionId != _currentSessionId) return;

        _dispatcher.Run(() =>
        {
            // Akışı toparla ki onay kartı metnin ortasına düşmesin.
            FlushBuffer();

            var card = new ChatMessage(ChatRole.Approval)
            {
                ApprovalRequestId = req.RequestId,
                ApprovalCommand = req.Command,
                ApprovalDescription = req.Description,
            };
            if (!string.IsNullOrEmpty(req.RequestId))
            {
                _approvalByRequestId[req.RequestId] = card;
            }
            Messages.Add(card);
            NotifyMessagesChanged();
            RequestScroll();
        });
    }

    private void OnApprovalResolved(string sessionId, string requestId)
    {
        if (!string.IsNullOrEmpty(_currentSessionId) && sessionId != _currentSessionId) return;

        _dispatcher.Run(() =>
        {
            if (!string.IsNullOrEmpty(requestId)
                && _approvalByRequestId.TryGetValue(requestId, out var card))
            {
                if (!card.ApprovalResolved)
                {
                    card.ApprovalResolved = true;
                }
            }
        });
    }

    /// <summary>
    /// Kullanıcının onay kartındaki seçimini köprüye iletir.
    /// <paramref name="choice"/>: once | session | always | deny.
    /// </summary>
    public async Task RespondApprovalAsync(ChatMessage card, string choice)
    {
        if (card is null || card.ApprovalResolved) return;
        var sessionId = _currentSessionId;
        if (string.IsNullOrEmpty(sessionId)) return;

        // Anında geri bildirim: düğmeleri kapat ve sonucu göster. Köprüden
        // gelecek approval_resolved olayı yalnızca yedek doğrulamadır.
        card.ApprovalOutcome = ApprovalOutcomeText(choice);
        card.ApprovalResolved = true;

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await _bridge.ApproveAsync(sessionId, choice, ct: cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatConversationController.RespondApproval", ex, ex.Message);
        }
    }

    private static string ApprovalOutcomeText(string choice) => choice switch
    {
        "once" => Loc.T("chat.approval.outcome_once"),
        "session" => Loc.T("chat.approval.outcome_session"),
        "always" => Loc.T("chat.approval.outcome_always"),
        _ => Loc.T("chat.approval.outcome_denied"),
    };

    private void ResolveOutstandingApprovals()
    {
        foreach (var card in _approvalByRequestId.Values)
        {
            if (!card.ApprovalResolved)
            {
                card.ApprovalOutcome = Loc.T("chat.approval.outcome_denied");
                card.ApprovalResolved = true;
            }
        }
        _approvalByRequestId.Clear();
    }

    // ── Tampon ve Segment Yönetimi ──────────────────────────────────────────

    private void QueueText(ChatRole kind, string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        if (kind != _bufferKind)
        {
            FlushBuffer();
        }
        _bufferKind = kind;
        _buffer.Append(text);
    }

    public void FlushBuffer()
    {
        if (_buffer.Length == 0) return;
        var text = _buffer.ToString();
        _buffer.Clear();

        if (_bufferKind == ChatRole.Thought)
        {
            CloseAgentSegment();
            var act = EnsureActivity();
            if (_thoughtStep == null)
            {
                _thoughtStep = new ChatMessage(ChatRole.Thought)
                {
                    IsStreaming = true,
                    ParentGroup = act
                };
                act.Steps.Add(_thoughtStep);
            }
            _thoughtStep.Text += text;
            act.UpdateThoughtText(_thoughtStep.Text, isClosing: false);
            act.Refresh();
        }
        else
        {
            CloseThoughtStep();
            CloseActivity();
            _streamingMessage ??= AddSegment(ChatRole.Agent);
            _streamingMessage.Text += text;
        }

        RequestScroll();
    }

    public ActivityGroup EnsureActivity()
    {
        if (_activity == null)
        {
            _activity = new ActivityGroup();
            Messages.Add(_activity);
            NotifyMessagesChanged();
            RequestScroll();
        }
        return _activity;
    }

    private void CloseActivity(bool cancelled = false)
    {
        CloseThoughtStep();
        if (_activity != null)
        {
            if (_activity.Steps.Count == 0)
            {
                Messages.Remove(_activity);
            }
            else
            {
                _activity.Complete(cancelled);
            }
            _activity = null;
        }
    }

    private void CloseThoughtStep()
    {
        if (_thoughtStep != null)
        {
            _thoughtStep.IsStreaming = false;
            if (string.IsNullOrWhiteSpace(_thoughtStep.Text))
            {
                _activity?.Steps.Remove(_thoughtStep);
            }
            else
            {
                _activity?.UpdateThoughtText(_thoughtStep.Text, isClosing: true);
            }
            _thoughtStep = null;
        }
    }

    private ChatMessage AddSegment(ChatRole role)
    {
        var m = new ChatMessage(role) { IsStreaming = true };
        Messages.Add(m);
        NotifyMessagesChanged();
        return m;
    }

    private void CloseAgentSegment()
    {
        if (_streamingMessage == null) return;
        _streamingMessage.IsStreaming = false;
        if (string.IsNullOrWhiteSpace(_streamingMessage.Text))
        {
            Messages.Remove(_streamingMessage);
        }
        _streamingMessage = null;
        NotifyMessagesChanged();
    }

    // ── Tur Yaşam Döngüsü ───────────────────────────────────────────────────

    public void BeginTurn()
    {
        _streamingMessage = null;
        _thoughtStep = null;
        _activity = null;
        _lastTool = null;
        _toolByCallId.Clear();
        _approvalByRequestId.Clear();
        _buffer.Clear();

        SetBusy(true);

        StartFlushTimer();
        StartGapTimer();
    }

    public void EndTurn(bool cancelled = false, string? error = null)
    {
        if (!_busy) return;

        StopFlushTimer();
        CancelGapTimer();

        FlushBuffer();
        CloseThoughtStep();
        CloseActivity(cancelled);
        CloseAgentSegment();
        ResolveOutstandingApprovals();

        if (cancelled)
        {
            AddSystem(Loc.T("chat.cancelled") ?? "İşlem kullanıcı tarafından durduruldu.");
        }
        else if (!string.IsNullOrEmpty(error))
        {
            // Bilinen sağlayıcı durumlarında açıklama; değilse tek satıra
            // indirilmiş ham hata (çok satırlı JSON sohbete basılmasın).
            AddSystem(ProviderErrorText.Friendly(error)
                      ?? "Hata: " + ProviderErrorText.Shorten(error, 400));
        }

        // Tur bitti — akan segment/aktivite yok; en eski öğeleri güvenle kırp.
        ChatHistoryTrimmer.Trim(Messages);

        SetBusy(false);
        NotifyMessagesChanged();
    }

    private void SetBusy(bool busy)
    {
        if (_busy == busy) return;
        _busy = busy;
        BusyChanged?.Invoke(busy);
    }

    public void AddSystem(string text)
    {
        Messages.Add(new ChatMessage(ChatRole.System, text));
        NotifyMessagesChanged();
        SystemMessageAdded?.Invoke(text);
        RequestScroll();
    }

    public void NotifyMessagesChanged()
    {
        MessagesChanged?.Invoke();
    }

    public void RequestScroll()
    {
        ScrollRequested?.Invoke();
    }

    // ── Zamanlayıcılar (Flush & 600ms Gap Timer) ─────────────────────────────

    private void StartFlushTimer()
    {
        StopFlushTimer();
        _flushTimer = new Timer(_ =>
        {
            _dispatcher.Run(() =>
            {
                FlushBuffer();
                _activity?.Tick();
            });
            // 80 ms: akışı daha büyük parçalarda uygula. Markdown görünümü her
            // Text değişiminde son bloğu yeniden kurduğu için, daha seyrek flush
            // = daha az yeniden-çizim = algılanan "titreme"nin yarıya inmesi.
            // Gecikme gözle fark edilmez.
        }, null, 80, 80);
    }

    private void StopFlushTimer()
    {
        _flushTimer?.Dispose();
        _flushTimer = null;
    }

    private void StartGapTimer()
    {
        CancelGapTimer();
        // 600ms içinde henüz bir aktivite veya mesaj gelmemişse boşluğu önlemek için placeholder aç
        _gapTimer = new Timer(_ =>
        {
            _dispatcher.Run(() =>
            {
                if (_busy && _activity == null && _streamingMessage == null)
                {
                    EnsureActivity();
                }
            });
        }, null, 600, Timeout.Infinite);
    }

    private void CancelGapTimer()
    {
        _gapTimer?.Dispose();
        _gapTimer = null;
    }

    // ── Gönder & Durdur ─────────────────────────────────────────────────────

    public async Task SendAsync(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || _busy) return;

        var editTarget = EditTarget;
        EditTarget = null;

        if (editTarget is not null && ApplyEdit(editTarget, text))
        {
            // Edit uygulandı
        }
        else
        {
            Messages.Add(new ChatMessage(ChatRole.User, text));
            NotifyMessagesChanged();
        }

        BeginTurn();

        try
        {
            await SendWithSessionRecoveryAsync(text).ConfigureAwait(false);
            _dispatcher.Run(() =>
            {
                if (_busy)
                {
                    EndTurn();
                }
            });
        }
        catch (Exception ex)
        {
            _dispatcher.Run(() => EndTurn(error: ex.Message));
        }
    }

    public async Task StopTurnAsync()
    {
        if (!_busy || string.IsNullOrEmpty(_currentSessionId)) return;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await _bridge.CancelAsync(_currentSessionId, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatConversationController.StopTurn", ex, ex.Message);
        }
        finally
        {
            _dispatcher.Run(() => EndTurn(cancelled: true));
        }
    }

    private async Task<JsonElement> SendWithSessionRecoveryAsync(string text)
    {
        await _bridge.EnsureConnectedAsync().ConfigureAwait(false);

        var sessionId = _currentSessionId;
        if (string.IsNullOrEmpty(sessionId))
        {
            sessionId = await _bridge.CreateSessionAsync().ConfigureAwait(false);
            _currentSessionId = sessionId;
            ChatSessionService.Shared.CurrentSessionId = sessionId;
        }

        try
        {
            return await _bridge.SendMessageAsync(
                text,
                sessionId: sessionId,
                stream: true).ConfigureAwait(false);
        }
        catch (BridgeRpcException rpc) when (rpc.Code == SessionNotFoundCode)
        {
            _currentSessionId = null;
            _dispatcher.Run(() => AddSystem(Loc.T("chat.session_timeout")));

            var fresh = await _bridge.CreateSessionAsync().ConfigureAwait(false);
            _currentSessionId = fresh;
            ChatSessionService.Shared.CurrentSessionId = fresh;

            return await _bridge.SendMessageAsync(
                text,
                sessionId: fresh,
                stream: true).ConfigureAwait(false);
        }
    }

    // ── Oturum Değiştirme / Yeni Sohbet ─────────────────────────────────────

    public async Task SwitchSessionAsync(string sessionId)
    {
        // Eğer zaten bu oturumdaysak ve canlı tur çalışıyorsa oturumu yeniden yükleyip canlı akışı ezme!
        if (_currentSessionId == sessionId && (_busy || Messages.Count > 0))
        {
            return;
        }

        if (_busy)
        {
            await StopTurnAsync();
        }

        _currentSessionId = sessionId;
        ChatSessionService.Shared.CurrentSessionId = sessionId;
        _toolByCallId.Clear();
        _streamingMessage = null;
        _activity = null;
        _thoughtStep = null;
        EditTarget = null;

        try
        {
            var res = await _bridge.LoadSessionAsync(sessionId).ConfigureAwait(false);
            _dispatcher.Run(() =>
            {
                Messages.Clear();
                var reconstructed = TranscriptBuilder.Build(res.Items);
                foreach (var m in reconstructed)
                {
                    Messages.Add(m);
                }
                // Çok uzun bir geçmişi yüklerken de tavanı uygula.
                ChatHistoryTrimmer.Trim(Messages);
                NotifyMessagesChanged();
                RequestScroll();
            });
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatConversationController.SwitchSession", ex, ex.Message);
        }
    }

    public void NewChat()
    {
        if (_busy)
        {
            _ = StopTurnAsync();
        }

        _currentSessionId = null;
        ChatSessionService.Shared.CurrentSessionId = null;
        Messages.Clear();
        _toolByCallId.Clear();
        _streamingMessage = null;
        _activity = null;
        _thoughtStep = null;
        EditTarget = null;
        LastTokenTotal = 0;
        TokensUpdated?.Invoke(0);
        NotifyMessagesChanged();
    }

    public bool ApplyEdit(ChatMessage target, string newText)
    {
        var index = Messages.IndexOf(target);
        if (index < 0) return false;

        while (Messages.Count > index + 1)
        {
            Messages.RemoveAt(Messages.Count - 1);
        }

        target.Text = newText;
        _toolByCallId.Clear();
        _streamingMessage = null;
        _activity = null;
        _thoughtStep = null;

        return true;
    }

    private sealed class NullDispatcher : IUiDispatcher
    {
        public void Run(Action action) => action();
        public bool HasThreadAccess => true;
    }
}
