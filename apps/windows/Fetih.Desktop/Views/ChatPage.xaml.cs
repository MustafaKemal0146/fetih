using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.ComponentModel;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.System;
using Windows.UI.Core;

namespace Fetih.Desktop.Views;

/// <summary>
/// Sohbet sayfası: mesajları GERÇEK Masaüstü Köprüsü'ne (<c>session.send</c>)
/// iletir, akış yanıtını (<c>session.delta</c>) token token gösterir ve
/// araç-kullanım olaylarını (<c>session.tool_call</c> / <c>session.tool_result</c>)
/// sohbet akışında ayrı kartlar olarak çizer.
/// </summary>
public sealed partial class ChatPage : Page
{
    private static readonly ObservableCollection<ChatMessage> SharedMessages = CreateInitialMessages();

    private readonly BridgeClient _bridge = BridgeClient.Shared;

    /// <summary>Bu sayfa açıkken kullanılan sohbet oturumu (köprü tarafı).</summary>
    private static string? _sessionId;

    /// <summary>Akış sırasında büyütülen, o anki ajan yanıtı baloncuğu.</summary>
    private ChatMessage? _streamingMessage;

    /// <summary>tool_call id → kart eşlemesi (sonuç gelince güncellenir).</summary>
    private readonly Dictionary<string, ChatMessage> _toolCards = new(StringComparer.Ordinal);

    private bool _turnInProgress;
    private bool _handlersHooked;

    public ChatPage()
    {
        InitializeComponent();
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    /// <summary>Sabit arayüz metinlerini etkin dile göre ayarlar.</summary>
    private void ApplyLanguage()
    {
        PromptBox.PlaceholderText = Loc.T("chat.placeholder");
        HintText.Text = Loc.T("chat.hint");
        UpdateSendButton();
    }

    public ObservableCollection<ChatMessage> Messages => SharedMessages;

    public BridgeStatus Status => BridgeStatus.Shared;

    private static ObservableCollection<ChatMessage> CreateInitialMessages() => new()
    {
        new ChatMessage(ChatRole.System, Loc.T("chat.welcome")),
    };

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        HookBridgeEvents();

        // Bağlantı durumu değiştikçe Gönder butonunu güncelle: köprü "Bağlı"
        // olmadan mesaj gönderip sessizce kaybetmeyi önler (Görev B).
        Status.PropertyChanged += OnStatusChanged;
        Loc.LanguageChanged += ApplyLanguage;

        UpdateSendButton();
        ScrollToEnd();

        // Köprüyü arka planda ısıt: kullanıcı ilk mesajını yazana kadar bağlanmış olsun.
        _ = WarmUpAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        // Sayfa yeniden gezinince olayları iki kez bağlamamak için çöz.
        UnhookBridgeEvents();
        Status.PropertyChanged -= OnStatusChanged;
        Loc.LanguageChanged -= ApplyLanguage;
    }

    private void OnStatusChanged(object? sender, PropertyChangedEventArgs e)
    {
        // Durum güncellemeleri UI iş parçacığında yayınlanır (BridgeStatus.Update),
        // yine de güvenli tarafta kalıp yönlendiriyoruz.
        RunOnUi(UpdateSendButton);
    }

    private async Task WarmUpAsync()
    {
        try
        {
            await _bridge.EnsureConnectedAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.WarmUp", ex, ex.Message);
            RunOnUi(() => AddSystem(
                "Masaüstü Köprüsü'ne bağlanılamadı: " + DescribeException(ex) +
                " · İlk mesajı gönderdiğinde tekrar denenecek."));
        }
    }

    private static string DescribeException(Exception ex)
    {
        var msg = ex.Message;
        if (string.IsNullOrWhiteSpace(msg))
        {
            msg = ex.GetType().Name;
        }
        if (ex.InnerException is { } inner && !string.IsNullOrWhiteSpace(inner.Message))
        {
            msg += " (" + inner.Message + ")";
        }
        return msg;
    }

    // ── Köprü olayları ───────────────────────────────────────────────────────

    private void HookBridgeEvents()
    {
        if (_handlersHooked)
        {
            return;
        }
        _bridge.SessionDelta += OnSessionDelta;
        _bridge.SessionToolCall += OnToolCall;
        _bridge.SessionToolResult += OnToolResult;
        _bridge.SessionError += OnSessionError;
        _handlersHooked = true;
    }

    private void UnhookBridgeEvents()
    {
        if (!_handlersHooked)
        {
            return;
        }
        _bridge.SessionDelta -= OnSessionDelta;
        _bridge.SessionToolCall -= OnToolCall;
        _bridge.SessionToolResult -= OnToolResult;
        _bridge.SessionError -= OnSessionError;
        _handlersHooked = false;
    }

    private void OnSessionDelta(string sessionId, string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }
        RunOnUi(() =>
        {
            if (_streamingMessage is null)
            {
                _streamingMessage = new ChatMessage(ChatRole.Agent, text);
                Messages.Add(_streamingMessage);
            }
            else
            {
                _streamingMessage.Text += text;
            }
            ScrollToEnd();
        });
    }

    private void OnToolCall(BridgeToolCall call)
    {
        RunOnUi(() =>
        {
            var card = new ChatMessage(ChatRole.Tool, "")
            {
                ToolName = call.Name,
                ToolArguments = call.ArgumentsJson,
                IsRunning = true,
            };
            _toolCards[call.Id] = card;
            Messages.Add(card);
            ScrollToEnd();
        });
    }

    private void OnToolResult(BridgeToolResult result)
    {
        RunOnUi(() =>
        {
            if (_toolCards.TryGetValue(result.Id, out var card))
            {
                card.IsRunning = false;
                card.ToolResult = Shorten(result.ResultText, 1200);
            }
            ScrollToEnd();
        });
    }

    private void OnSessionError(BridgeErrorEvent err)
    {
        RunOnUi(() =>
        {
            // session.error olayı; ayrıca RPC de hata döneceği için Send() de
            // yakalayacak. Burada yalnızca akış varsa mühürleriz.
            FinishStreaming();
        });
    }

    // ── Gönderme ─────────────────────────────────────────────────────────────

    private void SendButton_Click(object sender, RoutedEventArgs e) => _ = SendAsync();

    private void PromptBox_TextChanged(object sender, TextChangedEventArgs e) => UpdateSendButton();

    private void PromptBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        // Görev D: Enter yeni satır ekler (varsayılan davranış, AcceptsReturn=True);
        // yalnızca Ctrl+Enter gönderir.
        if (e.Key != VirtualKey.Enter)
        {
            return;
        }
        if (!IsCtrlDown())
        {
            // Ctrl basılı değil → Enter'ı TextBox'a bırak (yeni satır).
            return;
        }
        e.Handled = true;
        _ = SendAsync();
    }

    private static bool IsCtrlDown()
    {
        try
        {
            var state = InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Control);
            if (state.HasFlag(CoreVirtualKeyStates.Down))
            {
                return true;
            }
        }
        catch
        {
        }

        try
        {
            if ((GetKeyState(0x11) & 0x8000) != 0) return true;
        }
        catch
        {
        }

        try
        {
            return (GetAsyncKeyState(0x11) & 0x8000) != 0;
        }
        catch
        {
            return false;
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern short GetKeyState(int vKey);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);

    /// <summary>
    /// Gönder butonunun etkinliğini ve etiketini bağlantı durumuna göre günceller.
    /// Köprü bağlanırken buton "Bağlanıyor…" gösterip devre dışı kalır; böylece
    /// mesaj bağlantı kurulmadan gönderilip sessizce kaybolmaz (Görev B). Hata
    /// durumunda (Faulted) buton yeniden denemeye izin vermek için açık kalır.
    /// </summary>
    private void UpdateSendButton()
    {
        var hasText = !string.IsNullOrWhiteSpace(PromptBox.Text);
        var state = Status.State;
        var connecting = state is BridgeConnectionState.Idle
            or BridgeConnectionState.Connecting
            or BridgeConnectionState.Reconnecting;

        if (connecting && !_turnInProgress)
        {
            SendButton.Content = Loc.T("chat.connecting");
            SendButton.IsEnabled = false;
        }
        else
        {
            SendButton.Content = Loc.T("chat.send");
            SendButton.IsEnabled = !_turnInProgress && hasText;
        }
    }

    private async Task SendAsync()
    {
        if (_turnInProgress)
        {
            return;
        }

        var text = PromptBox.Text?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        PromptBox.Text = string.Empty;
        _turnInProgress = true;
        UpdateSendButton();

        Messages.Add(new ChatMessage(ChatRole.User, text));
        _streamingMessage = null;
        _toolCards.Clear();
        ScrollToEnd();

        try
        {
            await _bridge.EnsureConnectedAsync().ConfigureAwait(false);

            // Groq'un 8K-TPM ücretsiz katmanında FETİH'in tam AGENTS.md + hafıza
            // önsözü + tüm araç şemaları sığmaz (413 Payload Too Large). Bu yüzden
            // küçük bağlamla gönderiyoruz: bağlam dosyaları ve hafıza atlanır,
            // araç seti dosya+kabuk+web ile sınırlanır (bkz. RPC belgesi §session.new
            // "Ölçülmüş kısıt"). Böylece taban ~1.8K token'a iner ve gerçek yanıt
            // ile araç çağrıları akabilir.
            var result = await _bridge.SendMessageAsync(
                text,
                sessionId: _sessionId,
                stream: true,
                toolsets: _sessionId is null ? new[] { "file", "terminal", "web" } : null,
                skipContextFiles: true,
                skipMemory: true).ConfigureAwait(false);

            RunOnUi(() =>
            {
                // session_id'yi ilk turdan sakla ki konuşma sürsün.
                if (result.ValueKind == System.Text.Json.JsonValueKind.Object &&
                    result.TryGetProperty("session_id", out var sid) &&
                    sid.ValueKind == System.Text.Json.JsonValueKind.String)
                {
                    _sessionId = sid.GetString();
                }

                var finalText = result.ValueKind == System.Text.Json.JsonValueKind.Object &&
                                result.TryGetProperty("text", out var t)
                    ? t.GetString() ?? ""
                    : "";

                if (_streamingMessage is null)
                {
                    // Akış gelmedi (stream kapalı veya kısa yanıt): sonucu bir kez ekle.
                    if (!string.IsNullOrWhiteSpace(finalText))
                    {
                        Messages.Add(new ChatMessage(ChatRole.Agent, finalText));
                    }
                }
                else if (!string.IsNullOrWhiteSpace(finalText) &&
                         _streamingMessage.Text != finalText)
                {
                    // Nihai metin akıştan farklıysa (nadiren) düzelt.
                    _streamingMessage.Text = finalText;
                }

                FinishStreaming();
                ScrollToEnd();
            });
        }
        catch (BridgeRpcException rpc)
        {
            RunOnUi(() =>
            {
                FinishStreaming();
                AddSystem(DescribeRpcError(rpc));
            });
        }
        catch (Exception ex)
        {
            RunOnUi(() =>
            {
                FinishStreaming();
                AddSystem("Mesaj gönderilemedi: " + ex.Message);
            });
        }
        finally
        {
            RunOnUi(() =>
            {
                _turnInProgress = false;
                UpdateSendButton();
            });
        }
    }

    private static string DescribeRpcError(BridgeRpcException rpc)
    {
        var detail = rpc.Message;
        // Sağlayıcının kendi mesajı 'data' içinde olabilir (ör. Groq TPM limiti).
        if (rpc.Data2 is { } data && data.ValueKind == System.Text.Json.JsonValueKind.Object &&
            data.TryGetProperty("error", out var e) &&
            e.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            var inner = e.GetString();
            if (!string.IsNullOrWhiteSpace(inner) && inner != detail)
            {
                detail = inner!;
            }
        }
        return rpc.Code switch
        {
            -32002 => "Bu oturumda zaten bir tur çalışıyor; bitmesini bekle.",
            -32003 => "Ajan çalıştı ama başarısız oldu: " + detail,
            -32000 => "Köprü kimlik doğrulaması reddedildi.",
            _ => "Köprü hatası (" + rpc.Code + "): " + detail,
        };
    }

    private void FinishStreaming()
    {
        _streamingMessage = null;
        // Yarım kalmış araç kartları varsa "tamamlandı" olarak mühürle.
        foreach (var card in _toolCards.Values)
        {
            if (card.IsRunning)
            {
                card.IsRunning = false;
            }
        }
    }

    private void AddSystem(string text) => Messages.Add(new ChatMessage(ChatRole.System, text));

    private static string Shorten(string s, int max)
        => string.IsNullOrEmpty(s) || s.Length <= max ? s : s[..max] + $"… (+{s.Length - max})";

    private void RunOnUi(Action action)
    {
        if (DispatcherQueue.HasThreadAccess)
        {
            SafeRun(action);
        }
        else
        {
            DispatcherQueue.TryEnqueue(() => SafeRun(action));
        }
    }

    private static void SafeRun(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.RunOnUi", ex, ex.Message);
        }
    }

    private void ScrollToEnd()
    {
        if (Messages.Count == 0)
        {
            return;
        }
        DispatcherQueue.TryEnqueue(() =>
        {
            try
            {
                MessageList.ScrollIntoView(Messages[^1]);
            }
            catch (Exception ex)
            {
                App.LogCrash("ChatPage.ScrollToEnd", ex, ex.Message);
            }
        });
    }
}
