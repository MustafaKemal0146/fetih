using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;
using Windows.UI.Core;

// Windows.System de bir DispatcherQueueTimer taşır; sohbet sayfası UI
// iş parçacığınınkini kullanır.
using DispatcherQueueTimer = Microsoft.UI.Dispatching.DispatcherQueueTimer;

namespace Fetih.Desktop.Views;

/// <summary>
/// Sohbet sayfası: mesajları GERÇEK Masaüstü Köprüsü'ne (<c>session.send</c>)
/// iletir, akış yanıtını (<c>session.delta</c>) token token gösterir ve
/// araç-kullanım olaylarını (<c>session.tool_call</c> / <c>session.tool_result</c>)
/// sohbet akışında ayrı kartlar olarak çizer.
///
/// <para>Sohbet geçmişi bu SAYFA ÖRNEĞİNE aittir (paylaşılan <c>static</c> liste
/// yoktur) ve <c>%LOCALAPPDATA%\Fetih\Desktop\sohbet-gecmisi.json</c> içine
/// yazılıp uygulama açılışında geri yüklenir.</para>
/// </summary>
public sealed partial class ChatPage : Page
{
    /// <summary>Kalıcı sohbet geçmişinin yolu (yoksa null — geçmiş tutulmaz).</summary>
    private static readonly string? HistoryPath = ResolveHistoryPath();

    /// <summary>Dosyada tutulan en fazla mesaj sayısı (eskiler düşer).</summary>
    private const int MaxStoredMessages = 400;

    /// <summary>Tek bir alan için saklanan en fazla karakter (dev dosyaları önler).</summary>
    private const int MaxStoredChars = 20000;

    /// <summary>RPC: oturum kimliği bilinmiyor (köprü yeniden başladı).</summary>
    private const int SessionNotFoundCode = -32001;

    private readonly BridgeClient _bridge = BridgeClient.Shared;

    /// <summary>tool_call id → kart eşlemesi (sonuç gelince güncellenir).</summary>
    private readonly Dictionary<string, ChatMessage> _toolCards = new(StringComparer.Ordinal);

    /// <summary>Geçmişi geciktirerek yazan zamanlayıcı (her tuş vuruşunda disk yazmamak için).</summary>
    private DispatcherQueueTimer? _flushTimer;

    /// <summary>Bu sayfaya ait sohbet oturumu (köprü tarafı).</summary>
    private string? _sessionId;

    /// <summary>Akış sırasında büyütülen, o anki ajan yanıtı baloncuğu.</summary>
    private ChatMessage? _streamingMessage;

    /// <summary>"Düzenle" ile giriş kutusuna alınan kullanıcı mesajı.</summary>
    private ChatMessage? _editTarget;

    private bool _turnInProgress;
    private bool _cancelRequested;
    private bool _handlersHooked;
    private bool _historyRestored;
    private bool _historyDirty;
    private int _hintToken;
    private UiLanguage? _lastLanguage;

    public ChatPage()
    {
        InitializeComponent();
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    /// <summary>
    /// Bu sayfa örneğinin mesaj listesi. Bilinçli olarak <c>static</c> DEĞİLDİR:
    /// paylaşılan liste yüzünden oturumlar birbirine karışıyordu.
    /// </summary>
    public ObservableCollection<ChatMessage> Messages { get; } = new();

    public BridgeStatus Status => BridgeStatus.Shared;

    // ── Yaşam döngüsü ────────────────────────────────────────────────────────

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        HookBridgeEvents();

        // Bağlantı durumu değiştikçe Gönder butonunu güncelle: köprü "Bağlı"
        // olmadan mesaj gönderip sessizce kaybetmeyi önler (Görev B).
        Status.PropertyChanged += OnStatusChanged;
        Loc.LanguageChanged += ApplyLanguage;

        // Geçmiş, ısınma ve ilk sistem mesajından ÖNCE yüklenir; böylece
        // "köprüye bağlanılamadı" satırı listenin başında kalmaz.
        RestoreHistory();
        StartFlushTimer();

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

        _flushTimer?.Stop();
        FlushHistoryNow();
    }

    /// <summary>Sabit arayüz metinlerini etkin dile göre ayarlar.</summary>
    private void ApplyLanguage()
    {
        PromptBox.PlaceholderText = Loc.T("chat.placeholder");

        // Ekran okuyucu için adlar: düğmelerin içeriği kod ile yazıldığından
        // Name açıkça kurulmazsa denetimler adsız kalıyordu.
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            PromptBox, Loc.T("chat.placeholder"));
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            SendButton, Loc.T("chat.send"));
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            StopButton, ChatActionText.Stop);

        var language = Loc.Current;
        var changed = _lastLanguage is { } previous && previous != language;
        _lastLanguage = language;

        RefreshHint();
        UpdateSendButton();

        if (changed)
        {
            // Eylem düğmelerinin etiketleri dönüştürücüyle, kap oluşturulurken
            // çözülür; dili değiştirmek için kapların yeniden kurulması gerekir.
            RefreshMessageLabels();
        }
    }

    private void RefreshMessageLabels()
    {
        try
        {
            MessageList.ItemsSource = null;
            MessageList.ItemsSource = Messages;
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.RefreshMessageLabels", ex, ex.Message);
        }
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
                Loc.T("chat.warmup_failed") + DescribeException(ex) + Loc.T("chat.warmup_retry")));
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
        _bridge.SessionThought += OnSessionThought;
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
        _bridge.SessionThought -= OnSessionThought;
        _bridge.SessionToolCall -= OnToolCall;
        _bridge.SessionToolResult -= OnToolResult;
        _bridge.SessionError -= OnSessionError;
        _handlersHooked = false;
    }

    private void OnSessionThought(string sessionId, string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }
        RunOnUi(() =>
        {
            if (_streamingMessage is null)
            {
                _streamingMessage = new ChatMessage(ChatRole.Agent, "")
                {
                    IsThinking = true,
                    IsThoughtExpanded = true,
                };
                Messages.Add(_streamingMessage);
            }
            else
            {
                _streamingMessage.IsThinking = true;
            }
            _streamingMessage.AppendThought(text);
            RequestScrollToEnd();
        });
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
                if (_streamingMessage.IsThinking)
                {
                    _streamingMessage.IsThinking = false;
                }
                _streamingMessage.Text += text;
            }
            RequestScrollToEnd();
        });
    }

    private void OnToolCall(BridgeToolCall call)
    {
        RunOnUi(() =>
        {
            if (_streamingMessage is not null && _streamingMessage.IsThinking)
            {
                _streamingMessage.IsThinking = false;
            }
            var card = new ChatMessage(ChatRole.Tool, "")
            {
                ToolName = call.Name,
                ToolArguments = call.ArgumentsJson,
                IsRunning = true,
            };
            _toolCards[call.Id] = card;
            Messages.Add(card);
            MarkHistoryDirty();
            RequestScrollToEnd();
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
                MarkHistoryDirty();
            }
            RequestScrollToEnd();
        });
    }

    private void OnSessionError(BridgeErrorEvent err)
    {
        RunOnUi(() =>
        {
            // session.error olayı; ayrıca RPC de hata döneceği için Send() de
            // yakalayacak. Burada yalnızca akış varsa mühürleriz.
            FinishStreaming();
            MarkHistoryDirty();
        });
    }

    // ── Mesaj eylemleri (kopyala / düzenle / yeniden dene) ───────────────────

    private static ChatMessage? MessageOf(object sender)
        => (sender as FrameworkElement)?.DataContext as ChatMessage;

    /// <summary>Bir mesajın panoya kopyalanacak metni (araç kartında sonuç gövdesi).</summary>
    private static string CopyTextFor(ChatMessage message)
    {
        if (!message.IsTool)
        {
            return message.Text ?? string.Empty;
        }

        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(message.ToolName))
        {
            parts.Add(message.ToolName);
        }
        if (!string.IsNullOrWhiteSpace(message.ToolArguments))
        {
            parts.Add(message.ToolArguments);
        }
        if (!string.IsNullOrWhiteSpace(message.ToolResult))
        {
            parts.Add(message.ToolResult);
        }
        return string.Join(Environment.NewLine, parts);
    }

    private void CopyMessage_Click(object sender, RoutedEventArgs e)
    {
        if (MessageOf(sender) is not { } message)
        {
            return;
        }

        var text = CopyTextFor(message);
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        try
        {
            var package = new DataPackage { RequestedOperation = DataPackageOperation.Copy };
            package.SetText(text);
            Clipboard.SetContent(package);
            ShowTransientHint(ChatActionText.Copied);
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.CopyMessage", ex, ex.Message);
            ShowTransientHint(ChatActionText.CopyFailed);
        }
    }

    private void EditMessage_Click(object sender, RoutedEventArgs e)
    {
        if (MessageOf(sender) is not { } message || message.Role != ChatRole.User)
        {
            return;
        }
        if (_turnInProgress)
        {
            ShowTransientHint(ChatActionText.Busy);
            return;
        }

        _editTarget = message;
        PromptBox.Text = message.Text;
        PromptBox.SelectionStart = PromptBox.Text.Length;
        PromptBox.Focus(FocusState.Programmatic);
        RefreshHint();
        UpdateSendButton();
    }

    private void RetryMessage_Click(object sender, RoutedEventArgs e)
    {
        if (MessageOf(sender) is not { } message)
        {
            return;
        }
        if (_turnInProgress)
        {
            ShowTransientHint(ChatActionText.Busy);
            return;
        }

        // Bekleyen bir "düzenle" hedefi varsa düşer: bu tur onu kullanmaz.
        if (_editTarget is not null)
        {
            _editTarget = null;
            RefreshHint();
        }

        var text = message.Role switch
        {
            ChatRole.User => message.Text,
            ChatRole.Agent => PrecedingUserText(message),
            _ => null,
        };

        if (string.IsNullOrWhiteSpace(text))
        {
            ShowTransientHint(ChatActionText.NoTurnToRepeat);
            return;
        }

        _ = RunTurnAsync(text);
    }

    /// <summary>Bir ajan yanıtından önceki son kullanıcı mesajının metni.</summary>
    private string? PrecedingUserText(ChatMessage agentMessage)
    {
        var index = Messages.IndexOf(agentMessage);
        if (index < 0)
        {
            index = Messages.Count;
        }
        for (var i = index - 1; i >= 0; i--)
        {
            if (Messages[i].Role == ChatRole.User && !string.IsNullOrWhiteSpace(Messages[i].Text))
            {
                return Messages[i].Text;
            }
        }
        return null;
    }

    // ── Gönderme ─────────────────────────────────────────────────────────────

    private void SendButton_Click(object sender, RoutedEventArgs e) => _ = SendFromComposerAsync();

    private void StopButton_Click(object sender, RoutedEventArgs e)
    {
        if (!_turnInProgress || _cancelRequested)
        {
            return;
        }

        _cancelRequested = true;
        ShowTransientHint(ChatActionText.Cancelling);
        UpdateSendButton();
        _ = CancelTurnAsync();
    }

    /// <summary>
    /// Sürerken turu köprüde iptal eder (<c>session.cancel</c>). Tur henüz yeni
    /// başlamışsa oturum kimliği birkaç yüz milisaniye sonra oluşur; bu yüzden
    /// kısa süre beklenir. İptal edilecek bir şey yoksa sessizce dönülür.
    /// </summary>
    private async Task CancelTurnAsync()
    {
        for (var i = 0; i < 40 && _turnInProgress && string.IsNullOrEmpty(_sessionId); i++)
        {
            await Task.Delay(100).ConfigureAwait(false);
        }

        var sessionId = _sessionId;
        if (string.IsNullOrEmpty(sessionId))
        {
            return;
        }

        try
        {
            await _bridge.CancelAsync(sessionId).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.CancelTurn", ex, ex.Message);
        }
    }

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
        _ = SendFromComposerAsync();
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
    /// Gönder/Durdur düğmelerinin görünürlüğünü ve etkinliğini bağlantı ve tur
    /// durumuna göre günceller. Köprü bağlanırken Gönder "Bağlanıyor…" gösterip
    /// devre dışı kalır; böylece mesaj bağlantı kurulmadan gönderilip sessizce
    /// kaybolmaz (Görev B). Tur sürerken Gönder'in yerini Durdur alır.
    /// </summary>
    private void UpdateSendButton()
    {
        var hasText = !string.IsNullOrWhiteSpace(PromptBox.Text);
        var state = Status.State;
        var connecting = state is BridgeConnectionState.Idle
            or BridgeConnectionState.Connecting
            or BridgeConnectionState.Reconnecting;

        if (_turnInProgress)
        {
            SendButton.Visibility = Visibility.Collapsed;
            SendButton.IsEnabled = false;
            StopButton.Content = ChatActionText.Stop;
            StopButton.Visibility = Visibility.Visible;
            StopButton.IsEnabled = !_cancelRequested;
            return;
        }

        StopButton.Visibility = Visibility.Collapsed;
        StopButton.IsEnabled = false;
        SendButton.Visibility = Visibility.Visible;

        if (connecting)
        {
            SendButton.Content = Loc.T("chat.connecting");
            SendButton.IsEnabled = false;
        }
        else
        {
            SendButton.Content = Loc.T("chat.send");
            SendButton.IsEnabled = hasText;
        }
    }

    private async Task SendFromComposerAsync()
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

        // Düzenleme hedefi gönderimden ÖNCE alınır: hemen aşağıda sıfırlanıyor.
        var editTarget = _editTarget;
        _editTarget = null;

        PromptBox.Text = string.Empty;
        RefreshHint();
        UpdateSendButton();

        await RunTurnAsync(text, editTarget);
    }

    /// <summary>Bir turu gönderir ve akışı tüketir.</summary>
    private async Task RunTurnAsync(string text, ChatMessage? editTarget = null)
    {
        if (_turnInProgress)
        {
            return;
        }

        _turnInProgress = true;
        _cancelRequested = false;
        UpdateSendButton();

        // Düzenleme yolunda kullanıcı baloncuğu YENİDEN EKLENMEZ: düzenlenen
        // mesaj zaten metni taşıyor ve listenin sonunda duruyor.
        var edited = editTarget is not null && ApplyEdit(editTarget, text);
        if (!edited)
        {
            Messages.Add(new ChatMessage(ChatRole.User, text));
        }

        _streamingMessage = new ChatMessage(ChatRole.Agent, "")
        {
            IsThinking = true,
            IsThoughtExpanded = true,
        };
        Messages.Add(_streamingMessage);
        _toolCards.Clear();
        MarkHistoryDirty();
        RequestScrollToEnd(force: true);

        try
        {
            var result = await SendWithSessionRecoveryAsync(text).ConfigureAwait(false);
            RunOnUi(() => ApplyTurnResult(result));
        }
        catch (BridgeRpcException rpc)
        {
            // Durdurma bayrağı RunOnUi kuyruğa girmeden okunmalı: finally onu sıfırlar.
            var cancelled = _cancelRequested;
            RunOnUi(() =>
            {
                FinishStreaming();
                AddSystem(cancelled ? ChatActionText.Cancelled : DescribeRpcError(rpc));
            });
        }
        catch (Exception ex)
        {
            var cancelled = _cancelRequested;
            RunOnUi(() =>
            {
                FinishStreaming();
                AddSystem(cancelled
                    ? ChatActionText.Cancelled
                    : ChatActionText.SendFailed + ex.Message);
            });
        }
        finally
        {
            RunOnUi(() =>
            {
                _turnInProgress = false;
                _cancelRequested = false;
                UpdateSendButton();
                MarkHistoryDirty();
            });
        }
    }

    /// <summary>
    /// Düzenlenen mesajı yerine koyar: ONDAN SONRAKİ her şey listeden çıkarılır,
    /// çünkü artık geçerli değildir. Köprü oturumu geri sarılamadığı için
    /// düzenlemeden sonra yeni bir oturum açılır — aksi hâlde ajanın bağlamı
    /// ekranda görünen konuşmayla çelişirdi.
    /// </summary>
    /// <returns>Düzenleme uygulandıysa <c>true</c> (mesaj artık listenin sonunda).</returns>
    private bool ApplyEdit(ChatMessage target, string newText)
    {
        var index = Messages.IndexOf(target);
        if (index < 0)
        {
            return false;
        }

        while (Messages.Count > index + 1)
        {
            Messages.RemoveAt(Messages.Count - 1);
        }

        target.Text = newText;
        _toolCards.Clear();
        _streamingMessage = null;

        if (!string.IsNullOrEmpty(_sessionId))
        {
            _sessionId = null;
            AddSystem(ChatActionText.EditRestartedSession);
        }

        return true;
    }

    /// <summary>
    /// Oturumu hazırlar ve mesajı gönderir. Geri yüklenen bir oturum kimliği
    /// köprü yeniden başladığında geçersiz olur (<c>-32001</c>); bu durumda bir
    /// kez yeni oturumla yeniden denenir.
    /// </summary>
    private async Task<JsonElement> SendWithSessionRecoveryAsync(string text)
    {
        await _bridge.EnsureConnectedAsync().ConfigureAwait(false);

        // Oturum ÖNCEDEN açılır: kimlik elimizde olmadan "Durdur" sunucu
        // tarafında iptal edecek bir tur bulamaz.
        var sessionId = _sessionId;
        if (string.IsNullOrEmpty(sessionId))
        {
            sessionId = await _bridge.NewSessionAsync(
                toolsets: DefaultToolsets,
                skipContextFiles: true,
                skipMemory: true).ConfigureAwait(false);
            _sessionId = sessionId;
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
            _sessionId = null;
            RunOnUi(() => AddSystem(ChatActionText.SessionGone));

            var fresh = await _bridge.NewSessionAsync(
                toolsets: DefaultToolsets,
                skipContextFiles: true,
                skipMemory: true).ConfigureAwait(false);
            _sessionId = fresh;

            return await _bridge.SendMessageAsync(
                text,
                sessionId: fresh,
                stream: true).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Groq'un 8K-TPM ücretsiz katmanında FETİH'in tam AGENTS.md + hafıza
    /// önsözü + tüm araç şemaları sığmaz (413 Payload Too Large). Bu yüzden
    /// küçük bağlamla gönderiyoruz: bağlam dosyaları ve hafıza atlanır,
    /// araç seti dosya+kabuk+web ile sınırlanır (bkz. RPC belgesi §session.new
    /// "Ölçülmüş kısıt"). Böylece taban ~1.8K token'a iner.
    /// </summary>
    private static readonly string[] DefaultToolsets = { "file", "terminal", "web" };

    private void ApplyTurnResult(JsonElement result)
    {
        // session_id'yi ilk turdan sakla ki konuşma sürsün.
        if (result.ValueKind == JsonValueKind.Object &&
            result.TryGetProperty("session_id", out var sid) &&
            sid.ValueKind == JsonValueKind.String)
        {
            _sessionId = sid.GetString();
        }

        var finalText = result.ValueKind == JsonValueKind.Object &&
                        result.TryGetProperty("text", out var t)
            ? t.GetString() ?? ""
            : "";
        var thoughtText = result.ValueKind == JsonValueKind.Object &&
                         result.TryGetProperty("thought", out var th)
            ? th.GetString() ?? ""
            : "";

        if (_streamingMessage is null)
        {
            // Akış gelmedi (stream kapalı veya kısa yanıt): sonucu bir kez ekle.
            if (!string.IsNullOrWhiteSpace(finalText) || !string.IsNullOrWhiteSpace(thoughtText))
            {
                var msg = new ChatMessage(ChatRole.Agent, finalText);
                if (!string.IsNullOrWhiteSpace(thoughtText))
                {
                    msg.Thought = thoughtText;
                    msg.IsThoughtExpanded = false;
                }
                Messages.Add(msg);
            }
        }
        else
        {
            _streamingMessage.IsThinking = false;
            if (!string.IsNullOrWhiteSpace(thoughtText) && string.IsNullOrEmpty(_streamingMessage.Thought))
            {
                _streamingMessage.Thought = thoughtText;
            }
            if (!string.IsNullOrWhiteSpace(finalText))
            {
                _streamingMessage.Text = finalText;
            }
        }

        FinishStreaming();
        MarkHistoryDirty();
        RequestScrollToEnd(force: true);
    }

    private static string DescribeRpcError(BridgeRpcException rpc)
    {
        var detail = rpc.Message;
        // Sağlayıcının kendi mesajı 'data' içinde olabilir (ör. Groq TPM limiti).
        if (rpc.Data2 is { } data && data.ValueKind == JsonValueKind.Object &&
            data.TryGetProperty("error", out var e) &&
            e.ValueKind == JsonValueKind.String)
        {
            var inner = e.GetString();
            if (!string.IsNullOrWhiteSpace(inner) && inner != detail)
            {
                detail = inner!;
            }
        }
        return rpc.Code switch
        {
            -32001 => Loc.T("chat.error.session_unknown"),
            -32002 => Loc.T("chat.error.busy"),
            -32003 => Loc.T("chat.error.agent_failed") + detail,
            -32000 => Loc.T("chat.error.auth"),
            -32005 => Loc.T("chat.error.cancel_failed") + detail,
            _ => Loc.T("chat.error.bridge") + rpc.Code + "): " + detail,
        };
    }

    private void FinishStreaming()
    {
        if (_streamingMessage is not null)
        {
            _streamingMessage.IsThinking = false;
            // Eğer hiçbir metin ve düşünce gelmemişse boş kartı listeden kaldır
            if (string.IsNullOrWhiteSpace(_streamingMessage.Text) && !_streamingMessage.HasThought)
            {
                Messages.Remove(_streamingMessage);
            }
            _streamingMessage = null;
        }

        // Yarım kalmış araç kartları varsa "tamamlandı" olarak mühürle.
        foreach (var card in _toolCards.Values)
        {
            if (card.IsRunning)
            {
                card.IsRunning = false;
            }
        }
    }

    private void AddSystem(string text)
    {
        Messages.Add(new ChatMessage(ChatRole.System, text));
        MarkHistoryDirty();
    }

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

    private void RefreshHint()
    {
        _hintToken++;
        HintText.Text = _editTarget is null ? Loc.T("chat.hint") : ChatActionText.EditHint;
    }

    /// <summary>Kısa süreliğine ipucu satırına bilgi yazar, sonra normale döner.</summary>
    private void ShowTransientHint(string text)
    {
        var token = ++_hintToken;
        HintText.Text = text;
        _ = Task.Delay(1800).ContinueWith(
            _ => RunOnUi(() =>
            {
                if (_hintToken == token)
                {
                    RefreshHint();
                }
            }),
            TaskScheduler.Default);
    }

    // ── Kalıcılık ────────────────────────────────────────────────────────────

    private static string? ResolveHistoryPath()
    {
        try
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Fetih", "Desktop", "sohbet-gecmisi.json");
        }
        catch
        {
            return null;
        }
    }

    private void StartFlushTimer()
    {
        if (_flushTimer is not null)
        {
            return;
        }

        try
        {
            _flushTimer = DispatcherQueue.CreateTimer();
            _flushTimer.Interval = TimeSpan.FromMilliseconds(700);
            _flushTimer.Tick += OnFlushTick;
            _flushTimer.Start();
        }
        catch (Exception ex)
        {
            _flushTimer = null;
            App.LogCrash("ChatPage.StartFlushTimer", ex, ex.Message);
        }
    }

    private void OnFlushTick(DispatcherQueueTimer sender, object args) => FlushHistoryNow();

    /// <summary>Değişiklik varsa geçmişi diske yazar (UI iş parçacığından çağrılır).</summary>
    private void FlushHistoryNow()
    {
        if (!_historyDirty || !_historyRestored)
        {
            return;
        }
        _historyDirty = false;
        WriteHistorySnapshot();
    }

    /// <summary>
    /// Geçmişin değiştiğini bildirir. Akış sırasındaki HER token'da çağrılmaz:
    /// tur bitince, araç sonuçlarında ve iptalde işaretlenir — aksi hâlde büyük
    /// bir geçmiş her 700 ms'de baştan yazılırdı.
    /// </summary>
    private void MarkHistoryDirty()
    {
        if (_historyRestored)
        {
            _historyDirty = true;
        }
    }

    private void WriteHistorySnapshot()
    {
        var path = HistoryPath;
        if (path is null)
        {
            return;
        }

        StoredChatHistory snapshot;
        try
        {
            snapshot = BuildSnapshot();
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.BuildSnapshot", ex, ex.Message);
            return;
        }

        // G/Ç arka planda; anlık görüntü UI iş parçacığında alındı.
        _ = Task.Run(() =>
        {
            try
            {
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var json = JsonSerializer.Serialize(snapshot, SnapshotOptions);
                var temp = path + ".tmp";
                File.WriteAllText(temp, json);
                File.Move(temp, path, overwrite: true);
            }
            catch (Exception ex)
            {
                App.LogCrash("ChatPage.SaveHistory", ex, ex.Message);
            }
        });
    }

    private static readonly JsonSerializerOptions SnapshotOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private StoredChatHistory BuildSnapshot()
    {
        var start = Math.Max(0, Messages.Count - MaxStoredMessages);
        var list = new List<StoredChatMessage>(Messages.Count - start);
        for (var i = start; i < Messages.Count; i++)
        {
            var m = Messages[i];
            list.Add(new StoredChatMessage
            {
                Role = m.Role.ToString(),
                Text = ClampText(m.Text),
                Thought = ClampText(m.Thought),
                ToolName = ClampText(m.ToolName),
                ToolArguments = ClampText(m.ToolArguments),
                ToolResult = ClampText(m.ToolResult),
            });
        }

        return new StoredChatHistory
        {
            SessionId = _sessionId ?? string.Empty,
            Messages = list,
        };
    }

    private static string ClampText(string? value)
        => string.IsNullOrEmpty(value) || value.Length <= MaxStoredChars
            ? value ?? string.Empty
            : value[..MaxStoredChars];

    /// <summary>
    /// Diskteki geçmişi okur. Bozuk/okunamayan dosya sessizce yok sayılır —
    /// sohbet ekranı her hâlükârda açılmalıdır.
    /// </summary>
    private void RestoreHistory()
    {
        if (_historyRestored)
        {
            return;
        }
        _historyRestored = true;

        StoredChatHistory? data = null;
        var path = HistoryPath;
        try
        {
            if (path is not null && File.Exists(path))
            {
                var json = File.ReadAllText(path);
                if (!string.IsNullOrWhiteSpace(json))
                {
                    data = JsonSerializer.Deserialize<StoredChatHistory>(json, SnapshotOptions);
                }
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.RestoreHistory", ex, ex.Message);
        }

        var restored = 0;
        if (data?.Messages is { Count: > 0 })
        {
            foreach (var stored in data.Messages)
            {
                if (ToChatMessage(stored) is not { } message)
                {
                    continue;
                }
                Messages.Add(message);
                restored++;
            }
        }

        if (restored == 0)
        {
            Messages.Add(new ChatMessage(ChatRole.System, Loc.T("chat.welcome")));
            return;
        }

        if (!string.IsNullOrWhiteSpace(data!.SessionId))
        {
            // Köprü hâlâ ayaktaysa (sayfa yalnızca yeniden açıldı) konuşma
            // kaldığı yerden sürer; köprü yeniden başladıysa kimlik geçersizdir
            // ve gönderim sırasında yeni oturum açılır.
            _sessionId = data.SessionId;
        }
    }

    private static ChatMessage? ToChatMessage(StoredChatMessage stored)
    {
        if (!Enum.TryParse<ChatRole>(stored.Role, ignoreCase: true, out var role))
        {
            role = ChatRole.System;
        }

        if (role == ChatRole.Tool)
        {
            if (string.IsNullOrWhiteSpace(stored.ToolName))
            {
                return null;
            }
            return new ChatMessage(ChatRole.Tool, string.Empty)
            {
                ToolName = stored.ToolName,
                ToolArguments = stored.ToolArguments,
                ToolResult = stored.ToolResult,
                IsRunning = false,
            };
        }

        if (string.IsNullOrWhiteSpace(stored.Text) && string.IsNullOrWhiteSpace(stored.Thought))
        {
            return null;
        }

        var message = new ChatMessage(role, stored.Text);
        if (!string.IsNullOrWhiteSpace(stored.Thought))
        {
            message.Thought = stored.Thought;
            message.IsThoughtExpanded = false;
        }
        return message;
    }

    // ── Kaydırma ─────────────────────────────────────────────────────────────

    private long _lastScrollTicks;
    private bool _scrollPending;

    private void ScrollToEnd(bool force = false) => RequestScrollToEnd(force);

    private void RequestScrollToEnd(bool force = false)
    {
        if (Messages.Count == 0)
        {
            return;
        }
        var now = Environment.TickCount64;
        if (force || now - _lastScrollTicks > 80)
        {
            _lastScrollTicks = now;
            _scrollPending = false;
            DispatcherQueue.TryEnqueue(() =>
            {
                try
                {
                    if (Messages.Count > 0)
                    {
                        MessageList.ScrollIntoView(Messages[^1]);
                    }
                }
                catch (Exception ex)
                {
                    App.LogCrash("ChatPage.ScrollToEnd", ex, ex.Message);
                }
            });
        }
        else if (!_scrollPending)
        {
            _scrollPending = true;
            DispatcherQueue.TryEnqueue(async () =>
            {
                await Task.Delay(80);
                if (_scrollPending)
                {
                    _scrollPending = false;
                    _lastScrollTicks = Environment.TickCount64;
                    try
                    {
                        if (Messages.Count > 0)
                        {
                            MessageList.ScrollIntoView(Messages[^1]);
                        }
                    }
                    catch (Exception ex)
                    {
                        App.LogCrash("ChatPage.ScrollToEnd", ex, ex.Message);
                    }
                }
            });
        }
    }
}

/// <summary>
/// Diske yazılan tek bir sohbet öğesi. <see cref="ChatMessage"/> XAML'e bağlı bir
/// model olduğu için (salt-okunur zaman damgası, hesaplanan görünüm üyeleri)
/// doğrudan serileştirilmez; kalıcı biçim bu taşıyıcıyla ayrılır.
/// </summary>
internal sealed class StoredChatMessage
{
    public string Role { get; set; } = nameof(ChatRole.System);

    public string Text { get; set; } = string.Empty;

    public string Thought { get; set; } = string.Empty;

    public string ToolName { get; set; } = string.Empty;

    public string ToolArguments { get; set; } = string.Empty;

    public string ToolResult { get; set; } = string.Empty;
}

/// <summary>Sohbet geçmişi dosyasının gövdesi.</summary>
internal sealed class StoredChatHistory
{
    /// <summary>Kalıcı biçim sürümü; ileride biçim değişirse okuma buna bakar.</summary>
    public int Version { get; set; } = 1;

    /// <summary>Konuşmanın sürdüğü köprü oturumu (yoksa boş).</summary>
    public string SessionId { get; set; } = string.Empty;

    public List<StoredChatMessage> Messages { get; set; } = new();
}

/// <summary>
/// Sohbet eylemi düğmelerinin etiket ve ipuçları. Bütün metinler
/// <see cref="Loc"/> tablosundadır; bu sınıf yalnızca çağrı yerlerinin
/// okunabilir kalması için anahtar adlarını sarmalar.
/// </summary>
internal static class ChatActionText
{
    public static string Copy => Loc.T("chat.action.copy");

    public static string CopyHint => Loc.T("chat.action.copy.hint");

    public static string Edit => Loc.T("chat.action.edit");

    public static string EditHint => Loc.T("chat.action.edit.hint");

    public static string Retry => Loc.T("chat.action.retry");

    public static string RetryHint => Loc.T("chat.action.retry.hint");

    public static string Stop => Loc.T("chat.action.stop");

    public static string Copied => Loc.T("chat.action.copied");

    public static string CopyFailed => Loc.T("chat.action.copy_failed");

    public static string Busy => Loc.T("chat.action.busy");

    public static string NoTurnToRepeat => Loc.T("chat.action.no_turn");

    public static string Cancelling => Loc.T("chat.action.cancelling");

    public static string Cancelled => Loc.T("chat.action.cancelled");

    public static string SendFailed => Loc.T("chat.action.send_failed");

    public static string EditRestartedSession => Loc.T("chat.action.edit_restarted");

    public static string SessionGone => Loc.T("chat.action.session_gone");
}

/// <summary>
/// Mesaj eylemi düğmesinin etiketini/ipucunu çözer. <c>ConverterParameter</c>
/// eylemin adıdır: <c>copy</c>, <c>copy.hint</c>, <c>edit</c>, <c>retry</c>…
/// </summary>
public sealed partial class ChatActionLabelConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
        => (parameter as string) switch
        {
            "copy" => ChatActionText.Copy,
            "copy.hint" => ChatActionText.CopyHint,
            "edit" => ChatActionText.Edit,
            "edit.hint" => ChatActionText.EditHint,
            "retry" => ChatActionText.Retry,
            "retry.hint" => ChatActionText.RetryHint,
            _ => string.Empty,
        };

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotSupportedException();
}

/// <summary>
/// Eylem düğmesini yalnızca mesajın rolü izin verilenler arasındaysa gösterir.
/// <c>ConverterParameter</c> rolleri "|" ile ayırır (ör. <c>User|Agent</c>).
/// </summary>
public sealed partial class ChatActionVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is not ChatRole role || parameter is not string allowed || allowed.Length == 0)
        {
            return Visibility.Collapsed;
        }

        foreach (var name in allowed.Split(
                     '|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (Enum.TryParse<ChatRole>(name, ignoreCase: true, out var parsed) && parsed == role)
            {
                return Visibility.Visible;
            }
        }

        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotSupportedException();
}
