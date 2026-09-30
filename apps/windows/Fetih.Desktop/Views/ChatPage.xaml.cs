using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;
using Windows.UI.Core;
using DispatcherQueueTimer = Microsoft.UI.Dispatching.DispatcherQueueTimer;
using DispatcherQueuePriority = Microsoft.UI.Dispatching.DispatcherQueuePriority;

namespace Fetih.Desktop.Views;

/// <summary>
/// Sohbet sayfası: Segment mimarisi, Claude tarzı konsolide aktivite kartları (ActivityGroup),
/// akıcı çizim ve SQLite destekli kalıcı çoklu sohbet geçmişi sunar.
/// </summary>
public sealed partial class ChatPage : Page
{
    private const int SessionNotFoundCode = -32001;

    private readonly BridgeClient _bridge = BridgeClient.Shared;
    private readonly Dictionary<string, ChatMessage> _toolByCallId = new(StringComparer.Ordinal);
    private ChatMessage? _lastTool;

    private DispatcherQueueTimer? _flushTimer;

    private string? _sessionId;
    private ActivityGroup? _activity;
    private ChatMessage? _thoughtStep;
    private ChatMessage? _streamingMessage;
    private ChatMessage? _editTarget;

    private readonly StringBuilder _buffer = new();
    private ChatRole _bufferKind = ChatRole.Agent;

    private bool _busy;
    private bool _stickToBottom = true;
    private bool _handlersHooked;
    private UiLanguage? _lastLanguage;
    private Microsoft.UI.Xaml.Media.Animation.Storyboard? _spinnerStoryboard;
    private DispatcherQueueTimer? _spinnerHideDebounceTimer;

    public ChatPage()
    {
        InitializeComponent();
        ApplyLanguage();
        InitTimers();
        InitWorkingSpinner();

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    public ObservableCollection<ChatMessage> Messages { get; } = new();
    public BridgeStatus Status => BridgeStatus.Shared;

    private void InitTimers()
    {
        _flushTimer = this.DispatcherQueue.CreateTimer();
        _flushTimer.Interval = TimeSpan.FromMilliseconds(40);
        _flushTimer.IsRepeating = true;
        _flushTimer.Tick += (_, _) =>
        {
            FlushBuffer();
            _activity?.Tick();
        };

        Scroller.ViewChanged += (_, _) =>
        {
            _stickToBottom = Scroller.VerticalOffset >= Scroller.ScrollableHeight - 40;
        };
    }

    private void InitWorkingSpinner()
    {
        var anim = new Microsoft.UI.Xaml.Media.Animation.DoubleAnimation
        {
            From = 0,
            To = 360,
            Duration = new Duration(TimeSpan.FromMilliseconds(1200)),
            RepeatBehavior = Microsoft.UI.Xaml.Media.Animation.RepeatBehavior.Forever
        };
        Microsoft.UI.Xaml.Media.Animation.Storyboard.SetTarget(anim, WorkingSpinnerRotation);
        Microsoft.UI.Xaml.Media.Animation.Storyboard.SetTargetProperty(anim, "Angle");

        _spinnerStoryboard = new Microsoft.UI.Xaml.Media.Animation.Storyboard();
        _spinnerStoryboard.Children.Add(anim);

        _spinnerHideDebounceTimer = this.DispatcherQueue.CreateTimer();
        _spinnerHideDebounceTimer.Interval = TimeSpan.FromMilliseconds(150);
        _spinnerHideDebounceTimer.IsRepeating = false;
        _spinnerHideDebounceTimer.Tick += (_, _) =>
        {
            if (!_busy)
            {
                _spinnerStoryboard?.Stop();
                BottomWorkingIndicator.Visibility = Visibility.Collapsed;
            }
        };
    }

    private void SetWorkingIndicator(bool busy)
    {
        if (busy)
        {
            if (BottomWorkingIndicator.Visibility != Visibility.Visible)
            {
                BottomWorkingIndicator.Visibility = Visibility.Visible;
                _spinnerStoryboard?.Begin();
                ScrollToEndIfSticky();
            }
        }
        else
        {
            _spinnerStoryboard?.Stop();
            BottomWorkingIndicator.Visibility = Visibility.Collapsed;
        }
    }

    private void ActivityScrollViewer_PointerWheelChanged(object sender, PointerRoutedEventArgs e)
    {
        if (sender is ScrollViewer sv)
        {
            var delta = e.GetCurrentPoint(sv).Properties.MouseWheelDelta;
            if ((delta < 0 && sv.VerticalOffset >= sv.ScrollableHeight - 0.5) ||
                (delta > 0 && sv.VerticalOffset <= 0.5))
            {
                Scroller.ChangeView(null, Scroller.VerticalOffset - delta, null, disableAnimation: true);
                e.Handled = true;
            }
        }
    }

    // ── Yaşam döngüsü ────────────────────────────────────────────────────────

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        HookBridgeEvents();
        Status.PropertyChanged += OnStatusChanged;
        ChatSessionService.Shared.NewChatRequested += OnServiceNewChatRequested;
        ChatSessionService.Shared.SessionOpenRequested += OnServiceSessionOpenRequested;

        _ = ChatSessionService.Shared.RefreshAsync();

        if (ChatSessionService.Shared.PendingSessionToOpen is not null)
        {
            var target = ChatSessionService.Shared.PendingSessionToOpen;
            ChatSessionService.Shared.PendingSessionToOpen = null;
            _ = SwitchSessionAsync(target.Id);
        }
        else if (string.IsNullOrEmpty(_sessionId) && ChatSessionService.Shared.Sessions.Count > 0)
        {
            _ = SwitchSessionAsync(ChatSessionService.Shared.Sessions[0].Id);
        }
        else if (string.IsNullOrEmpty(_sessionId))
        {
            _ = NewChatAsync();
        }

        _ = WarmUpAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        UnhookBridgeEvents();
        Status.PropertyChanged -= OnStatusChanged;
        ChatSessionService.Shared.NewChatRequested -= OnServiceNewChatRequested;
        ChatSessionService.Shared.SessionOpenRequested -= OnServiceSessionOpenRequested;
    }

    private void ApplyLanguage()
    {
        var lang = Loc.Current;
        if (_lastLanguage == lang) return;
        _lastLanguage = lang;

        PromptBox.PlaceholderText = Loc.T("chat.prompt_placeholder");
        EmptyStateTitle.Text = Loc.T("chat.empty_state_title");
        EmptyStateDesc.Text = Loc.T("chat.empty_state_desc");
        ToolTipService.SetToolTip(StopButton, Loc.T("chat.stop"));
        AutomationProperties.SetName(BottomWorkingIndicator, Loc.T("Chat_Working") ?? "Çalışıyor");
        RefreshHint();
        UpdateSendButton();
    }

    private void OnStatusChanged(object? sender, PropertyChangedEventArgs e)
    {
        RunOnUi(() =>
        {
            if (!_bridge.IsConnected && _busy)
            {
                EndTurn(error: Loc.T("bridge.detail.dropped") ?? "Köprü bağlantısı koptu.");
            }
            UpdateSendButton();
        });
    }

    private void OnConnectionLost()
    {
        RunOnUi(() =>
        {
            if (_busy)
            {
                EndTurn(error: Loc.T("bridge.detail.dropped") ?? "Köprü bağlantısı koptu.");
            }
            UpdateSendButton();
        });
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
        }
    }

    // ── Köprü olayları ───────────────────────────────────────────────────────

    private void HookBridgeEvents()
    {
        if (_handlersHooked) return;
        _bridge.SessionDelta += OnSessionDelta;
        _bridge.SessionThought += OnSessionThought;
        _bridge.SessionToolCall += OnToolCall;
        _bridge.SessionToolResult += OnToolResult;
        _bridge.SessionDone += OnSessionDone;
        _bridge.SessionError += OnSessionError;
        _bridge.ConnectionLost += OnConnectionLost;
        _handlersHooked = true;
    }

    private void UnhookBridgeEvents()
    {
        if (!_handlersHooked) return;
        _bridge.SessionDelta -= OnSessionDelta;
        _bridge.SessionThought -= OnSessionThought;
        _bridge.SessionToolCall -= OnToolCall;
        _bridge.SessionToolResult -= OnToolResult;
        _bridge.SessionDone -= OnSessionDone;
        _bridge.SessionError -= OnSessionError;
        _bridge.ConnectionLost -= OnConnectionLost;
        _handlersHooked = false;
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
        if (!_busy || (!string.IsNullOrEmpty(_sessionId) && sessionId != _sessionId)) return;
        var clean = StripDsml(text);
        if (string.IsNullOrEmpty(clean)) return;

        RunOnUi(() =>
        {
            QueueText(ChatRole.Thought, clean);
        });
    }

    private void OnSessionDelta(string sessionId, string text)
    {
        if (!_busy || (!string.IsNullOrEmpty(_sessionId) && sessionId != _sessionId)) return;
        var clean = StripDsml(text);
        if (string.IsNullOrEmpty(clean)) return;

        RunOnUi(() =>
        {
            QueueText(ChatRole.Agent, clean);
        });
    }

    private void OnToolCall(BridgeToolCall call)
    {
        if (!_busy || (!string.IsNullOrEmpty(_sessionId) && call.SessionId != _sessionId)) return;

        RunOnUi(() =>
        {
            FlushBuffer();
            CloseThoughtStep();

            var act = EnsureActivity();
            act.SetToolRunning(call.Name);

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
            ScrollToEndIfSticky();
        });
    }

    private void OnToolResult(BridgeToolResult result)
    {
        if (!_busy || (!string.IsNullOrEmpty(_sessionId) && result.SessionId != _sessionId)) return;

        RunOnUi(() =>
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
            ScrollToEndIfSticky();
        });
    }

    private void OnSessionDone(BridgeDone done)
    {
        if (!string.IsNullOrEmpty(_sessionId) && done.SessionId != _sessionId) return;

        RunOnUi(() =>
        {
            EndTurn();
        });
    }

    private void OnSessionError(BridgeErrorEvent err)
    {
        if (!string.IsNullOrEmpty(_sessionId) && err.SessionId != _sessionId) return;

        RunOnUi(() =>
        {
            EndTurn(error: err.Error);
        });
    }

    // ── Segment ve Tampon Yönetimi ──────────────────────────────────────────

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

    private void FlushBuffer()
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

        ScrollToEndIfSticky();
    }

    private ActivityGroup EnsureActivity()
    {
        if (_activity == null)
        {
            _activity = new ActivityGroup();
            Messages.Add(_activity);
            UpdateEmptyState();
            ScrollToEndIfSticky();
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
        UpdateEmptyState();
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
        UpdateEmptyState();
    }

    // ── Tur Yaşam Döngüsü (BeginTurn / EndTurn) ──────────────────────────────

    private void BeginTurn()
    {
        _streamingMessage = null;
        _thoughtStep = null;
        _activity = null;
        _lastTool = null;
        _toolByCallId.Clear();
        _buffer.Clear();

        SetBusy(true);
        _flushTimer?.Start();
    }

    private void EndTurn(bool cancelled = false, string? error = null)
    {
        if (!_busy) return;

        FlushBuffer();
        CloseThoughtStep();
        CloseActivity(cancelled);
        CloseAgentSegment();

        if (cancelled)
        {
            AddSystem(Loc.T("chat.cancelled") ?? "İşlem kullanıcı tarafından durduruldu.");
        }
        else if (!string.IsNullOrEmpty(error))
        {
            AddSystem("Hata: " + error);
        }

        _flushTimer?.Stop();
        SetBusy(false);
        UpdateEmptyState();
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        UpdateSendButton();
        PromptBox.IsEnabled = !busy;
        SetWorkingIndicator(busy);
    }

    private void UpdateSendButton()
    {
        if (_busy)
        {
            SendButton.Visibility = Visibility.Collapsed;
            StopButton.Visibility = Visibility.Visible;
            StopButton.IsEnabled = true;
            return;
        }

        StopButton.Visibility = Visibility.Collapsed;
        SendButton.Visibility = Visibility.Visible;
        SendButton.IsEnabled = _bridge.IsConnected && !string.IsNullOrWhiteSpace(PromptBox.Text);
    }

    private void UpdateEmptyState()
    {
        EmptyStatePanel.Visibility = Messages.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    // ── Gönder / Durdur Eylemleri ───────────────────────────────────────────

    private async void SendButton_Click(object sender, RoutedEventArgs e) => await SendAsync();

    private async Task SendAsync()
    {
        var text = PromptBox.Text?.Trim();
        if (string.IsNullOrEmpty(text) || _busy) return;

        var editTarget = _editTarget;
        _editTarget = null;

        PromptBox.Text = string.Empty;
        RefreshHint();
        UpdateSendButton();

        if (editTarget is not null && ApplyEdit(editTarget, text))
        {
            // Edit applied
        }
        else
        {
            Messages.Add(new ChatMessage(ChatRole.User, text));
            UpdateEmptyState();
        }

        _stickToBottom = true;
        BeginTurn();

        try
        {
            await SendWithSessionRecoveryAsync(text).ConfigureAwait(false);
            RunOnUi(() =>
            {
                if (_busy)
                {
                    EndTurn();
                }
            });
        }
        catch (Exception ex)
        {
            RunOnUi(() => EndTurn(error: ex.Message));
        }
    }

    private async Task StopTurnAsync()
    {
        if (!_busy || string.IsNullOrEmpty(_sessionId)) return;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await _bridge.CancelAsync(_sessionId, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.StopTurn", ex, ex.Message);
        }
        finally
        {
            RunOnUi(() => EndTurn(cancelled: true));
        }
    }

    private async void StopButton_Click(object sender, RoutedEventArgs e)
    {
        StopButton.IsEnabled = false;
        await StopTurnAsync();
    }

    private async Task<JsonElement> SendWithSessionRecoveryAsync(string text)
    {
        await _bridge.EnsureConnectedAsync().ConfigureAwait(false);

        var sessionId = _sessionId;
        if (string.IsNullOrEmpty(sessionId))
        {
            sessionId = await _bridge.CreateSessionAsync().ConfigureAwait(false);
            _sessionId = sessionId;
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
            _sessionId = null;
            RunOnUi(() => AddSystem(Loc.T("chat.session_timeout")));

            var fresh = await _bridge.CreateSessionAsync().ConfigureAwait(false);
            _sessionId = fresh;
            ChatSessionService.Shared.CurrentSessionId = fresh;

            return await _bridge.SendMessageAsync(
                text,
                sessionId: fresh,
                stream: true).ConfigureAwait(false);
        }
    }

    // ── Oturum Değişimi & Yönetimi ──────────────────────────────────────────

    private async Task<bool> CheckAndConfirmStopIfBusyAsync()
    {
        if (!_busy) return true;

        var dialog = new ContentDialog
        {
            Title = Loc.T("chat.cancel_busy_confirm_title"),
            Content = Loc.T("chat.cancel_busy_confirm_body"),
            PrimaryButtonText = Loc.T("dialog.stop"),
            CloseButtonText = Loc.T("dialog.cancel"),
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = this.XamlRoot
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            await StopTurnAsync();
            return true;
        }

        return false;
    }

    private void OnServiceNewChatRequested()
    {
        RunOnUi(async () => await NewChatAsync());
    }

    private void OnServiceSessionOpenRequested(ChatSessionInfo session)
    {
        RunOnUi(async () => await SwitchSessionAsync(session.Id));
    }

    private async Task SwitchSessionAsync(string sessionId)
    {
        if (_sessionId == sessionId && Messages.Count > 0) return;
        if (!await CheckAndConfirmStopIfBusyAsync()) return;

        _sessionId = sessionId;
        ChatSessionService.Shared.CurrentSessionId = sessionId;
        _toolByCallId.Clear();
        _streamingMessage = null;
        _activity = null;
        _thoughtStep = null;
        _editTarget = null;

        try
        {
            var (title, items) = await _bridge.LoadSessionAsync(sessionId);
            Messages.Clear();
            var reconstructed = TranscriptBuilder.Build(items);
            foreach (var m in reconstructed)
            {
                Messages.Add(m);
            }
            UpdateEmptyState();
            ScrollToEndIfSticky();
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.SwitchSession", ex, ex.Message);
        }
    }

    private async Task NewChatAsync()
    {
        if (!await CheckAndConfirmStopIfBusyAsync()) return;

        _sessionId = null;
        ChatSessionService.Shared.CurrentSessionId = null;
        Messages.Clear();
        _toolByCallId.Clear();
        _streamingMessage = null;
        _activity = null;
        _thoughtStep = null;
        _editTarget = null;
        UpdateEmptyState();
        PromptBox.Focus(FocusState.Programmatic);
    }

    private void ToggleGroup_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is ActivityGroup group)
        {
            group.Toggle();
        }
    }

    // ── Mesaj Eylemleri (Kopyala / Düzenle / Yeniden Dene) ────────────────────

    private void CopyMessage_Click(object sender, RoutedEventArgs e)
    {
        if (MessageOf(sender) is not { } message) return;
        var text = CopyTextFor(message);
        if (string.IsNullOrEmpty(text)) return;

        var dp = new DataPackage();
        dp.SetText(text);
        Clipboard.SetContent(dp);
    }

    private void EditMessage_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (MessageOf(sender) is not { } message || !message.IsUser) return;

        _editTarget = message;
        PromptBox.Text = message.Text;
        PromptBox.Focus(FocusState.Programmatic);
        PromptBox.Select(PromptBox.Text.Length, 0);
        RefreshHint();
        UpdateSendButton();
    }

    private async void RetryMessage_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        if (MessageOf(sender) is not { } message) return;

        var userText = message.IsUser ? message.Text : PrecedingUserText(message);
        if (string.IsNullOrEmpty(userText)) return;

        PromptBox.Text = userText;
        await SendAsync();
    }

    private static ChatMessage? MessageOf(object sender)
        => (sender as FrameworkElement)?.DataContext as ChatMessage;

    private static string CopyTextFor(ChatMessage message)
    {
        if (!message.IsTool)
        {
            return message.Text ?? string.Empty;
        }

        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(message.ToolTitle)) parts.Add(message.ToolTitle);
        if (!string.IsNullOrWhiteSpace(message.ToolInput)) parts.Add(message.ToolInput);
        if (!string.IsNullOrWhiteSpace(message.ToolOutput)) parts.Add(message.ToolOutput);
        return string.Join("\n\n", parts);
    }

    private string? PrecedingUserText(ChatMessage target)
    {
        var index = Messages.IndexOf(target);
        if (index <= 0) return null;
        for (var i = index - 1; i >= 0; i--)
        {
            if (Messages[i].IsUser && !string.IsNullOrWhiteSpace(Messages[i].Text))
            {
                return Messages[i].Text;
            }
        }
        return null;
    }

    private bool ApplyEdit(ChatMessage target, string newText)
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

    private void AddSystem(string text)
    {
        Messages.Add(new ChatMessage(ChatRole.System, text));
        UpdateEmptyState();
        ScrollToEndIfSticky();
    }

    // ── Giriş Kutusu Olayları ────────────────────────────────────────────────

    private void PromptBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        UpdateSendButton();
    }

    private async void PromptBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        var shift = InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Shift)
            .HasFlag(CoreVirtualKeyStates.Down);
        var ctrl = InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Control)
            .HasFlag(CoreVirtualKeyStates.Down);

        if (ctrl && e.Key == VirtualKey.N)
        {
            e.Handled = true;
            await NewChatAsync();
            return;
        }

        if (e.Key == VirtualKey.Enter && (ctrl || !shift))
        {
            e.Handled = true;
            await SendAsync();
        }
    }

    private void RefreshHint()
    {
        if (_editTarget is not null)
        {
            HintText.Text = Loc.T("chat.hint_editing");
            return;
        }

        HintText.Text = Loc.T("chat.hint_default");
    }

    // ── Kaydırma ve UI Yardımcıları ──────────────────────────────────────────

    private void RunOnUi(Action action)
    {
        if (DispatcherQueue.HasThreadAccess) action();
        else DispatcherQueue.TryEnqueue(() => action());
    }

    private void ScrollToEndIfSticky()
    {
        if (!_stickToBottom) return;
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            try
            {
                Scroller.UpdateLayout();
                Scroller.ChangeView(null, Scroller.ScrollableHeight, null, true);
            }
            catch { }
        });
    }
}
