using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;
using Windows.UI.Core;

namespace Fetih.Desktop.Views;

/// <summary>
/// Sohbet sayfası: ChatConversationController ile tam entegre, gezinmeye dirençli,
/// Claude tarzı konsolide aktivite kartları (ActivityGroup) sunan hafif görünüm katmanı.
/// </summary>
public sealed partial class ChatPage : Page
{
    private readonly BridgeClient _bridge = BridgeClient.Shared;
    private bool _stickToBottom = true;
    private UiLanguage? _lastLanguage;

    public ChatPage()
    {
        ChatConversationController.Initialize(new WinUiDispatcher(this.DispatcherQueue));
        InitializeComponent();
        ApplyLanguage();

        Scroller.ViewChanged += (_, _) =>
        {
            _stickToBottom = Scroller.VerticalOffset >= Scroller.ScrollableHeight - 40;
        };

        Controller.BusyChanged += OnControllerBusyChanged;
        Controller.ScrollRequested += OnControllerScrollRequested;
        Controller.MessagesChanged += OnControllerMessagesChanged;

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    public ChatConversationController Controller => ChatConversationController.Shared;
    public ObservableCollection<ChatMessage> Messages => Controller.Messages;
    public BridgeStatus Status => BridgeStatus.Shared;

    // ── Yaşam döngüsü ────────────────────────────────────────────────────────

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        Status.PropertyChanged += OnStatusChanged;
        ChatSessionService.Shared.NewChatRequested += OnServiceNewChatRequested;
        ChatSessionService.Shared.SessionOpenRequested += OnServiceSessionOpenRequested;

        _ = ChatSessionService.Shared.RefreshAsync();

        if (ChatSessionService.Shared.PendingSessionToOpen is not null)
        {
            var target = ChatSessionService.Shared.PendingSessionToOpen;
            ChatSessionService.Shared.PendingSessionToOpen = null;
            _ = Controller.SwitchSessionAsync(target.Id);
        }
        else if (string.IsNullOrEmpty(Controller.CurrentSessionId) && ChatSessionService.Shared.Sessions.Count > 0)
        {
            _ = Controller.SwitchSessionAsync(ChatSessionService.Shared.Sessions[0].Id);
        }
        else if (string.IsNullOrEmpty(Controller.CurrentSessionId))
        {
            Controller.NewChat();
        }

        UpdateSendButton();
        UpdateEmptyState();
        ScrollToEndIfSticky();

        _ = WarmUpAsync();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Status.PropertyChanged -= OnStatusChanged;
        ChatSessionService.Shared.NewChatRequested -= OnServiceNewChatRequested;
        ChatSessionService.Shared.SessionOpenRequested -= OnServiceSessionOpenRequested;
        Controller.BusyChanged -= OnControllerBusyChanged;
        Controller.ScrollRequested -= OnControllerScrollRequested;
        Controller.MessagesChanged -= OnControllerMessagesChanged;
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
        RefreshHint();
        UpdateSendButton();
    }

    private void OnStatusChanged(object? sender, PropertyChangedEventArgs e)
    {
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
        }
    }

    private void OnControllerBusyChanged(bool busy)
    {
        RunOnUi(UpdateSendButton);
    }

    private void OnControllerScrollRequested()
    {
        ScrollToEndIfSticky();
    }

    private void OnControllerMessagesChanged()
    {
        RunOnUi(UpdateEmptyState);
    }

    private void UpdateSendButton()
    {
        if (Controller.IsBusy)
        {
            SendButton.Visibility = Visibility.Collapsed;
            StopButton.Visibility = Visibility.Visible;
            StopButton.IsEnabled = true;
            PromptBox.IsEnabled = false;
            return;
        }

        StopButton.Visibility = Visibility.Collapsed;
        SendButton.Visibility = Visibility.Visible;
        SendButton.IsEnabled = _bridge.IsConnected && !string.IsNullOrWhiteSpace(PromptBox.Text);
        PromptBox.IsEnabled = true;
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
        if (string.IsNullOrEmpty(text) || Controller.IsBusy) return;

        PromptBox.Text = string.Empty;
        RefreshHint();
        UpdateSendButton();

        _stickToBottom = true;
        await Controller.SendAsync(text);
    }

    private async void StopButton_Click(object sender, RoutedEventArgs e)
    {
        StopButton.IsEnabled = false;
        await Controller.StopTurnAsync();
    }

    // ── Oturum Değişimi & Yönetimi ──────────────────────────────────────────

    private async Task<bool> CheckAndConfirmStopIfBusyAsync()
    {
        if (!Controller.IsBusy) return true;

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
            await Controller.StopTurnAsync();
            return true;
        }

        return false;
    }

    private void OnServiceNewChatRequested()
    {
        RunOnUi(async () =>
        {
            if (await CheckAndConfirmStopIfBusyAsync())
            {
                Controller.NewChat();
                PromptBox.Focus(FocusState.Programmatic);
            }
        });
    }

    private void OnServiceSessionOpenRequested(ChatSessionInfo session)
    {
        RunOnUi(async () =>
        {
            if (await CheckAndConfirmStopIfBusyAsync())
            {
                await Controller.SwitchSessionAsync(session.Id);
            }
        });
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
        if (Controller.IsBusy) return;
        if (MessageOf(sender) is not { } message || !message.IsUser) return;

        Controller.EditTarget = message;
        PromptBox.Text = message.Text;
        PromptBox.Focus(FocusState.Programmatic);
        PromptBox.Select(PromptBox.Text.Length, 0);
        RefreshHint();
        UpdateSendButton();
    }

    private async void RetryMessage_Click(object sender, RoutedEventArgs e)
    {
        if (Controller.IsBusy) return;
        if (MessageOf(sender) is not { } message) return;

        var userText = message.IsUser ? message.Text : PrecedingUserText(message);
        if (string.IsNullOrEmpty(userText)) return;

        PromptBox.Text = userText;
        await SendAsync();
    }

    // ── Onay Kartı Eylemleri ─────────────────────────────────────────────────

    private async void ApprovalAllowOnce_Click(object sender, RoutedEventArgs e)
        => await RespondApprovalAsync(sender, "once");

    private async void ApprovalAllowSession_Click(object sender, RoutedEventArgs e)
        => await RespondApprovalAsync(sender, "session");

    private async void ApprovalAllowAlways_Click(object sender, RoutedEventArgs e)
        => await RespondApprovalAsync(sender, "always");

    private async void ApprovalDeny_Click(object sender, RoutedEventArgs e)
        => await RespondApprovalAsync(sender, "deny");

    private async Task RespondApprovalAsync(object sender, string choice)
    {
        if (MessageOf(sender) is not { } message || !message.IsApproval) return;
        try
        {
            await Controller.RespondApprovalAsync(message, choice);
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatPage.RespondApproval", ex, ex.Message);
        }
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
            if (await CheckAndConfirmStopIfBusyAsync())
            {
                Controller.NewChat();
                PromptBox.Focus(FocusState.Programmatic);
            }
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
        if (Controller.EditTarget is not null)
        {
            HintText.Text = Loc.T("chat.hint_editing");
            return;
        }

        HintText.Text = Loc.T("chat.hint_default");
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

    // ── Kaydırma ve UI Yardımcıları ──────────────────────────────────────────

    private void RunOnUi(Action action)
    {
        if (DispatcherQueue.HasThreadAccess) action();
        else DispatcherQueue.TryEnqueue(() => action());
    }

    private void ScrollToEndIfSticky()
    {
        if (!_stickToBottom) return;
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
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
