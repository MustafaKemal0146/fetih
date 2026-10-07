using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Microsoft.UI.Dispatching;

namespace Fetih.Desktop.Services;

/// <summary>
/// Paylaşılan sohbet oturumu servisi (Singleton).
/// Hem sol gezinti menüsündeki sohbet listesini hem de ChatPage'deki
/// oturum durumunu tek merkezden yönetir.
/// </summary>
public sealed class ChatSessionService
{
    private static readonly Lazy<ChatSessionService> _lazy = new(() => new ChatSessionService());
    public static ChatSessionService Shared => _lazy.Value;

    private readonly BridgeClient _bridge = BridgeClient.Shared;
    private DispatcherQueue? _dispatcher;
    private string? _currentSessionId;
    private bool _isRefreshing;

    private ChatSessionService()
    {
        _bridge.SessionUpdated += OnBridgeSessionUpdated;
    }

    public DispatcherQueue? Dispatcher
    {
        get => _dispatcher;
        set => _dispatcher = value;
    }

    public ObservableCollection<ChatSessionInfo> Sessions { get; } = new();

    public string? CurrentSessionId
    {
        get => _currentSessionId;
        set
        {
            if (_currentSessionId != value)
            {
                _currentSessionId = value;
                RunOnUi(() => CurrentChanged?.Invoke(_currentSessionId));
            }
        }
    }

    /// <summary>
    /// Başka sayfadayken (örn. Skills) menüden bir sohbete tıklandığında,
    /// ChatPage henüz yüklenmediyse bekletilen oturum.
    /// </summary>
    public ChatSessionInfo? PendingSessionToOpen { get; set; }

    public event Action<string?>? CurrentChanged;
    public event Action? NewChatRequested;
    public event Action<ChatSessionInfo>? SessionOpenRequested;
    public event Action? SessionsUpdated;

    public void RequestNewChat()
    {
        PendingSessionToOpen = null;
        CurrentSessionId = null;
        RunOnUi(() => NewChatRequested?.Invoke());
    }

    public void RequestOpen(ChatSessionInfo session)
    {
        PendingSessionToOpen = session;
        CurrentSessionId = session.Id;
        RunOnUi(() => SessionOpenRequested?.Invoke(session));
    }

    public async Task RefreshAsync()
    {
        if (_isRefreshing) return;
        _isRefreshing = true;
        try
        {
            var list = await _bridge.ListSessionsAsync().ConfigureAwait(false);
            RunOnUi(() =>
            {
                var existingMap = Sessions.ToDictionary(s => s.Id, StringComparer.Ordinal);
                var newIds = new HashSet<string>(list.Select(s => s.SessionId), StringComparer.Ordinal);

                // Silinenleri listeden çıkar
                for (var i = Sessions.Count - 1; i >= 0; i--)
                {
                    if (!newIds.Contains(Sessions[i].Id))
                    {
                        Sessions.RemoveAt(i);
                    }
                }

                // Mevcutları güncelle veya yenileri ekle
                foreach (var item in list)
                {
                    if (existingMap.TryGetValue(item.SessionId, out var existing))
                    {
                        if (existing.Title != item.Title) existing.Title = item.Title;
                        if (Math.Abs(existing.UpdatedAt - item.UpdatedAt) > 0.001) existing.UpdatedAt = item.UpdatedAt;
                    }
                    else
                    {
                        Sessions.Add(new ChatSessionInfo
                        {
                            Id = item.SessionId,
                            Title = item.Title,
                            UpdatedAt = item.UpdatedAt
                        });
                    }
                }

                SortSessions();
                SessionsUpdated?.Invoke();
            });
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatSessionService.Refresh", ex, ex.Message);
        }
        finally
        {
            _isRefreshing = false;
        }
    }

    public async Task RenameAsync(string sessionId, string newTitle)
    {
        try
        {
            await _bridge.RenameSessionAsync(sessionId, newTitle).ConfigureAwait(false);
            RunOnUi(() =>
            {
                var target = Sessions.FirstOrDefault(s => s.Id == sessionId);
                if (target is not null)
                {
                    target.Title = newTitle;
                    SessionsUpdated?.Invoke();
                }
            });
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatSessionService.Rename", ex, ex.Message);
            throw;
        }
    }

    public async Task DeleteAsync(string sessionId)
    {
        try
        {
            await _bridge.DeleteSessionAsync(sessionId).ConfigureAwait(false);
            RunOnUi(() =>
            {
                var target = Sessions.FirstOrDefault(s => s.Id == sessionId);
                if (target is not null)
                {
                    Sessions.Remove(target);
                    SessionsUpdated?.Invoke();
                }

                if (_currentSessionId == sessionId)
                {
                    if (Sessions.Count > 0)
                    {
                        RequestOpen(Sessions[0]);
                    }
                    else
                    {
                        RequestNewChat();
                    }
                }
            });
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatSessionService.Delete", ex, ex.Message);
            throw;
        }
    }

    public async Task DeleteAllAsync()
    {
        try
        {
            await _bridge.DeleteAllSessionsAsync().ConfigureAwait(false);
            RunOnUi(() =>
            {
                Sessions.Clear();
                SessionsUpdated?.Invoke();
                RequestNewChat();
            });
        }
        catch (Exception ex)
        {
            App.LogCrash("ChatSessionService.DeleteAll", ex, ex.Message);
            throw;
        }
    }

    private void OnBridgeSessionUpdated(string sessionId, string title, double updatedAt)
    {
        RunOnUi(() =>
        {
            var target = Sessions.FirstOrDefault(s => s.Id == sessionId);
            if (target is not null)
            {
                if (!string.IsNullOrEmpty(title)) target.Title = title;
                if (updatedAt > 0) target.UpdatedAt = updatedAt;
            }
            else if (!string.IsNullOrEmpty(sessionId))
            {
                Sessions.Insert(0, new ChatSessionInfo
                {
                    Id = sessionId,
                    Title = string.IsNullOrEmpty(title) ? Loc.T("chat.default_title") : title,
                    UpdatedAt = updatedAt > 0 ? updatedAt : DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                });
            }
            SortSessions();
            SessionsUpdated?.Invoke();
        });
    }

    private void SortSessions()
    {
        var sorted = Sessions.OrderByDescending(s => s.UpdatedAt).ToList();
        for (var i = 0; i < sorted.Count; i++)
        {
            var oldIndex = Sessions.IndexOf(sorted[i]);
            if (oldIndex != i)
            {
                Sessions.Move(oldIndex, i);
            }
        }
    }

    private void RunOnUi(Action action)
    {
        if (_dispatcher is not null && !_dispatcher.HasThreadAccess)
        {
            _dispatcher.TryEnqueue(() =>
            {
                try { action(); }
                catch (Exception ex) { App.LogCrash("ChatSessionService.RunOnUi", ex, ex.Message); }
            });
        }
        else
        {
            try { action(); }
            catch (Exception ex) { App.LogCrash("ChatSessionService.RunOnUi.Direct", ex, ex.Message); }
        }
    }
}
