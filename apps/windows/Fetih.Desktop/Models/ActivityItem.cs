using System;
using System.ComponentModel;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Models;

/// <summary>Bir etkinlik satırının türü (sağ panel, issue #53).</summary>
public enum ActivityKind
{
    /// <summary>Ana ajanın turu.</summary>
    Agent,

    /// <summary><c>delegate_task</c> ile açılan alt-ajan.</summary>
    SubAgent,

    /// <summary><c>terminal(background=True)</c> ile başlatılan arka plan süreci.</summary>
    Process,
}

/// <summary>Bir etkinlik satırının durumu.</summary>
public enum ActivityStatus
{
    Running,
    Done,
    Error,
    Stopped,
}

/// <summary>
/// Sağ paneldeki tek bir canlı iş: alt-ajan veya arka plan süreci (issue #53).
/// Köprünün <c>session.tool_call</c>/<c>session.tool_result</c> olay akışından
/// türetilir; agent çekirdeğine dokunmadan "neler dönüyor"u gösterir.
/// </summary>
public sealed class ActivityItem : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Olay eşlemesi için anahtar: tool_call id (toplu görevlerde + index).</summary>
    public required string Key { get; init; }

    /// <summary>Hangi oturuma ait (panel yalnızca aktif oturumu gösterir).</summary>
    public required string SessionId { get; init; }

    public required ActivityKind Kind { get; init; }

    public required string Title { get; init; }

    private string _subtitle = "";
    public string Subtitle
    {
        get => _subtitle;
        set { _subtitle = value; Raise(nameof(Subtitle)); }
    }

    public DateTimeOffset StartedAt { get; } = DateTimeOffset.Now;

    private DateTimeOffset? _endedAt;
    public DateTimeOffset? EndedAt
    {
        get => _endedAt;
        set { _endedAt = value; Raise(nameof(EndedAt)); Raise(nameof(Elapsed)); }
    }

    private ActivityStatus _status = ActivityStatus.Running;
    public ActivityStatus Status
    {
        get => _status;
        set
        {
            _status = value;
            Raise(nameof(Status));
            Raise(nameof(StatusLabel));
            Raise(nameof(StatusBrushKey));
            Raise(nameof(IsRunning));
        }
    }

    private string _detail = "";
    public string Detail
    {
        get => _detail;
        set { _detail = value; Raise(nameof(Detail)); Raise(nameof(HasDetail)); }
    }

    public bool HasDetail => !string.IsNullOrWhiteSpace(_detail);

    public bool IsRunning => _status == ActivityStatus.Running;

    /// <summary>Simge: alt-ajan ⇄ süreç ⇄ ana ajan.</summary>
    public string Glyph => Kind switch
    {
        ActivityKind.Process => "",   // komut istemi
        ActivityKind.SubAgent => "",  // kişi/people
        _ => "",                        // robot benzeri
    };

    public string StatusLabel => _status switch
    {
        ActivityStatus.Running => Loc.T("activity.status.running"),
        ActivityStatus.Done => Loc.T("activity.status.done"),
        ActivityStatus.Error => Loc.T("activity.status.error"),
        ActivityStatus.Stopped => Loc.T("activity.status.stopped"),
        _ => "",
    };

    public string StatusBrushKey => _status switch
    {
        ActivityStatus.Running => "SystemFillColorAttentionBrush",
        ActivityStatus.Done => "SystemFillColorSuccessBrush",
        ActivityStatus.Error => "SystemFillColorCriticalBrush",
        _ => "SystemFillColorNeutralBrush",
    };

    /// <summary>Başlangıçtan bitişe (yoksa şimdiye) geçen süre, kısa biçim.</summary>
    public string Elapsed
    {
        get
        {
            var end = _endedAt ?? DateTimeOffset.Now;
            var span = end - StartedAt;
            if (span.TotalSeconds < 0) span = TimeSpan.Zero;
            return span.TotalMinutes >= 1
                ? $"{(int)span.TotalMinutes}d {span.Seconds}s"
                : $"{span.Seconds}s";
        }
    }

    /// <summary>Çalışan satırların süre etiketini saniyede bir tazelemek için.</summary>
    public void TouchElapsed()
    {
        if (_status == ActivityStatus.Running)
        {
            Raise(nameof(Elapsed));
        }
    }

    private void Raise(string name) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
