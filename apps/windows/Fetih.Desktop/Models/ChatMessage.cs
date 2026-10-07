using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Models;

/// <summary>Bir sohbet mesajının veya kartının rolü.</summary>
public enum ChatRole
{
    User,
    Agent,
    Tool,
    System,
    Thought,
    Activity,
    Approval
}

/// <summary>Bir araç yürütme kartının durumu.</summary>
public enum ToolStatus
{
    Running,
    Success,
    Error,
    Denied,
    Cancelled
}

/// <summary>
/// Sohbet akışındaki tek bir öğe. Segment mimarisiyle bağımsız Thought, Agent, Tool, Activity veya System öğeleridir.
/// </summary>
public class ChatMessage : INotifyPropertyChanged
{
    public ChatMessage(ChatRole role, string text = "")
    {
        Role = role;
        _text = text;
        Timestamp = DateTimeOffset.Now;
        StartedAt = DateTime.Now;
    }

    public ChatRole Role { get; }
    public DateTimeOffset Timestamp { get; }
    public DateTime StartedAt { get; }

    /// <summary>Bu adım bir Aktivite Grubu içindeyse ebeveyn grubu.</summary>
    public ActivityGroup? ParentGroup { get; set; }

    public string ThoughtHeaderText => Loc.T("chat.activity.thought_process");

    private string _text = "";
    public string Text
    {
        get => _text;
        set
        {
            if (Set(ref _text, value))
            {
                OnChanged(nameof(HasText));
            }
        }
    }
    public bool HasText => !string.IsNullOrEmpty(_text);

    private bool _isStreaming;
    public bool IsStreaming
    {
        get => _isStreaming;
        set => Set(ref _isStreaming, value);
    }

    private bool _isExpanded;
    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (Set(ref _isExpanded, value))
            {
                OnChanged(nameof(ChevronAngle));
            }
        }
    }

    public double ChevronAngle => IsExpanded ? 90 : 0;
    public void Toggle() => IsExpanded = !IsExpanded;

    // ── Tool kartı alanları ──────────────────────────────────────────────────
    public string? ToolCallId { get; set; }
    public string ToolName { get; set; } = "";

    private string _toolTitle = "";
    public string ToolTitle
    {
        get => _toolTitle;
        set => Set(ref _toolTitle, value);
    }

    private string _toolInput = "";
    public string ToolInput
    {
        get => _toolInput;
        set
        {
            if (Set(ref _toolInput, value))
            {
                OnChanged(nameof(HasInput));
                OnChanged(nameof(ToolArguments));
            }
        }
    }

    private string _toolOutput = "";
    public string ToolOutput
    {
        get => _toolOutput;
        set
        {
            if (Set(ref _toolOutput, value))
            {
                OnChanged(nameof(HasOutput));
                OnChanged(nameof(ToolResult));
                OnChanged(nameof(HasToolResult));
            }
        }
    }

    private string _duration = "";
    public string Duration
    {
        get => _duration;
        set => Set(ref _duration, value);
    }

    private ToolStatus _status = ToolStatus.Running;
    public ToolStatus Status
    {
        get => _status;
        set
        {
            if (!Set(ref _status, value)) return;
            OnChanged(nameof(IsRunning));
            OnChanged(nameof(IsNotRunning));
            OnChanged(nameof(StatusText));
            OnChanged(nameof(StatusGlyph));
            OnChanged(nameof(ToolHeader));
        }
    }

    public bool IsRunning => Status == ToolStatus.Running;
    public bool IsNotRunning => Status != ToolStatus.Running;
    public bool HasInput => !string.IsNullOrEmpty(ToolInput);
    public bool HasOutput => !string.IsNullOrEmpty(ToolOutput);

    public string StatusText => Status switch
    {
        ToolStatus.Running => Loc.T("chat.status.running"),
        ToolStatus.Success => Loc.T("chat.status.done"),
        ToolStatus.Error => Loc.T("chat.status.error"),
        ToolStatus.Denied => Loc.T("chat.status.denied"),
        ToolStatus.Cancelled => Loc.T("chat.status.stopped"),
        _ => ""
    };

    public string StatusGlyph => Status switch
    {
        ToolStatus.Success => "\uE73E",   // onay / check
        ToolStatus.Error => "\uE783",     // hata / warning
        ToolStatus.Denied => "\uE72E",    // kilit / lock
        ToolStatus.Cancelled => "\uE71A", // stop
        _ => ""
    };

    // ── Geriye dönük uyumluluk alanları ──────────────────────────────────────
    public string ToolArguments
    {
        get => _toolInput;
        set => ToolInput = value;
    }

    public string ToolResult
    {
        get => _toolOutput;
        set => ToolOutput = value;
    }

    public bool HasToolResult => HasOutput;

    public string Thought
    {
        get => _text;
        set => Text = value;
    }

    public bool HasThought => Role == ChatRole.Thought && HasText;
    public bool IsThinking => Role == ChatRole.Thought && IsStreaming;
    public bool IsThoughtExpanded
    {
        get => _isExpanded;
        set => IsExpanded = value;
    }
    public bool ShowThoughtSection => Role == ChatRole.Thought;
    public string ThoughtHeader => Loc.T(IsStreaming ? "chat.thought.thinking" : "chat.thought.header");

    public void AppendThought(string delta)
    {
        if (string.IsNullOrEmpty(delta)) return;
        Text += delta;
        OnChanged(nameof(Thought));
        OnChanged(nameof(HasThought));
        OnChanged(nameof(ThoughtHeader));
    }

    // ── Görünüm yardımcıları ─────────────────────────────────────────────────
    public string RoleLabel => Role switch
    {
        ChatRole.User => Loc.T("chat.role.user"),
        ChatRole.Agent => Loc.T("chat.role.agent"),
        ChatRole.Tool => Loc.T("chat.role.tool"),
        ChatRole.Thought => Loc.T("chat.thought.header"),
        ChatRole.Activity => "Aktivite",
        _ => Loc.T("chat.role.system"),
    };

    public string TimeLabel => Timestamp.ToString("HH:mm");
    public bool IsUser => Role == ChatRole.User;
    public bool IsSystem => Role == ChatRole.System;
    public bool IsTool => Role == ChatRole.Tool;
    public bool IsThought => Role == ChatRole.Thought;
    public bool IsActivity => Role == ChatRole.Activity;
    public bool IsApproval => Role == ChatRole.Approval;
    public bool IsBubble => Role != ChatRole.Tool && Role != ChatRole.Thought && Role != ChatRole.Activity && Role != ChatRole.Approval;

    // ── Onay (approval) kartı alanları ───────────────────────────────────────
    /// <summary>Köprünün ürettiği istek kimliği; FIFO çözümde ilişkilendirme için.</summary>
    public string? ApprovalRequestId { get; set; }

    /// <summary>Onay bekleyen komutun tam metni.</summary>
    public string ApprovalCommand { get; set; } = "";

    /// <summary>Komutun neden tehlikeli bulunduğunun açıklaması.</summary>
    public string ApprovalDescription { get; set; } = "";

    public bool HasApprovalDescription => !string.IsNullOrWhiteSpace(ApprovalDescription);

    private bool _approvalResolved;
    /// <summary>Kullanıcı yanıtladıktan sonra kart düğmeleri kapanır.</summary>
    public bool ApprovalResolved
    {
        get => _approvalResolved;
        set
        {
            if (Set(ref _approvalResolved, value))
            {
                OnChanged(nameof(ApprovalPending));
            }
        }
    }

    public bool ApprovalPending => !_approvalResolved;

    private string _approvalOutcome = "";
    /// <summary>Çözüm sonrası gösterilen özet (ör. "İzin verildi (bir kez)").</summary>
    public string ApprovalOutcome
    {
        get => _approvalOutcome;
        set
        {
            if (Set(ref _approvalOutcome, value))
            {
                OnChanged(nameof(HasApprovalOutcome));
            }
        }
    }

    public bool HasApprovalOutcome => !string.IsNullOrEmpty(_approvalOutcome);

    public string ApprovalTitle => Loc.T("chat.approval.title");
    public string ApprovalAllowOnceLabel => Loc.T("chat.approval.allow_once");
    public string ApprovalAllowSessionLabel => Loc.T("chat.approval.allow_session");
    public string ApprovalAllowAlwaysLabel => Loc.T("chat.approval.allow_always");
    public string ApprovalDenyLabel => Loc.T("chat.approval.deny");

    public string ToolHeader => $"🔧 {ToolTitle} {StatusText}";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? n = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnChanged(n!);
        return true;
    }
}
