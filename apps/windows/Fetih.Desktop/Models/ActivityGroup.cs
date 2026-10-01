using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Models;

public static class ActivityLabels
{
    public static string Thinking => Loc.T("Activity_Thinking") ?? Loc.T("chat.activity.thinking");

    public static string Running(string tool)
    {
        var key = $"Activity_Tool_{tool}";
        var localized = Loc.T(key);
        if (!string.IsNullOrEmpty(localized) && localized != key)
        {
            return localized;
        }

        return tool switch
        {
            "write_file" or "write_to_file" => Loc.T("Activity_Tool_write_file") ?? Loc.T("chat.activity.coding"),
            "terminal" or "execute_command" => Loc.T("Activity_Tool_terminal") ?? Loc.T("chat.activity.command"),
            "read_file" or "view_file"      => Loc.T("Activity_Tool_read_file") ?? Loc.T("chat.activity.reading"),
            _                               => Loc.T("Activity_Tool_Default") ?? Loc.T("chat.activity.running")
        };
    }
}

public sealed class ActivityGroup : ChatMessage
{
    private string _label = "";
    private bool _isLabelLocked;
    private bool _isRunning = true;
    private bool _isCancelled;
    private DateTime? _endedAt;
    private TimeSpan? _duration;
    private string _elapsedText = "";
    private int _lastSec = -1;

    public ActivityGroup(string? groupId = null) : base(ChatRole.Activity)
    {
        GroupId = groupId ?? Guid.NewGuid().ToString("N");
        StartedAt = DateTime.Now;
        _label = ActivityLabels.Thinking;
    }

    public string GroupId { get; }
    public ObservableCollection<ChatMessage> Steps { get; } = new();

    public new DateTime StartedAt { get; set; }

    public DateTime? EndedAt
    {
        get => _endedAt;
        set
        {
            if (Set(ref _endedAt, value))
            {
                OnChanged(nameof(Duration));
            }
        }
    }

    public new TimeSpan? Duration
    {
        get => _duration ?? (_endedAt.HasValue ? _endedAt.Value - StartedAt : null);
        set => Set(ref _duration, value);
    }

    public new bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (Set(ref _isRunning, value))
            {
                OnChanged(nameof(IsDone));
                OnChanged(nameof(SummaryText));
            }
        }
    }

    public bool IsDone => !IsRunning;

    public bool IsCancelled
    {
        get => _isCancelled;
        set
        {
            if (Set(ref _isCancelled, value))
            {
                OnChanged(nameof(SummaryText));
                OnChanged(nameof(HeaderGlyph));
            }
        }
    }

    public string Label
    {
        get => string.IsNullOrEmpty(_label) ? ActivityLabels.Thinking : _label;
        set
        {
            if (Set(ref _label, value))
            {
                OnChanged(nameof(SummaryText));
            }
        }
    }

    public bool IsLabelLocked
    {
        get => _isLabelLocked;
        set => Set(ref _isLabelLocked, value);
    }

    public string ElapsedText
    {
        get => _elapsedText;
        private set => Set(ref _elapsedText, value);
    }

    public bool HasError => Steps.Any(s => s.Role == ChatRole.Tool && s.Status is ToolStatus.Error or ToolStatus.Denied);

    public string HeaderGlyph
    {
        get
        {
            if (HasError) return "\uE7BA";
            if (IsCancelled) return "\uE71A";
            return "\uE73E";
        }
    }

    public string SummaryText => IsRunning ? Label : BuildDoneSummary();

    /// <summary>
    /// Gruptaki son düşünce adımına yeni metin geldiğinde çağrılır.
    /// Sıçrama önleme ve tek seferlik kilit kuralını işletir.
    /// </summary>
    public void UpdateThoughtText(string fullThoughtText, bool isClosing = false)
    {
        EndedAt = DateTime.Now;

        if (IsLabelLocked) return;

        var clean = fullThoughtText ?? "";
        var si = new StringInfo(clean);
        int graphemeCount = si.LengthInTextElements;

        if (graphemeCount < 15)
        {
            Label = ActivityLabels.Thinking;
            if (isClosing && graphemeCount > 0)
            {
                var finalLabel = ActivityLabelBuilder.BuildLabel(clean);
                if (!string.IsNullOrEmpty(finalLabel))
                {
                    Label = finalLabel;
                }
                IsLabelLocked = true;
            }
            return;
        }

        // 15 veya daha fazla karakter var: Cümle bitti mi veya 60 karaktere ulaşıldı mı?
        var sentence = ActivityLabelBuilder.ExtractFirstSentence(clean);
        bool sentenceFinished = sentence.Length < clean.Length;
        bool reached60 = graphemeCount >= 60;

        if (sentenceFinished || reached60 || isClosing)
        {
            var summary = ActivityLabelBuilder.BuildLabel(clean);
            if (!string.IsNullOrEmpty(summary))
            {
                Label = summary;
                IsLabelLocked = true;
            }
        }
    }

    /// <summary>
    /// Grupta yeni bir araç adımı başladığında çağrılır.
    /// </summary>
    public void SetToolRunning(string toolName, string? argumentsJson = null)
    {
        EndedAt = DateTime.Now;
        Label = ToolLabelBuilder.BuildLabel(toolName, argumentsJson);
        // Araç adımları doğrudan araç etiketini gösterir; kilit yeni düşünce adımı gelene kadar sabit kalır
        IsLabelLocked = true;
    }

    /// <summary>
    /// Köprüden veya depodan canlı/kalıcı düşünce etiketi geldiğinde çağrılır.
    /// </summary>
    public void SetThoughtLabel(string label)
    {
        if (string.IsNullOrWhiteSpace(label)) return;
        Label = label.Trim();
        IsLabelLocked = true;
    }

    /// <summary>
    /// Sayaç güncellemesi (UI flush timer'dan çağrılır).
    /// Yalnızca saniye değiştiğinde OnChanged tetikler.
    /// </summary>
    public void Tick()
    {
        if (!IsRunning) return;
        var now = DateTime.Now;
        var elapsed = now - StartedAt;
        int sec = (int)elapsed.TotalSeconds;
        if (sec != _lastSec)
        {
            _lastSec = sec;
            ElapsedText = sec < 1 ? "" : FormatDuration(elapsed);
        }
    }

    /// <summary>
    /// Grubu tamamlar. Süre son olayın zamanı (EndedAt) veya verilen süre üzerinden hesaplanır.
    /// </summary>
    public void Complete(bool cancelled, TimeSpan? elapsedOverride = null)
    {
        IsCancelled = cancelled;
        if (elapsedOverride.HasValue)
        {
            Duration = elapsedOverride.Value;
        }
        else if (EndedAt.HasValue)
        {
            Duration = EndedAt.Value - StartedAt;
        }
        else
        {
            Duration = DateTime.Now - StartedAt;
        }

        IsRunning = false;
        Refresh();
    }

    public void Refresh()
    {
        OnChanged(nameof(SummaryText));
        OnChanged(nameof(HasError));
        OnChanged(nameof(HeaderGlyph));
        OnChanged(nameof(IsRunning));
        OnChanged(nameof(IsDone));
    }

    /// <summary>
    /// Claude tarzı tamamlanmış grup özeti üretir.
    /// </summary>
    public string BuildDoneSummary()
    {
        var parts = new List<string>();

        // 1. Etiket
        parts.Add(Label);

        // 2. İşlem sayısı (yalnızca araç varsa)
        int toolCount = Steps.Count(s => s.Role == ChatRole.Tool);
        if (toolCount == 1)
        {
            parts.Add(Loc.T("Activity_Action_One") ?? Loc.Format("chat.activity.actions", 1));
        }
        else if (toolCount > 1)
        {
            parts.Add(Loc.Format("Activity_Actions_Many", toolCount) ?? Loc.Format("chat.activity.actions", toolCount));
        }

        // 3. Hata sayısı (varsa)
        int errorCount = Steps.Count(s => s.Role == ChatRole.Tool && s.Status is ToolStatus.Error or ToolStatus.Denied);
        if (errorCount == 1)
        {
            parts.Add(Loc.T("Activity_Error_One") ?? Loc.Format("chat.activity.errors", 1));
        }
        else if (errorCount > 1)
        {
            parts.Add(Loc.Format("Activity_Errors", errorCount) ?? Loc.Format("chat.activity.errors", errorCount));
        }

        // 4. İptal durumu (varsa)
        if (IsCancelled)
        {
            parts.Add(Loc.T("Activity_Cancelled") ?? Loc.T("chat.activity.stopped"));
        }

        // 5. Süre (varsa ve 1 saniyenin üzerindeyse)
        if (Duration.HasValue && Duration.Value.TotalSeconds >= 1.0)
        {
            parts.Add(FormatDuration(Duration.Value));
        }

        return string.Join(" · ", parts);
    }

    public static string FormatDuration(TimeSpan t)
    {
        var secUnit = Loc.T("Unit_Sec") ?? Loc.T("unit.sec");
        var minUnit = Loc.T("Unit_Min") ?? Loc.T("unit.min");

        if (t.TotalSeconds < 1.0)
        {
            return "";
        }

        if (t.TotalSeconds < 60)
        {
            return $"{t.TotalSeconds:0} {secUnit}";
        }

        return $"{(int)t.TotalMinutes} {minUnit} {t.Seconds} {secUnit}";
    }
}
