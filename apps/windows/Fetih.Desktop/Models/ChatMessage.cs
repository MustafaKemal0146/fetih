using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Fetih.Desktop.Models;

/// <summary>Bir sohbet mesajının kaynağı.</summary>
public enum ChatRole
{
    /// <summary>Kullanıcının yazdığı mesaj.</summary>
    User,

    /// <summary>Ajanın ürettiği yanıt.</summary>
    Agent,

    /// <summary>Sistem/bağlantı bilgisi (ör. köprü durumu).</summary>
    System,

    /// <summary>Araç kullanımı kartı (session.tool_call / session.tool_result).</summary>
    Tool,
}

/// <summary>
/// Sohbet akışındaki tek bir öğe. Normal mesaj baloncuğu veya (Role=Tool ise)
/// bir araç-kullanım kartı olabilir. Metin akış sırasında token token
/// güncellenebildiği için <see cref="INotifyPropertyChanged"/> uygular.
/// </summary>
public sealed class ChatMessage : INotifyPropertyChanged
{
    private string _text;
    private string _toolResult = "";
    private bool _isRunning;

    public ChatMessage(ChatRole role, string text)
    {
        Role = role;
        _text = text;
        Timestamp = DateTimeOffset.Now;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ChatRole Role { get; }

    /// <summary>Mesaj gövdesi (akışta güncellenebilir).</summary>
    public string Text
    {
        get => _text;
        set
        {
            if (_text == value)
            {
                return;
            }
            _text = value;
            Notify();
        }
    }

    public DateTimeOffset Timestamp { get; }

    // ── Araç kartı alanları (Role=Tool) ──────────────────────────────────────

    /// <summary>Araç adı (ör. <c>read_file</c>).</summary>
    public string ToolName { get; set; } = "";

    /// <summary>Araç argümanları (kırpılmış JSON metni).</summary>
    public string ToolArguments { get; set; } = "";

    /// <summary>Araç sonucu (tamamlanınca doldurulur).</summary>
    public string ToolResult
    {
        get => _toolResult;
        set
        {
            if (_toolResult == value)
            {
                return;
            }
            _toolResult = value;
            Notify();
            Notify(nameof(HasToolResult));
        }
    }

    /// <summary>Araç hâlâ çalışıyor mu?</summary>
    public bool IsRunning
    {
        get => _isRunning;
        set
        {
            if (_isRunning == value)
            {
                return;
            }
            _isRunning = value;
            Notify();
            Notify(nameof(ToolStatusLabel));
            Notify(nameof(ToolHeader));
        }
    }

    public bool HasToolResult => !string.IsNullOrWhiteSpace(ToolResult);

    public string ToolStatusLabel => IsRunning ? "çalışıyor…" : "tamamlandı";

    // ── Görünüm yardımcıları ─────────────────────────────────────────────────

    /// <summary>Baloncuğun üzerinde gösterilen kısa etiket.</summary>
    public string RoleLabel => Role switch
    {
        ChatRole.User => "Sen",
        ChatRole.Agent => "FETİH",
        ChatRole.Tool => "🔧 Araç",
        _ => "Sistem",
    };

    public string TimeLabel => Timestamp.ToString("HH:mm");

    public bool IsUser => Role == ChatRole.User;

    public bool IsSystem => Role == ChatRole.System;

    public bool IsTool => Role == ChatRole.Tool;

    /// <summary>Normal baloncuk mu (araç kartı değil)?</summary>
    public bool IsBubble => Role != ChatRole.Tool;

    /// <summary>Araç kartının başlığı: "🔧 read_file çalışıyor…".</summary>
    public string ToolHeader => $"🔧 {ToolName} {ToolStatusLabel}";

    private void Notify([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
