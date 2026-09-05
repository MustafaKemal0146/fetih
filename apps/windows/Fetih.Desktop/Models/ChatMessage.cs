using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;

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
        ChatRole.User => Loc.T("chat.role.user"),
        ChatRole.Agent => Loc.T("chat.role.agent"),
        ChatRole.Tool => "🔧 Araç",
        _ => Loc.T("chat.role.system"),
    };

    public string TimeLabel => Timestamp.ToString("HH:mm");

    public bool IsUser => Role == ChatRole.User;

    public bool IsSystem => Role == ChatRole.System;

    public bool IsTool => Role == ChatRole.Tool;

    /// <summary>Normal baloncuk mu (araç kartı değil)?</summary>
    public bool IsBubble => Role != ChatRole.Tool;

    // ── Baloncuk yerleşimi (modern sohbet tasarımı) ──────────────────────────

    /// <summary>Kullanıcı sağa, asistan/araç sola, sistem ortaya yaslanır.</summary>
    public HorizontalAlignment BubbleAlignment => Role switch
    {
        ChatRole.User => HorizontalAlignment.Right,
        ChatRole.System => HorizontalAlignment.Center,
        _ => HorizontalAlignment.Left,
    };

    /// <summary>Baloncuk arka planı için tema fırçası anahtarı.</summary>
    public string BubbleBrushKey => Role switch
    {
        ChatRole.User => "AccentFillColorDefaultBrush",
        ChatRole.System => "CardBackgroundFillColorSecondaryBrush",
        _ => "CardBackgroundFillColorDefaultBrush",
    };

    /// <summary>Baloncuk kenarlığı için tema fırçası anahtarı.</summary>
    public string BubbleBorderBrushKey => Role switch
    {
        ChatRole.User => "AccentFillColorSecondaryBrush",
        _ => "CardStrokeColorDefaultBrush",
    };

    /// <summary>Gövde metni fırçası (kullanıcı balonunda vurgu üstü metin).</summary>
    public string TextBrushKey => Role == ChatRole.User
        ? "TextOnAccentFillColorPrimaryBrush"
        : "TextFillColorPrimaryBrush";

    /// <summary>Rol/zaman etiketi fırçası.</summary>
    public string MetaBrushKey => Role == ChatRole.User
        ? "TextOnAccentFillColorSecondaryBrush"
        : "TextFillColorSecondaryBrush";

    /// <summary>Kuyruğu konuşana bakan asimetrik köşe yarıçapı.</summary>
    public CornerRadius BubbleCorner => Role switch
    {
        ChatRole.User => new CornerRadius(14, 14, 4, 14),
        ChatRole.System => new CornerRadius(10),
        _ => new CornerRadius(14, 14, 14, 4),
    };

    /// <summary>Baloncuk yatay iç boşluğu — sistem satırı daha dar.</summary>
    public Thickness BubbleMargin => Role switch
    {
        ChatRole.User => new Thickness(64, 0, 0, 0),
        ChatRole.System => new Thickness(24, 0, 24, 0),
        _ => new Thickness(0, 0, 64, 0),
    };

    /// <summary>Araç kartının başlığı: "🔧 read_file çalışıyor…".</summary>
    public string ToolHeader => $"🔧 {ToolName} {ToolStatusLabel}";

    private void Notify([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
