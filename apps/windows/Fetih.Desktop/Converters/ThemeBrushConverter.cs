using System;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;

namespace Fetih.Desktop.Converters;

/// <summary>
/// Bir tema kaynağı adını (ör. <c>SystemFillColorCriticalBrush</c>) fırçaya çevirir.
/// Model sınıfları XAML tipi taşımasın diye ciddiyet/durum renkleri metin anahtar
/// olarak tutulur; dönüşüm burada yapılır. Kaynak bulunamazsa şeffaf döner —
/// eksik bir tema anahtarı yüzünden sayfa çökmez.
/// </summary>
public sealed partial class ThemeBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush Fallback = new(Colors.Transparent);

    public object Convert(object value, Type targetType, object parameter, string language)
    {
        try
        {
            if (value is string key && key.Length > 0 &&
                Application.Current?.Resources is { } resources &&
                resources.TryGetValue(key, out var resource) &&
                resource is Brush brush)
            {
                return brush;
            }
        }
        catch
        {
            // Aşağıdaki şeffaf fırçaya düşülür.
        }

        return Fallback;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotSupportedException();
}

/// <summary>
/// <c>true</c> → <see cref="Visibility.Visible"/>. Ters çevirmek için
/// <c>ConverterParameter="invert"</c> kullanılır.
/// </summary>
public sealed partial class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var flag = value is bool b && b;
        if (parameter is string p && string.Equals(p, "invert", StringComparison.OrdinalIgnoreCase))
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotSupportedException();
}
