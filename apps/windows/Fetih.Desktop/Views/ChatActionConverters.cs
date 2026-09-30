using System;
using System.Linq;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Fetih.Desktop.Views;

public sealed class ChatActionVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is ChatRole role && parameter is string pattern)
        {
            var allowed = pattern.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return allowed.Any(a => string.Equals(a, role.ToString(), StringComparison.OrdinalIgnoreCase))
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotSupportedException();
}

public sealed class ChatActionLabelConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var action = parameter as string ?? "";
        return action switch
        {
            "copy" => Loc.T("chat.action.copy") ?? "Kopyala",
            "copy.hint" => Loc.T("chat.action.copy.hint") ?? "Panoya kopyala",
            "edit" => Loc.T("chat.action.edit") ?? "Düzenle",
            "edit.hint" => Loc.T("chat.action.edit.hint") ?? "Mesajı düzenle",
            "retry" => Loc.T("chat.action.retry") ?? "Yeniden dene",
            "retry.hint" => Loc.T("chat.action.retry.hint") ?? "Yeniden çalıştır",
            _ => action
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotSupportedException();
}
