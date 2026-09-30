using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Fetih.Desktop.Models;

namespace Fetih.Desktop.Views;

public sealed partial class StepTemplateSelector : DataTemplateSelector
{
    public DataTemplate? Thought { get; set; }
    public DataTemplate? Tool { get; set; }

    protected override DataTemplate? SelectTemplateCore(object item)
    {
        if (item is ChatMessage m)
        {
            return m.Role switch
            {
                ChatRole.Thought => Thought,
                ChatRole.Tool => Tool,
                _ => Tool ?? Thought
            };
        }
        return base.SelectTemplateCore(item);
    }

    protected override DataTemplate? SelectTemplateCore(object item, DependencyObject container) =>
        SelectTemplateCore(item);
}
