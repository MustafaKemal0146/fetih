using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Fetih.Desktop.Models;

namespace Fetih.Desktop.Views;

public sealed partial class ChatTemplateSelector : DataTemplateSelector
{
    public DataTemplate? User { get; set; }
    public DataTemplate? Agent { get; set; }
    public DataTemplate? Thought { get; set; }
    public DataTemplate? Tool { get; set; }
    public DataTemplate? Activity { get; set; }
    public DataTemplate? Approval { get; set; }
    public DataTemplate? System { get; set; }

    protected override DataTemplate? SelectTemplateCore(object item)
    {
        if (item is ChatMessage m)
        {
            return m.Role switch
            {
                ChatRole.User => User,
                ChatRole.Agent => Agent,
                ChatRole.Thought => Thought,
                ChatRole.Tool => Tool,
                ChatRole.Activity => Activity,
                ChatRole.Approval => Approval,
                _ => System
            };
        }
        return base.SelectTemplateCore(item);
    }

    protected override DataTemplate? SelectTemplateCore(object item, DependencyObject container) =>
        SelectTemplateCore(item);
}
