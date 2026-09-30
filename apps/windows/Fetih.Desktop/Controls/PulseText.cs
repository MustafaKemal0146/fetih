using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;

namespace Fetih.Desktop.Controls;

public sealed partial class PulseText : UserControl
{
    private readonly TextBlock _tb = new() { VerticalAlignment = VerticalAlignment.Center };
    private Storyboard? _sb;

    public PulseText()
    {
        Content = _tb;
        Unloaded += (_, _) => Stop();
    }

    public static readonly DependencyProperty TextProperty = DependencyProperty.Register(
        nameof(Text), typeof(string), typeof(PulseText),
        new PropertyMetadata("", (d, e) => ((PulseText)d)._tb.Text = (string)(e.NewValue ?? "")));

    public string Text
    {
        get => (string)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    public static readonly DependencyProperty IsActiveProperty = DependencyProperty.Register(
        nameof(IsActive), typeof(bool), typeof(PulseText),
        new PropertyMetadata(false, (d, e) =>
        {
            var c = (PulseText)d;
            if ((bool)e.NewValue) c.Start();
            else c.Stop();
        }));

    public bool IsActive
    {
        get => (bool)GetValue(IsActiveProperty);
        set => SetValue(IsActiveProperty, value);
    }

    private void Start()
    {
        if (_sb != null) return;
        var a = new DoubleAnimation
        {
            From = 1.0,
            To = 0.4,
            AutoReverse = true,
            Duration = new Duration(TimeSpan.FromMilliseconds(900)),
            RepeatBehavior = RepeatBehavior.Forever
        };
        Storyboard.SetTarget(a, _tb);
        Storyboard.SetTargetProperty(a, "Opacity");
        _sb = new Storyboard();
        _sb.Children.Add(a);
        _sb.Begin();
    }

    private void Stop()
    {
        _sb?.Stop();
        _sb = null;
        _tb.Opacity = 1.0;
    }
}
