using System.Collections.ObjectModel;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Xunit;

namespace Fetih.Desktop.Tests;

public class ChatHistoryTrimmerTests
{
    private static ObservableCollection<ChatMessage> Make(int n)
    {
        var c = new ObservableCollection<ChatMessage>();
        for (var i = 0; i < n; i++)
        {
            c.Add(new ChatMessage(ChatRole.Agent, $"m{i}"));
        }
        return c;
    }

    [Fact]
    public void UnderCap_DoesNothing()
    {
        var c = Make(10);
        var removed = ChatHistoryTrimmer.Trim(c, 600);
        Assert.Equal(0, removed);
        Assert.Equal(10, c.Count);
    }

    [Fact]
    public void AtCap_DoesNothing()
    {
        var c = Make(600);
        Assert.Equal(0, ChatHistoryTrimmer.Trim(c, 600));
        Assert.Equal(600, c.Count);
    }

    [Fact]
    public void OverCap_RemovesOldestFromFront()
    {
        var c = Make(650);
        var removed = ChatHistoryTrimmer.Trim(c, 600);
        Assert.Equal(50, removed);
        Assert.Equal(600, c.Count);
        // En eskiler (m0..m49) gitti; en yeniler kaldı.
        Assert.Equal("m50", c[0].Text);
        Assert.Equal("m649", c[^1].Text);
    }

    [Fact]
    public void NonPositiveCap_Disabled()
    {
        var c = Make(5);
        Assert.Equal(0, ChatHistoryTrimmer.Trim(c, 0));
        Assert.Equal(0, ChatHistoryTrimmer.Trim(c, -1));
        Assert.Equal(5, c.Count);
    }

    [Fact]
    public void DefaultCapIsApplied()
    {
        var c = Make(ChatHistoryTrimmer.DefaultCap + 25);
        var removed = ChatHistoryTrimmer.Trim(c);
        Assert.Equal(25, removed);
        Assert.Equal(ChatHistoryTrimmer.DefaultCap, c.Count);
    }
}
