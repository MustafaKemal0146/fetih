using Fetih.Desktop.Bridge;
using Xunit;

namespace Fetih.Desktop.Tests;

public class BridgeBackoffTests
{
    [Theory]
    [InlineData(0, 1000)]
    [InlineData(1, 2000)]
    [InlineData(2, 4000)]
    [InlineData(3, 8000)]
    [InlineData(4, 15000)]
    [InlineData(5, 30000)]
    [InlineData(6, 60000)]
    public void FollowsSchedule(int attempt, int expectedMs)
    {
        Assert.Equal(expectedMs, (int)BridgeBackoff.ForAttempt(attempt).TotalMilliseconds);
    }

    [Theory]
    [InlineData(7)]
    [InlineData(20)]
    [InlineData(999)]
    public void ClampsToMaxBeyondSchedule(int attempt)
    {
        Assert.Equal(BridgeBackoff.Max, BridgeBackoff.ForAttempt(attempt));
    }

    [Fact]
    public void NegativeAttemptUsesFirst()
    {
        Assert.Equal(1000, (int)BridgeBackoff.ForAttempt(-5).TotalMilliseconds);
    }

    [Fact]
    public void MaxIsSixtySeconds()
    {
        Assert.Equal(60000, (int)BridgeBackoff.Max.TotalMilliseconds);
    }
}
