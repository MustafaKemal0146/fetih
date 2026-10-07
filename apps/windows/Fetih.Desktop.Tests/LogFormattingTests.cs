using System;
using Fetih.Desktop.Services;
using Xunit;

namespace Fetih.Desktop.Tests;

public class LogFormattingTests
{
    private static readonly DateTimeOffset Ts =
        new(2026, 1, 2, 3, 4, 5, 678, TimeSpan.Zero);

    [Fact]
    public void FormatLine_HasTimestampLevelAndMessage()
    {
        var line = LogFormatting.FormatLine(Ts, LogLevel.Info, "merhaba");
        Assert.Equal("[2026-01-02 03:04:05.678] [INFO] merhaba", line);
    }

    [Theory]
    [InlineData(LogLevel.Debug, "DEBUG")]
    [InlineData(LogLevel.Info, "INFO")]
    [InlineData(LogLevel.Warn, "WARN")]
    [InlineData(LogLevel.Error, "ERROR")]
    public void FormatLine_LevelTag(LogLevel level, string tag)
    {
        Assert.Contains($"[{tag}]", LogFormatting.FormatLine(Ts, level, "x"));
    }

    [Fact]
    public void ShouldRotate_Boundary()
    {
        Assert.False(LogFormatting.ShouldRotate(4_999_999, 5_000_000));
        Assert.True(LogFormatting.ShouldRotate(5_000_000, 5_000_000));
        Assert.True(LogFormatting.ShouldRotate(9_000_000, 5_000_000));
        Assert.False(LogFormatting.ShouldRotate(10, 0)); // eşik 0 → kapalı
    }

    [Fact]
    public void Sanitize_RedactsBearerToken()
    {
        var s = LogFormatting.Sanitize("Authorization: Bearer abc123SECRETtoken");
        Assert.DoesNotContain("abc123SECRETtoken", s);
        Assert.Contains("[REDACTED]", s);
    }

    [Fact]
    public void Sanitize_RedactsJsonSecretValue()
    {
        var s = LogFormatting.Sanitize("{\"api_key\":\"sk-live-superse cret\"}".Replace(" ", ""));
        Assert.DoesNotContain("sk-live", s);
        Assert.Contains("[REDACTED]", s);
    }

    [Fact]
    public void Sanitize_RedactsHexToken()
    {
        var hex = new string('a', 64);
        var s = LogFormatting.Sanitize($"token={hex} done");
        Assert.DoesNotContain(hex, s);
        Assert.Contains("[REDACTED_TOKEN]", s);
    }

    [Fact]
    public void Sanitize_LeavesPlainTextAlone()
    {
        const string msg = "Köprü 3 sn içinde yeniden bağlanıyor.";
        Assert.Equal(msg, LogFormatting.Sanitize(msg));
    }

    [Fact]
    public void FormatLine_NullMessageSafe()
    {
        var line = LogFormatting.FormatLine(Ts, LogLevel.Warn, null);
        Assert.EndsWith("] ", line);
    }
}
