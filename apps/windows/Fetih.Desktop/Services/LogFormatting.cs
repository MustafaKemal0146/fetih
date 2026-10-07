using System;
using System.Text.RegularExpressions;

namespace Fetih.Desktop.Services;

/// <summary>Günlük seviyesi.</summary>
public enum LogLevel
{
    Debug,
    Info,
    Warn,
    Error,
}

/// <summary>
/// Günlük satırı biçimleme, rotasyon kararı ve gizli-bilgi redaksiyonu — saf,
/// IO'suz, WinUI'siz. Bu sayede birim testlenebilir; asıl dosya/kanal
/// makinesi <see cref="Logger"/>'dadır.
/// </summary>
public static class LogFormatting
{
    /// <summary>Bir günlük satırını biçimler: <c>[zaman] [SEVIYE] mesaj</c> (mesaj redakte edilir).</summary>
    public static string FormatLine(DateTimeOffset ts, LogLevel level, string? message)
        => $"[{ts:yyyy-MM-dd HH:mm:ss.fff}] [{Tag(level)}] {Sanitize(message ?? string.Empty)}";

    private static string Tag(LogLevel level) => level switch
    {
        LogLevel.Debug => "DEBUG",
        LogLevel.Info => "INFO",
        LogLevel.Warn => "WARN",
        LogLevel.Error => "ERROR",
        _ => "INFO",
    };

    /// <summary>Aktif günlük dosyası <paramref name="thresholdBytes"/>'ı aştıysa rotasyon gerekir.</summary>
    public static bool ShouldRotate(long currentBytes, long thresholdBytes)
        => thresholdBytes > 0 && currentBytes >= thresholdBytes;

    // ReDoS'a karşı kısa zaman aşımı; aşılırsa fail-closed (tüm satır redakte).
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly Regex BearerRe = new(
        @"(?i)(authorization:\s*bearer\s+)[^\s]+", RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex JsonSecretRe = new(
        @"(?i)(""[^""]*(?:token|secret|password|api[_-]?key|authorization)[^""]*""\s*:\s*"")[^""]+("")",
        RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex HexTokenRe = new(
        @"\b[0-9a-fA-F]{64}\b", RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex UrlLongTokenRe = new(
        @"\b[A-Za-z0-9_\-]{43}\b", RegexOptions.Compiled, RegexTimeout);

    /// <summary>
    /// Mesajdaki yaygın gizli-bilgi biçimlerini redakte eder. Bir güvenlik
    /// aracının günlükleri sızıntı yüzeyi olmamalı. ReDoS zaman aşımında tüm
    /// satır güvenli tarafta redakte edilir.
    /// </summary>
    public static string Sanitize(string message)
    {
        if (string.IsNullOrEmpty(message))
        {
            return message ?? string.Empty;
        }
        try
        {
            var s = BearerRe.Replace(message, "$1[REDACTED]");
            s = JsonSecretRe.Replace(s, "$1[REDACTED]$2");
            s = HexTokenRe.Replace(s, "[REDACTED_TOKEN]");
            s = UrlLongTokenRe.Replace(s, "[REDACTED_TOKEN]");
            return s;
        }
        catch (RegexMatchTimeoutException)
        {
            return "[REDACTED_UNSAFE_LOG_LINE]";
        }
    }
}
