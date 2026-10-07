using System;

namespace Fetih.Desktop.Bridge;

/// <summary>
/// Yeniden bağlanma denemeleri için üstel-benzeri backoff çizelgesi.
/// OpenClaw'ın standart gateway backoff dizisinden uyarlanmıştır:
/// 1,2,4,8,15,30,60 sn; son değer tavandır (süresiz tekrar aynı 60 sn'de).
/// Saf ve deterministik — WinUI'siz birim testiyle doğrulanır.
/// </summary>
public static class BridgeBackoff
{
    private static readonly int[] ScheduleMs = { 1000, 2000, 4000, 8000, 15000, 30000, 60000 };

    /// <summary>En büyük (tavan) gecikme — çizelgenin son elemanı.</summary>
    public static TimeSpan Max => TimeSpan.FromMilliseconds(ScheduleMs[^1]);

    /// <summary>
    /// 0-tabanlı deneme indeksine karşılık gelen gecikme. Negatif indeks 0'a,
    /// çizelgeyi aşan indeks son (tavan) değere sabitlenir (clamp).
    /// </summary>
    public static TimeSpan ForAttempt(int attempt)
    {
        if (attempt < 0)
        {
            attempt = 0;
        }
        var idx = attempt < ScheduleMs.Length ? attempt : ScheduleMs.Length - 1;
        return TimeSpan.FromMilliseconds(ScheduleMs[idx]);
    }
}
