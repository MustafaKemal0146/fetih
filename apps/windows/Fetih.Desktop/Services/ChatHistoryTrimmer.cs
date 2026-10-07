using System.Collections.Generic;
using Fetih.Desktop.Models;

namespace Fetih.Desktop.Services;

/// <summary>
/// Transkriptin sınırsız büyümesini engelleyen saf yardımcı. Sohbet akışı
/// (ItemsControl) sanallaştırılmadığı için her üst düzey öğe bir görsel düğüm
/// demektir; uzun oturumlarda bu, bellek ve layout maliyetini doğrusal artırır.
///
/// <para>Yalnızca GÜVENLİ anlardan (tur bitişi, oturum yükleme sonrası)
/// çağrılmalıdır: o anlarda akan bir segment/aktivite olmaz, dolayısıyla en
/// eski öğeleri baştan kırpmak canlı durumu bozmaz. Saf tutulduğu için
/// WinUI'siz birim testiyle doğrulanabilir.</para>
/// </summary>
public static class ChatHistoryTrimmer
{
    /// <summary>Varsayılan üst sınır — denge: uzun oturum geçmişi vs. görsel ağaç maliyeti.</summary>
    public const int DefaultCap = 600;

    /// <summary>
    /// <paramref name="messages"/> en fazla <paramref name="cap"/> öğe kalana
    /// dek en eskileri (baştan) siler. <paramref name="cap"/> ≤ 0 ise hiçbir
    /// şey yapmaz. Silinen öğe sayısını döndürür.
    /// </summary>
    public static int Trim(IList<ChatMessage> messages, int cap = DefaultCap)
    {
        if (messages is null || cap <= 0 || messages.Count <= cap)
        {
            return 0;
        }

        var toRemove = messages.Count - cap;
        for (var i = 0; i < toRemove; i++)
        {
            messages.RemoveAt(0);
        }
        return toRemove;
    }
}
