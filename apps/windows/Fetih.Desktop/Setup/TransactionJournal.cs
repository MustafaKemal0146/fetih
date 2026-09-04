using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Fetih.Desktop.Setup;

/// <summary>
/// Append-only <c>.jsonl</c> kurulum günlüğü (OpenClaw'ın <c>TransactionJournal</c>
/// deseni, bkz. docs/openclaw-inceleme-notlari.md §5.2). Her olay tek satır bir
/// JSON nesnesidir; kurulum çökerse var olan girdiler yeniden okunabilir
/// (<see cref="LoadExisting"/>) → çökme sonrası kurtarma ve adli inceleme.
///
/// <para><b>Güvenlik:</b> API anahtarı değeri asla bu günlüğe yazılmaz —
/// adımlar yalnızca anahtar <i>adını</i> ve "yazıldı/yazılmadı" durumunu bildirir.</para>
/// </summary>
public sealed class TransactionJournal
{
    private readonly string _path;
    private readonly object _lock = new();

    public TransactionJournal(string path)
    {
        _path = path;
        try
        {
            var dir = System.IO.Path.GetDirectoryName(path);
            if (dir is not null)
            {
                Directory.CreateDirectory(dir);
            }
        }
        catch
        {
            // Klasör oluşturulamazsa yazma denemeleri sessizce yutulur.
        }
    }

    public string Path => _path;

    /// <summary>Bir olayı JSONL olarak ekler. Asla istisna fırlatmaz.</summary>
    public void Write(string eventName, Dictionary<string, object?> fields)
    {
        try
        {
            fields["event"] = eventName;
            fields["ts"] = DateTimeOffset.Now.ToString("o");
            var line = JsonSerializer.Serialize(fields);
            lock (_lock)
            {
                File.AppendAllText(_path, line + "\n");
            }
        }
        catch
        {
            // Günlükleme hiçbir zaman kurulumu bozmamalı.
        }
    }

    /// <summary>Var olan günlük satırlarını okur (çökme sonrası kurtarma için).</summary>
    public IReadOnlyList<string> LoadExisting()
    {
        try
        {
            return File.Exists(_path) ? File.ReadAllLines(_path) : Array.Empty<string>();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    /// <summary>Yeni bir kurulum çalışması için günlüğü sıfırlar (öncekini yedekler).</summary>
    public void Reset()
    {
        try
        {
            if (File.Exists(_path))
            {
                var bak = _path + ".prev";
                try { File.Delete(bak); } catch { }
                File.Move(_path, bak);
            }
        }
        catch
        {
            // Yedekleme başarısızsa üzerine yazılır.
        }
    }
}
