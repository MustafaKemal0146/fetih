using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Fetih.Desktop.Services;

/// <summary>
/// API anahtarı gibi gizli değerleri ad→değer olarak, şifreli bir dosyada
/// saklar. Değerler diske düz metin yazılmaz: tüm sözlük serileştirilip
/// <see cref="ICredentialProtector"/> ile şifrelenir. Üretimde DPAPI kullanınca
/// dosya yalnızca aynı Windows kullanıcısı tarafından çözülebilir.
///
/// <para>Saf mantık (IO + serileştirme), kripto <see cref="ICredentialProtector"/>
/// arkasında soyutlandığı için sahte bir protector ile test edilebilir.</para>
/// </summary>
public sealed class CredentialStore
{
    private readonly string _path;
    private readonly ICredentialProtector _protector;
    private readonly Dictionary<string, string> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private bool _loaded;

    public CredentialStore(string path, ICredentialProtector protector)
    {
        _path = path ?? throw new ArgumentNullException(nameof(path));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
    }

    /// <summary>Saklanan anahtarın değerini döndürür; yoksa null.</summary>
    public string? Get(string name)
    {
        lock (_lock)
        {
            EnsureLoaded();
            return _items.TryGetValue(name, out var v) ? v : null;
        }
    }

    /// <summary>Bir anahtarı ekler/günceller ve diske şifreli yazar. Boş değer anahtarı siler.</summary>
    public void Set(string name, string? value)
    {
        if (string.IsNullOrEmpty(name)) throw new ArgumentException("name boş olamaz", nameof(name));
        lock (_lock)
        {
            EnsureLoaded();
            if (string.IsNullOrEmpty(value))
            {
                _items.Remove(name);
            }
            else
            {
                _items[name] = value;
            }
            Save();
        }
    }

    /// <summary>Bir anahtarı siler.</summary>
    public void Remove(string name)
    {
        lock (_lock)
        {
            EnsureLoaded();
            if (_items.Remove(name))
            {
                Save();
            }
        }
    }

    /// <summary>Saklanan anahtar adları.</summary>
    public IReadOnlyCollection<string> Names
    {
        get
        {
            lock (_lock)
            {
                EnsureLoaded();
                return new List<string>(_items.Keys);
            }
        }
    }

    private void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            if (!File.Exists(_path)) return;
            var encrypted = File.ReadAllBytes(_path);
            if (encrypted.Length == 0) return;
            var json = Encoding.UTF8.GetString(_protector.Unprotect(encrypted));
            var data = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (data is not null)
            {
                foreach (var kv in data)
                {
                    _items[kv.Key] = kv.Value;
                }
            }
        }
        catch
        {
            // Bozuk/çözülemeyen dosya: boş başla (kullanıcı yeniden girer).
            _items.Clear();
        }
    }

    private void Save()
    {
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        var json = JsonSerializer.Serialize(_items);
        var encrypted = _protector.Protect(Encoding.UTF8.GetBytes(json));
        // Atomik yazım: önce temp, sonra taşı.
        var tmp = _path + ".tmp";
        File.WriteAllBytes(tmp, encrypted);
        File.Move(tmp, _path, overwrite: true);
    }
}
