using System;
using System.Collections.Generic;
using System.IO;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Setup;

/// <summary>
/// <c>~/.fetih/.env</c> dosyasına anahtar/değer yazan minimal yardımcı.
/// FETİH'in Python tarafı bu dosyayı <c>save_env_value</c> ile yönetir; ilk
/// kurulumda henüz köprü/anahtar olmadığı için değeri doğrudan (ve YALNIZCA
/// yerel diske) yazarız. <b>Değer asla loglanmaz.</b>
/// </summary>
public static class EnvFileWriter
{
    /// <summary>Bir anahtarı ekler veya var olanı günceller.</summary>
    public static void SetValue(string path, string key, string value)
    {
        var dir = Path.GetDirectoryName(path);
        if (dir is not null)
        {
            Directory.CreateDirectory(dir);
        }

        var lines = File.Exists(path) ? new List<string>(File.ReadAllLines(path)) : new List<string>();
        var replaced = false;
        var prefix = key + "=";

        for (var i = 0; i < lines.Count; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (trimmed.StartsWith(prefix, StringComparison.Ordinal) ||
                trimmed.StartsWith("export " + prefix, StringComparison.Ordinal))
            {
                lines[i] = prefix + value;
                replaced = true;
                break;
            }
        }

        if (!replaced)
        {
            lines.Add(prefix + value);
        }

        File.WriteAllLines(path, lines);
    }

    /// <summary>Bir anahtar satırını (varsa) siler.</summary>
    public static void RemoveValue(string path, string key)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var prefix = key + "=";
        var kept = new List<string>();
        foreach (var line in File.ReadAllLines(path))
        {
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith(prefix, StringComparison.Ordinal) ||
                trimmed.StartsWith("export " + prefix, StringComparison.Ordinal))
            {
                continue;
            }
            kept.Add(line);
        }
        File.WriteAllLines(path, kept);
    }
}

/// <summary>Köprüyü başlatabilecek bir Python var mı, kabaca denetler.</summary>
public static class BridgeLauncherProbe
{
    public static bool HasUsablePython(out string where)
    {
        where = "";
        try
        {
            var explicitPy = Environment.GetEnvironmentVariable("FETIH_PYTHON");
            if (!string.IsNullOrWhiteSpace(explicitPy) && File.Exists(explicitPy))
            {
                where = explicitPy;
                return true;
            }
        }
        catch { }

        try
        {
            var known = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Python", "pythoncore-3.14-64", "python.exe");
            if (File.Exists(known))
            {
                where = known;
                return true;
            }
        }
        catch { }

        try
        {
            var path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (var dir in path.Split(Path.PathSeparator))
            {
                if (string.IsNullOrWhiteSpace(dir))
                {
                    continue;
                }
                foreach (var exe in new[] { "python.exe", "py.exe" })
                {
                    var candidate = Path.Combine(dir.Trim(), exe);
                    if (File.Exists(candidate))
                    {
                        where = candidate;
                        return true;
                    }
                }
            }
        }
        catch { }

        return false;
    }
}

/// <summary>
/// İlk kurulum gerekli mi, karar verir. Config yoksa VEYA hiçbir sağlayıcı
/// anahtarı görünmüyorsa (taze kullanıcı) sihirbaz gösterilir; aksi halde
/// doğrudan Sohbet'e gidilir ("zaten girişli" hali).
/// </summary>
public static class SetupDetector
{
    public static bool NeedsSetup()
    {
        try
        {
            var cfg = FetihConfigService.Current;
            cfg.Reload();

            if (!cfg.ConfigExists)
            {
                return true;
            }

            // Config var; en az bir bilinen sağlayıcı anahtarı tanımlı mı?
            foreach (var provider in ProviderRegistry.All)
            {
                foreach (var envVar in provider.ApiKeyEnvVars)
                {
                    if (cfg.GetKeyPresence(envVar) != EnvKeyPresence.Missing)
                    {
                        return false;
                    }
                }
            }

            // Anahtarsız (OAuth/yerel) bir sağlayıcı yapılandırılmış olabilir;
            // .env dosyası hiç yoksa ve hiçbir anahtar yoksa taze sayılır.
            return !cfg.EnvFileExists;
        }
        catch
        {
            // Karar verilemiyorsa sihirbazı zorlama; sohbete düş.
            return false;
        }
    }
}
