using System;
using System.Collections.Generic;
using System.IO;

namespace Fetih.Desktop.Services;

/// <summary>
/// <c>~/.fetih/config.yaml</c> ve <c>~/.fetih/.env</c> dosyalarını okur.
/// Faz 1'de canlı Python sürecine bağlanmıyoruz; yapılandırmayı doğrudan
/// diskten okuyup gösteriyoruz. <b>Salt okunur</b> — hiçbir sayfa geri yazmaz.
/// </summary>
public sealed class FetihConfigService
{
    private static readonly Lazy<FetihConfigService> Instance = new(() => new FetihConfigService());

    private FetihConfigService()
    {
        Reload();
    }

    /// <summary>Süreç genelinde paylaşılan tek örnek.</summary>
    public static FetihConfigService Current => Instance.Value;

    /// <summary>Ayrıştırılmış config.yaml ağacı (okunamadıysa boş eşleme).</summary>
    public YamlNode Config { get; private set; } = YamlNode.FromMap(new Dictionary<string, YamlNode>(StringComparer.Ordinal));

    /// <summary>config.yaml diskte var mı?</summary>
    public bool ConfigExists { get; private set; }

    /// <summary>config.yaml okunurken oluşan hata (varsa).</summary>
    public string? ConfigError { get; private set; }

    /// <summary>config.yaml'ın son değişiklik zamanı.</summary>
    public DateTimeOffset? ConfigModified { get; private set; }

    /// <summary>
    /// <c>.env</c> dosyasında tanımlı olan anahtar <b>adları</b>.
    /// Değerler hiçbir zaman saklanmaz veya gösterilmez — bu bir güvenlik aracı.
    /// </summary>
    public HashSet<string> EnvFileKeys { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>.env dosyası diskte var mı?</summary>
    public bool EnvFileExists { get; private set; }

    /// <summary>Yapılandırmayı diskten yeniden okur.</summary>
    public void Reload()
    {
        try
        {
            ConfigExists = File.Exists(FetihPaths.ConfigYamlPath);
            ConfigModified = ConfigExists
                ? new DateTimeOffset(File.GetLastWriteTime(FetihPaths.ConfigYamlPath))
                : null;
            Config = YamlLite.LoadFile(FetihPaths.ConfigYamlPath);
            ConfigError = ConfigExists && Config.Map.Count == 0
                ? "config.yaml okundu ancak hiçbir anahtar ayrıştırılamadı."
                : null;
        }
        catch (Exception ex)
        {
            ConfigError = ex.Message;
            Config = YamlNode.FromMap(new Dictionary<string, YamlNode>(StringComparer.Ordinal));
        }

        EnvFileKeys = ReadEnvKeyNames(FetihPaths.EnvFilePath, out var envExists);
        EnvFileExists = envExists;
    }

    /// <summary>
    /// Bir ortam değişkeninin tanımlı olup olmadığını söyler.
    /// Önce süreç ortamına, sonra <c>~/.fetih/.env</c> dosyasına bakar.
    /// <b>Değer asla döndürülmez.</b>
    /// </summary>
    public EnvKeyPresence GetKeyPresence(string variableName)
    {
        if (string.IsNullOrWhiteSpace(variableName))
        {
            return EnvKeyPresence.Missing;
        }

        try
        {
            var fromProcess = Environment.GetEnvironmentVariable(variableName);
            if (!string.IsNullOrWhiteSpace(fromProcess))
            {
                return EnvKeyPresence.Environment;
            }
        }
        catch
        {
            // Ortam okunamıyorsa yalnızca .env'e bakılır.
        }

        return EnvFileKeys.Contains(variableName) ? EnvKeyPresence.EnvFile : EnvKeyPresence.Missing;
    }

    /// <summary>
    /// <c>.env</c> dosyasındaki anahtar adlarını toplar. Değerler okunur ama
    /// yalnızca "boş mu" kontrolü için kullanılır; hiçbir yerde saklanmaz.
    /// </summary>
    private static HashSet<string> ReadEnvKeyNames(string path, out bool exists)
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        exists = false;

        try
        {
            if (!File.Exists(path))
            {
                return keys;
            }

            exists = true;
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line[0] == '#')
                {
                    continue;
                }

                if (line.StartsWith("export ", StringComparison.Ordinal))
                {
                    line = line[7..].TrimStart();
                }

                var eq = line.IndexOf('=');
                if (eq <= 0)
                {
                    continue;
                }

                var name = line[..eq].Trim();
                var hasValue = line.Length > eq + 1 && line[(eq + 1)..].Trim().Trim('"', '\'').Length > 0;
                if (name.Length > 0 && hasValue)
                {
                    keys.Add(name);
                }
            }
        }
        catch
        {
            // Okunamayan .env: anahtarlar "tanımsız" görünür, uygulama çalışmaya devam eder.
        }

        return keys;
    }
}

/// <summary>Bir API anahtarının nerede tanımlı olduğu (değeri değil).</summary>
public enum EnvKeyPresence
{
    /// <summary>Hiçbir yerde tanımlı değil.</summary>
    Missing,

    /// <summary>Süreç ortam değişkenlerinde tanımlı.</summary>
    Environment,

    /// <summary><c>~/.fetih/.env</c> dosyasında tanımlı.</summary>
    EnvFile,
}
