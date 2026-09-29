using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Fetih.Desktop.Services;

/// <summary>
/// GitHub Releases'den "desktop-v*" etiketli en son masaüstü sürümünü
/// sorgulayan, indiren ve kuran otomatik güncelleme servisi.
///
/// <para>Depo hem PyPI (CalVer, <c>v20*</c> etiketleri) hem masaüstü uygulaması
/// (SemVer, <c>desktop-v*</c> etiketleri) için sürüm yayınlar — bu yüzden
/// GitHub'ın "latest release" uç noktası yerine <c>/releases</c> listesini
/// çekip <see cref="TagPrefix"/> ile başlayan ilk (en yeni) kaydı seçeriz.
/// Yayın workflow'u: <c>.github/workflows/windows-desktop-release.yml</c>.</para>
///
/// <para>İki dağıtım şekli desteklenir:</para>
/// <list type="bullet">
/// <item>Inno Setup ile kurulmuş (kayıt defterinde uninstall anahtarı var) →
/// yeni installer'ı indirip <c>/VERYSILENT</c> ile sessizce çalıştırırız;
/// Inno Setup çalışan .exe'yi kendi kapatıp üzerine yazar.</item>
/// <item>Taşınabilir (zip'ten çıkarılmış klasör) → yeni sürümü ayrı bir
/// klasöre indirip, bu süreç kapandıktan sonra dosyaları kopyalayıp
/// uygulamayı yeniden başlatan küçük bir yardımcı <c>.cmd</c> betiği
/// kullanırız (Windows çalışan bir .exe/.dll'in üzerine yazılmasına izin
/// vermez).</item>
/// </list>
/// </summary>
public static class UpdateService
{
    private const string Owner = "MustafaKemal0146";
    private const string Repo = "fetih";
    private const string TagPrefix = "desktop-v";
    private const string InnoSetupAppId = "E844AC82-70F4-41A8-B6A7-7C5F5E4E3A01";

    private static readonly Lazy<HttpClient> HttpLazy = new(CreateClient);
    private static HttpClient Http => HttpLazy.Value;

    private static string StatePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Fetih", "Desktop", "update-check.json");

    /// <summary>Son başarılı arka plan denetiminde bulunan güncelleme (varsa). UI bunu okur.</summary>
    public static UpdateInfo? LastKnownUpdate { get; private set; }

    /// <summary>Bir arka plan denetimi yeni bir güncelleme bulduğunda tetiklenir (UI dispatcher'da DEĞİL — çağıran taşımalı).</summary>
    public static event Action<UpdateInfo>? UpdateFound;

    private static HttpClient CreateClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Fetih-Desktop-Updater/1.0");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return http;
    }

    /// <summary>
    /// Açılışta çağrılır: son denetimden bu yana &gt;= <paramref name="minInterval"/>
    /// geçtiyse GitHub'ı sorgular. Ağ/parse hatalarını yutar — güncelleme
    /// denetimi asla uygulamanın açılışını engellememeli veya çökertmemeli.
    /// </summary>
    public static async Task CheckInBackgroundAsync(TimeSpan minInterval, CancellationToken ct = default)
    {
        try
        {
            if (!ShouldCheckNow(minInterval))
            {
                return;
            }

            var info = await CheckForUpdateAsync(ct).ConfigureAwait(false);
            WriteLastCheckTimestamp();

            if (info is not null)
            {
                LastKnownUpdate = info;
                UpdateFound?.Invoke(info);
            }
        }
        catch
        {
            // En iyi çaba — sessizce vazgeç.
        }
    }

    private static bool ShouldCheckNow(TimeSpan minInterval)
    {
        try
        {
            if (!File.Exists(StatePath))
            {
                return true;
            }

            using var doc = JsonDocument.Parse(File.ReadAllText(StatePath));
            if (doc.RootElement.TryGetProperty("lastCheckUtc", out var el) &&
                DateTimeOffset.TryParse(el.GetString(), out var last))
            {
                return DateTimeOffset.UtcNow - last >= minInterval;
            }
        }
        catch
        {
            // Bozuk durum dosyası: yine de denetle.
        }

        return true;
    }

    private static void WriteLastCheckTimestamp()
    {
        try
        {
            var dir = Path.GetDirectoryName(StatePath);
            if (dir is not null)
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllText(StatePath, JsonSerializer.Serialize(new
            {
                lastCheckUtc = DateTimeOffset.UtcNow.ToString("O"),
            }));
        }
        catch
        {
            // Yazılamazsa bir sonraki açılışta tekrar denetlenir — zararsız.
        }
    }

    /// <summary>GitHub Releases'i sorgular ve mevcut sürümden daha yeni bir "desktop-v*" yayını varsa döndürür.</summary>
    public static async Task<UpdateInfo?> CheckForUpdateAsync(CancellationToken ct = default)
    {
        try
        {
            var url = $"https://api.github.com/repos/{Owner}/{Repo}/releases?per_page=15";
            using var resp = await Http.GetAsync(url, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);

            var currentVersion = ParseVersion(AppInfo.Version) ?? new Version(0, 0, 0);

            foreach (var release in doc.RootElement.EnumerateArray())
            {
                if (GetBool(release, "draft") || GetBool(release, "prerelease"))
                {
                    continue;
                }

                var tag = GetString(release, "tag_name");
                if (tag is null || !tag.StartsWith(TagPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var versionText = tag[TagPrefix.Length..];
                var remoteVersion = ParseVersion(versionText);
                if (remoteVersion is null || remoteVersion <= currentVersion)
                {
                    // Releases listesi en yeniden en eskiye sıralıdır: ilk
                    // "desktop-v*" kaydı güncel/eskiyse daha yenisi yoktur.
                    return null;
                }

                Uri? installerUrl = null;
                Uri? portableUrl = null;
                if (release.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
                {
                    foreach (var asset in assets.EnumerateArray())
                    {
                        var name = GetString(asset, "name") ?? "";
                        var download = GetString(asset, "browser_download_url");
                        if (download is null)
                        {
                            continue;
                        }

                        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                            name.Contains("Setup", StringComparison.OrdinalIgnoreCase))
                        {
                            installerUrl = new Uri(download);
                        }
                        else if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                                 name.Contains("Portable", StringComparison.OrdinalIgnoreCase))
                        {
                            portableUrl = new Uri(download);
                        }
                    }
                }

                var notesUrl = GetString(release, "html_url") ?? AppInfo.ReleasesUrl;
                return new UpdateInfo(versionText, tag, installerUrl, portableUrl, notesUrl);
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static string? GetString(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool GetBool(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False && v.GetBoolean();

    /// <summary>"1.2.0", "v1.2.0", "1.2" gibi girdileri <see cref="Version"/>'a çevirir; olmazsa null döner.</summary>
    private static Version? ParseVersion(string text)
    {
        var trimmed = text.Trim().TrimStart('v', 'V');
        var plus = trimmed.IndexOf('+');
        if (plus >= 0)
        {
            trimmed = trimmed[..plus];
        }

        var dash = trimmed.IndexOf('-');
        if (dash >= 0)
        {
            trimmed = trimmed[..dash];
        }

        var parts = trimmed.Split('.');
        if (parts.Length == 1)
        {
            trimmed += ".0";
        }

        return Version.TryParse(trimmed, out var v) ? v : null;
    }

    /// <summary>
    /// Uygulama Inno Setup ile kuruldu mu (aksi hâlde taşınabilir/geliştirme
    /// dağıtımı kabul edilir)? <c>packaging/windows/installer.iss</c>'teki
    /// sabit <c>AppId</c>'ye karşılık gelen kayıt defteri anahtarını arar.
    /// </summary>
    public static bool IsInstalledViaSetup()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                $@"Software\Microsoft\Windows\CurrentVersion\Uninstall\{{{InnoSetupAppId}}}_is1");
            return key is not null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Bir dosyayı geçici klasöre indirir; ilerleme 0..1 aralığında raporlanır.</summary>
    public static async Task<string> DownloadAsync(Uri url, IProgress<double>? progress, CancellationToken ct = default)
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"fetih-update-{Guid.NewGuid():N}{Path.GetExtension(url.LocalPath)}");

        using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        var total = resp.Content.Headers.ContentLength ?? -1L;
        await using var httpStream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await using var fileStream = new FileStream(
            tempFile, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);

        var buffer = new byte[81920];
        long readTotal = 0;
        int read;
        while ((read = await httpStream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            await fileStream.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            readTotal += read;
            if (total > 0)
            {
                progress?.Report((double)readTotal / total);
            }
        }

        return tempFile;
    }

    /// <summary>
    /// İndirilen installer'ı sessizce çalıştırır ve süreci sonlandırır.
    /// Inno Setup varsayılanı olarak çalışan uygulamayı kapatıp yeniden açar
    /// (<c>/CLOSEAPPLICATIONS /RESTARTAPPLICATIONS</c>).
    /// </summary>
    public static void RunInstallerSilentlyAndExit(string installerPath)
    {
        var psi = new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /NOCANCEL",
            UseShellExecute = true,
        };
        Process.Start(psi);
        Environment.Exit(0);
    }

    /// <summary>
    /// Taşınabilir dağıtım için: zip'i geçici bir hazırlama klasörüne açar,
    /// bu süreç kapandıktan sonra dosyaları kurulum klasörünün üzerine
    /// kopyalayıp uygulamayı yeniden başlatan bir <c>.cmd</c> betiği üretir ve
    /// çalıştırır, sonra kendi sürecini sonlandırır.
    /// </summary>
    public static void ApplyPortableUpdateAndExit(string zipPath, string installDir, string exeFileName = "Fetih.Desktop.exe")
    {
        var staging = Path.Combine(Path.GetTempPath(), $"fetih-update-staging-{Guid.NewGuid():N}");
        Directory.CreateDirectory(staging);
        ZipFile.ExtractToDirectory(zipPath, staging, overwriteFiles: true);

        var pid = Environment.ProcessId;
        var scriptPath = Path.Combine(Path.GetTempPath(), $"fetih-updater-{Guid.NewGuid():N}.cmd");
        var exePath = Path.Combine(installDir, exeFileName);

        // robocopy /E /IS /IT: alt klasörler dâhil, mevcut/aynı/eski dosyaları
        // da kopyala (üzerine yaz). Exit code >=8 gerçek hatadır; 0-7 normaldir.
        var script = $@"@echo off
setlocal
:wait
tasklist /FI ""PID eq {pid}"" 2>NUL | find ""{pid}"" >NUL
if not errorlevel 1 (
    timeout /t 1 /nobreak >NUL
    goto wait
)
robocopy ""{staging}"" ""{installDir}"" /E /IS /IT /NFL /NDL /NJH /NJS /R:3 /W:1
start """" ""{exePath}""
rmdir /s /q ""{staging}"" >NUL 2>&1
(goto) 2>nul & del ""%~f0""
";
        File.WriteAllText(scriptPath, script);

        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c \"{scriptPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        Process.Start(psi);
        Environment.Exit(0);
    }
}

/// <summary>Bulunan bir masaüstü sürümü hakkında GitHub Release verisi.</summary>
public sealed record UpdateInfo(
    string Version,
    string TagName,
    Uri? InstallerUrl,
    Uri? PortableZipUrl,
    string ReleaseNotesUrl);
