using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Services;

namespace Fetih.Desktop.Setup;

/// <summary>
/// FETİH'in gerçek ön koşullarına uyarlanmış kurulum adımları. Bizim
/// ön koşulumuz yalnızca Python + bir sağlayıcı anahtarı olduğu için liste
/// kısadır ama aynı soyutlamayı kullanır: <c>CanSkip</c> ikinci çalıştırmayı
/// onarım moduna çevirir.
///
/// <para>Adım adları ve sonuç metinleri <see cref="Loc"/> üzerinden gelir:
/// ilerleme listesi kullanıcıya görünen tek yerdir ve orada sabit metin
/// kalırsa İngilizce arayüzde Türkçe satırlar kalırdı.</para>
/// </summary>
public static class SetupStepFactory
{
    public static IReadOnlyList<SetupStep> BuildDefaultSteps() => new SetupStep[]
    {
        new PreflightOsStep(),
        new DetectPythonStep(),
        new EnsureFetihHomeStep(),
        new WriteEnvKeyStep(),
        new WriteConfigStep(),
        new StartDesktopBridgeStep(),
        new EnsureProviderAuthStep(),
        new VerifyEndToEndStep(),
    };
}

/// <summary>İşletim sistemi Windows mu?</summary>
public sealed class PreflightOsStep : SetupStep
{
    public override string Id => "preflight_os";
    public override string DisplayName => Loc.T("setup.step.os.name");

    public override Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct)
        => Task.FromResult(OperatingSystem.IsWindows()
            ? StepResult.Ok(Loc.T("setup.step.os.ok"))
            : StepResult.Fail(Loc.T("setup.step.os.fail")));
}

/// <summary>Köprüyü başlatabilecek bir Python var mı?</summary>
public sealed class DetectPythonStep : SetupStep
{
    public override string Id => "detect_python";
    public override string DisplayName => Loc.T("setup.step.python.name");

    public override Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct)
    {
        if (BridgeLauncherProbe.HasUsablePython(out var where))
        {
            ctx.Notes.Add("Python: " + where);
            return Task.FromResult(StepResult.Ok(
                string.Format(Loc.T("setup.step.python.ok"), where)));
        }
        return Task.FromResult(StepResult.Fail(Loc.T("setup.step.python.fail")));
    }
}

/// <summary><c>~/.fetih</c> durum dizinini oluşturur.</summary>
public sealed class EnsureFetihHomeStep : SetupStep
{
    public override string Id => "ensure_fetih_home";
    public override string DisplayName => Loc.T("setup.step.home.name");

    private bool _created;

    public override Task<bool> CanSkipAsync(SetupContext ctx)
        => Task.FromResult(Directory.Exists(FetihPaths.FetihHome));

    public override Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct)
    {
        Directory.CreateDirectory(FetihPaths.FetihHome);
        _created = true;
        return Task.FromResult(StepResult.Ok(
            string.Format(Loc.T("setup.step.home.ok"), FetihPaths.FetihHome)));
    }

    public override Task RollbackAsync(SetupContext ctx, CancellationToken ct)
    {
        // Yalnızca BU adımın oluşturduğu boş dizini geri al; dolu dizine dokunma.
        try
        {
            if (_created && Directory.Exists(FetihPaths.FetihHome) &&
                Directory.GetFileSystemEntries(FetihPaths.FetihHome).Length == 0)
            {
                Directory.Delete(FetihPaths.FetihHome);
            }
        }
        catch
        {
            // Silinemezse bırak; boş dizin zararsız.
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// API anahtarını <c>~/.fetih/.env</c> dosyasına YAZAR. Anahtar değeri köprü
/// üzerinden GEÇMEZ (config.set gizli anahtarları reddeder); doğrudan yerel
/// dosyaya yazılır ve <b>hiçbir yerde loglanmaz</b>.
/// </summary>
public sealed class WriteEnvKeyStep : SetupStep
{
    public override string Id => "write_env_key";
    public override string DisplayName => Loc.T("setup.step.key.name");

    private bool _wrote;

    public override Task<bool> CanSkipAsync(SetupContext ctx)
    {
        // OAuth/yerel gibi anahtarsız sağlayıcılarda bu adım atlanır.
        var skip = string.IsNullOrWhiteSpace(ctx.KeyEnvVar) || string.IsNullOrWhiteSpace(ctx.ApiKey);
        return Task.FromResult(skip);
    }

    public override Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct)
    {
        try
        {
            EnvFileWriter.SetValue(FetihPaths.EnvFilePath, ctx.KeyEnvVar, ctx.ApiKey);
            _wrote = true;
            // Yalnızca anahtar ADI bildirilir, DEĞERİ değil.
            return Task.FromResult(StepResult.Ok(
                string.Format(Loc.T("setup.step.key.ok"), ctx.KeyEnvVar)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(StepResult.Fail(Loc.T("setup.step.key.fail") + ex.Message));
        }
    }

    public override Task RollbackAsync(SetupContext ctx, CancellationToken ct)
    {
        try
        {
            if (_wrote)
            {
                EnvFileWriter.RemoveValue(FetihPaths.EnvFilePath, ctx.KeyEnvVar);
            }
        }
        catch
        {
            // Geri alma başarısızsa .env'de kalan satır zararsız.
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// Sağlayıcıyı ve varsayılan modeli köprünün <c>config.set</c> RPC'siyle
/// diske yazar (elle YAML düzenlemesi yok).
/// </summary>
public sealed class WriteConfigStep : SetupStep
{
    public override string Id => "write_config";
    public override string DisplayName => Loc.T("setup.step.config.name");

    public override async Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct)
    {
        try
        {
            await BridgeClient.Shared.EnsureConnectedAsync(ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(ctx.ProviderId))
            {
                await BridgeClient.Shared.ConfigSetAsync("model.provider", ctx.ProviderId, ct).ConfigureAwait(false);
            }
            if (!string.IsNullOrWhiteSpace(ctx.Model))
            {
                await BridgeClient.Shared.ConfigSetAsync("model.default", ctx.Model, ct).ConfigureAwait(false);
            }
            return StepResult.Ok(Loc.T("setup.step.config.ok"));
        }
        catch (BridgeRpcException rpc) when (rpc.Code == -32004)
        {
            return StepResult.Fail(Loc.T("setup.step.config.fail_managed") + rpc.Message);
        }
        catch (Exception ex)
        {
            return StepResult.Fail(Loc.T("setup.step.config.fail") + ex.Message);
        }
    }
}

/// <summary>Masaüstü Köprüsü sürecini başlatıp bağlanır.</summary>
public sealed class StartDesktopBridgeStep : SetupStep
{
    public override string Id => "start_bridge";
    public override string DisplayName => Loc.T("setup.step.bridge.name");

    public override async Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct)
    {
        await BridgeClient.Shared.EnsureConnectedAsync(ct).ConfigureAwait(false);
        return StepResult.Ok(string.Format(
            Loc.T("setup.step.bridge.ok"), BridgeClient.Shared.ProtocolVersion));
    }
}

/// <summary>
/// OAuth / CLI tabanlı oturum gerektiren sağlayıcılar (Gemini CLI, OpenAI Codex, Qwen, xAI vb.)
/// için kimlik doğrulamasının gerçekten tamamlandığını denetler. Önceden oturum açılmamışsa
/// kullanıcının oturum açabilmesi için görünür bir konsol penceresi açar ve sonucunu doğrular.
/// </summary>
public sealed class EnsureProviderAuthStep : SetupStep
{
    public override string Id => "ensure_provider_auth";
    public override string DisplayName => Loc.T("setup.step.auth.name");

    public override Task<bool> CanSkipAsync(SetupContext ctx)
    {
        // 1. API anahtarı girilmişse bu adım atlanır (zaten WriteEnvKeyStep yazdı).
        if (!string.IsNullOrWhiteSpace(ctx.ApiKey))
        {
            return Task.FromResult(true);
        }

        // 2. Sağlayıcı yerel sunucuysa (Ollama, LM Studio, Custom) kimlik doğrulama gerekmez.
        var p = ProviderRegistry.ById(ctx.ProviderId);
        if (p is not null && p.Kind == ProviderKind.LocalServer)
        {
            return Task.FromResult(true);
        }

        // 3. AWS SDK kimlik zinciri kullanılıyorsa atla.
        if (p is not null && p.Kind == ProviderKind.AwsSdk)
        {
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    public override async Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct)
    {
        var provider = ctx.ProviderId;
        if (string.IsNullOrWhiteSpace(provider))
        {
            return StepResult.Fail(Loc.T("setup.step.auth.noprovider"));
        }

        // 1. Köprü üzerinden oturum durumunu denetle (zaten giriş yapılmış mı?)
        try
        {
            await BridgeClient.Shared.EnsureConnectedAsync(ct).ConfigureAwait(false);
            var status = await BridgeClient.Shared.ProvidersAuthStatusAsync(provider, ct).ConfigureAwait(false);
            if (status.TryGetProperty("logged_in", out var li) && li.GetBoolean())
            {
                var email = status.TryGetProperty("email", out var em) ? em.GetString() : null;
                var accountInfo = string.IsNullOrWhiteSpace(email) ? "" : $" ({email})";
                return StepResult.Ok(string.Format(Loc.T("setup.step.auth.confirmed"), accountInfo));
            }
        }
        catch (Exception ex)
        {
            App.LogCrash("EnsureProviderAuthStep.CheckInitial", ex, ex.Message);
        }

        // 2. Henüz oturum açılmamışsa, kullanıcı için gerçek OAuth / CLI giriş sürecini başlat
        if (!BridgeLauncherProbe.HasUsablePython(out var python))
        {
            return StepResult.Fail(Loc.T("setup.step.auth.nopython"));
        }

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = python,
                UseShellExecute = true, // Kendi konsol penceresini açsın (cihaz kodu / tarayıcı yönlendirmesi için)
                WorkingDirectory = FetihPaths.RepoRootOrCurrent,
            };
            psi.ArgumentList.Add("-m");
            psi.ArgumentList.Add("fetih_cli");
            psi.ArgumentList.Add("auth");
            psi.ArgumentList.Add("add");
            psi.ArgumentList.Add(provider);

            var proc = System.Diagnostics.Process.Start(psi);
            if (proc is null)
            {
                return StepResult.Fail(string.Format(
                    Loc.T("setup.step.auth.spawn_failed"), python, provider));
            }

            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return StepResult.Fail(Loc.T("setup.step.auth.cancelled"));
        }
        catch (Exception ex)
        {
            return StepResult.Fail(Loc.T("setup.step.auth.error") + ex.Message);
        }

        // 3. Giriş süreci bittikten sonra oturumun gerçekten açıldığını doğrula
        try
        {
            await BridgeClient.Shared.EnsureConnectedAsync(ct).ConfigureAwait(false);
            var status = await BridgeClient.Shared.ProvidersAuthStatusAsync(provider, ct).ConfigureAwait(false);
            if (status.TryGetProperty("logged_in", out var li) && li.GetBoolean())
            {
                var email = status.TryGetProperty("email", out var em) ? em.GetString() : null;
                var accountInfo = string.IsNullOrWhiteSpace(email) ? "" : $" ({email})";
                return StepResult.Ok(string.Format(Loc.T("setup.step.auth.opened"), accountInfo));
            }
        }
        catch (Exception ex)
        {
            return StepResult.Fail(Loc.T("setup.step.auth.verify_failed") + ex.Message);
        }

        return StepResult.Fail(string.Format(Loc.T("setup.step.auth.incomplete"), provider));
    }
}

/// <summary>
/// Uçtan uca doğrulama: GERÇEK bir sohbet turu.
///
/// <para>Bu adım eskiden yalnızca köprüyü ping'liyor ve anahtarın
/// <c>.env</c>'de görünüp görünmediğine bakıyordu. İkisi de doğruyken bile
/// ilk mesaj <c>Unknown provider</c> ya da <c>model_not_found</c> ile
/// ölebiliyordu: anahtarın var olması, sağlayıcının çözüldüğü ya da modelin
/// hâlâ yayında olduğu anlamına gelmiyor. Tek dürüst doğrulama, kullanıcının
/// birazdan yapacağı şeyi yapmaktır — bir mesaj gönderip yanıt beklemek.</para>
///
/// <para>Tur, sohbet sayfasının kullandığı kısıtların aynısıyla gönderilir
/// (küçük araç seti, bağlam dosyaları ve hafıza atlanır): küçük bağlamlı
/// ücretsiz katmanlar tam önsözü taşıyamıyor ve doğrulama 413 ile
/// düşüyordu.</para>
/// </summary>
public sealed class VerifyEndToEndStep : SetupStep
{
    public override string Id => "verify_end_to_end";
    public override string DisplayName => Loc.T("setup.step.verify.name");

    public override async Task<StepResult> ExecuteAsync(SetupContext ctx, CancellationToken ct)
    {
        await BridgeClient.Shared.PingAsync(ct).ConfigureAwait(false);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(90));

        try
        {
            var res = await BridgeClient.Shared.SendMessageAsync(
                Loc.T("setup.step.verify.prompt"),
                stream: false,
                toolsets: new[] { "file" },
                skipContextFiles: true,
                skipMemory: true,
                ct: timeout.Token).ConfigureAwait(false);

            var text = res.ValueKind == System.Text.Json.JsonValueKind.Object &&
                       res.TryGetProperty("text", out var t)
                ? (t.GetString() ?? "")
                : "";

            return string.IsNullOrWhiteSpace(text)
                ? StepResult.Ok(Loc.T("setup.step.verify.empty"))
                : StepResult.Ok(Loc.T("setup.step.verify.ok") + Shorten(text));
        }
        catch (BridgeRpcException rpc)
        {
            // Sağlayıcı/model hatasını BURADA yakala: kullanıcı sihirbazdan
            // çıkmadan düzeltebilsin, ilk mesajında sürprizle karşılaşmasın.
            return StepResult.Fail(string.Format(
                Loc.T("setup.step.verify.fail"), rpc.Code, Shorten(rpc.Message, 260)));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return StepResult.Fail(Loc.T("setup.step.verify.timeout"));
        }
    }

    private static string Shorten(string s, int max = 120)
    {
        s = s.Replace("\r", " ").Replace("\n", " ").Trim();
        return s.Length <= max ? s : s[..max] + "…";
    }
}
