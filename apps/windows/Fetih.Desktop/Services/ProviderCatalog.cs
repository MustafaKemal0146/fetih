using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;

namespace Fetih.Desktop.Services;

/// <summary>
/// Sağlayıcı kataloğunun CANLI kaynağı.
///
/// <para><b>Neden var:</b> <see cref="ProviderRegistry"/> elle tutulan bir C#
/// tablosudur. Oradaki bir kimlik Python tarafındaki
/// <c>auth.PROVIDER_REGISTRY</c>'den saparsa, kurulum sihirbazı sorunsuz
/// tamamlanır ve ilk sohbet mesajı <c>Unknown provider '&lt;id&gt;'</c> ile ölür —
/// kullanıcıya iki ekran arayla iki farklı gerçek anlatılmış olur. Bu sınıf
/// listeyi köprünün <c>providers.catalog</c> RPC'sinden, yani
/// <c>resolve_provider()</c>'ın baktığı kayıt defterinin ta kendisinden alır.
/// Listelenen bir kimlik, tanım gereği çözülebilir bir kimliktir.</para>
///
/// <para>Köprü henüz ayakta değilken (ilk çizim, çevrimdışı tanılama)
/// <see cref="ProviderRegistry.All"/> yedeğe düşülür. Yedek, kimliklerin
/// kaynağı değil; yalnızca köprü konuşana kadarki geçici görüntüdür.</para>
/// </summary>
public static class ProviderCatalog
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static IReadOnlyList<ProviderEntry>? _live;

    /// <summary>Canlı katalog alındı mı? (Tanılama sayfası bunu gösterir.)</summary>
    public static bool IsLive => _live is not null;

    /// <summary>
    /// En iyi bilinen katalog: köprüden alınmışsa o, yoksa gömülü yedek.
    /// Ağ/köprü beklemez — çağıran taze liste istiyorsa
    /// <see cref="RefreshAsync"/> kullanmalı.
    /// </summary>
    public static IReadOnlyList<ProviderEntry> Current => _live ?? ProviderRegistry.All;

    /// <summary>
    /// Kataloğu köprüden tazeler. Başarısız olursa sessizce yedekte kalır —
    /// sihirbaz köprü çökmüş diye açılamaz hâle gelmemeli.
    /// </summary>
    public static async Task<IReadOnlyList<ProviderEntry>> RefreshAsync(CancellationToken ct = default)
    {
        await Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var res = await BridgeClient.Shared.ProvidersCatalogAsync(ct).ConfigureAwait(false);
            var parsed = Parse(res);
            if (parsed.Count > 0)
            {
                _live = parsed;
            }
        }
        catch
        {
            // Köprü yok / RPC eski sürüm: yedek listeyle devam.
        }
        finally
        {
            Gate.Release();
        }

        return Current;
    }

    /// <summary>Kimliğe göre kayıt (canlı katalogda yoksa yedeğe bakar).</summary>
    public static ProviderEntry? ById(string id)
    {
        foreach (var p in Current)
        {
            if (string.Equals(p.Id, id, StringComparison.Ordinal))
            {
                return p;
            }
        }
        return ProviderRegistry.ById(id);
    }

    private static IReadOnlyList<ProviderEntry> Parse(JsonElement res)
    {
        var list = new List<ProviderEntry>();
        if (res.ValueKind != JsonValueKind.Object ||
            !res.TryGetProperty("providers", out var arr) ||
            arr.ValueKind != JsonValueKind.Array)
        {
            return list;
        }

        foreach (var p in arr.EnumerateArray())
        {
            var id = Str(p, "id");
            if (id.Length == 0)
            {
                continue;
            }

            var envVars = new List<string>();
            if (p.TryGetProperty("api_key_env_vars", out var ev) && ev.ValueKind == JsonValueKind.Array)
            {
                foreach (var v in ev.EnumerateArray())
                {
                    if (v.ValueKind == JsonValueKind.String)
                    {
                        envVars.Add(v.GetString() ?? "");
                    }
                }
            }

            // Yerel tablodaki insan-dostu Türkçe adı ve "toplayıcı" işaretini
            // koru: Python tarafı bunları taşımıyor, ama kimlikler oradan
            // geliyor. Yani KİMLİK canlı, SUNUM yerel.
            var local = ProviderRegistry.ById(id);

            list.Add(new ProviderEntry(
                Id: id,
                DisplayName: local?.DisplayName is { Length: > 0 } dn ? dn : Str(p, "display_name", Str(p, "name", id)),
                Transport: Str(p, "api_mode", local?.Transport ?? "chat_completions"),
                AuthType: Str(p, "auth_type", local?.AuthType ?? "api_key"),
                ApiKeyEnvVars: envVars.Count > 0 ? envVars : (local?.ApiKeyEnvVars ?? Array.Empty<string>()),
                BaseUrlEnvVar: Str(p, "base_url_env_var", local?.BaseUrlEnvVar ?? ""),
                IsAggregator: local?.IsAggregator ?? false,
                IsLocal: Bool(p, "is_local", local?.IsLocal ?? false),
                Kind: KindFrom(Str(p, "kind"), local?.Kind ?? ProviderKind.CloudApiKey),
                DefaultBaseUrl: Str(p, "base_url", local?.DefaultBaseUrl ?? ""),
                SignupUrl: Str(p, "signup_url", local?.SignupUrl ?? ""),
                CliCommand: local?.CliCommand ?? ""));
        }

        return list;
    }

    private static ProviderKind KindFrom(string kind, ProviderKind fallback) => kind switch
    {
        "local_server" => ProviderKind.LocalServer,
        "cli_login" => ProviderKind.CliLogin,
        "aws_sdk" => ProviderKind.AwsSdk,
        "cloud_api_key" => ProviderKind.CloudApiKey,
        "no_auth" => ProviderKind.LocalServer,
        _ => fallback,
    };

    private static string Str(JsonElement e, string name, string fallback = "")
        => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? (v.GetString() ?? fallback)
            : fallback;

    private static bool Bool(JsonElement e, string name, bool fallback)
        => e.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? v.GetBoolean()
            : fallback;
}
