namespace Fetih.Desktop.Bridge;

/// <summary>Kalıcı depolanmış transcript öğesi.</summary>
public sealed record StoredItem(
    string Kind,
    string? Text,
    string? CallId,
    string? Name,
    string? Args,
    string? Result,
    double? DurationMs,
    double? TsStart = null,
    double? TsEnd = null);
