namespace Fetih.Desktop.Models;

/// <summary>
/// Ayarlar sayfalarındaki tek bir "anahtar → değer" satırı.
/// Faz 1'de tüm ayar sayfaları salt okunurdur: değerler
/// <c>~/.fetih/config.yaml</c>'dan okunur, geri yazılmaz.
/// </summary>
public sealed class SettingRow
{
    public SettingRow(string label, string value, string note = "", string configKey = "")
    {
        Label = label;
        Value = value;
        Note = note;
        ConfigKey = configKey;
    }

    /// <summary>Türkçe etiket.</summary>
    public string Label { get; }

    /// <summary>config.yaml'dan okunan değer.</summary>
    public string Value { get; }

    /// <summary>Açıklama satırı.</summary>
    public string Note { get; }

    /// <summary>Karşılık gelen config.yaml anahtarı (ör. <c>terminal.backend</c>).</summary>
    public string ConfigKey { get; }

    public bool HasNote => !string.IsNullOrWhiteSpace(Note);

    public bool HasConfigKey => !string.IsNullOrWhiteSpace(ConfigKey);
}

/// <summary>
/// Sağlayıcı sayfasındaki tek bir API anahtarı satırı.
/// <b>Değer asla tutulmaz veya gösterilmez</b> — yalnızca tanımlı/tanımsız durumu.
/// </summary>
public sealed class EnvKeyRow
{
    public EnvKeyRow(string variableName, string statusLabel, bool isDefined, string sourceLabel)
    {
        VariableName = variableName;
        StatusLabel = statusLabel;
        IsDefined = isDefined;
        SourceLabel = sourceLabel;
    }

    /// <summary>Ortam değişkeninin adı.</summary>
    public string VariableName { get; }

    /// <summary>"Tanımlı" / "Tanımsız".</summary>
    public string StatusLabel { get; }

    public bool IsDefined { get; }

    /// <summary>Nerede tanımlı olduğu (ortam değişkeni / .env dosyası).</summary>
    public string SourceLabel { get; }

    public string StatusBrushKey => IsDefined
        ? "SystemFillColorSuccessBrush"
        : "SystemFillColorNeutralBrush";
}

/// <summary>Sağlayıcı kartı için görünüm modeli.</summary>
public sealed class ProviderRow
{
    public ProviderRow(
        string displayName,
        string id,
        string transport,
        string auth,
        string badges,
        bool isConfigured,
        bool isActive,
        System.Collections.Generic.IReadOnlyList<EnvKeyRow> keys)
    {
        DisplayName = displayName;
        Id = id;
        Transport = transport;
        Auth = auth;
        Badges = badges;
        IsConfigured = isConfigured;
        IsActive = isActive;
        Keys = keys;
    }

    public string DisplayName { get; }

    public string Id { get; }

    public string Transport { get; }

    public string Auth { get; }

    /// <summary>"Toplayıcı", "Yerel" gibi ek etiketler.</summary>
    public string Badges { get; }

    /// <summary>Gerekli anahtarlardan en az biri tanımlı mı?</summary>
    public bool IsConfigured { get; }

    /// <summary>config.yaml'daki <c>model.provider</c> bu sağlayıcı mı?</summary>
    public bool IsActive { get; }

    public System.Collections.Generic.IReadOnlyList<EnvKeyRow> Keys { get; }

    public bool HasKeys => Keys.Count > 0;

    public bool HasBadges => !string.IsNullOrWhiteSpace(Badges);

    public string StatusLabel => IsConfigured ? "Kimlik bilgisi tanımlı" : "Kimlik bilgisi yok";

    public string StatusBrushKey => IsConfigured
        ? "SystemFillColorSuccessBrush"
        : "SystemFillColorNeutralBrush";

    public string MetaLine => $"{Id} · {Transport} · {Auth}";
}
