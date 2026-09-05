using System;
using System.Collections.Generic;

namespace Fetih.Desktop.Services;

/// <summary>
/// İki dilli sabit metin. <see cref="Value"/> etkin arayüz diline göre çözülür.
/// </summary>
public readonly record struct Text2(string Tr, string En)
{
    /// <summary>Etkin dildeki karşılık.</summary>
    public string Value => Loc.Current == UiLanguage.Turkish ? Tr : En;

    /// <summary>Her iki dilde de boş mu?</summary>
    public bool IsEmpty => string.IsNullOrEmpty(Tr) && string.IsNullOrEmpty(En);
}

/// <summary>Sadeleştirilmiş ayar sayfalarındaki kontrol türü.</summary>
public enum SimpleKind
{
    /// <summary>Aç/kapa anahtarı (bool config anahtarı).</summary>
    Toggle,

    /// <summary>Az sayıda seçenek: her biri başlık + açıklamalı radyo düğmesi.</summary>
    Choice,

    /// <summary>Çok seçenekli açılır liste + seçime göre değişen açıklama.</summary>
    Select,

    /// <summary>Sayı kutusu (+ birim etiketi).</summary>
    Number,

    /// <summary>Tek satırlık metin kutusu.</summary>
    Text,

    /// <summary>Salt okunur dize listesi (+ isteğe bağlı "boşalt" düğmesi).</summary>
    StringList,

    /// <summary>Arayüz dili seçicisi — config.yaml'da değil, yerel tercihte tutulur.</summary>
    Language,

    /// <summary>Yalnızca bilgi veren, hiçbir anahtara bağlı olmayan satır.</summary>
    Note,
}

/// <summary>Bir <see cref="SimpleKind.Choice"/> / <see cref="SimpleKind.Select"/> seçeneği.</summary>
public sealed record SimpleOption(string Value, Text2 Title, Text2 Description);

/// <summary>
/// Sadeleştirilmiş tek bir ayar kontrolü. <see cref="Key"/> gerçek config
/// anahtarıdır — sunum sadeleşir, yazılan yer aynı kalır (Detaylı Mod ile
/// birebir senkron).
/// </summary>
public sealed class SimpleControl
{
    /// <summary>Kontrol türü.</summary>
    public SimpleKind Kind { get; init; } = SimpleKind.Toggle;

    /// <summary>Yazılacak ham config anahtarı (ör. <c>security.tirith_enabled</c>).</summary>
    public string Key { get; init; } = string.Empty;

    /// <summary>Gündelik dilde başlık.</summary>
    public Text2 Title { get; init; }

    /// <summary>Ne işe yaradığını ve değiştirilirse ne olacağını anlatan tek cümle.</summary>
    public Text2 Description { get; init; }

    /// <summary>Segoe Fluent Icons kod noktası; boşsa anahtardan türetilir.</summary>
    public string Glyph { get; init; } = string.Empty;

    /// <summary>Choice / Select seçenekleri.</summary>
    public IReadOnlyList<SimpleOption> Options { get; init; } = Array.Empty<SimpleOption>();

    /// <summary>Number için alt sınır.</summary>
    public double Min { get; init; }

    /// <summary>Number için üst sınır.</summary>
    public double Max { get; init; } = 1_000_000;

    /// <summary>Number kutusunun sağındaki birim etiketi ("saniye", "MB"…).</summary>
    public Text2 Unit { get; init; }

    /// <summary>StringList boşken gösterilecek açıklama.</summary>
    public Text2 EmptyNote { get; init; }

    /// <summary>StringList için "listeyi boşalt" düğmesi çizilsin mi?</summary>
    public bool AllowClear { get; init; }

    /// <summary>
    /// Anahtar config'de yoksa da kontrolü çiz (Language gibi anahtarsız
    /// kontroller ve henüz yazılmamış varsayılanlar için).
    /// </summary>
    public bool AlwaysShow { get; init; }
}

/// <summary>"Hangi komutlar onay ister?" gibi salt okunur referans satırı.</summary>
public sealed class SimpleFact
{
    /// <summary>Kısa başlık.</summary>
    public Text2 Title { get; init; }

    /// <summary>Açıklama.</summary>
    public Text2 Detail { get; init; }
}

/// <summary>Sadeleştirilmiş sayfadaki bir kart.</summary>
public sealed class SimpleSection
{
    /// <summary>Kart başlığı.</summary>
    public Text2 Title { get; init; }

    /// <summary>Kart altbaşlığı.</summary>
    public Text2 Description { get; init; }

    /// <summary>Kart ikonu.</summary>
    public string Glyph { get; init; } = "";

    /// <summary>Doğrudan görünen kontroller.</summary>
    public IReadOnlyList<SimpleControl> Controls { get; init; } = Array.Empty<SimpleControl>();

    /// <summary>"Gelişmiş" genişleticisi içinde gizlenen, nadiren değişen kontroller.</summary>
    public IReadOnlyList<SimpleControl> Advanced { get; init; } = Array.Empty<SimpleControl>();

    /// <summary>Salt okunur referans listesi (genişletici içinde).</summary>
    public IReadOnlyList<SimpleFact> Facts { get; init; } = Array.Empty<SimpleFact>();

    /// <summary>Referans listesinin başlığı.</summary>
    public Text2 FactsTitle { get; init; }
}

/// <summary>Sadeleştirilmiş bir ayar sayfasının tam tanımı.</summary>
public sealed class SimplePage
{
    /// <summary>Gezinme parametresi olarak kullanılan kimlik.</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>Sayfa başlığı.</summary>
    public Text2 Title { get; init; }

    /// <summary>Sayfanın ne işe yaradığını anlatan giriş cümlesi.</summary>
    public Text2 Intro { get; init; }

    /// <summary>Kartlar.</summary>
    public IReadOnlyList<SimpleSection> Sections { get; init; } = Array.Empty<SimpleSection>();
}
