using System;
using System.Collections.Generic;
using System.Globalization;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Fetih.Desktop.Views;
using Xunit;

namespace Fetih.Desktop.Tests;

public class ActivityTests
{
    // ── 1. Temel Girdi ve Boşluk Denetimleri ─────────────────────────────────

    [Fact]
    public void ActivityLabelBuilder_Empty_ReturnsNull()
    {
        Assert.Null(ActivityLabelBuilder.BuildLabel(""));
        Assert.Null(ActivityLabelBuilder.BuildLabel(null));
    }

    [Fact]
    public void ActivityLabelBuilder_WhitespaceOnly_ReturnsNull()
    {
        Assert.Null(ActivityLabelBuilder.BuildLabel("   \r\n\t  "));
    }

    [Fact]
    public void ActivityLabelBuilder_SingleWord_ReturnsWord()
    {
        Assert.Equal("İnceleme", ActivityLabelBuilder.BuildLabel("İnceleme"));
    }

    // ── 2. Eşik ve Kilit Kuralı Denetimleri ──────────────────────────────────

    [Fact]
    public void ActivityGroup_14Characters_RemainsThinkingAndUnlocked()
    {
        Loc.SetPreference("tr");
        var group = new ActivityGroup();

        // 14 karakter: eşiğin altında (< 15), ActivityLabels.Thinking kalmalı ve kilitlenmemeli
        group.UpdateThoughtText("Kısa metin bir");
        Assert.Equal(Loc.T("Activity_Thinking"), group.Label);
        Assert.False(group.IsLabelLocked);
    }

    [Fact]
    public void ActivityGroup_LockRule_LocksOnceAfterThreshold()
    {
        Loc.SetPreference("tr");
        var group = new ActivityGroup();

        // 15+ karakter ve cümle tamamlanışı: kilitlenmeli
        group.UpdateThoughtText("Hedef portlar taranıyor. İkinci cümle başladı.");
        Assert.True(group.IsLabelLocked);
        var lockedLabel = group.Label;
        Assert.Equal("Hedef portlar taranıyor", lockedLabel);

        // Sonradan gelen daha fazla metin etiketi değiştirmemeli
        group.UpdateThoughtText("Hedef portlar taranıyor. İkinci cümle başladı. Üçüncü cümle devam ediyor.");
        Assert.Equal(lockedLabel, group.Label);
    }

    // ── 3. Uzun Cümle, Kısaltma ve Çift Üç Nokta Denetimleri ─────────────────

    [Fact]
    public void ActivityLabelBuilder_300CharacterSingleSentence_TruncatedAtWordBoundaryWithEllipsis()
    {
        var input = "Bu test cümlesi yaklaşık üç yüz karakter uzunluğunda tasarlanmış olup hiçbir ara noktalama işareti içermemektedir ve tek bir akıcı düşünce zincirini temsil ederek karakter sınırını aşan uzun metinlerin kelime sınırında kesilip kesilmediğini ve cümlenin sonunda düzgün bir üç nokta yer alıp almadığını doğrulamak amacıyla yazılmıştır test.";
        var result = ActivityLabelBuilder.BuildLabel(input);

        Assert.NotNull(result);
        Assert.True(new StringInfo(result).LengthInTextElements <= 61); // 60 grapheme + '…'
        Assert.EndsWith("…", result);
        Assert.DoesNotContain("……", result);
    }

    [Fact]
    public void ActivityLabelBuilder_TextWithoutTerminators_HandledGracefully()
    {
        var input = "Sonlandırıcı noktalama işareti olmayan düşünce metni akışı";
        var result = ActivityLabelBuilder.BuildLabel(input);
        Assert.Equal("Sonlandırıcı noktalama işareti olmayan düşünce metni akışı", result);
    }

    [Fact]
    public void ActivityLabelBuilder_NoDoubleEllipsisAtEnd()
    {
        var dots = "Hedef aranıyor...";
        Assert.Equal("Hedef aranıyor", ActivityLabelBuilder.BuildLabel(dots));

        var singleEllipsis = "Hedef taranıyor…";
        Assert.Equal("Hedef taranıyor", ActivityLabelBuilder.BuildLabel(singleEllipsis));

        var longWithDots = "Bu çok uzun bir düşünce cümlesidir ve amacı 60 karakterlik sınırı aşarak kesilmektir kesinlikle...";
        var res = ActivityLabelBuilder.BuildLabel(longWithDots);
        Assert.NotNull(res);
        Assert.EndsWith("…", res);
        Assert.DoesNotContain("……", res);
    }

    // ── 4. Unicode, Türkçe, Emoji, Aksan ve Grapheme Cluster Denetimleri ─────

    [Fact]
    public void ActivityLabelBuilder_TurkishCharacters_HandledCorrectly()
    {
        var trText = "İstanbul'da ığüşöç İĞÜŞÖÇ karakterleri kontrol ediliyor.";
        var trRes = ActivityLabelBuilder.BuildLabel(trText);
        Assert.Equal("İstanbul'da ığüşöç İĞÜŞÖÇ karakterleri kontrol ediliyor", trRes);
    }

    [Fact]
    public void ActivityLabelBuilder_Emoji_HandledSafely()
    {
        var emojiText = "Tarama başlatıldı 👍 ve sonuçlar inceleniyor 🚀.";
        var emojiRes = ActivityLabelBuilder.BuildLabel(emojiText);
        Assert.Equal("Tarama başlatıldı 👍 ve sonuçlar inceleniyor 🚀", emojiRes);
    }

    [Fact]
    public void ActivityLabelBuilder_FamilyEmojiZwjSequence_TreatedAsSingleGrapheme()
    {
        // Aile emojisi ZWJ dizisidir: 👨 + ZWJ + 👩 + ZWJ + 👧
        var familyText = "Kullanıcı grubu 👨‍👩‍👧 analiz ediliyor.";
        var familyRes = ActivityLabelBuilder.BuildLabel(familyText);
        Assert.Equal("Kullanıcı grubu 👨‍👩‍👧 analiz ediliyor", familyRes);
    }

    [Fact]
    public void ActivityLabelBuilder_FlagEmoji_HandledAsSingleCluster()
    {
        // Bayrak emojisi iki bölgesel gösterge (regional indicator) çiftidir: 🇹 + 🇷
        var flagText = "Türkiye lokasyonu 🇹🇷 için sunucular taranıyor.";
        var flagRes = ActivityLabelBuilder.BuildLabel(flagText);
        Assert.Equal("Türkiye lokasyonu 🇹🇷 için sunucular taranıyor", flagRes);
    }

    [Fact]
    public void ActivityLabelBuilder_CombiningAccent_HandledAsSingleCluster()
    {
        // Birleşik aksan: e + acute accent (U+0301)
        var accentText = "Caf\u0065\u0301 menüsü analiz ediliyor.";
        var accentRes = ActivityLabelBuilder.BuildLabel(accentText);
        Assert.Equal("Caf\u0065\u0301 menüsü analiz ediliyor", accentRes);
    }

    [Fact]
    public void ActivityLabelBuilder_Truncation_DoesNotSplitGraphemeClusters()
    {
        // 50 karakter metin + 👨‍👩‍👧 (ZWJ sekansı) + kalan metin (toplamda 60'ı geçer)
        var input = "Bu bir güvenlik denetimidir ve hedef kullanıcı grubu 👨‍👩‍👧 profili ayrıntılı biçimde incelenmektedir.";
        var result = ActivityLabelBuilder.BuildLabel(input);

        Assert.NotNull(result);
        Assert.EndsWith("…", result);
        // Kesilme grapheme kümesini parçalamamalıdır
        var si = new StringInfo(result);
        Assert.True(si.LengthInTextElements <= 61);
    }

    // ── 5. Markdown ve Cümle Çıkarma Denetimleri ────────────────────────────

    [Fact]
    public void ActivityLabelBuilder_MarkdownStripping_CleansFormatting()
    {
        var input = "**Önce** dosyayı `config.json` oku ve incele.";
        var result = ActivityLabelBuilder.BuildLabel(input);
        Assert.Equal("Önce dosyayı config.json oku ve incele", result);

        var headerInput = "### Hedef sistem taranıyor\nİkinci satır";
        Assert.Equal("Hedef sistem taranıyor", ActivityLabelBuilder.BuildLabel(headerInput));

        var listInput = "- İlk adım olarak portları kontrol et.";
        Assert.Equal("İlk adım olarak portları kontrol et", ActivityLabelBuilder.BuildLabel(listInput));
    }

    [Fact]
    public void ActivityLabelBuilder_DoesNotSplitOnNumbersAndAbbreviations()
    {
        var input = "Python v1.2 ve pi 3.14 değerleri örn. test için okunuyor.";
        var result = ActivityLabelBuilder.BuildLabel(input);
        Assert.Equal("Python v1.2 ve pi 3.14 değerleri örn. test için okunuyor", result);
    }

    [Fact]
    public void ActivityLabelBuilder_ExtractsFirstSentenceOnPunctuation()
    {
        var input = "Hedef sunucuya ping atılıyor: yanıt bekleniyor. İkinci cümle.";
        var result = ActivityLabelBuilder.BuildLabel(input);
        Assert.Equal("Hedef sunucuya ping atılıyor", result);

        var exclamation = "Ağ bağlantısı başarılı! Şimdi tarama başlayacak.";
        Assert.Equal("Ağ bağlantısı başarılı", ActivityLabelBuilder.BuildLabel(exclamation));

        var question = "Port açık mı? Kontrol edelim.";
        Assert.Equal("Port açık mı", ActivityLabelBuilder.BuildLabel(question));
    }

    // ── 6. SummaryText Türkçe ve İngilizce Varyant Denetimleri ───────────────

    [Fact]
    public void ActivityGroup_SummaryText_Turkish_AllVariants()
    {
        Loc.SetPreference("tr");

        // 1. Yalnızca düşünce
        var g1 = new ActivityGroup { Label = "Talebi inceliyor" };
        g1.Complete(false, TimeSpan.FromSeconds(10));
        Assert.Equal("Talebi inceliyor · 10 sn", g1.SummaryText);

        // 2. 1 işlem tekil
        var g2 = new ActivityGroup { Label = "Talebi inceliyor" };
        g2.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g2.Complete(false, TimeSpan.FromSeconds(12));
        Assert.Equal("Talebi inceliyor · 1 işlem · 12 sn", g2.SummaryText);

        // 3. Çoklu araç (3 işlem)
        var g3 = new ActivityGroup { Label = "Yeni prompt hazırlanıyor" };
        g3.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g3.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g3.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g3.Complete(false, TimeSpan.FromSeconds(26));
        Assert.Equal("Yeni prompt hazırlanıyor · 3 işlem · 26 sn", g3.SummaryText);

        // 4. Araç + 1 Hata
        var g4 = new ActivityGroup { Label = "Komut çalıştırılıyor…" };
        g4.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g4.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Error });
        g4.Complete(false, TimeSpan.FromSeconds(15));
        Assert.Equal("Komut çalıştırılıyor… · 2 işlem · 1 hata · 15 sn", g4.SummaryText);

        // 5. Durduruldu (Cancelled)
        var g5 = new ActivityGroup { Label = "Kodlanıyor…" };
        g5.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Cancelled });
        g5.Complete(true, TimeSpan.FromSeconds(8));
        Assert.Equal("Kodlanıyor… · 1 işlem · durduruldu · 8 sn", g5.SummaryText);

        // 6. 60 saniyenin üzeri süre formatı (1 dk 15 sn)
        var g6 = new ActivityGroup { Label = "Büyük dosya taranıyor" };
        g6.Complete(false, TimeSpan.FromSeconds(75));
        Assert.Equal("Büyük dosya taranıyor · 1 dk 15 sn", g6.SummaryText);
    }

    [Fact]
    public void ActivityGroup_SummaryText_English_AllVariants()
    {
        Loc.SetPreference("en");

        // 1. Thought only
        var g1 = new ActivityGroup { Label = "Analyzing request" };
        g1.Complete(false, TimeSpan.FromSeconds(10));
        Assert.Equal("Analyzing request · 10 s", g1.SummaryText);

        // 2. 1 action singular
        var g2 = new ActivityGroup { Label = "Analyzing request" };
        g2.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g2.Complete(false, TimeSpan.FromSeconds(12));
        Assert.Equal("Analyzing request · 1 action · 12 s", g2.SummaryText);

        // 3. Multiple tools (3 actions)
        var g3 = new ActivityGroup { Label = "Writing code…" };
        g3.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g3.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g3.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g3.Complete(false, TimeSpan.FromSeconds(26));
        Assert.Equal("Writing code… · 3 actions · 26 s", g3.SummaryText);

        // 4. Tool + 1 error
        var g4 = new ActivityGroup { Label = "Writing code…" };
        g4.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Success });
        g4.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Error });
        g4.Complete(false, TimeSpan.FromSeconds(20));
        Assert.Equal("Writing code… · 2 actions · 1 error · 20 s", g4.SummaryText);

        // 5. Cancelled / stopped
        var g5 = new ActivityGroup { Label = "Writing code…" };
        g5.Steps.Add(new ChatMessage(ChatRole.Tool) { Status = ToolStatus.Cancelled });
        g5.Complete(true, TimeSpan.FromSeconds(8));
        Assert.Equal("Writing code… · 1 action · stopped · 8 s", g5.SummaryText);

        // 6. Over 60 seconds
        var g6 = new ActivityGroup { Label = "Scanning large repository" };
        g6.Complete(false, TimeSpan.FromSeconds(75));
        Assert.Equal("Scanning large repository · 1 m 15 s", g6.SummaryText);
    }

    // ── 7. TranscriptBuilder Grup Bölme ve Geçmiş Yükleme Denetimleri ────────

    [Fact]
    public void TranscriptBuilder_SplitsGroupsCorrectly_AndHandlesCancelledTools()
    {
        Loc.SetPreference("tr");

        var items = new List<StoredItem>
        {
            new("user", "Merhaba dosya oluştur", null, null, null, null, null),
            // Grup 1: düşünce + araç
            new("thought", "Dosya oluşturma planı yapılıyor.", null, null, null, null, 2500, 100.0, 102.5),
            new("tool_call", null, "call-1", "write_file", "{\"path\":\"a.txt\"}", null, null),
            new("tool_result", null, "call-1", "write_file", null, "OK", 1200),
            // Araya ajan metni giriyor -> Grup 1 kapanmalı
            new("assistant", "Dosyayı oluşturdum.", null, null, null, null, null),
            // Grup 2: düşünce + sonuçsuz kalan araç -> ToolStatus.Cancelled olmalı
            new("thought", "İkinci dosyayı hazırlıyorum.", null, null, null, null, 1500, 105.0, 106.5),
            new("tool_call", null, "call-2", "terminal", "{\"command\":\"ls\"}", null, null),
            // Legacy süresiz düşünce
            new("assistant", "Bitti.", null, null, null, null, null),
            new("thought", "Eski kayıt düşüncesi.", null, null, null, null, null)
        };

        var messages = TranscriptBuilder.Build(items);

        // Beklenen sıralama:
        // 0: User ("Merhaba dosya oluştur")
        // 1: ActivityGroup 1 (plan yapılıyor, 1 tool)
        // 2: Agent ("Dosyayı oluşturdum.")
        // 3: ActivityGroup 2 (hazırlıyorum, 1 tool - Cancelled)
        // 4: Agent ("Bitti.")
        // 5: ActivityGroup 3 (Eski kayıt - süresiz)
        Assert.Equal(6, messages.Count);

        Assert.Equal(ChatRole.User, messages[0].Role);
        Assert.Equal(ChatRole.Activity, messages[1].Role);
        Assert.Equal(ChatRole.Agent, messages[2].Role);
        Assert.Equal(ChatRole.Activity, messages[3].Role);
        Assert.Equal(ChatRole.Agent, messages[4].Role);
        Assert.Equal(ChatRole.Activity, messages[5].Role);

        var act1 = (ActivityGroup)messages[1];
        Assert.True(act1.Duration.HasValue);
        Assert.True(act1.Duration.Value.TotalMilliseconds > 0);

        var act2 = (ActivityGroup)messages[3];
        var uncompletedTool = act2.Steps[1];
        Assert.Equal(ToolStatus.Cancelled, uncompletedTool.Status);

        var act3 = (ActivityGroup)messages[5];
        // Süresiz eski kayıt "0 sn" içermemeli
        Assert.DoesNotContain("0 sn", act3.SummaryText);
    }

    // ── 10. Canlı Etiket ve Araç Etiketi Denetimleri (ToolLabelBuilder) ───────

    [Fact]
    public void ToolLabelBuilder_Terminal_MasksSecretsAndExtractsFirstLine()
    {
        Loc.SetPreference("tr");
        var args = "{\"command\": \"curl -H 'Authorization: Bearer my_secret_token_12345' https://api.fetih.dev\\nnext line\"}";
        var label = ToolLabelBuilder.BuildLabel("terminal", args);

        Assert.NotNull(label);
        Assert.DoesNotContain("my_secret_token_12345", label);
        Assert.Contains("Bearer ***", label);
        Assert.DoesNotContain("next line", label);
    }

    [Fact]
    public void ToolLabelBuilder_ReadFile_ExtractsFileName()
    {
        Loc.SetPreference("tr");
        var args = "{\"path\": \"C:\\\\Users\\\\Project\\\\src\\\\config.json\"}";
        var label = ToolLabelBuilder.BuildLabel("read_file", args);

        Assert.NotNull(label);
        Assert.Contains("config.json", label);
    }

    [Fact]
    public void ToolLabelBuilder_WriteFile_ExtractsFileName()
    {
        Loc.SetPreference("tr");
        var args = "{\"TargetFile\": \"/etc/nginx/sites-available/default\"}";
        var label = ToolLabelBuilder.BuildLabel("write_file", args);

        Assert.NotNull(label);
        Assert.Contains("default", label);
    }

    [Fact]
    public void ToolLabelBuilder_SearchWeb_ExtractsAndMasksQuery()
    {
        Loc.SetPreference("tr");
        var args = "{\"query\": \"fetih agent password=SuperSecretPassword123\"}";
        var label = ToolLabelBuilder.BuildLabel("search_web", args);

        Assert.NotNull(label);
        Assert.DoesNotContain("SuperSecretPassword123", label);
        Assert.Contains("password=***", label);
    }

    [Fact]
    public void ToolLabelBuilder_ReadUrl_ExtractsHost()
    {
        Loc.SetPreference("tr");
        var args = "{\"url\": \"https://github.com/google/fetih/issues/42\"}";
        var label = ToolLabelBuilder.BuildLabel("read_url_content", args);

        Assert.NotNull(label);
        Assert.Contains("github.com", label);
    }

    [Fact]
    public void ToolLabelBuilder_NullOrEmptyArguments_FallsBackToDefaultTool()
    {
        Loc.SetPreference("tr");
        var label = ToolLabelBuilder.BuildLabel("custom_scanner", "");
        Assert.NotNull(label);
        Assert.Contains("custom_scanner", label);
    }

    [Fact]
    public void ActivityLabelBuilder_RawThoughtLeaks_Rejected()
    {
        Assert.Null(ActivityLabelBuilder.BuildLabel("kullanıcı benden dosyayı silmemi istiyor."));
        Assert.Null(ActivityLabelBuilder.BuildLabel("The user wants to analyze the logs first."));
        Assert.Null(ActivityLabelBuilder.BuildLabel("Okay, let's explore the directory structure."));
        Assert.Null(ActivityLabelBuilder.BuildLabel("I should check if the server is running."));
        Assert.Null(ActivityLabelBuilder.BuildLabel("I need to verify authentication keys."));
    }

    [Fact]
    public void TranscriptBuilder_WithStoredLabel_RestoresLabelOnGroup()
    {
        var items = new List<StoredItem>
        {
            new("thought", "Düşünce metni...", null, null, null, null, 1500, null, null, "Kimlik doğrulama kodu analiz ediliyor")
        };

        var messages = TranscriptBuilder.Build(items);
        Assert.Single(messages);
        Assert.IsType<ActivityGroup>(messages[0]);
        var group = (ActivityGroup)messages[0];
        Assert.Equal("Kimlik doğrulama kodu analiz ediliyor", group.Label);
    }
}
