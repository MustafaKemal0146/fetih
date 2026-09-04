using System;
using System.Collections.Generic;
using Fetih.Desktop.Models;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// Ses ayarları. Kaynak: <c>~/.fetih/config.yaml</c> içindeki <c>tts</c>,
/// <c>stt</c> ve <c>voice</c> bölümleri (Python karşılıkları
/// <c>fetih_cli/config.py</c> DEFAULT_CONFIG ve <c>fetih_cli/voice.py</c>).
/// </summary>
public sealed partial class VoicePage : Page
{
    public VoicePage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        Populate();
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        FetihConfigService.Current.Reload();
        Populate();
    }

    private void Populate()
    {
        try
        {
            var config = FetihConfigService.Current.Config;
            var ttsProvider = config.GetString("tts.provider") ?? string.Empty;
            var sttProvider = config.GetString("stt.provider") ?? string.Empty;

            var ttsRows = new List<SettingRow>
            {
                new("Sağlayıcı", string.IsNullOrWhiteSpace(ttsProvider) ? "(tanımsız)" : ttsProvider,
                    "Seçenekler: edge (ücretsiz), elevenlabs, openai, xai, minimax, mistral, gemini, " +
                    "neutts / kittentts / piper (yerel).",
                    "tts.provider"),
            };

            // Yalnızca etkin sağlayıcının kendi alt ayarları gösterilir —
            // config.yaml tüm sağlayıcıların varsayılanlarını taşır.
            switch (ttsProvider)
            {
                case "edge":
                    ttsRows.Add(new SettingRow("Ses", config.GetDisplay("tts.edge.voice"), configKey: "tts.edge.voice"));
                    break;
                case "elevenlabs":
                    ttsRows.Add(new SettingRow("Ses kimliği", config.GetDisplay("tts.elevenlabs.voice_id"), configKey: "tts.elevenlabs.voice_id"));
                    ttsRows.Add(new SettingRow("Model", config.GetDisplay("tts.elevenlabs.model_id"), configKey: "tts.elevenlabs.model_id"));
                    break;
                case "openai":
                    ttsRows.Add(new SettingRow("Model", config.GetDisplay("tts.openai.model"), configKey: "tts.openai.model"));
                    ttsRows.Add(new SettingRow("Ses", config.GetDisplay("tts.openai.voice"), configKey: "tts.openai.voice"));
                    break;
                case "xai":
                    ttsRows.Add(new SettingRow("Ses kimliği", config.GetDisplay("tts.xai.voice_id"), configKey: "tts.xai.voice_id"));
                    ttsRows.Add(new SettingRow("Dil", config.GetDisplay("tts.xai.language"), configKey: "tts.xai.language"));
                    break;
                case "mistral":
                    ttsRows.Add(new SettingRow("Model", config.GetDisplay("tts.mistral.model"), configKey: "tts.mistral.model"));
                    ttsRows.Add(new SettingRow("Ses kimliği", config.GetDisplay("tts.mistral.voice_id"), configKey: "tts.mistral.voice_id"));
                    break;
                case "neutts":
                    ttsRows.Add(new SettingRow("Model", config.GetDisplay("tts.neutts.model"), configKey: "tts.neutts.model"));
                    ttsRows.Add(new SettingRow("Aygıt", config.GetDisplay("tts.neutts.device"), "cpu / cuda / mps", "tts.neutts.device"));
                    break;
                case "piper":
                    ttsRows.Add(new SettingRow("Ses", config.GetDisplay("tts.piper.voice"), configKey: "tts.piper.voice"));
                    break;
            }

            TtsRows.ItemsSource = ttsRows;

            var sttRows = new List<SettingRow>
            {
                new("Etkin", Bool(config.GetBool("stt.enabled")), configKey: "stt.enabled"),
                new("Sağlayıcı", string.IsNullOrWhiteSpace(sttProvider) ? "(tanımsız)" : sttProvider,
                    "Seçenekler: local (faster-whisper, ücretsiz), groq, openai (Whisper API), mistral (Voxtral).",
                    "stt.provider"),
            };

            switch (sttProvider)
            {
                case "local":
                    sttRows.Add(new SettingRow("Model", config.GetDisplay("stt.local.model"),
                        "tiny / base / small / medium / large-v3", "stt.local.model"));
                    sttRows.Add(new SettingRow("Dil", config.GetDisplay("stt.local.language", "(otomatik algıla)"),
                        configKey: "stt.local.language"));
                    break;
                case "openai":
                    sttRows.Add(new SettingRow("Model", config.GetDisplay("stt.openai.model"), configKey: "stt.openai.model"));
                    break;
                case "mistral":
                    sttRows.Add(new SettingRow("Model", config.GetDisplay("stt.mistral.model"), configKey: "stt.mistral.model"));
                    break;
            }

            SttRows.ItemsSource = sttRows;

            RecordingRows.ItemsSource = new List<SettingRow>
            {
                new("Kayıt kısayolu", config.GetDisplay("voice.record_key"),
                    "Bas-konuş kaydını başlatır/durdurur.", "voice.record_key"),
                new("Azami kayıt süresi", Seconds(config.GetDisplay("voice.max_recording_seconds")),
                    configKey: "voice.max_recording_seconds"),
                new("Yanıtı otomatik seslendir", Bool(config.GetBool("voice.auto_tts")),
                    configKey: "voice.auto_tts"),
                new("Kayıt bip sesleri", Bool(config.GetBool("voice.beep_enabled")),
                    "Kayıt başlangıç/bitiş sinyali.", "voice.beep_enabled"),
                new("Sessizlik eşiği", config.GetDisplay("voice.silence_threshold"),
                    "RMS bu değerin altındaysa sessizlik sayılır (0–32767).", "voice.silence_threshold"),
                new("Sessizlik süresi", Seconds(config.GetDisplay("voice.silence_duration")),
                    "Sürekli (VAD) modda otomatik durdurma eşiği.", "voice.silence_duration"),
            };
        }
        catch (Exception ex)
        {
            App.LogCrash("VoicePage.Populate", ex, ex.Message);
        }
    }

    private static string Bool(bool? value) => value switch
    {
        true => "Açık",
        false => "Kapalı",
        _ => "(tanımsız)",
    };

    private static string Seconds(string value) => value is "—" or "" ? "(tanımsız)" : $"{value} sn";
}
