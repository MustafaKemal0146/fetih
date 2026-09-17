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
        ApplyLanguage();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged += OnLanguageChanged;
        Populate();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Loc.LanguageChanged -= OnLanguageChanged;
    }

    private void OnLanguageChanged()
    {
        ApplyLanguage();
        Populate();
    }

    private void ApplyLanguage()
    {
        PageTitleText.Text = Loc.T("voice.title");
        SubtitleText.Text = Loc.T("voice.subtitle");
        TtsHeader.Text = Loc.T("voice.section.tts");
        SttHeader.Text = Loc.T("voice.section.stt");
        RecordingHeader.Text = Loc.T("voice.section.recording");
        LiveInfo.Title = Loc.T("voice.live_title");
        LiveInfo.Message = Loc.T("voice.live_desc");
        RefreshButton.Content = Loc.T("common.reload");
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(
            RefreshButton, Loc.T("common.reload"));
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
                new(Loc.T("voice.provider"), string.IsNullOrWhiteSpace(ttsProvider) ? Loc.T("voice.undefined") : ttsProvider,
                    Loc.T("voice.tts.options"),
                    "tts.provider"),
            };

            // Yalnızca etkin sağlayıcının kendi alt ayarları gösterilir —
            // config.yaml tüm sağlayıcıların varsayılanlarını taşır.
            switch (ttsProvider)
            {
                case "edge":
                    ttsRows.Add(new SettingRow(Loc.T("voice.voice"), config.GetDisplay("tts.edge.voice"), configKey: "tts.edge.voice"));
                    break;
                case "elevenlabs":
                    ttsRows.Add(new SettingRow(Loc.T("voice.voice_id"), config.GetDisplay("tts.elevenlabs.voice_id"), configKey: "tts.elevenlabs.voice_id"));
                    ttsRows.Add(new SettingRow(Loc.T("voice.model"), config.GetDisplay("tts.elevenlabs.model_id"), configKey: "tts.elevenlabs.model_id"));
                    break;
                case "openai":
                    ttsRows.Add(new SettingRow(Loc.T("voice.model"), config.GetDisplay("tts.openai.model"), configKey: "tts.openai.model"));
                    ttsRows.Add(new SettingRow(Loc.T("voice.voice"), config.GetDisplay("tts.openai.voice"), configKey: "tts.openai.voice"));
                    break;
                case "xai":
                    ttsRows.Add(new SettingRow(Loc.T("voice.voice_id"), config.GetDisplay("tts.xai.voice_id"), configKey: "tts.xai.voice_id"));
                    ttsRows.Add(new SettingRow(Loc.T("voice.language"), config.GetDisplay("tts.xai.language"), configKey: "tts.xai.language"));
                    break;
                case "mistral":
                    ttsRows.Add(new SettingRow(Loc.T("voice.model"), config.GetDisplay("tts.mistral.model"), configKey: "tts.mistral.model"));
                    ttsRows.Add(new SettingRow(Loc.T("voice.voice_id"), config.GetDisplay("tts.mistral.voice_id"), configKey: "tts.mistral.voice_id"));
                    break;
                case "neutts":
                    ttsRows.Add(new SettingRow(Loc.T("voice.model"), config.GetDisplay("tts.neutts.model"), configKey: "tts.neutts.model"));
                    ttsRows.Add(new SettingRow(Loc.T("voice.device"), config.GetDisplay("tts.neutts.device"), "cpu / cuda / mps", "tts.neutts.device"));
                    break;
                case "piper":
                    ttsRows.Add(new SettingRow(Loc.T("voice.voice"), config.GetDisplay("tts.piper.voice"), configKey: "tts.piper.voice"));
                    break;
            }

            TtsRows.ItemsSource = ttsRows;

            var sttRows = new List<SettingRow>
            {
                new(Loc.T("voice.enabled"), Bool(config.GetBool("stt.enabled")), configKey: "stt.enabled"),
                new(Loc.T("voice.provider"), string.IsNullOrWhiteSpace(sttProvider) ? Loc.T("voice.undefined") : sttProvider,
                    Loc.T("voice.stt.options"),
                    "stt.provider"),
            };

            switch (sttProvider)
            {
                case "local":
                    sttRows.Add(new SettingRow(Loc.T("voice.model"), config.GetDisplay("stt.local.model"),
                        Loc.T("voice.stt.model.options"), "stt.local.model"));
                    sttRows.Add(new SettingRow(Loc.T("voice.language"),
                        config.GetDisplay("stt.local.language", Loc.T("voice.auto_detect")),
                        configKey: "stt.local.language"));
                    break;
                case "openai":
                    sttRows.Add(new SettingRow(Loc.T("voice.model"), config.GetDisplay("stt.openai.model"), configKey: "stt.openai.model"));
                    break;
                case "mistral":
                    sttRows.Add(new SettingRow(Loc.T("voice.model"), config.GetDisplay("stt.mistral.model"), configKey: "stt.mistral.model"));
                    break;
            }

            SttRows.ItemsSource = sttRows;

            RecordingRows.ItemsSource = new List<SettingRow>
            {
                new(Loc.T("voice.recording.key"), config.GetDisplay("voice.record_key"),
                    Loc.T("voice.recording.key.desc"), "voice.record_key"),
                new(Loc.T("voice.recording.max"), Seconds(config.GetDisplay("voice.max_recording_seconds")),
                    configKey: "voice.max_recording_seconds"),
                new(Loc.T("voice.recording.auto_tts"), Bool(config.GetBool("voice.auto_tts")),
                    configKey: "voice.auto_tts"),
                new(Loc.T("voice.recording.beep"), Bool(config.GetBool("voice.beep_enabled")),
                    Loc.T("voice.recording.beep.desc"), "voice.beep_enabled"),
                new(Loc.T("voice.recording.silence_threshold"), config.GetDisplay("voice.silence_threshold"),
                    Loc.T("voice.recording.silence_threshold.desc"), "voice.silence_threshold"),
                new(Loc.T("voice.recording.silence_duration"), Seconds(config.GetDisplay("voice.silence_duration")),
                    Loc.T("voice.recording.silence_duration.desc"), "voice.silence_duration"),
            };
        }
        catch (Exception ex)
        {
            App.LogCrash("VoicePage.Populate", ex, ex.Message);
        }
    }

    private static string Bool(bool? value) => value switch
    {
        true => Loc.T("common.on"),
        false => Loc.T("common.off"),
        _ => Loc.T("voice.undefined"),
    };

    private static string Seconds(string value)
        => value is "—" or ""
            ? Loc.T("voice.undefined")
            : string.Format(Loc.T("voice.seconds"), value);
}
