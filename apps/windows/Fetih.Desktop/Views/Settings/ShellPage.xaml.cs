using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Fetih.Desktop.Bridge;
using Fetih.Desktop.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Fetih.Desktop.Views.Settings;

/// <summary>
/// Windows kabuk backend'i (Git Bash / WSL) ayar sayfası — Görev A.
/// Durum <c>shell.status</c> RPC'sinden okunur; seçim <c>config.set</c> ile
/// <c>terminal.windows_shell</c> / <c>terminal.wsl_distro</c> anahtarlarına
/// yazılır; "FETİH için WSL kullanıcısı oluştur" butonu <c>shell.ensure_user</c>
/// RPC'sini tetikler.
/// </summary>
public sealed partial class ShellPage : Page
{
    private readonly BridgeClient _bridge = BridgeClient.Shared;

    /// <summary>Seçim olaylarını (programatik doldurma sırasında) bastırır.</summary>
    private bool _suppress;

    private bool _wslAvailable;
    private string _defaultUser = "fetih";

    public ShellPage()
    {
        InitializeComponent();
        ApplyLanguage();
        Loaded += OnLoaded;
    }

    private void ApplyLanguage()
    {
        TitleText.Text = Loc.T("shell.title");
        IntroText.Text = Loc.T("shell.intro");
        GitBashTitle.Text = Loc.T("shell.git_bash");
        GitBashDesc.Text = Loc.T("shell.git_bash.desc");
        WslTitle.Text = Loc.T("shell.wsl");
        WslDesc.Text = Loc.T("shell.wsl.desc");
        DistroLabel.Text = Loc.T("shell.distro");
        CreateUserDesc.Text = Loc.T("shell.create_user.desc");
        CreateUserButton.Content = Loc.T("shell.create_user");
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        _ = LoadAsync();
    }

    private async Task LoadAsync()
    {
        SetBusy(true);
        try
        {
            var res = await _bridge.ShellStatusAsync().ConfigureAwait(true);
            Populate(res);
        }
        catch (BridgeRpcException rpc)
        {
            ShowStatus($"Köprü hatası ({rpc.Code}): {rpc.Message}", InfoBarSeverity.Error);
        }
        catch (Exception ex)
        {
            ShowStatus(Loc.T("shell.needs_bridge") + " (" + ex.Message + ")", InfoBarSeverity.Informational);
            App.LogCrash("ShellPage.Load", ex, ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void Populate(JsonElement res)
    {
        _suppress = true;
        try
        {
            if (res.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            var available = res.TryGetProperty("available", out var av) && av.ValueKind == JsonValueKind.True;
            if (!available)
            {
                var detail = res.TryGetProperty("detail", out var d) ? d.GetString() : null;
                ShowStatus(detail ?? "Kabuk seçimi yalnızca Windows'ta geçerlidir.", InfoBarSeverity.Informational);
                GitBashRadio.IsEnabled = false;
                WslRadio.IsEnabled = false;
                return;
            }

            HideStatus();

            var selected = res.TryGetProperty("selected", out var s) ? s.GetString() ?? "git-bash" : "git-bash";
            var gitBashPath = res.TryGetProperty("git_bash_path", out var gp) ? gp.GetString() ?? "" : "";
            var effective = res.TryGetProperty("effective", out var ef) ? ef.GetString() ?? "" : "";
            _defaultUser = res.TryGetProperty("default_wsl_user", out var du) ? du.GetString() ?? "fetih" : "fetih";

            GitBashPath.Text = string.IsNullOrEmpty(gitBashPath) ? "" : gitBashPath;

            // WSL alt bilgisi.
            var distros = new List<string>();
            var wslDefault = "";
            if (res.TryGetProperty("wsl", out var wsl) && wsl.ValueKind == JsonValueKind.Object)
            {
                _wslAvailable = wsl.TryGetProperty("available", out var wa) && wa.ValueKind == JsonValueKind.True;
                wslDefault = wsl.TryGetProperty("default", out var wd) ? wd.GetString() ?? "" : "";
                if (wsl.TryGetProperty("distros", out var dl) && dl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in dl.EnumerateArray())
                    {
                        if (el.ValueKind == JsonValueKind.String)
                        {
                            distros.Add(el.GetString() ?? "");
                        }
                    }
                }
            }

            var selectedDistro = res.TryGetProperty("selected_distro", out var sd) ? sd.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(selectedDistro))
            {
                selectedDistro = wslDefault;
            }

            DistroCombo.Items.Clear();
            foreach (var name in distros)
            {
                DistroCombo.Items.Add(name);
            }
            if (!string.IsNullOrEmpty(selectedDistro) && distros.Contains(selectedDistro))
            {
                DistroCombo.SelectedItem = selectedDistro;
            }
            else if (DistroCombo.Items.Count > 0)
            {
                DistroCombo.SelectedIndex = 0;
            }

            WslRadio.IsEnabled = _wslAvailable;
            WslMissingText.Text = Loc.T("shell.wsl_not_installed");
            WslMissingText.Visibility = _wslAvailable ? Visibility.Collapsed : Visibility.Visible;

            if (selected == "wsl" && _wslAvailable)
            {
                WslRadio.IsChecked = true;
            }
            else
            {
                GitBashRadio.IsChecked = true;
            }

            UpdateWslDetailVisibility();
            UpdateUserStatus(res);

            EffectiveText.Text = $"{Loc.T("shell.effective")}: {effective}";
        }
        finally
        {
            _suppress = false;
        }
    }

    private void UpdateUserStatus(JsonElement res)
    {
        if (res.TryGetProperty("wsl_user_exists", out var ue) && ue.ValueKind == JsonValueKind.True)
        {
            CreateUserStatus.Text = Loc.T("shell.user_exists");
        }
        else
        {
            CreateUserStatus.Text = "";
        }
    }

    private void UpdateWslDetailVisibility()
    {
        WslDetailPanel.Visibility = WslRadio.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void Backend_Checked(object sender, RoutedEventArgs e)
    {
        UpdateWslDetailVisibility();
        if (_suppress)
        {
            return;
        }

        var value = WslRadio.IsChecked == true ? "wsl" : "git-bash";
        await SaveKeyAsync("terminal.windows_shell", value).ConfigureAwait(true);

        // WSL seçildiyse ve bir dağıtım seçiliyse onu da yaz.
        if (value == "wsl" && DistroCombo.SelectedItem is string distro && !string.IsNullOrEmpty(distro))
        {
            await SaveKeyAsync("terminal.wsl_distro", distro).ConfigureAwait(true);
        }
        await LoadAsync().ConfigureAwait(true);
    }

    private async void DistroCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppress)
        {
            return;
        }
        if (DistroCombo.SelectedItem is string distro && !string.IsNullOrEmpty(distro))
        {
            await SaveKeyAsync("terminal.wsl_distro", distro).ConfigureAwait(true);
        }
    }

    private async Task SaveKeyAsync(string key, object value)
    {
        try
        {
            await _bridge.ConfigSetAsync(key, value).ConfigureAwait(true);
            ShowStatus(Loc.T("shell.saved"), InfoBarSeverity.Success);
        }
        catch (Exception ex)
        {
            ShowStatus(Loc.T("shell.save_failed") + ": " + ex.Message, InfoBarSeverity.Error);
            App.LogCrash("ShellPage.SaveKey", ex, ex.Message);
        }
    }

    private async void CreateUserButton_Click(object sender, RoutedEventArgs e)
    {
        CreateUserButton.IsEnabled = false;
        CreateUserStatus.Text = "…";
        try
        {
            var distro = DistroCombo.SelectedItem as string;
            var res = await _bridge.ShellEnsureUserAsync(distro, _defaultUser).ConfigureAwait(true);
            var detail = res.TryGetProperty("detail", out var d) ? d.GetString() : null;
            CreateUserStatus.Text = detail ?? Loc.T("shell.saved");

            // Kullanıcı oluşturulduysa terminal.wsl_user'ı da işaretle.
            await SaveKeyAsync("terminal.wsl_user", _defaultUser).ConfigureAwait(true);
        }
        catch (BridgeRpcException rpc)
        {
            CreateUserStatus.Text = "✗ " + rpc.Message;
        }
        catch (Exception ex)
        {
            CreateUserStatus.Text = "✗ " + ex.Message;
            App.LogCrash("ShellPage.CreateUser", ex, ex.Message);
        }
        finally
        {
            CreateUserButton.IsEnabled = true;
        }
    }

    private void SetBusy(bool busy) => BusyRing.IsActive = busy;

    private void ShowStatus(string message, InfoBarSeverity severity)
    {
        StatusBar.Message = message;
        StatusBar.Severity = severity;
        StatusBar.IsOpen = true;
    }

    private void HideStatus() => StatusBar.IsOpen = false;
}
