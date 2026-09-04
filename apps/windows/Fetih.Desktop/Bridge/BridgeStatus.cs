using System.ComponentModel;
using System.Runtime.CompilerServices;
using Microsoft.UI.Dispatching;

namespace Fetih.Desktop.Bridge;

/// <summary>
/// Masaüstü Köprüsü (Python <c>fetih_desktop_bridge</c>) bağlantısının durumu.
/// Not: bu katman mesajlaşma köprüsünden (Telegram/Discord) tamamen ayrıdır;
/// adlandırma ayrımı için bkz. docs/windows-app-plani.md (b) bölümü.
/// </summary>
public enum BridgeConnectionState
{
    /// <summary>Henüz bağlanma denenmedi.</summary>
    Idle,

    /// <summary>Python süreci başlatılıyor / el sıkışma bekleniyor.</summary>
    Connecting,

    /// <summary><c>bridge.ready</c> olayı alındı.</summary>
    Ready,

    /// <summary>Bağlantı koptu, yeniden denenecek.</summary>
    Reconnecting,

    /// <summary>Bağlantı kurulamadı; kullanıcı müdahalesi gerekiyor.</summary>
    Faulted,
}

/// <summary>
/// Kabuk üstündeki bağlantı rozetini besleyen gözlemlenebilir durum nesnesi.
/// Faz 1'de yalnızca durum taşır; NDJSON JSON-RPC istemcisi (BridgeClient)
/// ve süreç yöneticisi bir sonraki adımda bu durumu güncelleyecek.
/// </summary>
public sealed class BridgeStatus : INotifyPropertyChanged
{
    /// <summary>
    /// Kabuk, sohbet sayfası ve Masaüstü Köprüsü ayar sayfası aynı durumu
    /// göstersin diye süreç genelinde paylaşılan tek örnek.
    /// </summary>
    public static BridgeStatus Shared { get; } = new();

    private BridgeConnectionState _state = BridgeConnectionState.Idle;
    private string _detail = "Masaüstü Köprüsü henüz başlatılmadı.";

    /// <summary>
    /// UI iş parçacığının kuyruğu. Köprü istemcisi durum güncellemelerini arka
    /// plan iş parçacıklarından yaptığı için, x:Bind'e bağlı PropertyChanged
    /// olaylarını bu kuyruğa yönlendirir (aksi halde RPC_E_WRONG_THREAD).
    /// MainWindow açılışta UI iş parçacığından ayarlar.
    /// </summary>
    public DispatcherQueue? Dispatcher { get; set; }

    public event PropertyChangedEventHandler? PropertyChanged;

    public BridgeConnectionState State
    {
        get => _state;
        private set
        {
            if (_state == value)
            {
                return;
            }

            _state = value;
            Notify();
            Notify(nameof(StateLabel));
            Notify(nameof(IsBusy));
        }
    }

    public string Detail
    {
        get => _detail;
        private set
        {
            if (_detail == value)
            {
                return;
            }

            _detail = value;
            Notify();
        }
    }

    public bool IsBusy =>
        State is BridgeConnectionState.Connecting or BridgeConnectionState.Reconnecting;

    public string StateLabel => State switch
    {
        BridgeConnectionState.Idle => "Bağlantı bekleniyor…",
        BridgeConnectionState.Connecting => "Bağlanılıyor…",
        BridgeConnectionState.Ready => "Bağlı",
        BridgeConnectionState.Reconnecting => "Yeniden bağlanılıyor…",
        _ => "Bağlantı hatası",
    };

    public void Update(BridgeConnectionState state, string detail)
    {
        // Her zaman UI iş parçacığında uygula: State/Detail setter'ları x:Bind'e
        // bağlı PropertyChanged tetikler ve bu yalnızca UI iş parçacığından güvenlidir.
        var dispatcher = Dispatcher;
        if (dispatcher is not null && !dispatcher.HasThreadAccess)
        {
            dispatcher.TryEnqueue(() =>
            {
                State = state;
                Detail = detail;
            });
        }
        else
        {
            State = state;
            Detail = detail;
        }
    }

    private void Notify([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
