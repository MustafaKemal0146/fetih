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

    /// <summary>
    /// Köprü ayakta ve konuşuyor, ama modele gidilemiyor: sağlayıcı çözülemedi,
    /// API anahtarı yok/geçersiz ya da model kimliği reddedildi.
    ///
    /// <para>Ayrı bir durum olmasının sebebi: taşıma sağlığı ile model sağlığı
    /// birbirinden bağımsızdır. Rozet yalnızca sokete baktığı sürece, ilk
    /// mesajı <c>Unknown provider</c> ile ölen bir kurulumda bile "Bağlı"
    /// yazıyordu — yani kullanıcıya çalıştığını söylüyordu.</para>
    /// </summary>
    ModelError,
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
            Notify(nameof(IsActionable));
            Notify(nameof(BadgeBrushKey));
            Notify(nameof(BadgeBrush));
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

    /// <summary>
    /// Bağlantı rozetinin metni. Arayüzün geri kalanıyla aynı dilde olsun diye
    /// sabit Türkçe metin yerine yerelleştirme tablosundan okunur.
    /// </summary>
    public string StateLabel => State switch
    {
        BridgeConnectionState.Idle => Services.Loc.T("bridge.state.idle"),
        BridgeConnectionState.Connecting => Services.Loc.T("bridge.state.connecting"),
        BridgeConnectionState.Ready => Services.Loc.T("bridge.state.ready"),
        BridgeConnectionState.Reconnecting => Services.Loc.T("bridge.state.reconnecting"),
        BridgeConnectionState.ModelError => Services.Loc.T("bridge.state.model_error"),
        _ => Services.Loc.T("bridge.state.error"),
    };

    /// <summary>
    /// Rozet noktasının rengi — tema kaynağı ADI olarak.
    /// Nokta eskiden koşulsuz sarıydı: hangi durumda olursak olalım aynı
    /// rengi gösteriyordu.
    /// </summary>
    public string BadgeBrushKey => State switch
    {
        BridgeConnectionState.Ready => "SystemFillColorSuccessBrush",
        BridgeConnectionState.Connecting or BridgeConnectionState.Reconnecting
            => "SystemFillColorCautionBrush",
        BridgeConnectionState.ModelError or BridgeConnectionState.Faulted
            => "SystemFillColorCriticalBrush",
        _ => "SystemFillColorNeutralBrush",
    };

    /// <summary>
    /// <see cref="BadgeBrushKey"/>'in fırça karşılığı.
    ///
    /// <para>Dönüşüm neden burada, <c>ThemeBrushConverter</c>'da değil:
    /// başlık çubuğu bir <c>Window</c> kökünde yaşıyor ve x:Bind dönüştürücü
    /// araması yalnızca <c>FrameworkElement</c> köklerinde derleniyor
    /// (CS1503). Fırçayı özellik olarak vermek, aynı sonucu dönüştürücüsüz
    /// üretir.</para>
    /// </summary>
    public Microsoft.UI.Xaml.Media.Brush BadgeBrush
    {
        get
        {
            try
            {
                if (Microsoft.UI.Xaml.Application.Current?.Resources is { } resources &&
                    resources.TryGetValue(BadgeBrushKey, out var resource) &&
                    resource is Microsoft.UI.Xaml.Media.Brush brush)
                {
                    return brush;
                }
            }
            catch
            {
                // Tasarım zamanı / erken açılış: aşağıdaki şeffaf fırçaya düş.
            }

            return TransparentBrush;
        }
    }

    private static readonly Microsoft.UI.Xaml.Media.SolidColorBrush TransparentBrush =
        new(Microsoft.UI.Colors.Transparent);

    /// <summary>
    /// Rozete tıklamak bir işe yarar mı? Hata durumlarında kullanıcıyı
    /// doğrudan düzeltebileceği sayfaya götürürüz; sağlıklıyken tıklanmaz.
    /// </summary>
    public bool IsActionable =>
        State is BridgeConnectionState.ModelError or BridgeConnectionState.Faulted;

    /// <summary>
    /// Hata durumundaki rozetin götüreceği ayar sayfasının etiketi.
    /// Model hatası → Model/Sağlayıcı; taşıma hatası → Masaüstü Köprüsü.
    /// </summary>
    public string ActionNavTag => State == BridgeConnectionState.ModelError
        ? "nav_settings_provider"
        : "nav_settings_bridge";

    /// <summary>
    /// Arayüz dili değiştiğinde rozet metnini yeniden okutur (durum aynı kalır).
    /// </summary>
    public void RefreshLabels() => Notify(nameof(StateLabel));

    /// <summary>
    /// Bir tur, modele ulaşamadığı için başarısız oldu.
    ///
    /// <para>Soket hâlâ açık — bu yüzden <see cref="Update"/> ile
    /// <c>Faulted</c>'a düşmek yanlış olurdu; ayrı bir
    /// <see cref="BridgeConnectionState.ModelError"/> durumuna geçeriz.
    /// Sağlayıcı çözümlemesi (-32004) ve ajan hataları (-32003) içinde
    /// yalnızca yapılandırmayla ilgili olanlar buraya düşer: ağ zaman aşımı
    /// ya da kullanıcının iptali rozeti kırmızıya çevirmemeli.</para>
    /// </summary>
    public void ReportModelFault(int code, string message)
        => Update(BridgeConnectionState.ModelError,
                  Services.Loc.T("bridge.detail.model_error") + " (" + code + ") " + message);

    /// <summary>
    /// Bir tur modele ulaşıp tamamlandı — model hatası varsa temizle.
    /// Yalnızca <see cref="BridgeConnectionState.ModelError"/> durumundan
    /// döner; taşıma durumlarına dokunmaz (onları bağlantı döngüsü yönetir).
    /// </summary>
    public void ReportModelHealthy()
    {
        if (State == BridgeConnectionState.ModelError)
        {
            Update(BridgeConnectionState.Ready, Services.Loc.T("bridge.detail.model_ok"));
        }
    }

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
