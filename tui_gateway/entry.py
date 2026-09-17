"""FETIH TUI ağ geçidinin giriş noktası.

Bu modül süreç seviyesindeki kurulumu yapar (sinyal yönlendirmesi) ve
ardından stdio sunum döngüsünü başlatır. Windows'ta POSIX sinyallerinin
büyük bölümü bulunmadığı için her sinyal ``hasattr`` ile yoklanır;
böylece modülü içe aktarmak hiçbir platformda hata vermez.
"""

from __future__ import annotations

import signal


def _installable_signals():
    """Platformda bulunan (ad, sinyal) çiftlerini döndür.

    ``SIGPIPE``/``SIGHUP`` Windows'ta yoktur; ``hasattr`` kontrolü
    olmadan erişmek ``AttributeError`` ile içe aktarmayı bozardı.
    """
    pairs = []
    if hasattr(signal, "SIGPIPE"):
        pairs.append(("SIGPIPE", signal.SIGPIPE))
    if hasattr(signal, "SIGHUP"):
        pairs.append(("SIGHUP", signal.SIGHUP))
    if hasattr(signal, "SIGTERM"):
        pairs.append(("SIGTERM", signal.SIGTERM))
    if hasattr(signal, "SIGINT"):
        pairs.append(("SIGINT", signal.SIGINT))
    return pairs


def install_signal_handlers(handler=None) -> None:
    """Kapanış sinyallerini bağla; yok olanları sessizce atla.

    ``SIGPIPE`` yok sayılır (istemci boruyu kapattığında süreç ölmesin),
    ``SIGTERM``/``SIGINT`` ise verilen işleyiciye yönlendirilir.
    """
    for name, number in _installable_signals():
        try:
            if name == "SIGPIPE":
                signal.signal(number, signal.SIG_IGN)
            elif handler is not None and name in ("SIGTERM", "SIGINT"):
                signal.signal(number, handler)
        except Exception:
            # Ana iş parçacığı dışında ya da desteklenmeyen platformlarda
            # sinyal bağlamak zorunlu değil.
            continue


def main(argv=None) -> int:
    """Sinyalleri kur ve stdio sunum döngüsünü çalıştır."""
    from tui_gateway.server import main as serve

    install_signal_handlers()
    return serve(argv)
