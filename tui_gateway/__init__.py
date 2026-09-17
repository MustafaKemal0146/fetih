"""TUI gateway paketi.

FETIH masaüstü/TUI istemcisi ile ajan çalışma zamanı arasındaki
JSON-RPC köprüsünü barındırır. Genel giriş noktası
``tui_gateway.server:main`` (``python -m tui_gateway``).

Alt modüller:
    server   — stdio üzerinden satır bazlı JSON-RPC sunucusu
"""

__all__ = ["server"]
