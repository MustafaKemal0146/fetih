"""FETIH TUI ağ geçidi — satır bazlı JSON-RPC 2.0 sunucusu (stdio).

Masaüstü/TUI istemcisi ile ajan çalışma zamanı arasındaki köprü burada
kurulur. Protokol newline ile ayrılmış JSON-RPC 2.0'dır: istemci stdin'e
tek satırlık istek yazar, sunucu her isteğe tek satırlık yanıt üretir.
Ajan çalışırken oluşan olaylar (``status.update``, ``message.delta``,
``browser.progress`` ...) yanıt akışından bağımsız olarak aynı stdout'a
düşer; istemci bunları ``method`` alanı olan iletiler olarak ayırt eder.

Tasarım notları
---------------
* İstemciye giden her şey ``write_json`` üzerinden gider; ``print`` ile
  JSON yazılmaz.
* Modül seviyesinde değiştirilebilir durum (``_sessions``, ``_pending``,
  ``_answers``, ``_methods`` ...) tutulur ve bu isimlere **çağrı anında**
  erişilir; böylece testler durumu takas edebilir.
* Testlerin yamaladığı işbirlikçiler (``tools.voice_mode``,
  ``fetih_cli.voice``, ``cli`` ...) çağrı anında içe aktarılır. Modül
  seviyesinde yalnızca standart kütüphane ve yamalanmayan yardımcılar
  içe aktarılır.
* Oturumlar ``session.create`` çağrısında hemen kurulmaz: ajan inşası
  gerçek bir arka plan iş parçacığında ~50 ms gecikmeyle başlatılır ve
  bu arada istemci yanıtı almış olur.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import yaml

# --------------------------------------------------------------------------
# Modül durumu
# --------------------------------------------------------------------------

#: stdout'un gerçek referansı. Testler bunu takas edip yazma yollarını
#: doğrular; bu yüzden çağrı anında okunur.
_real_stdout = sys.stdout

#: Aynı satırın iki iş parçacığı tarafından iç içe yazılmasını engeller.
_write_lock = threading.RLock()

#: İnşa iş parçacığını başlatmak için kullanılan gerçek Thread sınıfı.
#: Testler ``server.threading.Thread`` adını yamaladığı için burada
#: içe aktarma anında sabitlenir.
_real_thread = threading.Thread

#: sid → oturum sözlüğü
_sessions: dict = {}
#: request_id → (sid, threading.Event) çifti; istemciden yanıt bekleyen istekler
_pending: dict = {}
#: request_id → istemciden gelen yanıt metni
_answers: dict = {}
#: proje kökü → (dosya listesi, zaman damgası)
_fuzzy_cache: dict = {}
#: ses olaylarının hedef oturumu
_voice_event_sid = None
#: FETIH_HOME (config.yaml ve sessions/ dizininin kökü)
_fetih_home = None
#: önbelleğe alınmış SessionDB örneği ve başlatma hatası
_db = None
_db_error = None
#: sunum döngüsü çalışıyor mu (bildirim dinleyicisi bu bayrağa bakar)
_serve_loop_active = False

_METHODS: dict = {}

#: Oturum oluşturulurken ajanın kurulmasını geciktiren süre (saniye).
_BUILD_DELAY_S = 0.05

#: Yol tamamlamalarında döndürülecek en fazla girdi sayısı.
_MAX_PATH_ITEMS = 30

_DEFAULT_COLS = 80
_DEFAULT_MAX_TURNS = 90
_DEFAULT_BACKGROUND_MAX_TURNS = 25
_DEFAULT_SESSION_LIST_LIMIT = 200
_DEFAULT_RECORD_KEY = "ctrl+b"
_DEFAULT_CDP_URL = "http://127.0.0.1:9222"
_INDICATOR_DEFAULT = "kaomoji"
_INDICATORS = (
    "ascii",
    "emoji",
    "kaomoji",
    "off",
    "unicode",
)
_DETAIL_MODES = ("collapsed", "expanded", "hidden")
_DETAIL_SECTIONS = ("thinking", "tools", "subagents", "activity")
_VERBOSE_CYCLE = ("off", "all", "verbose")
_STATUS_BAR_POSITIONS = ("top", "bottom", "hidden")
_BUSY_MODES = ("interrupt", "steer", "queue")
_FAST_MODE_KEYS = ("service_tier", "speed")
_SNAPSHOT_ALIASES = ("snapshot", "snap")
_PROGRESS_SECTIONS = ("thinking", "tools", "subagents", "activity")

#: Bağlam referansı tamamlamaları (``@`` ile başlayan girdiler).
_STATIC_REFS = (
    "@diff",
    "@staged",
    "@file:",
    "@folder:",
    "@url:",
    "@git:",
)

#: ``/details`` komutunun TUI tarafında tamamlanan argümanları.
_TUI_COMMANDS = (
    ("/details", "Kompakt bölüm ayrıntı seviyesini ayarla"),
    ("/mouse", "Fare takibini aç/kapat"),
)

_ENV_TUI_TOOLSETS = "FETIH_TUI_TOOLSETS"
_ENV_TUI_PROVIDER = "FETIH_TUI_PROVIDER"
_ENV_MODEL = "FETIH_MODEL"
_ENV_INFERENCE_MODEL = "FETIH_INFERENCE_MODEL"
_ENV_INFERENCE_PROVIDER = "FETIH_INFERENCE_PROVIDER"
_ENV_VOICE = "FETIH_VOICE"
_ENV_VOICE_TTS = "FETIH_VOICE_TTS"
_ENV_CDP = "BROWSER_CDP_URL"
_ENV_YOLO = "FETIH_YOLO_MODE"

_TRUTHY = {"1", "true", "yes", "on", "enabled"}

_CREDENTIAL_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "DEEPSEEK_API_KEY",
    "XAI_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "TOGETHER_API_KEY",
    "FIREWORKS_API_KEY",
)


def _mod(name):
    """Bir modülü **çağrı anında** çöz ve döndür.

    Testler sahte modülleri ``sys.modules`` üzerinden enjekte ettiği için
    ``from paket.alt import ad`` biçimi güvenilir değildir: alt modül
    önbellekten geldiğinde CPython ata pakete niteliği yeniden yazmaz ve
    ``from ... import`` başarısız olur. ``importlib.import_module`` ise
    doğrudan ``sys.modules`` girdisini döndürür.
    """
    return importlib.import_module(name)


def _init_fetih_home() -> None:
    """``FETIH_HOME`` kökünü (config.yaml'ın bulunduğu dizin) çöz."""
    global _fetih_home
    try:
        _fetih_home = Path(_mod("fetih_cli.config").get_fetih_home())
        return
    except Exception:
        pass
    raw = os.environ.get("FETIH_HOME")
    _fetih_home = Path(raw) if raw else Path.home() / ".fetih"


_init_fetih_home()


# --------------------------------------------------------------------------
# JSON yazımı ve zarf yardımcıları
# --------------------------------------------------------------------------


def write_json(payload) -> bool:
    """Tek bir JSON satırını stdout'a yaz ve tamponu boşalt.

    Satır, kilit alınmadan **önce** serileştirilir; kilit yalnızca
    ``write``+``flush`` çiftini korur. Böylece yavaş bir stdout iki
    iletinin karakterlerinin birbirine karışmasına yol açmaz.
    Herhangi bir hata (bozuk boru, kapalı tampon) ``False`` döner.
    """
    try:
        line = json.dumps(payload, ensure_ascii=False) + "\n"
    except Exception:
        return False
    try:
        with _write_lock:
            out = _real_stdout
            if out is None:
                return False
            out.write(line)
            out.flush()
        return True
    except Exception:
        return False


def _result(request_id, result):
    """JSON-RPC başarı zarfı."""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id, code, message):
    """JSON-RPC hata zarfı."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": int(code), "message": str(message)},
    }


def _emit(event, session_id=None, payload=None):
    """Sunucudan istemciye olay gönder (hatalar yutulur)."""
    params = {"session_id": session_id}
    if isinstance(payload, dict):
        params.update(payload)
    try:
        write_json({"jsonrpc": "2.0", "method": event, "params": params})
    except Exception:
        pass


def _require_sid(params) -> str | None:
    """``session_id`` zorunlu uçlar için kimlik çözümlemesi."""
    sid = params.get("session_id")
    if isinstance(sid, str) and sid.strip():
        return sid
    return None


# --------------------------------------------------------------------------
# Yapılandırma okuma/yazma
# --------------------------------------------------------------------------


def _load_cfg():
    """``config.yaml`` içeriğini her çağrıda yeniden oku (en iyi çaba)."""
    try:
        path = Path(_fetih_home) / "config.yaml"
        if not path.is_file():
            return {}
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _cfg_dict() -> dict:
    """``_load_cfg`` sonucunu her zaman bir sözlüğe indirge."""
    try:
        cfg = _load_cfg()
    except Exception:
        return {}
    return cfg if isinstance(cfg, dict) else {}


def _cfg_get(cfg, dotted, default=None):
    """``a.b.c`` biçiminde iç içe anahtar okuma."""
    node = cfg
    for part in str(dotted).split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _write_config_key(dotted_path, value) -> None:
    """``config.yaml`` içinde iç içe bir anahtarı yaz.

    Ara düğümler sözlük değilse (elle düzenlenmiş bozuk bir dosya)
    üzerine yazılır. Hatalar yutulur; istemciye her zaman yanıt döner.
    """
    try:
        cfg = _cfg_dict()
        parts = [part for part in str(dotted_path).split(".") if part]
        if not parts:
            return
        node = cfg
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        node[parts[-1]] = value
        home = Path(_fetih_home)
        home.mkdir(parents=True, exist_ok=True)
        with (home / "config.yaml").open("w", encoding="utf-8") as handle:
            yaml.safe_dump(cfg, handle, allow_unicode=True, sort_keys=False)
    except Exception:
        pass


def _available_personalities(cfg=None) -> dict:
    """``agent.personalities`` haritasını oku (ad → sistem istemi)."""
    if cfg is None:
        cfg = _cfg_dict()
    if not isinstance(cfg, dict):
        return {}
    raw = _cfg_get(cfg, "agent.personalities")
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    for name, entry in raw.items():
        if isinstance(entry, dict):
            prompt = (
                entry.get("system_prompt")
                or entry.get("prompt")
                or entry.get("description")
                or ""
            )
        else:
            prompt = entry
        out[str(name)] = "" if prompt is None else str(prompt)
    return out


def _resolve_model() -> str:
    """Etkin model kimliğini çöz (env → config → boş)."""
    for env_name in (_ENV_MODEL, _ENV_INFERENCE_MODEL):
        raw = os.environ.get(env_name)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    cfg = _cfg_dict()
    raw = _cfg_get(cfg, "model.default")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return ""


def _resolve_startup_runtime():
    """(model, sağlayıcı) çiftini çöz.

    ``FETIH_TUI_PROVIDER`` bu süreçte yapılmış **açık** bir seçimi
    taşır; ``FETIH_INFERENCE_PROVIDER`` ise ortamdan gelen bir ipucudur
    ve açık seçim sayılmaz. Açık seçim yoksa model adı statik katalogdan
    bir sağlayıcıya çözülebilir (ağ erişimi yok).
    """
    model = _resolve_model()
    explicit = os.environ.get(_ENV_TUI_PROVIDER)
    if isinstance(explicit, str) and explicit.strip():
        return model, explicit.strip()

    cfg = _cfg_dict()
    current = _cfg_get(cfg, "model.provider")
    if not isinstance(current, str):
        current = None
    try:
        detected = _mod("fetih_cli.models").detect_static_provider_for_model(
            model, current
        )
    except Exception:
        detected = None
    if isinstance(detected, (tuple, list)) and len(detected) == 2:
        provider, resolved = detected
        return (resolved or model), provider
    return model, None


def _max_turns_from_cfg(cfg, default: int) -> int:
    """``agent.max_turns`` → kök ``max_turns`` → varsayılan."""
    value = None
    if isinstance(cfg, dict):
        value = _cfg_get(cfg, "agent.max_turns")
        if value is None:
            value = cfg.get("max_turns")
    try:
        if value is None:
            return int(default)
        return int(value)
    except Exception:
        return int(default)


def _load_tool_progress_mode() -> str:
    """Araç ilerleme modunu oku: off / all / verbose."""
    raw = _cfg_get(_cfg_dict(), "display.tool_progress_mode")
    if isinstance(raw, str) and raw.strip().lower() in _VERBOSE_CYCLE:
        return raw.strip().lower()
    return "all"


def _load_reasoning_config():
    """Canlı ajan için akıl yürütme yapılandırması (yoksa ``None``)."""
    cfg = _cfg_dict()
    raw = _cfg_get(cfg, "agent.reasoning")
    if raw is None:
        raw = _cfg_get(cfg, "agent.reasoning_config")
    if isinstance(raw, dict):
        return raw
    effort = _cfg_get(cfg, "display.reasoning_effort")
    if isinstance(effort, str) and effort.strip():
        return {"enabled": True, "effort": effort.strip()}
    return None


def _load_service_tier():
    """``agent.service_tier`` yapılandırması (yoksa ``None``)."""
    raw = _cfg_get(_cfg_dict(), "agent.service_tier")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


def _mcp_servers_cfg() -> dict:
    """``mcp_servers`` haritasını oku (ham yapılandırma üzerinden)."""
    try:
        raw = _mod("fetih_cli.config").read_raw_config()
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    servers = raw.get("mcp_servers")
    return servers if isinstance(servers, dict) else {}


def _toolsets_from_config():
    """Yapılandırmadaki CLI araç setlerine düş (başarısızsa ``None``)."""
    try:
        cfg = _mod("fetih_cli.config").load_config()
    except Exception:
        sys.stderr.write(
            "[tui_gateway] FETIH_TUI_TOOLSETS entries were unknown and the "
            "configured toolsets could not be loaded from config.yaml\n"
        )
        return None
    tools: list = []
    try:
        tools = sorted(
            str(name)
            for name in _mod("fetih_cli.tools_config")._get_platform_tools(cfg, "cli")
        )
    except Exception:
        tools = []
    if tools:
        sys.stderr.write(
            "[tui_gateway] using configured CLI toolsets: " + ", ".join(tools) + "\n"
        )
    return tools


def _load_enabled_toolsets():
    """Etkin araç setlerini çöz.

    ``None`` → "tümü" anlamına gelir. Tanınmayan adlar için sırasıyla
    eklenti keşfi denenir, ardından ``mcp_servers`` girdileri (kapalı
    olanlar ayrı bir uyarıyla) değerlendirilir; hiçbiri tutmazsa
    yapılandırmadaki CLI araç setlerine düşülür.
    """
    raw = os.environ.get(_ENV_TUI_TOOLSETS) or ""
    entries = [item.strip() for item in raw.split(",")]
    entries = [item for item in entries if item]
    if not entries:
        return _toolsets_from_config()

    lowered = [item.lower() for item in entries]
    if "all" in lowered or "*" in lowered:
        extras = [
            item for item in entries if item.lower() not in ("all", "*")
        ]
        if extras:
            sys.stderr.write(
                "[tui_gateway] FETIH_TUI_TOOLSETS=all — ignoring additional "
                "entries: " + ", ".join(extras) + "\n"
            )
        return None

    toolsets = _mod("toolsets")

    valid: list = []
    unknown: list = []

    def _is_valid(name: str) -> bool:
        try:
            return bool(toolsets.validate_toolset(name))
        except Exception:
            return False

    for name in entries:
        if _is_valid(name):
            valid.append(name)
        else:
            unknown.append(name)

    if unknown:
        # Eklentiler araç seti kaydedebilir; keşiften sonra yeniden dene.
        try:
            _mod("fetih_cli.plugins").discover_plugins()
        except Exception:
            pass
        still_unknown = []
        for name in unknown:
            if _is_valid(name):
                valid.append(name)
            else:
                still_unknown.append(name)
        unknown = still_unknown

    disabled: list = []
    if unknown:
        servers = _mcp_servers_cfg()
        remaining = []
        for name in unknown:
            entry = servers.get(name)
            if entry is None:
                remaining.append(name)
                continue
            enabled = True
            if isinstance(entry, dict):
                try:
                    enabled = bool(
                        _mod("fetih_cli.tools_config")._parse_enabled_flag(
                            entry.get("enabled", True), default=True
                        )
                    )
                except Exception:
                    enabled = True
            if enabled:
                valid.append(name)
            else:
                disabled.append(name)
        unknown = remaining

    if disabled:
        sys.stderr.write(
            "[tui_gateway] ignoring disabled MCP servers (set enabled: true in "
            "config.yaml to use): " + ", ".join(disabled) + "\n"
        )
    if unknown:
        sys.stderr.write(
            "[tui_gateway] ignoring unknown FETIH_TUI_TOOLSETS entries: "
            + ", ".join(unknown)
            + "\n"
        )
    if not valid:
        return _toolsets_from_config()
    return valid


# --------------------------------------------------------------------------
# Durum veritabanı
# --------------------------------------------------------------------------


def _get_db():
    """Önbelleğe alınmış ``SessionDB`` örneğini döndür (yoksa ``None``)."""
    global _db, _db_error
    if _db is not None:
        return _db
    try:
        _db = _mod("fetih_state").SessionDB()
        _db_error = None
        return _db
    except Exception as exc:
        _db_error = str(exc) or type(exc).__name__
        return None


def _state_db_error() -> str:
    return "state.db unavailable: " + (_db_error or "unknown error")


# --------------------------------------------------------------------------
# Geçmiş dönüşümleri
# --------------------------------------------------------------------------


def _content_to_text(content) -> str:
    """Mesaj içeriğini düz metne çevir (çok kipli içerik dahil)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if not isinstance(part, dict):
                continue
            kind = part.get("type")
            if kind == "text":
                text = part.get("text")
                if isinstance(text, str) and text:
                    parts.append(text)
            elif kind == "image_url":
                parts.append("[image]")
        return "\n".join(parts)
    if content is None:
        return ""
    return str(content)


def _tool_call_context(arguments) -> str:
    """Araç çağrısı argümanlarını görüntülenecek bağlama indirge."""
    try:
        parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
    except Exception:
        return str(arguments)
    if isinstance(parsed, dict):
        if len(parsed) == 1:
            return str(next(iter(parsed.values())))
        return json.dumps(parsed, ensure_ascii=False)
    return str(parsed)


def _history_to_messages(history) -> list:
    """Ajan geçmişini istemcinin gösterdiği mesaj listesine çevir.

    Araç çağrıları görüntülenebilir bir ``tool`` satırına dönüşür; boş
    asistan metinleri ve araç sonuçları düşürülür (istemci bunları
    yeniden göstermez).
    """
    out: list = []
    for message in history or []:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if role == "user":
            text = _content_to_text(message.get("content"))
            if text:
                out.append({"role": "user", "text": text})
        elif role == "assistant":
            text = _content_to_text(message.get("content"))
            if isinstance(text, str) and text:
                out.append({"role": "assistant", "text": text})
            for call in message.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                function = call.get("function")
                if not isinstance(function, dict):
                    continue
                out.append(
                    {
                        "role": "tool",
                        "name": function.get("name") or "",
                        "context": _tool_call_context(function.get("arguments")),
                    }
                )
    return out


def _last_assistant_text(messages) -> str:
    for message in reversed(list(messages or [])):
        if not isinstance(message, dict):
            continue
        if message.get("role") != "assistant":
            continue
        text = _content_to_text(message.get("content"))
        if text:
            return text
    return ""


# --------------------------------------------------------------------------
# Oturum yardımcıları
# --------------------------------------------------------------------------


def _session_info(agent) -> dict:
    """İstemcinin durum çubuğu için ajan özeti."""
    info = {
        "model": "",
        "provider": "",
        "tools": {},
        "skills": {},
        "mcp_servers": [],
    }
    if agent is not None:
        info["model"] = getattr(agent, "model", "") or ""
        info["provider"] = getattr(agent, "provider", "") or ""
        tools = getattr(agent, "tools", None)
        if tools is not None:
            info["tools"] = tools
        skills = getattr(agent, "skills", None)
        if skills is not None:
            info["skills"] = skills
    try:
        info["mcp_servers"] = _mod("tools.mcp_tool").get_mcp_status()
    except Exception:
        info["mcp_servers"] = []
    return info


def _get_usage(agent) -> dict:
    """Ajanın jeton kullanım özeti."""
    usage: dict = {}
    if agent is None:
        return usage
    for attr, key in (
        ("session_total_tokens", "total_tokens"),
        ("session_prompt_tokens", "prompt_tokens"),
        ("session_completion_tokens", "completion_tokens"),
    ):
        try:
            usage[key] = int(getattr(agent, attr, 0) or 0)
        except Exception:
            usage[key] = 0
    return usage


def _agent_cbs(sid) -> dict:
    """Ajan geri çağrıları.

    ``status_callback(kind, text)`` ya da tek argümanlı
    ``status_callback(text)`` biçiminde çağrılabilir.
    """

    def status_callback(kind, text=None):
        if text is None:
            payload = {"kind": "status", "text": str(kind)}
        else:
            payload = {"kind": str(kind), "text": str(text)}
        _emit("status.update", sid, payload)

    def stream_callback(chunk):
        text = _content_to_text(chunk) if not isinstance(chunk, str) else chunk
        if text:
            _emit("message.delta", sid, {"text": text})

    return {
        "status_callback": status_callback,
        "stream_callback": stream_callback,
    }


def _wire_callbacks(sid) -> None:
    """Ajan nesnesine geri çağrıları bağla."""
    try:
        session = _sessions.get(sid)
    except Exception:
        return
    if not isinstance(session, dict):
        return
    agent = session.get("agent")
    if agent is None:
        return
    for name, callback in _agent_cbs(sid).items():
        try:
            setattr(agent, name, callback)
        except Exception:
            pass


def _probe_credentials(agent) -> None:
    """Kimlik bilgisi yokluğunu erken bildir (ağ erişimi yok)."""
    try:
        configured = any(os.environ.get(name) for name in _CREDENTIAL_ENV_VARS)
        if not configured:
            _emit(
                "credentials.update",
                None,
                {"provider": getattr(agent, "provider", "") or "", "configured": False},
            )
    except Exception:
        pass


def _notify_session_boundary(event, session_id) -> None:
    """Eklentilere oturum sınırı olayını bildir (en iyi çaba)."""
    try:
        _mod("fetih_cli.plugins").invoke_hook(
            event, session_id=session_id, platform="tui"
        )
    except Exception:
        pass


def _register_approval_notify(session_key, session=None) -> None:
    """Onay istemlerini istemciye iletecek geri çağrıyı kaydet."""
    if not isinstance(session_key, str) or not session_key:
        return
    sid = None
    if isinstance(session, dict):
        sid = session.get("id")
    try:
        approval = _mod("tools.approval")

        def _notify(approval_data):
            _emit(
                "approval.request",
                sid,
                {
                    "request": approval_data
                    if isinstance(approval_data, dict)
                    else {"command": str(approval_data)}
                },
            )

        approval.register_gateway_notify(session_key, _notify)
        approval.load_permanent_allowlist()
    except Exception:
        pass


def _unregister_approval_notify(session_key) -> None:
    """Onay geri çağrısını kaydından düşür."""
    if not isinstance(session_key, str) or not session_key:
        return
    try:
        _mod("tools.approval").unregister_gateway_notify(session_key)
    except Exception:
        pass


def _enable_gateway_prompts() -> None:
    """Ağ geçidi sürecini etkileşimli/onaylı moda al."""
    os.environ["FETIH_GATEWAY_SESSION"] = "1"
    os.environ["FETIH_EXEC_ASK"] = "1"
    os.environ["FETIH_INTERACTIVE"] = "1"


def _install_session_row(session_key, agent) -> None:
    """Oturumu durum veritabanına kaydet (en iyi çaba)."""
    db = _get_db()
    if db is None or not session_key:
        return
    try:
        db.create_session(
            session_id=session_key,
            source="tui",
            model=getattr(agent, "model", "") or "",
            provider=getattr(agent, "provider", "") or "",
        )
    except Exception:
        pass


def _make_agent(sid, key):
    """Ajan örneğini kur.

    ``session_id`` olarak oturum anahtarı kullanılır; sıkıştırma
    sırasında döndürülürse ``_sync_session_key_after_compress`` takip eder.
    """
    cfg = _cfg_dict()
    model, provider = _resolve_startup_runtime()
    max_turns = _max_turns_from_cfg(cfg, _DEFAULT_MAX_TURNS)

    runtime: dict = {}
    try:
        runtime = (
            _mod("fetih_cli.runtime_provider").resolve_runtime_provider(
                requested=provider, target_model=model
            )
            or {}
        )
    except Exception:
        runtime = {}
    if not isinstance(runtime, dict):
        runtime = {}

    try:
        progress_mode = _load_tool_progress_mode()
    except Exception:
        progress_mode = "all"

    kwargs = {
        "model": model,
        "provider": runtime.get("provider") or provider,
        "base_url": runtime.get("base_url"),
        "api_key": runtime.get("api_key"),
        "api_mode": runtime.get("api_mode"),
        "command": runtime.get("command"),
        "args": runtime.get("args"),
        "credential_pool": runtime.get("credential_pool"),
        "max_iterations": max_turns,
        "enabled_toolsets": _load_enabled_toolsets(),
        "verbose_logging": progress_mode == "verbose",
        "reasoning_config": _load_reasoning_config(),
        "service_tier": _load_service_tier(),
        "session_id": key,
        "session_db": _get_db(),
    }
    for name, callback in _agent_cbs(sid).items():
        kwargs[name] = callback

    return _mod("run_agent").AIAgent(**kwargs)


def _background_agent_kwargs(agent, task_id):
    """Arka plan (alt-ajan) çalışması için ajan argümanlarını üret.

    Tur sayısı üst ajanınkinden bağımsızdır: ``agent.max_turns`` →
    kök ``max_turns`` → 25.
    """
    cfg = _cfg_dict()
    max_turns = _max_turns_from_cfg(cfg, _DEFAULT_BACKGROUND_MAX_TURNS)
    kwargs = {
        "model": getattr(agent, "model", None),
        "provider": getattr(agent, "provider", None),
        "base_url": getattr(agent, "base_url", None),
        "api_key": getattr(agent, "api_key", None),
        "api_mode": getattr(agent, "api_mode", None),
        "acp_command": getattr(agent, "acp_command", None),
        "acp_args": getattr(agent, "acp_args", None),
        "enabled_toolsets": getattr(agent, "enabled_toolsets", None),
        "reasoning_config": getattr(agent, "reasoning_config", None),
        "service_tier": getattr(agent, "service_tier", None),
        "request_overrides": getattr(agent, "request_overrides", None),
        "max_iterations": max_turns,
        "session_id": task_id,
        "session_db": _get_db(),
    }
    for name in (
        "ephemeral_system_prompt",
        "providers_allowed",
        "providers_ignored",
        "providers_order",
        "provider_sort",
        "provider_require_parameters",
        "provider_data_collection",
        "_fallback_model",
    ):
        kwargs[name] = getattr(agent, name, None)
    return kwargs


class _SlashWorker:
    """Eğik çizgi komutlarını ajan oturumunda çalıştıran yardımcı.

    Her oturum kendi çalışanına sahiptir; oturum kapanırken
    ``close()`` çağrılır. Komut yürütme, ajanın kendi komut işleyicisine
    devredilir; hazır değilse ``exec`` boş dize döner.
    """

    def __init__(self, session_key, model=""):
        self.session_key = session_key
        self.model = model
        self._closed = False
        self._lock = threading.Lock()
        self._agent = None

    def attach(self, agent) -> None:
        self._agent = agent

    def exec(self, command):
        """Komutu çalıştır ve görüntülenecek çıktıyı döndür."""
        with self._lock:
            if self._closed:
                return ""
            agent = self._agent
        handler = getattr(agent, "run_slash_command", None)
        if callable(handler):
            try:
                out = handler(command)
                return "" if out is None else str(out)
            except Exception as exc:
                raise RuntimeError(str(exc) or type(exc).__name__)
        return ""

    def close(self) -> None:
        """Çalışanı kapat; sonraki ``exec`` çağrıları boş döner."""
        with self._lock:
            self._closed = True
            agent = self._agent
            self._agent = None
        closer = getattr(agent, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:
                pass


def _restart_slash_worker(session) -> None:
    """Oturumun eğik çizgi çalışanını yeniden kur (model/oturum değişti)."""
    if not isinstance(session, dict):
        return
    worker = session.get("slash_worker")
    if worker is not None:
        try:
            worker.close()
        except Exception:
            pass
    agent = session.get("agent")
    model = getattr(agent, "model", "") if agent is not None else ""
    try:
        session["slash_worker"] = _SlashWorker(
            session.get("session_key") or "", model or ""
        )
    except Exception:
        session["slash_worker"] = None


def _init_session(sid, key, agent, history, cols=80) -> None:
    """Var olan bir oturumu (yeniden) kur: çalışan, geri çağrılar, kayıt."""
    try:
        session = _sessions.get(sid)
    except Exception:
        session = None
    worker = None
    if isinstance(session, dict):
        worker = session.get("slash_worker")
    if worker is None:
        try:
            worker = _SlashWorker(
                key, (getattr(agent, "model", "") if agent is not None else "") or ""
            )
        except Exception:
            worker = None
    if isinstance(session, dict):
        session["slash_worker"] = worker
        if agent is not None:
            session["agent"] = agent
        if history is not None:
            session["history"] = list(history)
        if cols:
            session["cols"] = cols
        attacher = getattr(worker, "attach", None)
        if callable(attacher):
            try:
                attacher(agent)
            except Exception:
                pass
    _register_approval_notify(key, session)
    _wire_callbacks(sid)
    _notify_session_boundary("on_session_reset", key)


def _finalize_session(session, end_reason="tui_close") -> None:
    """Oturumu kapat: belleği kalıcılaştır, DB satırını kapat, olay yay."""
    if not isinstance(session, dict):
        return
    agent = session.get("agent")
    history = session.get("history") or []
    target = session.get("session_key")
    if agent is not None:
        target = getattr(agent, "session_id", None) or target
        commit = getattr(agent, "commit_memory_session", None)
        if callable(commit):
            try:
                commit(history)
            except Exception:
                pass
    db = _get_db()
    if db is not None and target:
        try:
            db.end_session(target, end_reason)
        except Exception:
            pass
    _notify_session_boundary("on_session_finalize", target)


def _build(sid, key, cols) -> None:
    """Geciktirilmiş ajan inşası.

    İnşa sırasında oturum kapatılmışsa (hızlı ``/new`` yarışı) yeni
    ayrılan çalışan ve onay kaydı geri bırakılır; oturum sözlüğüne
    dokunulmaz.
    """
    agent = None
    error = None
    try:
        agent = _make_agent(sid, key)
    except Exception as exc:
        error = str(exc) or type(exc).__name__

    worker = None
    if agent is not None:
        try:
            worker = _SlashWorker(key, getattr(agent, "model", "") or "")
        except Exception as exc:
            if error is None:
                error = str(exc) or type(exc).__name__

    try:
        session = _sessions.get(sid)
    except Exception:
        session = None

    if session is None:
        # Oturum inşa sürerken kapatıldı: yetim kaynakları serbest bırak.
        if worker is not None:
            try:
                worker.close()
            except Exception:
                pass
        _unregister_approval_notify(key)
        return

    try:
        if error is not None:
            session["agent_error"] = error
            _emit("error", sid, {"message": error})
            return
        session["agent"] = agent
        session["agent_error"] = None
        session["slash_worker"] = worker
        attacher = getattr(worker, "attach", None)
        if callable(attacher):
            try:
                attacher(agent)
            except Exception:
                pass
        _install_session_row(key, agent)
        _probe_credentials(agent)
        _wire_callbacks(sid)
        _register_approval_notify(key, session)
    finally:
        try:
            session["agent_ready"].set()
        except Exception:
            pass
    if error is None:
        _emit("session.info", sid, _session_info(agent))
        _notify_session_boundary("on_session_reset", key)


def _start_agent_build(sid, key, cols) -> None:
    """Ajan inşasını kısa bir gecikmeyle arka planda başlat."""

    def _delayed():
        try:
            time.sleep(_BUILD_DELAY_S)
        except Exception:
            pass
        _build(sid, key, cols)

    try:
        _real_thread(target=_delayed, daemon=True).start()
    except Exception:
        pass


# --------------------------------------------------------------------------
# Geçmiş mutasyonları (sıkıştırma, model değişimi)
# --------------------------------------------------------------------------


def _compress_session_history(session, focus_topic=None, **_kw):
    """Oturum geçmişini sıkıştır; (silinen, kullanım) çifti döndür.

    Anlık görüntü ``history_lock`` altında alınır; ajanın sıkıştırma
    yardımcısı varsa çağrılır ve sonuç geçmişin yerine yazılır.
    """
    if not isinstance(session, dict):
        return 0, {}
    lock = session.get("history_lock") or contextlib.nullcontext()
    with lock:
        snapshot = list(session.get("history") or [])
    removed = 0
    usage: dict = {}
    agent = session.get("agent")
    compress = None
    for name in ("_compress_context", "_manual_compress"):
        candidate = getattr(agent, name, None) if agent is not None else None
        if callable(candidate):
            compress = candidate
            break
    if compress is not None:
        try:
            outcome = compress(snapshot, focus_topic)
        except Exception:
            outcome = None
        if isinstance(outcome, tuple) and len(outcome) == 2:
            messages, comp_usage = outcome
            if isinstance(messages, list):
                removed = max(0, len(snapshot) - len(messages))
                with lock:
                    session["history"] = list(messages)
                    session["history_version"] = (
                        session.get("history_version", 0) + 1
                    )
            if isinstance(comp_usage, dict):
                usage = comp_usage
    return removed, usage


def _sync_session_key_after_compress(sid, session, **_kw) -> None:
    """Sıkıştırma oturum kimliğini döndürdüyse ağ geçidi anahtarını taşı."""
    if not isinstance(session, dict):
        return
    agent = session.get("agent")
    new_key = getattr(agent, "session_id", None) if agent is not None else None
    old_key = session.get("session_key")
    if not isinstance(new_key, str) or not new_key or new_key == old_key:
        return
    _unregister_approval_notify(old_key)
    session["session_key"] = new_key
    session["pending_title"] = None
    _register_approval_notify(new_key, session)
    _restart_slash_worker(session)


def _split_model_args(raw):
    """Model argümanını ve ``--provider`` / ``--global`` bayraklarını ayır."""
    text = "" if raw is None else str(raw)
    provider = ""
    is_global = False
    kept = []
    tokens = text.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--provider" and index + 1 < len(tokens):
            provider = tokens[index + 1]
            index += 2
            continue
        if token.startswith("--provider="):
            provider = token.split("=", 1)[1]
            index += 1
            continue
        if token == "--global":
            is_global = True
            index += 1
            continue
        kept.append(token)
        index += 1
    return " ".join(kept).strip(), provider, is_global


def _apply_model_switch(sid, session, raw) -> dict:
    """Canlı oturumda model değiştir; ``{"value", "warning"}`` döndür."""
    agent = session.get("agent") if isinstance(session, dict) else None
    model_arg, explicit_provider, is_global = _split_model_args(raw)
    cfg = _cfg_dict()
    try:
        result = _mod("fetih_cli.model_switch").switch_model(
            raw_input=model_arg,
            current_provider=getattr(agent, "provider", "") or "",
            current_model=getattr(agent, "model", "") or "",
            current_base_url=getattr(agent, "base_url", "") or "",
            current_api_key=getattr(agent, "api_key", "") or "",
            is_global=is_global,
            explicit_provider=explicit_provider,
            user_providers=cfg.get("providers") or {},
            custom_providers=cfg.get("custom_providers") or [],
        )
    except Exception as exc:
        return {"value": model_arg, "warning": "model switch failed: " + str(exc)}
    if result is None:
        return {"value": model_arg, "warning": "model switch failed"}
    if not getattr(result, "success", False):
        warning = getattr(result, "warning_message", "") or "model switch failed"
        return {"value": model_arg, "warning": warning}

    new_model = getattr(result, "new_model", "") or model_arg
    target_provider = getattr(result, "target_provider", "") or explicit_provider
    base_url = getattr(result, "base_url", None)
    api_key = getattr(result, "api_key", None)
    api_mode = getattr(result, "api_mode", None)

    if agent is not None:
        for name, value in (
            ("model", new_model),
            ("provider", target_provider),
            ("base_url", base_url),
            ("api_key", api_key),
            ("api_mode", api_mode),
        ):
            try:
                setattr(agent, name, value)
            except Exception:
                pass

    # Ortam değişkenleri sonraki /new çözümlemesinin açık seçimi görmesi
    # için güncellenir: FETIH_TUI_PROVIDER koşulsuz yazılır.
    os.environ[_ENV_MODEL] = new_model
    os.environ[_ENV_INFERENCE_MODEL] = new_model
    if target_provider:
        os.environ[_ENV_INFERENCE_PROVIDER] = target_provider
        os.environ[_ENV_TUI_PROVIDER] = target_provider

    _restart_slash_worker(session)

    if is_global:
        try:
            cfg = _cfg_dict()
            model_cfg = cfg.get("model")
            if not isinstance(model_cfg, dict):
                model_cfg = {}
                cfg["model"] = model_cfg
            model_cfg["default"] = new_model
            model_cfg["provider"] = target_provider
            model_cfg["base_url"] = base_url
            _mod("fetih_cli.config").save_config(cfg)
        except Exception:
            pass

    return {"value": new_model, "warning": getattr(result, "warning_message", "") or ""}


def _mirror_slash_side_effects(sid, session, command) -> str:
    """Eğik çizgi komutunun yan etkilerini ağ geçidi tarafında uygula.

    Çalışan bir oturumda geçmişi/ajanı değiştiren komutlar reddedilir ve
    istemciye gösterilecek uyarı döndürülür; boş dize "sorun yok" demektir.
    """
    if not isinstance(command, str) or not command.strip():
        return ""
    text = command.strip()
    if not text.startswith("/"):
        text = "/" + text
    parts = text.split(None, 1)
    name = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""
    if name not in ("/model", "/personality", "/prompt", "/compress"):
        return ""
    running = bool(session.get("running")) if isinstance(session, dict) else False
    if running:
        return (
            "session busy: "
            + name
            + " cannot run while the agent is working — try again once the turn ends"
        )
    if name == "/model":
        outcome = _apply_model_switch(sid, session, arg)
        return outcome.get("warning") or ""
    if name == "/personality":
        session["ephemeral_personality"] = arg
        return ""
    if name == "/prompt":
        session["ephemeral_prompt"] = arg
        return ""
    # /compress
    _compress_session_history(session, arg or None)
    _sync_session_key_after_compress(sid, session)
    _emit("session.info", sid, _session_info(session.get("agent")))
    return ""


# --------------------------------------------------------------------------
# Bekleyen istemci istekleri (clarify / sudo / secret / approval)
# --------------------------------------------------------------------------


def _unpack_pending(entry):
    """``_pending`` girdisini (sahip, Event) çiftine çöz."""
    if isinstance(entry, tuple) and len(entry) == 2:
        return entry[0], entry[1]
    if entry is not None and hasattr(entry, "set"):
        return None, entry
    return None, None


def _clear_pending(sid=None) -> None:
    """Bekleyen istemci isteklerini boş yanıtla serbest bırak.

    ``sid`` verilirse yalnızca o oturuma ait istekler etkilenir; ``None``
    verilirse tümü (kapanış yolu).
    """
    try:
        items = list(_pending.items())
    except Exception:
        return
    for request_id, entry in items:
        owner, event = _unpack_pending(entry)
        if isinstance(sid, str) and sid and owner != sid:
            continue
        _answers[request_id] = ""
        try:
            _pending.pop(request_id, None)
        except Exception:
            pass
        if event is not None:
            try:
                event.set()
            except Exception:
                pass


def _respond(request_id, answer) -> None:
    """İstemciden gelen yanıtı bekleyen isteğe ilet."""
    if not request_id:
        return
    try:
        entry = _pending.pop(request_id, None)
    except Exception:
        entry = None
    _answers[request_id] = "" if answer is None else str(answer)
    _owner, event = _unpack_pending(entry)
    if event is not None:
        try:
            event.set()
        except Exception:
            pass


def _await_client(session_id, request_id, kind, payload, timeout=None):
    """İstemciye bir istek gönder ve yanıtını bekle (yanıt yoksa "")."""
    event = threading.Event()
    try:
        _pending[request_id] = (session_id, event)
        _emit(kind, session_id, dict(payload or {}, request_id=request_id))
        event.wait(timeout)
    except Exception:
        pass
    finally:
        try:
            _pending.pop(request_id, None)
        except Exception:
            pass
    return _answers.pop(request_id, "")


# --------------------------------------------------------------------------
# Ajan turu
# --------------------------------------------------------------------------


def make_stream_renderer(cols):
    """Sessiz bir yayın çizici üret: gelen parçayı istemciye iletir.

    ``cols`` terminal genişliğidir; çizici, ham parçayı yeniden
    biçimlendirmek için ``render_message`` kullanır.
    """
    width = cols if isinstance(cols, int) and cols > 0 else _DEFAULT_COLS

    def _render(raw):
        text = render_message(raw, width)
        if text:
            _emit("message.delta", None, {"text": text})
        return text

    return _render


def render_message(raw, cols=_DEFAULT_COLS):
    """Ham ajan çıktısını istemcide gösterilecek metne çevir.

    Ağ geçidi satır bazlı çalıştığı için biçimlendirme yapılmaz; boş
    parçalar düşürülür.
    """
    if raw is None:
        return ""
    text = raw if isinstance(raw, str) else _content_to_text(raw)
    return text


def _expand_context_refs(agent, prompt_text, cwd=None):
    """``@diff`` gibi bağlam referanslarını genişlet (en iyi çaba)."""
    try:
        preprocess = _mod("agent.context_references").preprocess_context_references
    except Exception:
        return prompt_text, None
    context_length = 0
    try:
        model_name = getattr(agent, "model", "") or ""
        context_length = (
            _mod("agent.model_metadata").get_model_context_length(model_name) or 0
        )
    except Exception:
        context_length = 0
    try:
        processed = preprocess(
            prompt_text,
            cwd=str(cwd or Path.cwd()),
            context_length=context_length,
        )
    except Exception:
        return prompt_text, None
    if isinstance(processed, str):
        return processed, None
    if isinstance(processed, dict):
        blocked = bool(processed.get("blocked"))
        message = processed.get("message")
        warnings = processed.get("warnings") or []
    elif processed is not None:
        blocked = bool(getattr(processed, "blocked", False))
        message = getattr(processed, "message", None)
        warnings = getattr(processed, "warnings", None) or []
    else:
        return prompt_text, None
    if blocked:
        detail = "; ".join(str(item) for item in warnings) or "blocked"
        return prompt_text, detail
    if isinstance(message, str) and message:
        return message, None
    return prompt_text, None


def _noop_failure(*_args, **_kwargs) -> None:
    """Başlık üretimi başarısız olduğunda sessizce yut."""
    return None


def _start_turn(session_id, session, user_text, title_text=None, auto_title=True):
    """Yeni bir ajan turunu arka planda başlat.

    Burada bilinçli olarak modül globali ``threading.Thread`` kullanılır
    (inşa iş parçacığının aksine): testler Thread sınıfını eşzamanlı bir
    taklitle değiştirir ve turun satır içi çalışmasını bekler.
    """
    if not isinstance(session, dict):
        return False
    session["running"] = True
    label = user_text if title_text is None else title_text

    def _runner():
        _run_turn(session_id, session, user_text, label, auto_title)

    threading.Thread(target=_runner, daemon=True).start()
    return True


def _run_turn(session_id, session, user_text, title_text, auto_title=True) -> None:
    """Ajanı bir kez çalıştır, olayları yay, geçmişi tazecik tut."""
    agent = session.get("agent")
    session_key = session.get("session_key") or ""
    version_before = session.get("history_version", 0)
    messages = None
    final_text = ""
    status = "complete"
    usage: dict = {}
    token = None

    try:
        try:
            token = _mod("tools.approval").set_current_session_key(session_key)
        except Exception:
            token = None

        prompt_text = user_text
        blocked_reason = None
        try:
            prompt_text, blocked_reason = _expand_context_refs(
                agent, user_text, session.get("cwd")
            )
        except Exception:
            prompt_text, blocked_reason = user_text, None

        if blocked_reason:
            messages = list(session.get("history") or [])
            final_text = "Error: " + blocked_reason
            status = "error"
            return

        turn_history = list(session.get("history") or [])
        turn_history.append({"role": "user", "content": prompt_text})

        cols = session.get("cols") or _DEFAULT_COLS
        try:
            streamer = make_stream_renderer(cols)
        except Exception:
            streamer = None

        def _on_chunk(chunk):
            raw = chunk if isinstance(chunk, str) else _content_to_text(chunk)
            if streamer is not None:
                try:
                    streamer(raw)
                    return
                except Exception:
                    pass
            try:
                text = render_message(raw, cols)
            except Exception:
                text = raw
            if text:
                _emit("message.delta", session_id, {"text": text})

        result = None
        try:
            result = agent.run_conversation(
                prompt_text,
                conversation_history=turn_history,
                stream_callback=_on_chunk,
            )
        except TypeError:
            result = agent.run_conversation(prompt_text)

        if isinstance(result, dict):
            raw_messages = result.get("messages")
            if isinstance(raw_messages, list) and raw_messages:
                messages = raw_messages
            final_value = result.get("final_response")
            if final_value is None:
                final_value = result.get("response")
            final_text = _content_to_text(final_value)
            if bool(result.get("interrupted")):
                status = "interrupted"
            backend_error = result.get("error")
            if not final_text and backend_error:
                final_text = "Error: " + str(backend_error)
                status = "error"
        elif isinstance(result, list):
            messages = result
            final_text = _last_assistant_text(result)
        if messages is None:
            messages = list(session.get("history") or [])
            if not final_text:
                final_text = _last_assistant_text(messages)

        if session.get("interrupted"):
            status = "interrupted"
    except Exception as exc:
        status = "error"
        final_text = final_text or ("Error: " + (str(exc) or type(exc).__name__))
    finally:
        try:
            if token is not None:
                _mod("tools.approval").reset_current_session_key(token)
        except Exception:
            pass

        session["running"] = False
        session["interrupted"] = False

        # Geçmiş yalnızca tur boyunca dışarıdan değiştirilmediyse yazılır;
        # aksi halde ajanın çıktısı kaydedilmeden gösterilirdi.
        warning = ""
        try:
            version_after = session.get("history_version", 0)
            if version_after != version_before:
                warning = (
                    "history changed during the turn — the agent's reply was "
                    "not saved to the session history"
                )
            else:
                if messages:
                    with session["history_lock"]:
                        session["history"] = list(messages)
                with session["history_lock"]:
                    session["history_version"] = version_after + 1
        except Exception as exc:
            warning = "history write failed: " + (str(exc) or type(exc).__name__)

        try:
            usage = _get_usage(agent)
        except Exception:
            usage = {}

        payload = {"status": status, "text": final_text, "usage": usage}
        if warning:
            payload["warning"] = warning
        _emit("message.complete", session_id, payload)

        try:
            _flush_pending_title(session)
        except Exception:
            pass

        if auto_title and status == "complete" and final_text:
            try:
                _mod("agent.title_generator").maybe_auto_title(
                    _get_db(),
                    session.get("session_key") or "",
                    title_text,
                    final_text,
                    session.get("history") or [],
                    failure_callback=_noop_failure,
                )
            except Exception:
                pass

        try:
            _sync_session_key_after_compress(session_id, session)
        except Exception:
            pass


def _flush_pending_title(session) -> None:
    """İlk mesajdan sonra sırada bekleyen başlığı kalıcılaştır.

    ``ValueError`` kalıcı bir reddir (başlık zaten kullanımda) ve bekleyen
    başlık düşürülür; diğer hatalar başlığı kuyrukta bırakır ki sonraki
    turda yeniden denensin.
    """
    if not isinstance(session, dict):
        return
    title = session.get("pending_title")
    if not isinstance(title, str) or not title.strip():
        return
    key = session.get("session_key")
    db = _get_db()
    if db is None or not key:
        return
    try:
        ok = db.set_session_title(key, title)
    except ValueError:
        session["pending_title"] = None
        return
    except Exception:
        return
    if ok:
        session["pending_title"] = None


# --------------------------------------------------------------------------
# Bildirim dinleyicisi (arka plan süreç tamamlanmaları)
# --------------------------------------------------------------------------


def _process_events(session_id, session, events) -> None:
    """Tamamlanma olaylarını oturuma uygula."""
    process_registry = _mod("tools.process_registry").process_registry

    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("type") != "completion":
            continue
        proc_sid = event.get("session_id")
        try:
            consumed = bool(process_registry.is_completion_consumed(proc_sid))
        except Exception:
            consumed = False
        if consumed:
            continue
        text = "Background process {} finished (exit code {})".format(
            proc_sid, event.get("exit_code")
        )
        if session.get("running"):
            _emit("status.update", session_id, {"kind": "process", "text": text})
            try:
                process_registry.completion_queue.put(event)
            except Exception:
                pass
            continue
        _emit("status.update", session_id, {"kind": "process", "text": text})
        prompt = (
            "[IMPORTANT: Background process {} completed (exit code {})."
            " Command: {}. Output:\n{}\n"
            "Report the result to the user.]".format(
                proc_sid,
                event.get("exit_code"),
                event.get("command"),
                event.get("output", ""),
            )
        )
        try:
            # Arka plan tamamlanma turlarında başlık üretimi çalıştırılmaz:
            # gerçek bir LLM çağrısı yapan iş parçacığı burada istenmez.
            _start_turn(session_id, session, prompt, auto_title=False)
        except Exception:
            pass


def _notification_poller_loop(stop_event, session_id, session) -> None:
    """Tamamlanma kuyruğunu boşalt ve ilgili oturuma ilet.

    Kuyruk iç döngüde yerel bir listeye alınır: meşgul bir oturum için
    geri konulan olay aynı geçişte yeniden tüketilmez.
    """
    process_registry = _mod("tools.process_registry").process_registry

    while True:
        pending: list = []
        try:
            while not process_registry.completion_queue.empty():
                try:
                    pending.append(process_registry.completion_queue.get_nowait())
                except Exception:
                    break
        except Exception:
            pending = []
        try:
            _process_events(session_id, session, pending)
        except Exception:
            pass
        if stop_event.is_set():
            return
        try:
            stop_event.wait(0.5)
        except Exception:
            try:
                time.sleep(0.5)
            except Exception:
                return


# --------------------------------------------------------------------------
# session.* uçları
# --------------------------------------------------------------------------


def _h_session_create(rid, params):
    """Yeni bir TUI oturumu aç; ajan arka planda kurulur."""
    cols = params.get("cols")
    if not isinstance(cols, int) or isinstance(cols, bool) or cols <= 0:
        cols = _DEFAULT_COLS
    sid = uuid.uuid4().hex[:16]
    key = params.get("session_key")
    if not isinstance(key, str) or not key.strip():
        key = "tui-" + sid
    try:
        progress_mode = _load_tool_progress_mode()
    except Exception:
        progress_mode = "all"
    session = {
        "id": sid,
        "agent": None,
        "session_key": key,
        "history": [],
        "history_lock": threading.Lock(),
        "history_version": 0,
        "running": False,
        "interrupted": False,
        "attached_images": [],
        "image_counter": 0,
        "cols": cols,
        "slash_worker": None,
        "show_reasoning": False,
        "tool_progress_mode": progress_mode,
        "pending_title": None,
        "agent_ready": threading.Event(),
        "agent_error": None,
    }
    _sessions[sid] = session
    _start_agent_build(sid, key, cols)
    if _serve_loop_active:
        stop_event = threading.Event()
        session["poller_stop"] = stop_event
        try:
            _real_thread(
                target=_notification_poller_loop,
                args=(stop_event, sid, session),
                daemon=True,
            ).start()
        except Exception:
            pass
    return _result(rid, {"session_id": sid, "session_key": key, "cols": cols})


def _h_session_close(rid, params):
    """Oturumu kapat: belleği kalıcılaştır, kaynakları bırak."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _result(rid, {"closed": False})
    try:
        _finalize_session(session)
    except Exception:
        pass
    worker = session.get("slash_worker")
    if worker is not None:
        try:
            worker.close()
        except Exception:
            pass
    _unregister_approval_notify(session.get("session_key"))
    stop_event = session.get("poller_stop")
    if stop_event is not None:
        try:
            stop_event.set()
        except Exception:
            pass
    try:
        _sessions.pop(sid, None)
    except Exception:
        pass
    return _result(rid, {"closed": True})


def _h_session_list(rid, params):
    """Kayıtlı oturumları listele (TUI kaynaklı olanlar)."""
    db = _get_db()
    if db is None:
        return _error(rid, 5036, _state_db_error())
    limit = params.get("limit")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        limit = _DEFAULT_SESSION_LIST_LIMIT
    try:
        rows = db.list_sessions_rich(source=None, limit=max(limit * 2, 200))
    except Exception as exc:
        return _error(rid, 5007, "session list failed: " + (str(exc) or "unknown"))
    sessions = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        if (row.get("source") or "") == "tool":
            continue
        sessions.append(row)
    return _result(rid, {"sessions": sessions[:limit]})


def _h_session_most_recent(rid, params):
    """Devam ettirilebilecek en son oturumu döndür (yoksa ``None``)."""
    db = _get_db()
    if db is None:
        return _result(rid, {"session_id": None})
    try:
        rows = db.list_sessions_rich(source=None, limit=_DEFAULT_SESSION_LIST_LIMIT)
    except Exception:
        return _result(rid, {"session_id": None})
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        if (row.get("source") or "") == "tool":
            continue
        return _result(
            rid,
            {
                "session_id": row.get("id"),
                "title": row.get("title"),
                "source": row.get("source"),
            },
        )
    return _result(rid, {"session_id": None})


def _h_session_delete(rid, params):
    """Oturumu veritabanından ve diskten sil."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    db = _get_db()
    if db is None:
        return _error(rid, 5036, _state_db_error())
    try:
        active = {
            entry.get("session_key")
            for entry in _sessions.values()
            if isinstance(entry, dict)
        }
    except Exception:
        return _error(rid, 5036, "could not enumerate active sessions")
    if sid in active:
        return _error(rid, 4023, "session is an active session; close it first")
    sessions_dir = Path(_fetih_home) / "sessions"
    try:
        deleted = db.delete_session(sid, sessions_dir=sessions_dir)
    except Exception as exc:
        return _error(rid, 5036, str(exc) or type(exc).__name__)
    if not deleted:
        return _error(rid, 4007, "session not found: " + sid)
    return _result(rid, {"deleted": sid})


def _h_session_resume(rid, params):
    """Kayıtlı bir oturumu canlı TUI oturumuna dönüştür."""
    target = _require_sid(params)
    if target is None:
        return _error(rid, 4006, "missing session_id")
    db = _get_db()
    if db is None:
        return _error(rid, 5036, _state_db_error())
    try:
        row = db.get_session(target)
    except Exception as exc:
        return _error(rid, 4007, "session not found: " + (str(exc) or target))
    if not row:
        return _error(rid, 4007, "session not found: " + target)
    try:
        db.reopen_session(target)
    except Exception:
        pass
    _enable_gateway_prompts()
    try:
        tokens = _set_session_context(target)
    except Exception:
        tokens = []
    own_history = []
    history = []
    try:
        own_history = list(
            db.get_messages_as_conversation(target, include_ancestors=False) or []
        )
        history = own_history
    except Exception:
        own_history = []
    try:
        lineage = list(
            db.get_messages_as_conversation(target, include_ancestors=True) or []
        )
        if lineage:
            history = lineage
    except Exception:
        pass
    try:
        _clear_session_context(tokens)
    except Exception:
        pass

    cols = params.get("cols")
    if not isinstance(cols, int) or isinstance(cols, bool) or cols <= 0:
        cols = _DEFAULT_COLS
    sid = uuid.uuid4().hex[:16]
    key = target
    try:
        agent = _make_agent(sid, key)
    except Exception as exc:
        return _error(rid, 5007, "agent build failed: " + (str(exc) or "unknown"))
    session = {
        "id": sid,
        "agent": agent,
        "session_key": key,
        "history": list(history),
        "history_lock": threading.Lock(),
        "history_version": 0,
        "running": False,
        "interrupted": False,
        "attached_images": [],
        "image_counter": 0,
        "cols": cols,
        "slash_worker": None,
        "show_reasoning": False,
        "tool_progress_mode": _load_tool_progress_mode(),
        "pending_title": None,
        "agent_ready": threading.Event(),
        "agent_error": None,
    }
    session["agent_ready"].set()
    _sessions[sid] = session
    _init_session(sid, key, agent, history, cols=cols)
    return _result(
        rid,
        {
            "session_id": sid,
            "session_key": key,
            "messages": _history_to_messages(history),
            "info": _session_info(agent),
            "cols": cols,
        },
    )


def _set_session_context(target):
    """Veritabanı okumaları sırasında bağlam referanslarını bastır."""
    try:
        return _mod("agent.context_references").set_context_source(target)
    except Exception:
        return []


def _clear_session_context(tokens) -> None:
    """``_set_session_context`` ile kurulan bağlamı geri al."""
    try:
        _mod("agent.context_references").clear_context_source(tokens)
    except Exception:
        pass


def _h_session_status(rid, params):
    """İnsan okuyabilir oturum durumu metni üret."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    agent = session.get("agent")
    key = session.get("session_key") or ""
    title = None
    db = _get_db()
    if db is not None and key:
        try:
            row = db.get_session(key)
        except Exception:
            row = None
        if isinstance(row, dict):
            title = row.get("title")
    lines = [
        "FETIH TUI Status",
        "Session ID: " + str(key),
        "Title: " + (title or "(untitled)"),
        "Model: {} ({})".format(
            getattr(agent, "model", "") or "", getattr(agent, "provider", "") or ""
        ),
    ]
    try:
        tokens = int(getattr(agent, "session_total_tokens", 0) or 0)
    except Exception:
        tokens = 0
    lines.append("Tokens: {:,}".format(tokens))
    lines.append("Agent Running: " + ("Yes" if session.get("running") else "No"))
    return _result(rid, {"output": "\n".join(lines)})


def _h_session_title(rid, params):
    """Oturum başlığını oku ya da yaz (satır hazır değilse kuyruğa al)."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    key = session.get("session_key") or ""

    if "title" not in params:
        return _result(rid, {"title": _session_title_get(session, key)})

    raw = params.get("title")
    if not isinstance(raw, str) or not raw.strip():
        return _error(rid, 4021, "title must not be empty")
    title = raw.strip()

    db = _get_db()
    if db is None:
        session["pending_title"] = title
        return _result(rid, {"pending": True, "title": title})
    try:
        ok = db.set_session_title(key, title)
    except ValueError as exc:
        return _error(rid, 4022, "title rejected: " + (str(exc) or "invalid"))
    except Exception as exc:
        return _error(rid, 5007, str(exc) or type(exc).__name__)
    if ok:
        session["pending_title"] = None
        return _result(rid, {"pending": False, "title": title})
    # UPDATE 0 satır etkiledi: ya satır hiç yok ya da başlık zaten aynı.
    try:
        row = db.get_session(key)
    except Exception as exc:
        return _error(rid, 5007, "row lookup failed: " + (str(exc) or "unknown"))
    if isinstance(row, dict) and (row.get("title") or "") == title:
        session["pending_title"] = None
        return _result(rid, {"pending": False, "title": title})
    session["pending_title"] = title
    return _result(rid, {"pending": True, "title": title})


def _session_title_get(session, key):
    """Bekleyen başlık varsa önce onu kalıcılaştırmayı dene."""
    pending = session.get("pending_title")
    db = _get_db()
    if isinstance(pending, str) and pending:
        if db is None:
            return pending
        try:
            ok = db.set_session_title(key, pending)
        except ValueError:
            session["pending_title"] = None
            return pending
        except Exception:
            return pending
        if ok:
            session["pending_title"] = None
        return pending
    if db is None:
        return None
    try:
        return db.get_session_title(key)
    except Exception:
        return None


def _h_session_undo(rid, params):
    """Son kullanıcı/asistan çiftini geçmişten düş."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    if session.get("running"):
        return _error(rid, 4009, "session busy: cannot undo while the agent is running")
    removed = 0
    with session["history_lock"]:
        history = session.get("history")
        if isinstance(history, list):
            if history and isinstance(history[-1], dict) and history[-1].get("role") == "assistant":
                history.pop()
                removed += 1
            if history and isinstance(history[-1], dict) and history[-1].get("role") == "user":
                history.pop()
                removed += 1
        session["history_version"] = session.get("history_version", 0) + 1
    return _result(rid, {"removed": removed})


def _h_session_compress(rid, params):
    """Geçmişi sıkıştır ve istemciyi bilgilendir."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    if session.get("running"):
        return _error(
            rid, 4009, "session busy: cannot compress while the agent is running"
        )
    focus = params.get("focus") or params.get("topic") or None
    removed, usage = _compress_session_history(session, focus)
    _sync_session_key_after_compress(sid, session)
    _emit("session.info", sid, _session_info(session.get("agent")))
    _emit("status.update", sid, {"kind": "status", "text": "ready"})
    return _result(rid, {"removed": removed, "usage": usage})


def _h_session_interrupt(rid, params):
    """Tur'u kes: ajanı uyar ve bu oturumun bekleyen isteklerini bırak."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    session["interrupted"] = True
    agent = session.get("agent")
    interrupt = getattr(agent, "interrupt", None) if agent is not None else None
    if callable(interrupt):
        try:
            interrupt()
        except Exception:
            pass
    _clear_pending(sid)
    return _result(rid, {"status": "interrupted"})


def _h_session_steer(rid, params):
    """Çalışan tura ara metin gönder."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    text = params.get("text")
    if not isinstance(text, str) or not text.strip():
        return _error(rid, 4002, "text must not be empty")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    agent = session.get("agent")
    steer = getattr(agent, "steer", None) if agent is not None else None
    if not callable(steer):
        return _error(rid, 4010, "agent does not support steering")
    try:
        steer(text)
    except Exception as exc:
        return _error(rid, 5007, "steer failed: " + (str(exc) or "unknown"))
    return _result(rid, {"status": "queued", "text": text})


# --------------------------------------------------------------------------
# prompt.* uçları
# --------------------------------------------------------------------------


def _h_prompt_submit(rid, params):
    """Kullanıcı istemini ajan turuna çevir."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    text = params.get("text")
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    if not text.strip():
        return _error(rid, 4002, "prompt text must not be empty")
    if session.get("agent") is None:
        return _error(rid, 4007, "session agent is not ready yet")
    if session.get("running"):
        return _error(rid, 4009, "session busy: a turn is already running")
    try:
        _start_turn(sid, session, text)
    except Exception as exc:
        session["running"] = False
        return _error(rid, 5007, "prompt failed: " + (str(exc) or "unknown"))
    return _result(rid, {"status": "streaming"})


def _h_prompt_cancel(rid, params):
    """Çalışan turu iptal et."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    session["interrupted"] = True
    _clear_pending(sid)
    return _result(rid, {"status": "cancelled"})


# --------------------------------------------------------------------------
# Bekleyen istek yanıtları
# --------------------------------------------------------------------------


def _h_respond(rid, params):
    """clarify/sudo/secret/approval yanıtlarını bekleyen isteğe ilet."""
    request_id = params.get("request_id")
    _respond(request_id, params.get("answer"))
    return _result(rid, {"ok": True, "request_id": request_id})


# --------------------------------------------------------------------------
# config.* uçları
# --------------------------------------------------------------------------


def _statusbar_position(cfg) -> str:
    raw = _cfg_get(cfg, "display.tui_statusbar")
    if raw is None:
        raw = cfg.get("tui_statusbar") if isinstance(cfg, dict) else None
    if isinstance(raw, str) and raw.strip().lower() in _STATUS_BAR_POSITIONS:
        return raw.strip().lower()
    return "top"


def _busy_mode(cfg) -> str:
    raw = _cfg_get(cfg, "display.busy_input_mode")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return "interrupt"


def _mouse_enabled(cfg) -> bool:
    """Fare takibi açık mı?

    Belgelenen anahtar ``display.mouse_tracking``; eski
    ``display.tui_mouse`` yalnızca belgelenen anahtar hiç yoksa okunur.
    Açıkça ``null`` bırakılmış bir anahtar "varsayılan" sayılır.
    """
    display = _cfg_get(cfg, "display")
    value = None
    found = False
    if isinstance(display, dict):
        for name in ("mouse_tracking", "tui_mouse", "mouse"):
            if name in display:
                value = display.get(name)
                found = True
                break
    if not found and isinstance(cfg, dict) and "tui_mouse" in cfg:
        value = cfg.get("tui_mouse")
        found = True
    if not found or value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() not in ("", "off", "false", "0", "no")
    return bool(value)


def _normalize_indicator(value) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


def _indicator_style(cfg) -> str:
    raw = _cfg_get(cfg, "display.tui_status_indicator")
    if raw is None and isinstance(cfg, dict):
        raw = cfg.get("tui_status_indicator")
    style = _normalize_indicator(raw)
    if style in _INDICATORS:
        return style
    return _INDICATOR_DEFAULT


def _h_config_get(rid, params):
    """Yapılandırma değerini oku ve istemci için normalize et."""
    key = params.get("key")
    if not isinstance(key, str) or not key.strip():
        return _error(rid, 4002, "missing config key")
    key = key.strip()
    cfg = _load_cfg()
    if key == "statusbar":
        return _result(rid, {"value": _statusbar_position(cfg)})
    if key == "busy":
        return _result(rid, {"value": _busy_mode(cfg)})
    if key == "mouse":
        return _result(rid, {"value": "on" if _mouse_enabled(cfg) else "off"})
    if key == "indicator":
        return _result(rid, {"value": _indicator_style(cfg)})
    if key == "model":
        return _result(rid, {"value": _resolve_model()})
    if key == "details_mode":
        raw = _cfg_get(cfg, "display.details_mode")
        value = raw if isinstance(raw, str) and raw in _DETAIL_MODES else "collapsed"
        return _result(rid, {"value": value})
    if key == "yolo":
        enabled = _env_flag(_ENV_YOLO)
        return _result(rid, {"value": "1" if enabled else "0"})
    if key == "verbose":
        return _result(rid, {"value": _load_tool_progress_mode()})
    return _result(rid, {"value": None})


def _h_config_set(rid, params):
    """Yapılandırma ve canlı ajan durumunu güncelle."""
    key = params.get("key")
    if not isinstance(key, str) or not key.strip():
        return _error(rid, 4002, "missing config key")
    key = key.strip()
    value = params.get("value")
    sid = params.get("session_id")
    session = _sessions.get(sid) if isinstance(sid, str) and sid else None

    if key == "yolo":
        return _config_set_yolo(rid, session)
    if key == "fast":
        return _config_set_fast(rid, params, session)
    if key == "busy":
        mode = str(value) if value is not None else "interrupt"
        _write_config_key("display.busy_input_mode", mode)
        if isinstance(session, dict):
            session["busy_input_mode"] = mode
        return _result(rid, {"key": "busy", "value": mode})
    if key == "statusbar":
        position = str(value) if value is not None else "top"
        _write_config_key("display.tui_statusbar", position)
        return _result(rid, {"key": "statusbar", "value": position})
    if key == "mouse":
        current = _mouse_enabled(_load_cfg())
        new_value = not current
        _write_config_key("display.mouse_tracking", new_value)
        return _result(rid, {"key": "mouse", "value": "on" if new_value else "off"})
    if key == "indicator":
        return _config_set_indicator(rid, value)
    if key in ("reasoning", "verbose", "model", "personality"):
        if session is None and key in ("reasoning", "verbose", "model", "personality"):
            if key == "personality":
                pass
            elif key == "model":
                return _error(rid, 4006, "missing session_id")
            elif key in ("reasoning", "verbose"):
                return _error(rid, 4006, "missing session_id")
        if key == "reasoning":
            return _config_set_reasoning(rid, value, session)
        if key == "verbose":
            return _config_set_verbose(rid, session)
        if key == "model":
            return _config_set_model(rid, sid, value, session)
        return _config_set_personality(rid, sid, value, session)
    if key.startswith("details_mode."):
        return _config_set_section(rid, key.split(".", 1)[1], value)
    if key == "details_mode":
        return _config_set_details_mode(rid, value)
    return _error(rid, 4002, "unknown config key: " + key)


def _config_set_yolo(rid, session):
    """YOLO modunu oturum ya da süreç kapsamında aç/kapat."""
    if isinstance(session, dict) and session.get("session_key"):
        approval = _mod("tools.approval")
        key = session["session_key"]
        enabled = bool(approval.is_session_yolo_enabled(key))
        if enabled:
            approval.disable_session_yolo(key)
        else:
            approval.enable_session_yolo(key)
        return _result(rid, {"value": "0" if enabled else "1"})
    enabled = _env_flag(_ENV_YOLO)
    os.environ[_ENV_YOLO] = "0" if enabled else "1"
    return _result(rid, {"value": "0" if enabled else "1"})


def _config_set_fast(rid, params, session):
    """Hızlı mod: sağlayıcıya özel hız ipuçlarını uygula."""
    value = str(params.get("value") or "status").strip().lower()
    agent = session.get("agent") if isinstance(session, dict) else None
    if value == "status":
        tier = getattr(agent, "service_tier", None) if agent is not None else None
        return _result(rid, {"value": "fast" if tier else "normal"})
    if value not in ("fast", "normal"):
        return _error(rid, 4002, "unknown fast mode: " + value)

    model = (getattr(agent, "model", "") or "") if agent is not None else ""
    if not model:
        return _error(rid, 4002, "cannot enable fast mode without a selected model")
    overrides = None
    if value == "fast":
        # Yalnızca hızlı mod istenirken çözücü çağrılır; "normal" mod
        # sağlayıcı kataloğuna hiç dokunmaz.
        try:
            overrides = _mod("fetih_cli.models").resolve_fast_mode_overrides(model)
        except Exception:
            overrides = None
        if not isinstance(overrides, dict):
            return _error(rid, 4002, "fast mode is not available for " + model)
        agent.service_tier = overrides.get("service_tier")
        current = getattr(agent, "request_overrides", None)
        merged = dict(current) if isinstance(current, dict) else {}
        for name in _FAST_MODE_KEYS:
            merged.pop(name, None)
        merged.update(overrides)
        agent.request_overrides = merged
        _write_config_key("agent.service_tier", "fast")
    else:
        agent.service_tier = None
        current = getattr(agent, "request_overrides", None)
        merged = dict(current) if isinstance(current, dict) else {}
        for name in _FAST_MODE_KEYS:
            merged.pop(name, None)
        agent.request_overrides = merged
        _write_config_key("agent.service_tier", "normal")
    _emit("session.info", params.get("session_id"), _session_info(agent))
    return _result(rid, {"value": value})


def _config_set_indicator(rid, value):
    """Durum göstergesi stilini doğrula ve kaydet."""
    raw = "" if value is None else str(value)
    style = _normalize_indicator(value)
    if style not in _INDICATORS:
        return _error(
            rid,
            4002,
            "unknown indicator: '{}'; expected one of: {}".format(
                raw, ", ".join(_INDICATORS)
            ),
        )
    _write_config_key("display.tui_status_indicator", style)
    return _result(rid, {"key": "indicator", "value": style})


def _config_set_reasoning(rid, value, session):
    """Akıl yürütme eforunu ya da görünürlüğünü ayarla."""
    raw = "" if value is None else str(value).strip()
    agent = session.get("agent") if isinstance(session, dict) else None
    lowered = raw.lower()
    if lowered in ("show", "hide"):
        if lowered == "show":
            session["show_reasoning"] = True
            _write_config_key("display.sections.thinking", "expanded")
        else:
            session["show_reasoning"] = False
            _write_config_key("display.sections.thinking", "hidden")
        return _result(rid, {"key": "reasoning", "value": lowered})
    if not raw:
        return _error(rid, 4002, "reasoning effort must not be empty")
    if agent is not None:
        agent.reasoning_config = {"enabled": True, "effort": raw}
    _write_config_key("display.reasoning_effort", raw)
    return _result(rid, {"key": "reasoning", "value": raw})


def _config_set_verbose(rid, session):
    """Araç ilerleme modunu döngüsel olarak değiştir."""
    current = session.get("tool_progress_mode") or "all"
    if current not in _VERBOSE_CYCLE:
        current = "all"
    nxt = _VERBOSE_CYCLE[(_VERBOSE_CYCLE.index(current) + 1) % len(_VERBOSE_CYCLE)]
    session["tool_progress_mode"] = nxt
    agent = session.get("agent")
    if agent is not None:
        try:
            agent.verbose_logging = nxt == "verbose"
        except Exception:
            pass
    _write_config_key("display.tool_progress_mode", nxt)
    return _result(rid, {"key": "verbose", "value": nxt})


def _config_set_model(rid, sid, value, session):
    """Canlı model değişimi (``/model`` ile aynı yol)."""
    if session.get("running"):
        return _error(
            rid,
            4009,
            "session busy: cannot switch models while the agent is running",
        )
    outcome = _apply_model_switch(
        sid, session, value if value is not None else ""
    )
    return _result(
        rid,
        {
            "key": "model",
            "value": outcome.get("value"),
            "warning": outcome.get("warning") or "",
        },
    )


def _config_set_personality(rid, sid, value, session):
    """Kişilik pivosu: sistem istemini değiştir, geçmişi koru."""
    name = "" if value is None else str(value).strip()
    personalities = _available_personalities()
    if name and name.lower() not in ("none", "default", "off"):
        if name not in personalities:
            return _error(rid, 4002, "Unknown personality: " + name)
    prompt = personalities.get(name, "") if name in personalities else ""
    agent = session.get("agent") if isinstance(session, dict) else None
    if agent is not None:
        try:
            agent.ephemeral_system_prompt = prompt or None
        except Exception:
            pass
    if isinstance(session, dict):
        with session["history_lock"]:
            history = session.get("history")
            if isinstance(history, list):
                history.append(
                    {
                        "role": "user",
                        "content": (
                            "Personality switch: active personality is "
                            "'{}'.\n{}".format(name, prompt)
                        ),
                    }
                )
            session["history_version"] = session.get("history_version", 0) + 1
    _write_config_key("agent.personality", name)
    info = _session_info(agent)
    _emit("session.info", sid, info)
    return _result(rid, {"history_reset": False, "info": info})


def _config_set_section(rid, section, value):
    """Tek bir ayrıntı bölümü için geçersiz kılma yaz ya da sil."""
    if section not in _DETAIL_SECTIONS:
        return _error(rid, 4002, "unknown details section: " + str(section))
    mode = "" if value is None else str(value)
    if mode and mode not in _DETAIL_MODES:
        return _error(rid, 4002, "unknown details mode: " + mode)
    sections = _cfg_get(_load_cfg(), "display.sections")
    sections = dict(sections) if isinstance(sections, dict) else {}
    if mode:
        sections[section] = mode
    else:
        sections.pop(section, None)
    _write_config_key("display.sections", sections)
    return _result(rid, {"key": "details_mode." + section, "value": mode})


def _config_set_details_mode(rid, value):
    """Tüm ayrıntı bölümlerini tek modda sabitle."""
    mode = "" if value is None else str(value)
    if mode not in _DETAIL_MODES:
        return _error(rid, 4002, "unknown details mode: " + mode)
    _write_config_key("display.details_mode", mode)
    _write_config_key(
        "display.sections", {section: mode for section in _DETAIL_SECTIONS}
    )
    return _result(rid, {"key": "details_mode", "value": mode})


def _h_config_show(rid, params):
    """``/config`` ekranı için bölümlenmiş ayar dökümü."""
    cfg = _cfg_dict()
    max_turns = _max_turns_from_cfg(cfg, _DEFAULT_MAX_TURNS)
    toolsets = cfg.get("enabled_toolsets")
    if isinstance(toolsets, list) and toolsets:
        toolsets_text = ", ".join(str(item) for item in toolsets)
    else:
        toolsets_text = "all"
    try:
        model = _resolve_model()
    except Exception:
        model = ""
    sections = [
        {
            "title": "Model",
            "rows": [["Model", model], ["Provider", str(_cfg_get(cfg, "model.provider") or "-")]],
        },
        {
            "title": "Agent",
            "rows": [
                ["Max Turns", str(max_turns)],
                ["Toolsets", toolsets_text],
                ["Verbose", "on" if cfg.get("verbose") else "off"],
            ],
        },
        {
            "title": "Display",
            "rows": [
                ["Status Bar", _statusbar_position(cfg)],
                ["Busy Input", _busy_mode(cfg)],
                ["Mouse", "on" if _mouse_enabled(cfg) else "off"],
                ["Indicator", _indicator_style(cfg)],
                ["Details Mode", str(_cfg_get(cfg, "display.details_mode") or "collapsed")],
            ],
        },
    ]
    return _result(rid, {"sections": sections})


def _h_model_options(rid, params):
    """Küratörlü model listesini sağlayıcı bazında döndür."""
    cfg = _cfg_dict()
    model_cfg = cfg.get("model")
    if not isinstance(model_cfg, dict):
        model_cfg = {}
    try:
        providers = _mod("fetih_cli.model_switch").list_authenticated_providers(
            current_provider=str(model_cfg.get("provider") or ""),
            current_base_url=str(model_cfg.get("base_url") or ""),
            user_providers=cfg.get("providers") or {},
            custom_providers=cfg.get("custom_providers") or [],
            max_models=8,
            current_model=str(model_cfg.get("default") or ""),
        )
    except Exception as exc:
        return _error(rid, 5033, "model catalog failed: " + (str(exc) or "unknown"))
    return _result(rid, {"providers": providers})


# --------------------------------------------------------------------------
# Tamamlama (completion) uçları
# --------------------------------------------------------------------------


def _h_complete_slash(rid, params):
    """``/`` komut tamamlamaları (TUI komutları dahil)."""
    text = params.get("text")
    if not isinstance(text, str):
        text = ""
    items: list = []

    head = text[:1]

    # ``/details`` sekme tamamlaması: hem kök komut hem argüman fazı
    # eğik çizgi tamamlayıcısını atlar (komut kaydında yer almaz).
    if text == "/details" or text.startswith("/details "):
        command, _sep, rest = text.partition(" ")
        if command.lower() == "/details":
            items = _details_arg_items(text, rest)
            replace_from = items[0]["_from"] if items else len(text)
            return _result(
                rid,
                {
                    "items": [
                        {k: v for k, v in item.items() if k != "_from"}
                        for item in items
                    ],
                    "replace_from": replace_from,
                },
            )

    try:
        pt_completion = _mod("prompt_toolkit.completion")
        pt_document = _mod("prompt_toolkit.document")

        completer = _mod("fetih_cli.commands").SlashCommandCompleter()
        document = pt_document.Document(text, len(text))
        complete_event = pt_completion.CompleteEvent()
        for completion in completer.get_completions(document, complete_event):
            start = len(text) + int(getattr(completion, "start_position", 0) or 0)
            display = getattr(completion, "display_text", None) or completion.text
            meta = getattr(completion, "display_meta_text", "") or ""
            items.append(
                {
                    "text": completion.text,
                    "display": display,
                    "meta": meta,
                    "_from": max(0, start),
                }
            )
    except Exception as exc:
        return _error(rid, 5033, "no completer: " + (str(exc) or "unknown"))

    if head == "/" and " " not in text:
        prefix = text[1:].strip().lower()
        if prefix:
            for name, description in _TUI_COMMANDS:
                bare = name[1:]
                if bare.startswith(prefix) and bare != prefix:
                    items.append(
                        {
                            "text": name,
                            "display": name,
                            "meta": "TUI",
                            "_from": 0,
                        }
                    )

    replace_from = items[0]["_from"] if items else len(text)
    return _result(
        rid,
        {
            "items": [
                {k: v for k, v in item.items() if k != "_from"} for item in items
            ],
            "replace_from": replace_from,
        },
    )


def _details_arg_items(text, rest):
    """``/details`` argümanları için tamamlama önerileri.

    Faz 0 bölüm adlarını (``thinking``, ``tools`` ...), faz 1 ise görünüm
    modlarını (``expanded`` ...) önerir. Kök komutta (henüz boşluk
    yazılmadı) öneriler baştaki boşluğu taşır ki ekleme gibi davransın.
    """
    tokens = rest.split(" ")
    trailing_space = rest.endswith(" ")
    filled = [token for token in tokens if token]
    if trailing_space:
        current = ""
        phase = len(filled)
    else:
        current = tokens[-1] if tokens else ""
        phase = max(0, len(filled) - 1)
    start = len(text) - len(current)
    items = []
    lowered = current.lower()
    if phase == 0:
        root = not trailing_space and current == ""
        for section in _PROGRESS_SECTIONS:
            if root or section.startswith(lowered):
                items.append(
                    {
                        "text": (" " + section) if root else section,
                        "display": section,
                        "meta": "section",
                        "_from": len(text) if root else start,
                    }
                )
    else:
        for mode in _DETAIL_MODES:
            if mode.startswith(lowered):
                items.append(
                    {
                        "text": mode,
                        "display": mode,
                        "meta": "mode",
                        "_from": start,
                    }
                )
    return items


def _h_complete_path(rid, params):
    """``@`` ile başlayan dosya/dizin tamamlamaları."""
    word = params.get("word")
    if not isinstance(word, str):
        word = ""
    try:
        cwd = Path.cwd()
    except Exception:
        cwd = Path(".")
    items = _path_items(word, cwd)
    return _result(rid, {"items": items, "replace_from": 0})


def _path_item(text, display, meta):
    return {"text": text, "display": display, "meta": meta}


def _path_items(word, cwd):
    """Tamamlama girdilerini üret (statik referanslar → dizin → bulanık)."""
    if word == "@":
        return [_path_item(ref, ref, "context") for ref in _STATIC_REFS]

    tag = None
    query = ""
    if word.startswith("@file:"):
        tag, query = "file", word[len("@file:") :]
    elif word.startswith("@folder:"):
        tag, query = "folder", word[len("@folder:") :]
    elif word == "@file":
        tag, query = "file", ""
    elif word == "@folder":
        tag, query = "folder", ""
    elif word.startswith("@"):
        tag, query = None, word[1:]
    else:
        return []

    if tag == "folder":
        # Dizin taraması: bulanık tarayıcı yalnızca dosya gezer, bu yüzden
        # ``@folder:`` her zaman dizin listeleme yolundan gider.
        return _list_dir_items(cwd, query, want_dir=True, want_file=False)
    if tag == "file":
        if query and "/" not in query and "\\" not in query:
            return _fuzzy_items(cwd, query, "file")
        return _list_dir_items(cwd, query, want_dir=False, want_file=True)
    if "/" in query or "\\" in query:
        # Kullanıcı yol yazıyor: yalnızca adı geçen dizinin çocukları.
        return _list_dir_items(cwd, query, want_dir=True, want_file=True)
    if not query:
        return _list_dir_items(cwd, "", want_dir=True, want_file=False)
    return _fuzzy_items(cwd, query, tag)


def _list_dir_items(cwd, query, want_dir=True, want_file=True):
    """Belirli bir dizini (ya da cwd'yi) listeleyen tamamlamalar."""
    query = str(query).replace("\\", "/")
    directory_part, _sep, name_prefix = query.rpartition("/")
    target = cwd / directory_part if directory_part else cwd
    if not _inside(target, cwd):
        # Proje dışına çıkan yollar tamamlanmaz.
        return []
    try:
        entries = sorted(target.iterdir(), key=lambda entry: entry.name.lower())
    except Exception:
        return []
    out = []
    lowered = name_prefix.lower()
    for entry in entries:
        name = entry.name
        if lowered and not name.lower().startswith(lowered):
            continue
        if name.startswith(".") and not name_prefix.startswith("."):
            continue
        try:
            is_dir = entry.is_dir()
        except Exception:
            is_dir = False
        if is_dir and not want_dir:
            continue
        if not is_dir and not want_file:
            continue
        rel = _relpath(entry, cwd)
        if rel is None:
            continue
        if is_dir:
            out.append(
                _path_item("@folder:" + rel + "/", name + "/", _parent_of(rel))
            )
        else:
            out.append(_path_item("@file:" + rel, name, _parent_of(rel)))
    return out


def _fuzzy_items(cwd, query, tag):
    """Bulanık dosya araması (alt dizi + camelCase tümsekleri)."""
    lowered = query.lower()
    includes_dot = query.startswith(".")
    results = []
    for rel in _project_files(cwd):
        name = rel.rsplit("/", 1)[-1]
        if not includes_dot and any(
            part.startswith(".") for part in rel.split("/")
        ):
            continue
        score = _score_path(rel, name, lowered)
        if score <= 0:
            continue
        results.append((score, len(rel), rel, name))
    results.sort(key=lambda row: (-row[0], row[1], row[2]))
    out = []
    for _score, _length, rel, name in results[:_MAX_PATH_ITEMS]:
        text = "@file:" + rel
        if tag == "folder":
            text = "@folder:" + rel
        out.append(_path_item(text, name, _parent_of(rel)))
    return out


def _project_files(cwd):
    """Projedeki dosyaları listele (git varsa git, yoksa yürüyüş)."""
    key = str(cwd)
    cached = _fuzzy_cache.get(key)
    if isinstance(cached, tuple) and len(cached) == 2:
        try:
            if time.monotonic() - cached[1] < 5.0:
                return cached[0]
        except Exception:
            pass
    files = _git_files(cwd)
    if files is None:
        files = _walk_files(cwd)
    try:
        _fuzzy_cache[key] = (files, time.monotonic())
    except Exception:
        pass
    return files


def _git_files(cwd):
    """``git ls-files`` çıktısını cwd'ye göreli yollara çevir."""
    try:
        proc = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    raw = [line.strip() for line in (proc.stdout or "").splitlines()]
    raw = [line for line in raw if line]
    if not raw:
        return []
    root = None
    try:
        root_proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if root_proc.returncode == 0:
            root = Path((root_proc.stdout or "").strip())
    except Exception:
        root = None
    out = []
    for entry in raw:
        candidate = Path(entry)
        choices = []
        if candidate.is_absolute():
            choices.append(candidate)
        else:
            # ``git ls-files`` sürüme ve dizine göre bazen cwd'ye bazen depo
            # köküne göreli yol döndürür; iki tabanı da dene ve sonucu
            # her zaman cwd'ye göreli hale getir. cwd dışına çıkanlar düşer.
            choices.append(cwd / candidate)
            if root is not None:
                choices.append(root / candidate)
        for choice in choices:
            try:
                if not choice.exists():
                    continue
                rel = choice.resolve().relative_to(cwd.resolve())
            except Exception:
                continue
            out.append(rel.as_posix())
            break
    return out


def _walk_files(cwd):
    """Git yoksa dizin ağacını yürüyerek dosyaları topla."""
    out = []
    try:
        stack = [cwd]
        while stack:
            current = stack.pop()
            try:
                entries = list(current.iterdir())
            except Exception:
                continue
            for entry in entries:
                name = entry.name
                try:
                    if entry.is_dir():
                        # Gizli dizinler (.git, .venv ...) taranmaz ama
                        # gizli dosyalar listelenir; görünürlük kararı
                        # ``_fuzzy_items`` tarafında verilir.
                        if name.startswith(".") or name in ("node_modules", "__pycache__"):
                            continue
                        stack.append(entry)
                        continue
                except Exception:
                    continue
                try:
                    out.append(entry.resolve().relative_to(cwd.resolve()).as_posix())
                except Exception:
                    continue
    except Exception:
        return []
    return out


def _score_path(rel, name, lowered):
    """Tamamlama sıralaması için puan (0 → eşleşme yok).

    Sıralama katmanları: tam eşleşme → önek → camelCase sözcük başı →
    ad içinde geçiş → yol içinde geçiş → alt dizi (en zayıf).
    """
    lowered_name = name.lower()
    lowered_rel = rel.lower()
    if lowered_name == lowered:
        return 100
    if lowered_name.startswith(lowered):
        return 80
    if _matches_word_boundaries(lowered, name):
        return 70
    if lowered in lowered_name:
        return 60
    if lowered in lowered_rel:
        return 40
    if _is_subsequence(lowered, lowered_name):
        return 25
    return 0


def _is_subsequence(needle, haystack):
    index = 0
    for char in haystack:
        if index < len(needle) and char == needle[index]:
            index += 1
    return index == len(needle)


def _matches_word_boundaries(needle, name):
    """``Chrome`` → ``appChrome.tsx`` gibi sözcük başı eşleşmesi."""
    words = []
    current = ""
    for position, char in enumerate(name):
        if position and (char.isupper() or name[position - 1] in "_-."):
            words.append(current)
            current = char
        else:
            current += char
    if current:
        words.append(current)
    for word in words:
        if word and word.lower().startswith(needle):
            return True
    return False


def _relpath(path, base):
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except Exception:
        return None


def _parent_of(rel):
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def _inside(path, base):
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# Komut kataloğu ve eğik çizgi komutları
# --------------------------------------------------------------------------


def _h_commands_catalog(rid, params):
    """Klasik CLI komutlarını + TUI komutlarını + hızlı komutları dök."""
    commands_module = _mod("fetih_cli.commands")
    COMMANDS_BY_CATEGORY = commands_module.COMMANDS_BY_CATEGORY

    pairs: list = []
    categories: list = []
    canon: dict = {}

    for category_name, commands in COMMANDS_BY_CATEGORY.items():
        cat_pairs = []
        for name, description in commands.items():
            pair = [name, description]
            cat_pairs.append(pair)
            pairs.append(pair)
            canon[name] = name
        if cat_pairs:
            categories.append({"name": category_name, "pairs": cat_pairs})

    # Takma adları kanonik adlarına bağla.
    try:
        resolve_command = commands_module.resolve_command

        for name in list(canon):
            try:
                definition = resolve_command(name)
            except Exception:
                definition = None
            canonical = getattr(definition, "name", None)
            if isinstance(canonical, str) and canonical:
                canon[name] = "/" + canonical.lstrip("/")
    except Exception:
        pass

    quick = _cfg_get(_load_cfg(), "quick_commands")
    if isinstance(quick, dict) and quick:
        quick_pairs = []
        for name, entry in quick.items():
            if not isinstance(name, str) or not name:
                continue
            key = "/" + name.lstrip("/")
            description = ""
            if isinstance(entry, dict):
                description = str(entry.get("description") or "")
                kind = str(entry.get("type") or "exec")
                if not description:
                    if kind == "alias":
                        description = "alias → " + str(entry.get("target") or "")
                    else:
                        description = str(entry.get("command") or "")
            pair = [key, description]
            quick_pairs.append(pair)
            pairs.append(pair)
            canon[key] = key
        if quick_pairs:
            categories.append({"name": "User commands", "pairs": quick_pairs})

    tui_pairs = [
        [name, description] for name, description in _TUI_COMMANDS
    ]
    for pair in tui_pairs:
        pairs.append(pair)
        canon[pair[0]] = pair[0]
    categories.append({"name": "TUI", "pairs": tui_pairs})

    return _result(rid, {"pairs": pairs, "categories": categories, "canon": canon})


def _is_snapshot_restore(command) -> bool:
    """Komut ``snapshot restore`` mi (canlı durumu değiştirir)?"""
    tokens = str(command or "").split()
    if not tokens:
        return False
    head = tokens[0].lstrip("/").lower()
    if head not in _SNAPSHOT_ALIASES:
        return False
    return len(tokens) > 1 and tokens[1].lower() == "restore"


_SNAPSHOT_BLOCK_MSG = (
    "snapshot restore mutates live config/state and is blocked in the TUI "
    "gateway; run it from the classic CLI"
)


def _h_slash_exec(rid, params):
    """Eğik çizgi komutunu oturumun çalışanı üzerinden yürüt."""
    command = params.get("command")
    if not isinstance(command, str) or not command.strip():
        return _error(rid, 4002, "missing command")
    if _is_snapshot_restore(command):
        return _error(rid, 4018, _SNAPSHOT_BLOCK_MSG)
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    warning = _mirror_slash_side_effects(sid, session, command)
    worker = session.get("slash_worker")
    if worker is None:
        return _result(rid, {"output": warning})
    try:
        output = worker.exec(command)
    except Exception as exc:
        return _error(rid, 5007, "slash command failed: " + (str(exc) or "unknown"))
    text = "" if output is None else str(output)
    if warning:
        text = (text + "\n" + warning).strip() if text else warning
    return _result(rid, {"output": text})


def _h_command_dispatch(rid, params):
    """Hızlı komutları (exec/alias) çalıştır."""
    name = params.get("name")
    name = str(name or "").strip().lstrip("/")
    arg = params.get("arg")
    arg = "" if arg is None else str(arg)
    if not name:
        return _error(rid, 4002, "missing command name")
    if name.lower() in _SNAPSHOT_ALIASES and arg.strip().lower().startswith("restore"):
        return _result(
            rid,
            {
                "type": "exec",
                "output": (
                    "/snapshot restore is blocked in the TUI gateway "
                    "(mutates live config/state)"
                ),
            },
        )
    quick = _cfg_get(_load_cfg(), "quick_commands")
    entry = quick.get(name) if isinstance(quick, dict) else None
    if isinstance(entry, dict):
        kind = str(entry.get("type") or "exec")
        if kind == "alias":
            return _result(
                rid, {"type": "alias", "output": str(entry.get("target") or "")}
            )
        command = str(entry.get("command") or "")
        if arg:
            command = (command + " " + arg).strip()
        if not command:
            return _error(rid, 4002, "quick command has no command to run")
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True
            )
        except Exception as exc:
            return _error(rid, 5007, "command failed: " + (str(exc) or "unknown"))
        if getattr(proc, "returncode", 0) != 0:
            detail = getattr(proc, "stderr", "") or getattr(proc, "stdout", "")
            return _error(rid, 5007, "command failed: " + str(detail).strip())
        return _result(
            rid, {"type": "exec", "output": str(getattr(proc, "stdout", "") or "")}
        )
    return _result(
        rid,
        {
            "type": "exec",
            "output": "unknown command: " + name,
        },
    )


# --------------------------------------------------------------------------
# Eklenti, beceri, ortam ve kabuk uçları
# --------------------------------------------------------------------------


def _h_plugins_list(rid, params):
    """Yüklü eklentileri listele."""
    try:
        manager = _mod("fetih_cli.plugins").get_plugin_manager()
    except Exception as exc:
        return _error(rid, 5007, "plugin load failed: " + (str(exc) or "unknown"))
    plugins = []
    try:
        raw = getattr(manager, "plugins", None)
        if isinstance(raw, dict):
            for name, plugin in raw.items():
                plugins.append(
                    {
                        "name": str(name),
                        "version": str(getattr(plugin, "version", "") or ""),
                        "enabled": bool(getattr(plugin, "enabled", True)),
                    }
                )
        elif isinstance(raw, (list, tuple)):
            for plugin in raw:
                plugins.append(
                    {
                        "name": str(getattr(plugin, "name", plugin)),
                        "version": str(getattr(plugin, "version", "") or ""),
                        "enabled": bool(getattr(plugin, "enabled", True)),
                    }
                )
    except Exception:
        plugins = []
    return _result(rid, {"plugins": plugins})


def _h_skills_reload(rid, params):
    """Beceri kayıtlarını yeniden yükle (ağ geçidi sürecinde)."""
    try:
        result = _mod("agent.skill_commands").reload_skills() or {}
    except Exception as exc:
        return _error(rid, 5007, "skill reload failed: " + (str(exc) or "unknown"))
    added = result.get("added") or []
    removed = result.get("removed") or []
    lines = ["Reloaded skills: +{} -{}".format(len(added), len(removed))]
    for entry in added:
        name = entry.get("name") if isinstance(entry, dict) else entry
        description = entry.get("description", "") if isinstance(entry, dict) else ""
        lines.append("  + {} — {}".format(name, description))
    for entry in removed:
        name = entry.get("name") if isinstance(entry, dict) else entry
        lines.append("  - {}".format(name))
    lines.append("{} skill(s) available".format(result.get("total", 0)))
    return _result(rid, {"output": "\n".join(lines)})


def _h_setup_status(rid, params):
    """Kurulumun tamamlanıp tamamlanmadığını bildir."""
    configured = None
    try:
        configured = bool(_mod("fetih_cli.main")._has_any_provider_configured())
    except Exception:
        configured = False
    return _result(rid, {"provider_configured": configured})


def _h_reload_env(rid, params):
    """``.env`` dosyasını yeniden oku (klasik CLI ``/reload`` eşleniği)."""
    try:
        updated = _mod("fetih_cli.config").reload_env()
    except Exception as exc:
        return _error(rid, 5007, "env reload failed: " + (str(exc) or "unknown"))
    return _result(rid, {"updated": updated})


def _h_input_detect_drop(rid, params):
    """Sürüklenen/bırakılan dosya yolunu kullanıcı girdisinden ayıkla."""
    text = params.get("text")
    if not isinstance(text, str) or not text:
        return _result(rid, {"matched": False})
    try:
        drop = _mod("cli")._detect_file_drop(text)
    except Exception:
        drop = None
    if not isinstance(drop, dict):
        return _result(rid, {"matched": False})
    path = drop.get("path")
    if not path:
        return _result(rid, {"matched": False})
    is_image = bool(drop.get("is_image"))
    remainder = drop.get("remainder") or ""
    path_text = str(path)
    if is_image:
        _attach_image(params.get("session_id"), path_text)
    if remainder:
        output = str(remainder)
    elif is_image:
        output = "[User attached image: {}]".format(Path(path_text).name)
    else:
        output = path_text
    return _result(
        rid,
        {
            "matched": True,
            "is_image": is_image,
            "path": path_text,
            "text": output,
        },
    )


def _attach_image(session_id, path_text) -> None:
    """Ekli görseli oturuma kaydet."""
    session = _sessions.get(session_id) if isinstance(session_id, str) else None
    if not isinstance(session, dict):
        return
    images = session.setdefault("attached_images", [])
    if isinstance(images, list):
        images.append(path_text)
    try:
        session["image_counter"] = int(session.get("image_counter", 0)) + 1
    except Exception:
        session["image_counter"] = 1


def _h_image_attach(rid, params):
    """Yerel bir görseli oturuma ekle."""
    raw = params.get("path")
    if not isinstance(raw, str) or not raw.strip():
        return _error(rid, 4002, "missing attachment path")
    sid = params.get("session_id")
    session = _sessions.get(sid) if isinstance(sid, str) else None
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session")
    path = None
    remainder = ""
    is_image = True
    try:
        cli_module = _mod("cli")
        drop = cli_module._detect_file_drop(raw)
        if isinstance(drop, dict) and drop.get("path"):
            path = drop.get("path")
            remainder = drop.get("remainder") or ""
            is_image = bool(drop.get("is_image"))
        else:
            resolved = cli_module._resolve_attachment_path(raw)
            if resolved:
                path = resolved
                is_image = Path(str(resolved)).suffix.lower() in {
                    ".png",
                    ".jpg",
                    ".jpeg",
                    ".gif",
                    ".webp",
                    ".bmp",
                }
    except Exception:
        path = None
    if not path:
        return _error(rid, 4002, "attachment not found: " + raw)
    path_text = str(path)
    _attach_image(sid, path_text)
    return _result(
        rid,
        {
            "attached": True,
            "name": Path(path_text).name,
            "path": path_text,
            "remainder": str(remainder),
            "is_image": is_image,
        },
    )


# --------------------------------------------------------------------------
# Geri alma (checkpoint) ucu
# --------------------------------------------------------------------------


def _h_rollback_restore(rid, params):
    """Bir kontrol noktasına (tüm geçmiş ya da tek dosya) dön."""
    sid = _require_sid(params)
    if sid is None:
        return _error(rid, 4006, "missing session_id")
    session = _sessions.get(sid)
    if not isinstance(session, dict):
        return _error(rid, 4007, "unknown session: " + sid)
    file_path = params.get("file_path")
    if session.get("running") and not file_path:
        return _error(
            rid,
            4009,
            "session busy: full-history rollback is not allowed while running",
        )
    agent = session.get("agent")
    manager = getattr(agent, "_checkpoint_mgr", None) if agent is not None else None
    if manager is None or not getattr(manager, "enabled", False):
        return _error(rid, 4002, "checkpoints are not enabled for this session")
    cwd = os.getcwd()
    target = params.get("hash")
    if isinstance(target, str) and target.strip().isdigit():
        try:
            checkpoints = manager.list_checkpoints(cwd) or []
        except Exception:
            checkpoints = []
        index = int(target.strip()) - 1
        if 0 <= index < len(checkpoints):
            entry = checkpoints[index]
            if isinstance(entry, dict) and entry.get("hash"):
                target = entry["hash"]
    try:
        outcome = manager.restore(cwd, target, file_path=file_path)
    except Exception as exc:
        return _error(rid, 5007, "rollback failed: " + (str(exc) or "unknown"))
    if isinstance(outcome, dict):
        return _result(
            rid,
            {
                "success": bool(outcome.get("success")),
                "message": outcome.get("message", ""),
            },
        )
    return _result(rid, {"success": bool(outcome), "message": ""})


# --------------------------------------------------------------------------
# Ses (voice) uçları
# --------------------------------------------------------------------------


def _env_flag(name) -> bool:
    raw = os.environ.get(name)
    if not isinstance(raw, str):
        return False
    return raw.strip().lower() in _TRUTHY


def _voice_cfg_dict() -> dict:
    cfg = _load_cfg()
    if not isinstance(cfg, dict):
        return {}
    voice = cfg.get("voice")
    return voice if isinstance(voice, dict) else {}


def _num(value, default, cast):
    """Sayısal yapılandırma değerini doğrula (bool'lar reddedilir)."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return cast(value)
        except Exception:
            return default
    return default


def _record_key() -> str:
    raw = _voice_cfg_dict().get("record_key")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return _DEFAULT_RECORD_KEY


def _h_voice_toggle(rid, params):
    """Ses modunu aç/kapat ya da durumunu bildir."""
    action = str(params.get("action") or "status").strip().lower()
    available = True
    details = ""
    try:
        requirements = _mod("tools.voice_mode").check_voice_requirements()
        if isinstance(requirements, dict):
            available = bool(requirements.get("available", True))
            details = str(requirements.get("details", "") or "")
    except Exception:
        available = False
    if action == "on":
        os.environ[_ENV_VOICE] = "1"
    elif action == "off":
        os.environ.pop(_ENV_VOICE, None)
    elif action == "tts":
        if _env_flag(_ENV_VOICE_TTS):
            os.environ.pop(_ENV_VOICE_TTS, None)
        else:
            os.environ[_ENV_VOICE_TTS] = "1"
    return _result(
        rid,
        {
            "voice": _env_flag(_ENV_VOICE),
            "tts": _env_flag(_ENV_VOICE_TTS),
            "record_key": _record_key(),
            "available": available,
            "details": details,
        },
    )


def _h_voice_record(rid, params):
    """Sürekli ses kaydını başlat/durdur."""
    global _voice_event_sid
    action = str(params.get("action") or "start").strip().lower()
    sid = params.get("session_id")
    if action == "start":
        if not _env_flag(_ENV_VOICE):
            return _error(
                rid, 4002, "voice mode is disabled (set FETIH_VOICE=1 to enable)"
            )
        cfg = _voice_cfg_dict()
        threshold = _num(cfg.get("silence_threshold"), 200, int)
        duration = _num(cfg.get("silence_duration"), 3.0, float)
        auto_restart_raw = cfg.get("auto_restart")
        auto_restart = (
            auto_restart_raw if isinstance(auto_restart_raw, bool) else False
        )
        try:
            started = _mod("fetih_cli.voice").start_continuous(
                silence_threshold=threshold,
                silence_duration=duration,
                auto_restart=auto_restart,
            )
        except Exception as exc:
            return _error(rid, 5025, "voice start failed: " + (str(exc) or "unknown"))
        if started is False:
            return _result(rid, {"status": "busy", "record_key": _record_key()})
        if isinstance(sid, str) and sid:
            _voice_event_sid = sid
        return _result(
            rid,
            {
                "status": "recording",
                "record_key": _record_key(),
                "silence_threshold": threshold,
                "silence_duration": duration,
            },
        )
    if action == "stop":
        try:
            _mod("fetih_cli.voice").stop_continuous(force_transcribe=True)
        except Exception as exc:
            return _error(rid, 5025, "voice stop failed: " + (str(exc) or "unknown"))
        if isinstance(sid, str) and sid:
            _voice_event_sid = sid
        return _result(rid, {"status": "stopped"})
    return _error(rid, 4002, "unknown voice action: " + action)


# --------------------------------------------------------------------------
# Tarayıcı (browser.manage) ucu
# --------------------------------------------------------------------------


def _browser_tool():
    """Canlı tarayıcı aracını çağrı anında içe aktar (yoksa ``None``)."""
    try:
        return _mod("tools.browser_tool")
    except Exception:
        return None


def _cleanup_browsers() -> None:
    module = _browser_tool()
    cleanup = getattr(module, "cleanup_all_browsers", None) if module else None
    if callable(cleanup):
        try:
            cleanup()
        except Exception:
            pass


def _parse_cdp_url(raw):
    """CDP URL'sini çöz: (normalize_url, somut_ws, hata_mesajı).

    "Somut" uç noktalar ``/devtools/`` yolunu taşıyan ws/wss adresleridir;
    bunlar aynen korunur. Diğerleri ``scheme://host:port`` biçimine
    indirgenir (keşif yolları ve ``localhost`` takma adı normalize edilir).
    """
    if not isinstance(raw, str):
        return None, False, "url must be a string"
    text = raw.strip()
    if not text:
        return None, False, "url must be a string"
    if "://" not in text:
        text = "http://" + text
    try:
        parsed = urllib.parse.urlsplit(text)
    except Exception:
        return None, False, "invalid url"
    try:
        port = parsed.port
    except ValueError:
        return None, False, "invalid port"
    host = parsed.hostname
    if not host:
        return None, False, "missing host"
    scheme = (parsed.scheme or "http").lower()
    concrete = scheme in ("ws", "wss") and "/devtools/" in (parsed.path or "")
    if concrete:
        return text, True, None
    if not port:
        port = 443 if scheme in ("wss", "https") else 80
    if host.lower() == "localhost":
        host = "127.0.0.1"
    return "{}://{}:{}".format(scheme, host, port), False, None


def _is_local_host(url) -> bool:
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return False
    return host.lower() in ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def _http_probe(url) -> bool:
    """``/json/version`` keşif isteğiyle CDP ucunu yokla."""
    target = url.rstrip("/") + "/json/version"
    try:
        with urllib.request.urlopen(target, timeout=2.0):
            return True
    except Exception:
        return False


def _tcp_reachable(url) -> bool:
    """Somut bir ws adresinin TCP kapısını yokla."""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        if not host:
            return False
        port = parsed.port
        if not port:
            port = 443 if (parsed.scheme or "").lower() in ("wss", "https") else 80
        with socket.create_connection((host, port), timeout=2.0):
            return True
    except Exception:
        return False


def _publish_cdp(url) -> None:
    """Yeni CDP adresini yayınla: önce eski oturumları, sonra yenisini reapa et."""
    _cleanup_browsers()
    os.environ[_ENV_CDP] = url
    _cleanup_browsers()


def _browser_status(rid, params):
    """Etkin CDP adresini ağ erişimi olmadan bildir."""
    url = os.environ.get(_ENV_CDP) or ""
    if not url:
        try:
            raw = _mod("fetih_cli.config").read_raw_config()
            if isinstance(raw, dict):
                browser = raw.get("browser")
                if isinstance(browser, dict):
                    url = browser.get("cdp_url") or ""
        except Exception:
            url = ""
    return _result(rid, {"connected": bool(url), "url": url})


def _browser_connect(rid, params):
    """CDP ucuna bağlan: gerekirse yerel Chrome'u başlatmayı dene."""
    sid = params.get("session_id")
    session_id = sid if isinstance(sid, str) and sid else None
    raw = params.get("url")
    if raw is not None and not isinstance(raw, str):
        return _error(rid, 4015, "CDP url must be a string")
    if not isinstance(raw, str) or not raw.strip():
        raw = os.environ.get(_ENV_CDP) or _DEFAULT_CDP_URL

    norm, concrete, error = _parse_cdp_url(raw)
    if error:
        return _error(rid, 4015, "invalid CDP url: " + error)
    if norm is None:
        norm, concrete, error = _parse_cdp_url(_DEFAULT_CDP_URL)
        if error or norm is None:
            return _error(rid, 4015, "invalid CDP url: " + (error or "unknown"))
    try:
        port = urllib.parse.urlsplit(norm).port
    except Exception:
        port = None

    if concrete:
        if not _tcp_reachable(norm):
            return _error(
                rid, 5031, "failed to connect to the CDP endpoint: " + norm
            )
        _publish_cdp(norm)
        return _result(rid, {"connected": True, "url": norm})

    if _http_probe(norm):
        _publish_cdp(norm)
        return _result(
            rid,
            {
                "connected": True,
                "url": norm,
                "messages": [
                    "Chrome is already listening on port {}".format(port)
                ],
            },
        )

    if not _is_local_host(norm):
        return _error(rid, 5031, "CDP endpoint is not reachable: " + norm)

    messages = [
        "Chrome isn't running with remote debugging — attempting to launch..."
    ]
    _browser_progress(session_id, messages[-1])
    browser_connect = None
    try:
        browser_connect = _mod("fetih_cli.browser_connect")
    except Exception:
        browser_connect = None
    launched = False
    if browser_connect is not None:
        try:
            launched = bool(browser_connect.try_launch_chrome_debug())
        except Exception:
            launched = False
    if not launched:
        candidates = []
        try:
            candidates = list(browser_connect.get_chrome_debug_candidates() or [])
        except Exception:
            candidates = []
        if not candidates:
            messages.append(
                "No Chrome/Chromium executable was found. Install Chrome/Chromium "
                "or start it manually with remote debugging enabled."
            )
            _browser_progress(session_id, messages[-1])
        messages.append(
            "Start Chrome with: --remote-debugging-port={}".format(port or 9222)
        )
        _browser_progress(session_id, messages[-1])
        return _result(rid, {"connected": False, "url": norm, "messages": messages})

    ready = False
    for _attempt in range(30):
        try:
            time.sleep(0.25)
        except Exception:
            pass
        if _http_probe(norm):
            ready = True
            break
    if not ready:
        messages.append(
            "Chrome was launched but port {} never opened for debugging".format(
                port or 9222
            )
        )
        _browser_progress(session_id, messages[-1])
        return _result(rid, {"connected": False, "url": norm, "messages": messages})

    _publish_cdp(norm)
    messages.append(
        "Chrome launched and listening on port {}".format(port or 9222)
    )
    _browser_progress(session_id, messages[-1])
    return _result(rid, {"connected": True, "url": norm, "messages": messages})


def _browser_progress(session_id, message) -> None:
    if session_id:
        _emit("browser.progress", session_id, {"message": message})


def _h_browser_manage(rid, params):
    """Tarayıcı oturumunu yönet: status / connect / disconnect."""
    action = str(params.get("action") or "status").strip().lower()
    if action == "status":
        return _browser_status(rid, params)
    if action == "connect":
        return _browser_connect(rid, params)
    if action == "disconnect":
        _cleanup_browsers()
        os.environ.pop(_ENV_CDP, None)
        _cleanup_browsers()
        return _result(rid, {"connected": False})
    return _error(rid, 4002, "unknown browser action: " + action)


# --------------------------------------------------------------------------
# Yöntem tablosu
# --------------------------------------------------------------------------

_methods = {
    "session.create": _h_session_create,
    "session.close": _h_session_close,
    "session.list": _h_session_list,
    "session.most_recent": _h_session_most_recent,
    "session.delete": _h_session_delete,
    "session.resume": _h_session_resume,
    "session.status": _h_session_status,
    "session.title": _h_session_title,
    "session.undo": _h_session_undo,
    "session.compress": _h_session_compress,
    "session.interrupt": _h_session_interrupt,
    "session.steer": _h_session_steer,
    "prompt.submit": _h_prompt_submit,
    "prompt.cancel": _h_prompt_cancel,
    "clarify.respond": _h_respond,
    "sudo.respond": _h_respond,
    "secret.respond": _h_respond,
    "approval.respond": _h_respond,
    "config.get": _h_config_get,
    "config.set": _h_config_set,
    "config.show": _h_config_show,
    "model.options": _h_model_options,
    "complete.slash": _h_complete_slash,
    "complete.path": _h_complete_path,
    "commands.catalog": _h_commands_catalog,
    "slash.exec": _h_slash_exec,
    "command.dispatch": _h_command_dispatch,
    "plugins.list": _h_plugins_list,
    "skills.reload": _h_skills_reload,
    "setup.status": _h_setup_status,
    "reload.env": _h_reload_env,
    "input.detect_drop": _h_input_detect_drop,
    "image.attach": _h_image_attach,
    "rollback.restore": _h_rollback_restore,
    "voice.toggle": _h_voice_toggle,
    "voice.record": _h_voice_record,
    "browser.manage": _h_browser_manage,
}

_METHODS = _methods


# --------------------------------------------------------------------------
# Dağıtım ve sunum döngüsü
# --------------------------------------------------------------------------


def dispatch(request):
    """Tek bir JSON-RPC isteğini işle ve yanıt zarfını döndür."""
    if not isinstance(request, dict):
        return _error(None, -32600, "invalid request: expected an object")
    request_id = request.get("id")
    method = request.get("method")
    if not isinstance(method, str) or not method.strip():
        return _error(request_id, -32600, "invalid request: missing method")
    params = request.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _error(request_id, -32602, "invalid params: expected an object")
    handler = _methods.get(method)
    if handler is None:
        return _error(request_id, -32601, "method not found: " + method)
    try:
        return handler(request_id, params)
    except Exception as exc:
        return _error(
            request_id,
            5007,
            "internal error: {}: {}".format(type(exc).__name__, exc),
        )


#: İstemci tarafındaki eski ad — aynı fonksiyon nesnesi.
handle_request = dispatch


def _serve_line(line) -> None:
    """Tek bir stdin satırını işle (bozuk satırlar sessizce düşer)."""
    text = line.strip()
    if not text:
        return
    try:
        request = json.loads(text)
    except Exception:
        write_json(_error(None, -32700, "parse error: invalid JSON"))
        return
    write_json(dispatch(request))


def main(argv=None) -> int:
    """stdin/stdout üzerinden satır bazlı sunumu çalıştır."""
    global _serve_loop_active
    del argv
    _enable_gateway_prompts()
    _serve_loop_active = True
    try:
        for line in sys.stdin:
            _serve_line(line)
    except KeyboardInterrupt:
        pass
    except Exception:
        return 1
    finally:
        _serve_loop_active = False
        _clear_pending(None)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
