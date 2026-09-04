# Masaüstü Köprüsü — RPC Yüzeyi (protocol_version 1)

> Uygulama: `fetih_desktop_bridge/` — `protocol.py` (zarf), `server.py`
> (dispatch + metotlar), `transport.py` (stdio + WebSocket), `entry.py` (CLI).
> Tüketici: `apps/windows/Fetih.Desktop` (C#).
> İlgili: `docs/windows-app-plani.md`, `docs/fetih-ozellik-envanteri.md`,
> `docs/openclaw-inceleme-notlari.md`.
>
> **İsimlendirme:** Bu bir "gateway" **değildir**. Depoda `gateway/` mesajlaşma
> platformu köprüsüdür. Burası Masaüstü Köprüsü / `desktop_bridge`; ortam
> değişkenleri `FETIH_BRIDGE_*`.

---

## Çalıştırma

```
fetih desktop-bridge                  # WebSocket, boş port, üretilen token
fetih desktop-bridge --port 18790     # sabit port
fetih desktop-bridge --stdio          # NDJSON, stdin/stdout
fetih desktop-bridge --bridge-version # {"protocol_version": 1}
python -m fetih_desktop_bridge --stdio
```

WebSocket modu, dinlemeye başladığında **stdout'a tek satır** yazar:

```json
{"event":"bridge.listening","url":"ws://127.0.0.1:18791","protocol_version":1,"token":"…","pid":30444}
```

Başlatıcı bu satırı ayrıştırıp bağlanır. Token **yalnızca burada** görünür:
diske yazılmaz, config'e girmez, log'a düşmez. `FETIH_BRIDGE_TOKEN` ortam
değişkeni verilmişse üretim yerine o kullanılır.

## Taşıma ve zarf

Satır sonlu JSON (NDJSON), UTF-8, her satırda tam bir JSON nesnesi.
Her iki taşıma da **aynı** `BridgeServer.dispatch` yolunu kullanır.

| Çerçeve | Şekil |
|---|---|
| istek | `{"jsonrpc":"2.0","id":<int\|str>,"method":"…","params":{…}}` |
| yanıt | `{"jsonrpc":"2.0","id":<aynı>,"result":{…}}` |
| hata | `{"jsonrpc":"2.0","id":<aynı>,"error":{"code":…,"message":"…","data":{…}}}` |
| olay | `{"jsonrpc":"2.0","method":"…","params":{…}}` *(id yok — bildirim)* |

`id` verilmeyen istekler bildirim sayılır ve **yanıtlanmaz**.

## Güvenlik

- WebSocket **yalnızca `127.0.0.1`**'e bağlanır (`BIND_HOST`, yapılandırılamaz).
  `netstat` ile doğrulandı: `TCP 127.0.0.1:18791 … LISTENING`.
- WebSocket bağlantıları **kimliksiz** başlar. `bridge.authenticate` başarılı
  olana kadar yalnızca `bridge.ping`, `bridge.capabilities` ve
  `bridge.authenticate` kabul edilir; diğerleri `-32000 UNAUTHORIZED` döner.
  Token karşılaştırması `hmac.compare_digest` ile yapılır.
- stdio bağlantıları **önceden kimliklidir** — süreci başlatan ana uygulama
  zaten köprünün verebileceği her yetkiye sahiptir.
- `--no-auth` yalnızca `--stdio` içindir; WebSocket ile verilirse süreç
  **çalışmayı reddeder** (çıkış kodu 2).
- **Gizli veri asla dönmez.** `config.get` anahtar adı kimlik bilgisine benzeyen
  (`api_key`, `token`, `secret`, `password`, `credential`…) her yaprağı
  `"<redacted>"` ile değiştirir; `${ENV_ADI}` referansları **isim** olduğu için
  olduğu gibi kalır. `providers.list` yalnızca `key_present: true|false` der.
  `config.set` kimlik bilgisi anahtarına yazmayı `-32004` ile reddeder.

## Hata kodları

| Kod | Ad | Ne zaman |
|---|---|---|
| `-32700` | PARSE_ERROR | bozuk satır |
| `-32600` | INVALID_REQUEST | `method` yok |
| `-32601` | METHOD_NOT_FOUND | bilinmeyen metot |
| `-32602` | INVALID_PARAMS | eksik/yanlış tipte parametre |
| `-32603` | INTERNAL_ERROR | beklenmeyen istisna |
| `-32000` | UNAUTHORIZED | token yok/yanlış |
| `-32001` | SESSION_NOT_FOUND | `session_id` bilinmiyor |
| `-32002` | SESSION_BUSY | oturumda tur zaten çalışıyor |
| `-32003` | AGENT_ERROR | ajan çalıştı ama başarısız (sağlayıcı 4xx/5xx) |
| `-32004` | CONFIG_ERROR | `config.set` reddedildi, managed kurulum |
| `-32005` | CANCELLED | iptal başarısız |

---

## Metotlar

### `bridge.ping`
**params:** yok → **result:** `{pong, time, uptime_s}`

### `bridge.authenticate`
**params:** `{token: string}` → **result:** `{authenticated: true, protocol_version}`
Yanlış token → `-32000`. Token gerekmiyorsa her zaman başarılı.

### `bridge.capabilities`
**params:** yok (kimlik doğrulamadan önce de çağrılabilir)
**result:**
```json
{
  "protocol_version": 1,
  "min_supported_version": 1,
  "max_supported_version": 1,
  "auth_required": true,
  "authenticated": false,
  "transport": "ws",
  "fetih_version": "1.0.2",
  "methods": ["bridge.authenticate", "…"],
  "events": ["bridge.ready", "session.delta", "session.tool_call",
             "session.tool_result", "session.done", "session.error"]
}
```
> C# tarafı **aralık** kontrolü yapmalı (`min`/`max`), tam eşitlik değil —
> OpenClaw'ın `GatewayProtocolContract` deseni (bkz. inceleme notları §6).

### `session.new`
**params (hepsi opsiyonel):**
`model`, `provider`, `toolsets` (dizi veya virgüllü string), `cwd`,
`skip_context_files` (bool), `skip_memory` (bool)
**result:** `{session_id, model, provider, cwd, created_at, busy, turns}`

> `skip_context_files` / `skip_memory`, küçük bağlamlı uçlar içindir. FETİH'in
> tam AGENTS.md + hafıza önsözü + araç şemaları ~7.5K token; Groq'un ücretsiz
> katmanı 8000 TPM. İkisi `true` ve `toolsets: ["file"]` iken taban ~1.8K'ya iner.

### `session.list`
**params:** yok → **result:** `{sessions: [<snapshot>, …]}`

### `session.close`
**params:** `{session_id}` → **result:** `{closed: true, session_id}`

### `session.send`  ← **ana metot**
**params:** `{message: string}` + opsiyonel `session_id`, `stream` (varsayılan `true`),
ve `session_id` verilmediğinde `session.new`'ün tüm parametreleri (o zaman
oturum otomatik oluşturulur).

Tur boyunca **olaylar akar**, sonra yanıt döner:

**result / `session.done` olayı:**
```json
{
  "session_id": "d01e100c195b",
  "text": "…nihai yanıt…",
  "elapsed_ms": 46240,
  "api_calls": 4,
  "tool_calls": [{"id": "fc_…", "name": "read_file"}],
  "model": "openai/gpt-oss-20b",
  "provider": "custom"
}
```

Ajan başarısız olursa `session.error` olayı yayılır ve metot `-32003` döner;
`data` alanı sağlayıcının **kendi** mesajını taşır (ör. Groq'un
"Request too large … TPM: Limit 8000" metni). Oturum meşgulse `-32002`.

### `session.cancel`
**params:** `{session_id}` → **result:** `{cancelled: bool, session_id}`
`tools.interrupt.set_interrupt(True, thread_id)` çağırır. Oturum boştaysa
`{cancelled: false, reason: "session is idle"}`.

### `config.get`
**params:** `{key?}` — noktalı yol (`"agent.max_turns"`, `"model"`).
**result (anahtarlı):** `{key, value, path}`
**result (anahtarsız):** `{config, path, env_path}` — tüm config, redakteli.

### `config.set`
**params:** `{key: "noktalı.yol", value: any}`
**result:** `{key, value, saved: true}`
`fetih_cli.config._set_nested` + `save_config` kullanır — elle YAML yazımı yok,
`${ENV}` şablonları korunur. Kimlik bilgisi anahtarı → `-32004`.
Managed kurulum (`is_managed()`) → `-32004`.

### `providers.list`
**result:**
```json
{
  "active": {"provider": "groq", "model": "openai/gpt-oss-120b"},
  "providers": [{
    "id": "groq", "name": "Groq",
    "base_url": "https://api.groq.com/openai/v1",
    "api_mode": "chat_completions",
    "default_model": "openai/gpt-oss-120b",
    "context_length": 131072, "discover_models": true,
    "key_env": "GROQ_API_KEY", "key_present": true,
    "source": "user-config", "active": true
  }],
  "fallback_providers": []
}
```

### `skills.list`
**params:** `{category?, search?, limit? (100), offset? (0)}`
**result:** `{total, offset, limit, categories: {ad: adet, …}, skills: [{name, description, category, source}]}`
`source` ∈ `installed` (`~/.fetih/skills`) | `bundled` (`skills/`) | `optional` (`optional-skills/`).
Bu makinede toplam **1064** skill; en büyük kategoriler
`cybersecurity: 809`, `ctf: 54`, `mlops: 36`, `red-teaming: 32`.

### `diagnostics.info`
**result:** `fetih_version`, `protocol_version`, `python{version, executable,
implementation}`, `platform{system, release, machine, node_arch}`,
`paths{config, config_exists, env, fetih_home, repo_root, cwd}`,
`install{method, managed}`, `bridge{uptime_s, transport, auth_required,
connections, sessions, pid}`, `active_model{provider, model}`, `toolsets`.

> `install.method` (`git` / `pip` / `uv` …) ve `install.managed`, OpenClaw'ın
> "Unpackaged (developer)" göstergesinin bizdeki karşılığı — Tanılama
> sayfasında gösterilmeli.

---

## Olaylar (sunucu → istemci)

| Olay | params | Ne zaman |
|---|---|---|
| `bridge.ready` | `{protocol_version, auth_required, pid}` | bağlantı kurulur kurulmaz |
| `session.delta` | `{session_id, text}` | her akış parçası (`stream: true` iken) |
| `session.tool_call` | `{session_id, id, name, arguments}` | araç çalışmaya başlarken |
| `session.tool_result` | `{session_id, id, name, result}` | araç bitince |
| `session.done` | `session.send` sonucuyla aynı | tur başarıyla bitince |
| `session.error` | `{session_id, error, partial, api_calls, elapsed_ms, tool_calls}` | tur başarısız olunca |

Araç yükleri kırpılır (argümanlar ~2 KB, sonuçlar ~4 KB) — tek bir 45 KB'lık
`write_file` UI'yı boğmasın diye.

---

## Henüz yok (sıradaki turlar için)

`docs/windows-app-plani.md` §b tablosundaki yüzeye göre eksikler:
`session.history`/`rename`/`delete`/`checkpoint`, `approval.request`/`respond`
(altyapı `tools/approval.py`'de hazır — `register_gateway_notify` /
`resolve_gateway_approval`), `file.tree`/`read`/`diff`/`attach`,
`skills.detail`/`run`, `models.list`, `providers.test`, `setup.*`,
`audio.stt.*`/`audio.tts.speak`, `channels.status`/`list`,
`diagnostics.logs`, ve OpenClaw'ın Config sayfasından esinlenen
`config.schema` (jenerik ayar formu üretimi için).
