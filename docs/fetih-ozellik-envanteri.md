# FETİH Özellik Envanteri

> **Amaç:** Windows masaüstü uygulamasının (`apps/windows/Fetih.Desktop`) Ayarlar
> sayfalarını ve Masaüstü Köprüsü'nün (`fetih_desktop_bridge/`) RPC yüzeyini
> tasarlarken kullanılacak **temel referans**. Bu belge depo taranarak çıkarıldı;
> her başlık altında **gerçek dosya yolları**, **gerçek config anahtarları** ve
> **gerçek CLI komutları** var — tahmin yok.
>
> İlgili belgeler: `docs/windows-app-plani.md` (mimari plan),
> `docs/openclaw-inceleme-notlari.md` (native kabuk için referans uygulama).
>
> **İsimlendirme uyarısı:** Bu depoda "gateway" kelimesi **zaten dolu** —
> `gateway/` dizini mesajlaşma platformu köprüsüdür (Telegram/Discord/Slack...).
> Yeni masaüstü bileşenlerinde bu kelime **kullanılmaz**; onun yerine
> "Masaüstü Köprüsü" / "Bridge" / `desktop_bridge` / `FETIH_BRIDGE_*` kullanılır.

---

## 0) Bir bakışta: yapılandırma yüzeyi

Kullanıcının gerçek ayar dosyası: `~/.fetih/config.yaml` (`_config_version: 23`).
Bu dosyanın **kök anahtarları**, doğrudan Ayarlar sayfası sekmelerine karşılık gelir:

| Kök anahtar | Kapsam | Önerilen Ayarlar sekmesi |
|---|---|---|
| `model`, `providers`, `fallback_providers`, `fallback_model`, `credential_pool_strategies`, `model_catalog` | Sağlayıcı/model | **Model ve Sağlayıcı** |
| `toolsets`, `agent.disabled_toolsets` | Araç setleri | **Araçlar** |
| `agent` | Tur limiti, timeout, retry, tool-use zorlaması | **Ajan** |
| `terminal` | Sandbox/konteyner arka ucu | **Sandbox** |
| `browser`, `web` | Tarayıcı/otomasyon | **Tarayıcı** |
| `approvals`, `command_allowlist`, `quick_commands`, `hooks`, `hooks_auto_accept` | İzin/onay | **İzinler** |
| `security` | Tirith, gizli-veri redaksiyonu, site kara listesi, danışma uyarıları | **Güvenlik** |
| `tts`, `stt`, `voice` | Ses | **Ses ve Konuşma** |
| `slack`, `discord`, `telegram`, `whatsapp`, `mattermost`, `matrix` | Mesajlaşma köprüsü | **Kanallar** |
| `memory`, `curator`, `honcho`, `context`, `compression`, `prompt_caching` | Hafıza/bağlam | **Hafıza** |
| `skills` | Skill kataloğu | **Yetenekler (Skills)** |
| `cron`, `kanban`, `goals`, `delegation` | Otomasyon | **Otomasyon** |
| `display`, `dashboard`, `privacy` | Görünüm | **Görünüm** |
| `logging`, `sessions`, `checkpoints`, `updates`, `network`, `lsp` | Sistem | **Tanılama / Sistem** |

Yapılandırmaya **her zaman Fetih'in kendi API'siyle** dokunulur — elle YAML
düzenlemesi yapılmaz:

```python
from fetih_cli.config import (
    load_config, save_config,       # tam config oku/yaz (env-ref şablonlarını korur)
    read_raw_config,                # ${ENV} genişletmesi YAPILMADAN ham hali
    cfg_get,                        # güvenli iç içe okuma: cfg_get(cfg, "agent", "max_turns")
    set_config_value,               # noktalı anahtar ile tek değer yazma ("agent.max_turns")
    get_config_path, get_env_path,  # ~/.fetih/config.yaml, ~/.fetih/.env
    load_env, save_env_value, save_env_value_secure, remove_env_value,
    get_env_value, redact_key,      # API anahtarı yönetimi (değer ASLA loglanmaz)
    is_managed, managed_error,      # paket yöneticisiyle kurulmuş kurulumda yazmayı reddet
    validate_config_structure, migrate_config, check_config_version,
)
```

Gizli veriler `config.yaml`'da **değil**, `~/.fetih/.env` içinde tutulur;
`config.yaml` sadece `key_env: GROQ_API_KEY` gibi **isim** referansı taşır.
UI hiçbir zaman anahtar değeri göstermemeli — `redact_key()` kullanılmalı.

`~/.fetih/` içeriği (durum dizini): `config.yaml`, `.env`, `SOUL.md`,
`auth.json`, `state.db`, `sessions/`, `skills/`, `memories/`, `learnings/`,
`cron/`, `hooks/`, `pairing/`, `sandboxes/`, `logs/`, `audio_cache/`,
`image_cache/`, `cache/`, `models_dev_cache.json`.

---

## 1) Sağlayıcı ve model

**Kod:** `fetih_cli/providers.py`, `fetih_cli/models.py`, `fetih_cli/model_catalog.py`,
`fetih_cli/model_normalize.py`, `fetih_cli/model_switch.py`, `fetih_cli/codex_models.py`,
`fetih_cli/runtime_provider.py`, `providers/base.py`, `agent/models_dev.py`,
`agent/model_metadata.py`, `run_agent.py` (AIAgent).

**Model:** Sağlayıcı tanımı üç kaynaktan birleşir (`ProviderDef.source`):

1. `models.dev` kataloğu (`agent/models_dev.py`, önbellek: `~/.fetih/models_dev_cache.json`, ~4.5 MB),
2. FETİH overlay'i (`fetih_cli/providers.py::FETIHOverlay`) — depoya özgü ekler/düzeltmeler,
3. kullanıcının `config.yaml → providers:` bloğu (özel/OpenAI-uyumlu uçlar).

`ProviderDef` alanları: `id, name, transport, api_key_env_vars, base_url,
base_url_env_var, is_aggregator, auth_type, doc, source`.

**Taşıma (transport) → api_mode** eşlemesi (`TRANSPORT_TO_API_MODE`):

| transport | api_mode | Adaptör |
|---|---|---|
| `openai_chat` | `chat_completions` | `agent/chat_completion_helpers.py` |
| `anthropic_messages` | `anthropic_messages` | `agent/anthropic_adapter.py` |
| `codex_responses` | `codex_responses` | `agent/codex_responses_adapter.py` |
| `bedrock_converse` | `bedrock_converse` | `agent/bedrock_adapter.py` |

Ek adaptörler: `agent/gemini_native_adapter.py`, `agent/gemini_cloudcode_adapter.py`,
`agent/azure_identity_adapter.py`, `agent/copilot_acp_client.py`.

**Takma adlar:** `fetih_cli/providers.py::ALIASES` — `claude→anthropic`,
`grok→xai`, `qwen→alibaba`, `kimi→kimi-for-coding`, `zen→opencode`,
`nim→nvidia`, `hf→huggingface`, `aws→bedrock`, `lm-studio→lmstudio`,
`vllm/llamacpp→local`, `ollama→custom` vb.

**Bilinen sağlayıcı kimlikleri** (CLI'nin `--provider` tamamlaması,
`fetih_cli/main.py:9415`): `auto, openrouter, nous, openai-codex, xai-oauth,
copilot-acp, copilot, anthropic, gemini, google-gemini-cli, xai, bedrock,
azure-foundry, ollama-cloud, huggingface, zai, kimi-coding, kimi-coding-cn,
stepfun, minimax, minimax-cn, kilocode, novita, xiaomi, arcee, nvidia,
deepseek, alibaba, qwen-oauth, opencode-zen, opencode-go` — artı
`config.yaml → providers:` altında kullanıcının tanımladığı her özel uç
(bu depoda örnek: **groq**, `https://api.groq.com/openai/v1`, `key_env: GROQ_API_KEY`).

**Sağlayıcıya özgü uyumluluk katmanı** (`run_agent.py`, AIAgent metodları) —
UI'nin bilmesi gerekmez ama tanılamada görünür olmalı:

- `_needs_kimi_tool_reasoning()`, `_needs_deepseek_tool_reasoning()`,
  `_needs_mimo_tool_reasoning()` — bu uçlar `reasoning_content` alanının
  **geri gönderilmesini şart koşar**.
- `_rejects_reasoning_content_echo()` — tersi: Groq (`api.groq.com`) bu alanı
  **reddeder** (HTTP 400: `property 'reasoning_content' is unsupported`);
  `agent/agent_runtime_helpers.py::copy_reasoning_content_for_api()` bu durumda
  `reasoning_content`/`reasoning` alanlarını API kopyasından atar. Bu düzeltme
  olmadan Groq'ta çok turlu araç çağrısı **ikinci istekte kırılır**.
- `_sanitize_tool_calls_for_strict_api()` — Mistral/Fireworks gibi katı
  şemalarda `call_id`/`response_item_id` alanlarını temizler.

#### Ölçülmüş kısıt: küçük bağlamlı uçlar ve prompt tabanı

Canlı Groq testinde (2026-09-05) ortaya çıkan, **UI tasarımını doğrudan
etkileyen** bir gerçek:

| Yapılandırma | Sistem promptu | Araç şemaları | Yaklaşık istek tabanı |
|---|---|---|---|
| `toolsets=['file']`, bağlam dosyaları + hafıza **açık** | 24.774 karakter | 5.175 karakter | **~7.500 token** |
| `toolsets=['file','terminal']`, `skip_context_files` + `skip_memory` | 5.726 | 11.291 | ~4.250 token |
| `toolsets=[]`, `skip_context_files` + `skip_memory` | 2.204 | 0 | ~550 token |

Groq'un ücretsiz katmanı **8.000 TPM** (dakikada token) veriyor
(`x-ratelimit-limit-tokens: 8000`, hem `openai/gpt-oss-120b` hem
`openai/gpt-oss-20b` için). Yani FETİH'in **varsayılan CLI prompt tabanı tek
başına bütçenin %94'ünü yiyor** ve ajanik döngü ikinci istekte HTTP 413
("Request too large … TPM: Limit 8000") ile kırılıyor. `fetih-cli` toolset'i
(17 yetenek toolset'i, ~1064 skill'lik katalog dahil) bu uçlarda hiç
çalışmıyor.

**Sonuçlar:**

1. Masaüstü Köprüsü `session.new`/`session.send` bu yüzden
   `skip_context_files` ve `skip_memory` parametrelerini kabul ediyor
   (bkz. `docs/masaustu-koprusu-rpc.md`).
2. Ayarlar'daki **Model ve Sağlayıcı** sayfası, seçilen sağlayıcının rate-limit
   başlıklarını okuyup ("Bu uç dakikada 8.000 token veriyor; mevcut araç
   seçiminiz istek başına ~7.500 token kullanıyor") kullanıcıyı **önceden**
   uyarmalı. OpenClaw'ın Local AI sayfasındaki `See why` deseni buraya birebir
   uyar.
3. **Araçlar** sayfası, seçili toolset kombinasyonunun tahmini token maliyetini
   canlı göstermeli — kullanıcı `skills` toolset'ini açtığında ne ödediğini
   görmeli.

**Yedekleme (fallback) ve kimlik havuzu:** `fallback_providers`, `fallback_model`
(config sonundaki yorum bloğu tüm desteklenen yedek sağlayıcıları listeler),
`credential_pool_strategies` + `agent/credential_pool.py`, `agent/credential_sources.py`,
`agent/rate_limit_tracker.py`, `agent/nous_rate_guard.py`, `agent/retry_utils.py`.

**CLI:** `fetih model`, `fetih model list/set`, `fetih fallback <list|set|clear|test>`,
`fetih auth <add|list|remove|reset|status|logout|spotify>`, `fetih login`, `fetih logout`.

**Yardımcı (auxiliary) modeller** — `config.yaml → auxiliary:` altında **11 ayrı
görev** için bağımsız model/uç seçilebilir; her biri `{provider, model, base_url,
api_key, timeout, extra_body}` şemasında:
`vision, web_extract, compression, skills_hub, approval, mcp, title_generation,
triage_specifier, kanban_decomposer, profile_describer, curator`.
Kod: `agent/auxiliary_client.py`. **Bu, Ayarlar'da kendi başına bir alt sayfayı hak eder.**

---

## 2) Araç setleri (toolsets) ve araçlar

**Kod:** `toolsets.py` (kayıt defteri), `toolset_distributions.py` (olasılıksal
dağıtımlar), `tools/registry.py` (çalışma zamanı kaydı), `fetih_cli/tools_config.py`,
`fetih_cli/tool_installer.py`.

Yaklaşık **55 toolset**. Yetenek toolset'leri:
`web, search, x_search, vision, video, image_gen, video_gen, terminal, moa,
skills, browser, cronjob, messaging, file, tts, todo, memory, session_search,
clarify, code_execution, delegation, homeassistant, kanban, discord,
discord_admin, yuanbao, feishu_doc, feishu_drive, spotify, debugging, safe`.

Dağıtım/profil toolset'leri: `fetih-cli` (varsayılan), `fetih-acp`,
`fetih-api-server`, `fetih-cron`, ve her mesajlaşma platformu için birer tane
(`fetih-telegram`, `fetih-discord`, `fetih-whatsapp`, `fetih-slack`,
`fetih-signal`, `fetih-bluebubbles`, `fetih-homeassistant`, `fetih-email`,
`fetih-mattermost`, `fetih-matrix`, `fetih-dingtalk`, `fetih-feishu`,
`fetih-weixin`, `fetih-qqbot`, `fetih-wecom`, `fetih-wecom-callback`,
`fetih-yuanbao`, `fetih-sms`, `fetih-webhook`) — hepsinin birleşimi `fetih-gateway`.

Toolset'ler `includes:` ile bileşiktir; `resolve_toolset()` özyinelemeli çözer,
`"all"` / `"*"` takma adları her şeyi kapsar. Eklenti (plugin) ve MCP sunucuları
çalışma zamanında `tools/registry.py` üzerinden **yeni toolset ekleyebilir**, bu
yüzden UI listeyi **statik gömmemeli**, köprüden çekmeli.

`toolset_distributions.py::DISTRIBUTIONS` — `default`, `image_gen`, `research`,
`science` gibi adlandırılmış dağıtımlar; her toolset'e yüzde olasılık verip araç
setini turlar arası çeşitlendirir.

Öne çıkan tekil araçlar (`tools/`): `terminal_tool.py`, `file_tools.py`,
`file_operations.py`, `browser_tool.py` + `browser_cdp_tool.py` +
`browser_camofox.py`, `web_tools.py`, `x_search_tool.py`, `vision_tools.py`,
`image_generation_tool.py`, `video_generation_tool.py`, `tts_tool.py`,
`transcription_tools.py`, `voice_mode.py`, `memory_tool.py`, `todo_tool.py`,
`kanban_tools.py`, `cronjob_tools.py`, `delegate_tool.py`,
`mixture_of_agents_tool.py`, `code_execution_tool.py`, `mcp_tool.py`,
`skills_tool.py` + `skill_manager_tool.py`, `send_message_tool.py`,
`session_search_tool.py`, `clarify_tool.py`, `osv_check.py`,
`tirith_security.py`, `url_safety.py`, `website_policy.py`, `path_security.py`,
`osint/`, `ctf/`, `git/`.

**CLI:** `fetih tools list`, `fetih tools enable <ad>`, `fetih tools disable <ad>`.

---

## 3) Yetenekler (Skills)

**Kod:** `tools/skills_tool.py`, `tools/skill_manager_tool.py`, `tools/skills_hub.py`,
`tools/skills_sync.py`, `tools/skills_guard.py`, `tools/skill_provenance.py`,
`tools/skill_usage.py`, `fetih_cli/skills_hub.py`, `fetih_cli/skills_config.py`,
`fetih_cli/skill_validator.py`, `agent/skill_commands.py`, `agent/skill_preprocessing.py`,
`agent/skill_utils.py`.

İki depo: **`skills/`** (gömülü, varsayılan yüklü) ve **`optional-skills/`**
(isteğe bağlı kurulur). Kullanıcı kurulumları `~/.fetih/skills/`.
Prompt anlık görüntüsü: `~/.fetih/.skills_prompt_snapshot.json`.

**Kategori × SKILL.md sayısı** (bu depodaki gerçek sayım):

`skills/` (toplam ≈ 916):
| Kategori | Adet | | Kategori | Adet |
|---|---|---|---|---|
| **cybersecurity** | **743** | | media | 5 |
| **ctf** | **55** | | research | 5 |
| **red-teaming** | **32** | | apple | 5 |
| creative | 22 | | autonomous-ai-agents | 4 |
| software-development | 11 | | devops | 3 |
| mlops | 8 | | gaming | 2 |
| productivity | 8 | | data-science / dogfood / email / mcp / note-taking / social-media / yuanbao | 1'er |
| github | 6 | | diagramming / domain / gifs / index-cache / inference-sh | 0 (varlık/önbellek dizinleri) |

`optional-skills/` (toplam ≈ 81): mlops 28, research 11, finance 8,
productivity 7, creative 5, devops 4, blockchain 3, security 3,
autonomous-ai-agents 2, health 2, mcp 2, communication/dogfood/email/
migration/software-development/web-development 1'er.

> **Ürün açısından kritik:** Skill kataloğunun **%80'inden fazlası siber güvenlik,
> CTF ve red-teaming**. Masaüstü uygulamasının skill tarayıcısı bu üç kategoriyi
> birinci sınıf gezinme öğesi yapmalı (bkz. `docs/windows-app-plani.md` §f).

`optional-skills/migration/openclaw-migration/SKILL.md` — kullanıcının
`~/.openclaw` kurulumunu FETİH'e taşır (`fetih claw migrate`,
`scripts/openclaw_to_fetih.py`).

**Config:** `skills.external_dirs`, `skills.template_vars`, `skills.inline_shell`,
`skills.inline_shell_timeout`, `skills.guard_agent_created`.

**CLI:** `fetih skills <browse|search|install|inspect|list|check|update|audit|
uninstall|reset|publish|snapshot export|snapshot import|tap list|tap add|tap remove>`.

---

## 4) Ses (TTS / STT / sesli mod)

**Kod:** `tools/tts_tool.py`, `tools/transcription_tools.py`, `tools/voice_mode.py`,
`tools/neutts_synth.py` (+ `tools/neutts_samples/`), `fetih_cli/voice.py`.

**TTS sağlayıcıları** (`config.yaml → tts.provider`):
| Sağlayıcı | Ayarlar |
|---|---|
| `edge` (varsayılan) | `tts.edge.voice` (örn. `en-US-AriaNeural`) |
| `elevenlabs` | `voice_id`, `model_id` |
| `openai` | `model` (`gpt-4o-mini-tts`), `voice` |
| `xai` | `voice_id`, `language`, `sample_rate`, `bit_rate` |
| `mistral` | `model` (voxtral), `voice_id` |
| `neutts` | `ref_audio`, `ref_text`, `model`, `device` (yerel, GGUF) |
| `piper` | `voice` (yerel) |

**STT** (`config.yaml → stt`): `enabled`, `provider` ∈ {`local` (Whisper,
`stt.local.model`/`language`), `openai` (`whisper-1`), `mistral`
(`voxtral-mini-latest`)}.

**Sesli mod** (`config.yaml → voice`): `record_key` (varsayılan `ctrl+b`),
`max_recording_seconds`, `auto_tts`, `beep_enabled`, `silence_threshold`,
`silence_duration`. Sürekli dinleme: `voice.start_continuous()` /
`stop_continuous()`, sessizlik tespitiyle otomatik gönderim.
Ses önbelleği: `~/.fetih/audio_cache/`.

**CLI:** `fetih voice ...` (bkz. `fetih_cli/voice.py`); toolset: `tts`.
Tanılama betiği: `scripts/discord-voice-doctor.py`.

---

## 5) Mesajlaşma köprüleri (mevcut `gateway/` — masaüstü köprüsüyle karıştırılmaz)

**Kod:** `gateway/run.py`, `gateway/session.py`, `gateway/delivery.py`,
`gateway/platform_registry.py`, `gateway/channel_directory.py`, `gateway/mirror.py`,
`gateway/pairing.py`, `gateway/status.py`, `gateway/restart.py`,
`gateway/shutdown_forensics.py`, `gateway/memory_monitor.py`,
`gateway/stream_consumer.py`, `gateway/hooks.py` + `gateway/builtin_hooks/`,
`gateway/slash_access.py`, `gateway/sticker_cache.py`.

**Platformlar** (`gateway/platforms/`): `telegram` (+`telegram_network`),
`discord`, `slack`, `whatsapp`, `signal` (+`signal_rate_limit`), `bluebubbles`,
`email`, `sms`, `matrix`, `mattermost`, `dingtalk`, `feishu`
(+`feishu_comment`, `feishu_comment_rules`), `wecom` (+`wecom_callback`,
`wecom_crypto`), `weixin`, `qqbot/`, `yuanbao` (+`yuanbao_media`,
`yuanbao_proto`, `yuanbao_sticker`), `homeassistant`, `msgraph_webhook`,
`webhook`, `api_server`. Yeni platform ekleme rehberi:
`gateway/platforms/ADDING_A_PLATFORM.md`.

**Config:** her platform için kök anahtar — `slack`, `discord`, `telegram`,
`whatsapp`, `mattermost`, `matrix` (`require_mention`, `allowed_channels`,
`free_response_channels`, `channel_prompts`, Discord'da ayrıca `auto_thread`,
`history_backfill`, `reactions`, `max_attachment_bytes`...).
Ayrıca `agent.gateway_timeout`, `agent.gateway_notify_interval`,
`agent.gateway_auto_continue_freshness`, `group_sessions_per_user`.

**CLI:** `fetih gateway <run|start|stop|restart|status|install|uninstall|list|setup|
migrate-legacy>`, `fetih whatsapp`, `fetih slack manifest`, `fetih send`,
`fetih pairing <list|approve|revoke|clear-pending>`, `fetih webhook <add|list|remove|test>`.
Windows'a özgü servis yolu: `fetih_cli/gateway_windows.py`.

> **Masaüstü uygulaması bu katmanı yönetmez, sadece durumunu okur** —
> `channels.status` / `channels.list` (bkz. `docs/windows-app-plani.md` §b tablosu).

---

## 6) Kanban (görev panosu ve iş dağıtımı)

**Kod:** `fetih_cli/kanban.py`, `fetih_cli/kanban_db.py`,
`fetih_cli/kanban_decompose.py`, `fetih_cli/kanban_diagnostics.py`,
`fetih_cli/kanban_specify.py`, `tools/kanban_tools.py`, `plugins/kanban/`.

SQLite tabanlı (`kanban.db`). Kavramlar: **board**, **task**, **assignee**,
**bağımlılık (parent→child)**, **yorum**, **olay akışı**, **worker/daemon**.

**CLI:** `fetih kanban <init|boards list|boards create|boards rm|boards switch|
boards rename|create|list|show|assign|reclaim|reassign|diagnose|link|unlink|
claim|comment|complete|edit|block|unblock|archive|tail|dispatch|daemon|watch|stats>`.

**Config (`kanban:`):** `dispatch_in_gateway` (mesajlaşma köprüsü sürecinde
görev dağıt), `dispatch_interval_seconds`, `failure_limit`,
`worker_log_rotate_bytes`, `worker_log_backup_count`, `orchestrator_profile`,
`default_assignee`, `auto_decompose`, `auto_decompose_per_tick`.
Otomatik ayrıştırma yardımcı modeli: `auxiliary.kanban_decomposer`.

---

## 7) Cron / zamanlanmış işler

**Kod:** `cron/jobs.py`, `cron/scheduler.py`, `fetih_cli/cron.py`,
`tools/cronjob_tools.py`. İş deposu: `~/.fetih/cron/`.

`parse_schedule()` hem cron ifadelerini hem süre ifadelerini (`parse_duration`)
kabul eder; `compute_next_run()` bir sonraki çalışmayı hesaplar, tek seferlik
işlerde kaçırılan çalışma için **grace** penceresi vardır
(`_compute_grace_seconds`, `_recoverable_oneshot_run_at`).
İş alanları arasında `skill`/`skills`, `workdir`, `profile` da var.

**CLI:** `fetih cron <list|create|edit|pause|resume|run|remove|status|tick>`.
**Config (`cron:`):** `wrap_response`, `max_parallel_jobs`.
**Güvenlik:** `approvals.cron_mode` (varsayılan `deny`) — zamanlanmış işlerde
tehlikeli komut onayının nasıl ele alınacağı.

---

## 8) Hafıza, SOUL.md ve bağlam yönetimi

**Kod:** `agent/memory_manager.py`, `agent/memory_provider.py`,
`agent/context_engine.py`, `agent/context_compressor.py`,
`agent/context_references.py`, `agent/conversation_compression.py`,
`agent/manual_compression_feedback.py`, `agent/prompt_caching.py`,
`agent/insights.py`, `tools/memory_tool.py`, `fetih_cli/memory_setup.py`,
`fetih_cli/learnings.py`, `fetih_cli/curator.py`, `agent/curator.py`,
`agent/curator_backup.py`, `plugins/memory/` (Honcho, Hindsight...),
`plugins/context_engine/`.

- **`~/.fetih/SOUL.md`** — kalıcı kişilik/kimlik dosyası; yoksa
  `fetih_cli/default_soul.py` üretir (`_ensure_default_soul_md`).
- **`~/.fetih/memories/`**, **`~/.fetih/learnings/`** — çıkarılan bilgi.
- **Config `memory:`** — `memory_enabled`, `user_profile_enabled`,
  `memory_char_limit` (2200), `user_char_limit` (1375), `provider` (harici
  sağlayıcı; boş = gömülü).
- **Config `context:`** — `engine` (`compressor` | eklenti motoru).
- **Config `compression:`** — `enabled`, `threshold` (0.5), `target_ratio` (0.2),
  `protect_last_n`, `protect_first_n`, `hygiene_hard_message_limit`,
  `abort_on_summary_failure`.
- **Config `prompt_caching.cache_ttl`** (`5m`).
- **Config `curator:`** — arka plan bakım ajanı: `enabled`, `interval_hours` (168),
  `min_idle_hours`, `stale_after_days`, `archive_after_days`, `backup.{enabled,keep}`.
- **Config `honcho: {}`** — harici Honcho AI hafızası;
  `fetih honcho <setup|status|sessions|map|peer|mode|tokens|identity|migrate>`.
- **Config `session_reset:`** — `mode` (`both`), `idle_minutes` (1440), `at_hour`.

**CLI:** `fetih memory <setup|status|off|reset>`, `fetih curator ...`,
`fetih insights ...`, `fetih sessions <list|export|delete|prune|stats|rename|browse>`,
`fetih checkpoints ...`.

---

## 9) İzin ve onay (yürütme güvenliği)

**Kod:** `tools/approval.py`, `tools/slash_confirm.py`, `agent/tool_guardrails.py`,
`agent/shell_hooks.py`, `fetih_cli/hooks.py`, `fetih_cli/agent_hooks.py`,
`tools/path_security.py`, `tools/url_safety.py`, `tools/website_policy.py`,
`tools/tirith_security.py`, `fetih_cli/security_advisories.py`.

**Config:**
```yaml
approvals:
  mode: manual            # onay modu
  timeout: 60             # saniye
  cron_mode: deny         # zamanlanmış işlerde
  mcp_reload_confirm: true
  destructive_slash_confirm: true
command_allowlist: []     # kalıcı olarak onaylı komut kalıpları
quick_commands: {}
hooks: {}                 # kullanıcı hook'ları (~/.fetih/hooks/)
hooks_auto_accept: false
security:
  allow_private_urls: false
  redact_secrets: true
  tirith_enabled: true            # harici politika motoru
  tirith_path: tirith
  tirith_timeout: 5
  tirith_fail_open: true
  website_blocklist: {enabled, domains, shared_files}
  acked_advisories: []
  allow_lazy_installs: true
```

**Onay akışının önemli kavramları** (`tools/approval.py`):
- `detect_dangerous_command()` / `detect_hardline_command()` — kalıp tabanlı tespit;
  "hardline" komutlar **onaylanamaz, doğrudan bloklanır** (`_hardline_block_result`),
  `sudo` + stdin koruması ayrıca var (`_check_sudo_stdin_guard`).
- Kapsamlar: **oturum bazlı onay** (`approve_session`), **kalıcı allowlist**
  (`approve_permanent`, `load_permanent_allowlist`, `save_permanent_allowlist`
  → `command_allowlist`), **YOLO modu** (`enable_session_yolo` — oturum boyunca
  tüm onayları atlar).
- `_smart_approve()` — `auxiliary.approval` yardımcı modeliyle model destekli karar.
- Mesajlaşma köprüsü bağlamında onay: `register_gateway_notify()`,
  `resolve_gateway_approval()`, `has_blocking_approval()`.

> **Masaüstü köprüsü için:** `approval.request` (olay) / `approval.respond`
> (metot) tam olarak bu API'nin üzerine oturur; oturum anahtarı
> `set_current_session_key()` / `get_current_session_key()` ile
> `contextvars` üzerinden taşınır.

**Tur döngüsü koruması** (`tool_loop_guardrails`): `warnings_enabled`,
`hard_stop_enabled`, `warn_after.{exact_failure, same_tool_failure,
idempotent_no_progress}`, `hard_stop_after.{...}`.

**Araç çıktısı limitleri** (`tool_output`): `max_bytes` 50000, `max_lines` 2000,
`max_line_length` 2000; `file_read_max_chars` 100000.

---

## 10) Sandbox / yürütme ortamları

**Kod:** `tools/environments/` — `local.py`, `docker.py`, `singularity.py`,
`modal.py` + `managed_modal.py` + `modal_utils.py`, `daytona.py`,
`vercel_sandbox.py`, `ssh.py`, `file_sync.py`, `base.py`.
Ayrıca `tools/code_execution_tool.py`, `tools/process_registry.py`,
`tools/env_passthrough.py`, `Dockerfile`, `docker/`, `docker-compose.yml`.
Sandbox durumu: `~/.fetih/sandboxes/`.

**Config (`terminal:`):**
`backend` (`local` | `docker` | `singularity` | `modal` | `daytona` | `vercel` | `ssh`),
`modal_mode` (`auto`), `cwd`, `timeout` (180), `env_passthrough`,
`shell_init_files`, `auto_source_bashrc`, `persistent_shell`,
`docker_image` (`nikolaik/python-nodejs:python3.11-nodejs20`),
`docker_forward_env`, `docker_env`, `docker_volumes`,
`docker_mount_cwd_to_workspace`, `docker_extra_args`, `docker_run_as_host_user`,
`singularity_image`, `modal_image`, `daytona_image`, `vercel_runtime` (`node24`),
ve konteyner kaynak limitleri: `container_cpu` (1), `container_memory` (5120 MB),
`container_disk` (51200 MB), `container_persistent`.

`code_execution.mode`: `project` (kod yürütme kapsamı).
Konteyner içinde çalışma tespiti: `fetih_cli/config.py::_is_container()`,
`get_container_exec_info()`.

---

## 11) Çoklu profil (izole örnekler)

**Kod:** `fetih_cli/profiles.py`, `fetih_cli/profile_distribution.py`,
`fetih_cli/profile_describer.py`, `fetih_cli/relaunch.py`,
`fetih_cli/config.py::_inject_profile_env_vars()`.

Her profil kendi `~/.fetih*` durum dizinine, kendi config/`.env`/oturumlarına
ve kendi mesajlaşma köprüsü servisine sahiptir (`fetih gateway list` profil
başına durum gösterir).

**CLI:** `fetih profile <list|use|create|delete|describe|show|alias|rename|
export|import|install|update|info>`.
Profil açıklaması yardımcı modeli: `auxiliary.profile_describer`.

---

## 12) MCP (Model Context Protocol)

**Kod:** `mcp_serve.py` (FETİH'i MCP **sunucusu** yapar), `tools/mcp_tool.py`
(MCP **istemcisi**), `tools/mcp_oauth.py`, `tools/mcp_oauth_manager.py`,
`fetih_cli/mcp_config.py`, `bridge/mcp-server.ts`, `bridge/plugin.ts`,
`skills/mcp/`, `optional-skills/mcp/`.

**CLI:** `fetih mcp <serve|add|remove|list|test|config|login>`.
MCP sunucuları çalışma zamanında yeni toolset kaydeder (toolset adı = sunucu adı;
`tools/registry.py::get_toolset_alias_target`).
**Config:** `approvals.mcp_reload_confirm`, `auxiliary.mcp`.

---

## 13) Eklentiler (plugins)

**Kod:** `plugins/` + `fetih_cli/plugins.py`, `fetih_cli/plugins_cmd.py`,
`agent/plugin_llm.py`.

Gömülü eklentiler: `browser`, `context_engine`, `disk-cleanup`,
`example-dashboard`, **`fetih-achievements`**, `google_meet`, `image_gen`,
`kanban`, `memory`, `model-providers`, `observability`, `platforms`, `spotify`,
`teams_pipeline`, `video_gen`, `web`.

Eklentiler **kendi CLI alt komutlarını** kaydedebilir
(`fetih_cli/main.py:10928` civarı, `_plugin_cli_discovery_needed()` ile tembel
keşif). Bu yüzden masaüstü uygulaması komut listesini köprüden dinamik almalı.

**CLI:** `fetih plugins <install|update|remove|list|enable|disable>`.

### Achievements (başarımlar)
`plugins/fetih-achievements/` — kendi `dashboard/` (web panosu + `plugin_api.py`),
`docs/`, `tests/` ve LICENSE'ı olan bağımsız eklenti. Kullanım istatistiklerinden
rozet/başarım üretir. Masaüstü uygulamasında **oyunlaştırma sekmesi** olarak
gösterilebilir; verisi eklenti API'sinden okunur.

---

## 14) Tanılama, doktor, durum, günlükler

**Kod:** `fetih_cli/doctor.py`, `fetih_cli/status.py`, `fetih_cli/logs.py`,
`fetih_cli/debug.py`, `fetih_cli/dump.py`, `fetih_cli/inventory.py`,
`fetih_cli/backup.py`, `fetih_cli/updater.py`, `fetih_cli/uninstall.py`,
`fetih_cli/dep_ensure.py`, `agent/stream_diag.py`, `fetih_logging.py`,
`gateway/shutdown_forensics.py`, `gateway/memory_monitor.py`.

**CLI:** `fetih doctor`, `fetih status`, `fetih logs`, `fetih debug <share|delete>`,
`fetih dump`, `fetih backup`, `fetih version`, `fetih update`, `fetih uninstall`,
`fetih config <show|edit|set|path|env-path|check|migrate>`.

**Config:** `logging.{level, max_size_mb, backup_count, memory_monitor.{enabled,
interval_seconds}}`, `updates.{pre_update_backup, backup_keep}`,
`network.force_ipv4`, `sessions.{auto_prune, retention_days, vacuum_after_prune,
min_interval_hours}`, `checkpoints.{enabled, max_snapshots, max_total_size_mb,
max_file_size_mb, auto_prune, retention_days, delete_orphans, min_interval_hours}`.

**Kurulum tipi tespiti:** `detect_install_method()`, `stamp_install_method()`,
`is_managed()` / `managed_error()` (paket yöneticisiyle kurulmuşsa yazma
işlemleri reddedilir), `recommended_update_command()`.
OpenClaw'ın "Unpackaged (developer)" göstergesinin bizdeki karşılığı budur —
Tanılama sayfasında **mutlaka** gösterilmeli.

---

## 15) Kimlik doğrulama ve kimlik bilgisi yönetimi

**Kod:** `fetih_cli/auth.py`, `fetih_cli/auth_commands.py`,
`fetih_cli/copilot_auth.py`, `fetih_cli/vercel_auth.py`,
`fetih_cli/dingtalk_auth.py`, `fetih_cli/nous_subscription.py`,
`fetih_cli/azure_detect.py`, `agent/google_oauth.py`,
`agent/google_code_assist.py`, `agent/credential_pool.py`,
`agent/credential_sources.py`, `tools/credential_files.py`,
`tools/microsoft_graph_auth.py`, `agent/redact.py`.

Depolama: `~/.fetih/auth.json` (+ `auth.lock`), gizli anahtarlar `~/.fetih/.env`.
`auth_type` ∈ {`api_key`, OAuth cihaz akışı, abonelik tabanlı}.

**CLI:** `fetih login`, `fetih logout`,
`fetih auth <add|list|remove|reset|status|logout|spotify>`.

**Kural:** UI hiçbir noktada anahtar **değerini** göstermez/loglamaz;
`redact_key()` ve `security.redact_secrets` bunun içindir.
`_check_non_ascii_credential()` yapıştırma hatalarını yakalar,
`sanitize_env_file()` bozuk `.env` satırlarını temizler.

---

## 16) HTTP API sunucusu ve ACP

**Kod:** `api/server.py`, `api/auth.py`, `api/routes/` — `chat`, `config`,
`cron_routes`, `files`, `gateway`, `models`, `plugins`, `profiles`, `sessions`,
`skills`, `system_routes`, `tools`; `api/models/`; `acp_registry/agent.json`;
`fetih_cli/stdio.py`.

**CLI:** `fetih acp` (editör entegrasyonu: VS Code, Zed, JetBrains),
`fetih proxy <start|stop|status>` (`fetih_cli/proxy/`).

> **Not:** `api/routes/*` mevcut REST yüzeyi, Masaüstü Köprüsü'nün RPC
> metotlarını adlandırırken **iyi bir eşleme kaynağı** — aynı alanları
> kapsıyorlar (config, models, sessions, skills, tools, plugins, profiles, cron).

---

## 17) Ajan çalışma zamanı ve görünüm

**Kod:** `run_agent.py` (AIAgent — ana sınıf), `agent/conversation_loop.py`,
`agent/tool_executor.py`, `agent/tool_dispatch_helpers.py`,
`agent/agent_init.py`, `agent/prompt_builder.py`, `agent/system_prompt.py`,
`agent/display.py`, `agent/trajectory.py`, `agent/title_generator.py`,
`agent/error_classifier.py`, `agent/iteration_budget.py`,
`agent/background_review.py`, `agent/think_scrubber.py`, `agent/i18n.py`,
`batch_runner.py`, `mini_swe_runner.py`, `trajectory_compressor.py`,
`model_tools.py`.

**Config `agent:`** — `max_turns` (90), `gateway_timeout` (1800),
`gateway_timeout_warning`, `gateway_notify_interval`,
`gateway_auto_continue_freshness`, `restart_drain_timeout`, `api_max_retries`,
`service_tier`, `tool_use_enforcement` (`auto`), `clarify_timeout`,
`image_input_mode` (`auto`), `disabled_toolsets`.

**Config `delegation:`** — alt ajan: `model`, `provider`, `base_url`, `api_key`,
`api_mode`, `inherit_mcp_toolsets`, `max_iterations` (50),
`child_timeout_seconds`, `reasoning_effort`, `max_concurrent_children` (3),
`max_spawn_depth` (1), `orchestrator_enabled`, `subagent_auto_approve`.

**Config `display:`** — `compact`, `personality` (`kawaii`), `skin` (`red`),
`language` (`en`), `resume_display`, `busy_input_mode`, `show_reasoning`,
`streaming`, `timestamps`, `final_response_markdown`, `persistent_output(+max_lines)`,
`inline_diffs`, `file_mutation_verifier`, `show_cost`, `tui_status_indicator`,
`user_message_preview.{first_lines,last_lines}`, `interim_assistant_messages`,
`tool_progress` / `tool_progress_command` / `tool_progress_overrides`,
`tool_preview_length`, `ephemeral_system_ttl`, `runtime_footer.{enabled,fields}`,
`copy_shortcut`, `bell_on_complete`, `tui_auto_resume_recent`, `platforms`.
Ayrıca `dashboard.{theme, show_token_analytics}`, `privacy.redact_pii`,
`human_delay.{mode,min_ms,max_ms}`, `personalities: {}`.
Deri/tema motoru: `fetih_cli/skin_engine.py`; yerelleştirme: `locales/`, `agent/i18n.py`.

**Diğer:** `goals.max_turns` + `fetih_cli/goals.py`,
`streaming`, `x_search.{model,timeout_seconds,retries}`,
`lsp.{enabled,wait_mode,wait_timeout,install_strategy,servers}` + `agent/lsp/`,
`fetih_cli/browser_connect.py`, `fetih_cli/clipboard.py`,
`fetih_cli/session_recap.py`, `fetih_cli/tips.py`, `fetih_cli/completion.py`,
`fetih_cli/curses_ui.py`, `fetih_cli/banner.py`, `fetih_cli/colors.py`.

---

## 18) Tam CLI alt komut listesi (masaüstü uygulamasının kapsaması gereken yüzey)

`_BUILTIN_SUBCOMMANDS` (`fetih_cli/main.py:9433`) + kayıtlı diğerleri:

```
acp        auth       backup     chat       checkpoints  claw      completion
config     cron       debug      doctor     dump         fallback  gateway
hooks      import     insights   kanban     login        logout    logs
lsp        mcp        memory     model      pairing      plugins   postinstall
profile    proxy      send       sessions   setup        skills    slack
status     tools      uninstall  update     version      webhook   whatsapp
curator    insights   download-tools
```
(+ eklentilerin çalışma zamanında kaydettiği komutlar)

**Eklenmesi planlanan:** `desktop-bridge` (Masaüstü Köprüsü sunucusu) —
yeni bir alt komut olarak `_BUILTIN_SUBCOMMANDS`'a da eklenmeli.

---

## 19) Ayarlar sayfası önceliklendirmesi (öneri)

Masaüstü uygulamasının ilk sürümünde şu sekmeler **gerçek işlevle** dolmalı
(OpenClaw'ın sekme yapısıyla karşılaştırma için bkz.
`docs/openclaw-inceleme-notlari.md`):

1. **Bağlantı** — köprü durumu, protokol sürümü, token, yeniden bağlanma.
2. **Model ve Sağlayıcı** — `model.default`/`model.provider`, `providers:`
   listesi, model keşfi, `fallback_*`, `auxiliary:` alt sayfası. *(FETİH'in
   model-agnostikliği burada görünür olmalı — planın §f maddesi.)*
3. **Yetenekler (Skills)** — cybersecurity/CTF/red-teaming odaklı katalog tarayıcı.
4. **İzinler** — `approvals`, `command_allowlist`, hook'lar, YOLO uyarısı.
5. **Sandbox** — `terminal.backend` + konteyner limitleri.
6. **Ses** — TTS/STT sağlayıcı ve kayıt tuşu.
7. **Kanallar** — mesajlaşma köprüsü durumu (salt okunur).
8. **Tanılama** — `doctor` çıktısı, kurulum tipi, sürümler, günlükler.
9. **Hakkında** — sürüm, lisans, güncelleme kanalı.
