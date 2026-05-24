# FETIH — FETIH Çekirdeğine FETIH Yamasi

## GÖREV

FETIH (Python) çekirdeğini aynen koru. Üstüne FETIH'in CTF/OSINT araçlarını ve plugin sistemini MCP üzerinden ekle. Ayrı servis yok, baştan yazmak yok — sadece yama (fine-tune).

---

## KISIM 1: KAYNAKLAR

### Ana: FETIH (Python — AYNEN KALIR)
**Konum:** `/home/ara/.fetih/fetih/`

```
├── providers/                 # 30+ AI provider — DOKUNMA
├── plugins/model-providers/   # Provider profilleri — DOKUNMA
├── run_agent.py               # Agent loop — DOKUNMA
├── model_tools.py             # Tool orchestration — DOKUNMA
├── tools/registry.py          # Tool registry — SADECE FETIH tool'larını EKLE
├── tools/terminal_tool.py     # Terminal — DOKUNMA
├── tools/mcp_tool.py          # MCP client — KULLAN (bridge için)
├── gateway/platforms/         # Telegram/Discord/CLI — DOKUNMA
├── skills/                    # Skill sistemi — DOKUNMA
├── cron/                      # Scheduler — DOKUNMA
└── fetih_state.py            # SessionDB — DOKUNMA
```

### Eklenti: FETIH TypeScript Araçları
**Konum:** `/home/ara/Desktop/seth-github/seth-main/src/tools/`

Alınacaklar:
```
tools/ctf/                     ← CTF araçları (hepsi)
tools/osint/                   ← OSINT araçları (hepsi)
tools/git/                     ← Git araçları
tools/agent-spawn.ts           ← Agent spawn
tools/agent-memory.ts          ← Agent memory
tools/ask-user.ts              ← Kullanıcıya sor
tools/fetih-engine.ts          ← FETIH motoru
```

### Eklenti: FETIH Plugin Sistemi
**Konum:** `/home/ara/Desktop/seth-github/seth-main/src/plugin/`
Alınacak: Plugin manifest + loader (TypeScript)

---

## KISIM 2: MİMARİ

```
┌─────────────────────────────────────────────────────┐
│                    FETIH (Python)                   │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │  providers/  (30+ AI provider)               │   │
│  │  • DeepSeek • Anthropic • OpenAI             │   │
│  │  • OpenRouter • Gemini • Ollama              │   │
│  └──────────────────────────────────────────────┘   │
│                                                      │
│  ┌─────────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │  Telegram   │ │ Discord  │ │     CLI          │  │
│  └─────────────┘ └──────────┘ └──────────────────┘  │
│                                                      │
│  ┌──────────┐ ┌──────┐ ┌─────┐ ┌───────┐ ┌──────┐ │
│  │  Skills  │ │Memory│ │Cron │ │  MCP  │ │ Agent│ │
│  └──────────┘ └──────┘ └─────┘ └───┬───┘ └──────┘ │
│                                     │               │
└─────────────────────────────────────┼───────────────┘
                                      │ MCP
              ┌───────────────────────┼───────────────────┐
              │     FETIH (TypeScript) │                  │
              │                       ▼                   │
              │  ┌────────────────────────────────────┐   │
              │  │  MCP Server (bridge/mcp-server.ts)  │   │
              │  └────────────────────────────────────┘   │
              │         │         │          │            │
              │         ▼         ▼          ▼            │
              │  ┌────────┐ ┌────────┐ ┌──────────┐      │
              │  │  CTF   │ │ OSINT  │ │  Plugin  │      │
              │  │ tools  │ │ tools  │ │  sistemi │      │
              │  └────────┘ └────────┘ └──────────┘      │
              └───────────────────────────────────────────┘
```

---

## KISIM 3: NE YAPILACAK

### 1. FETIH'i Kopyala

```bash
cp -r /home/ara/.fetih/fetih /home/ara/Desktop/fetih
cd /home/ara/Desktop/fetih
rm -rf acp_adapter/ tui_gateway/ ui-tui/ fetih_cli/ website/
git init && git add . && git commit -m "fetih: fetih fork + cleanup"
```

**Sadece bunlar silinecek:** acp_adapter, tui_gateway, ui-tui, fetih_cli, website
**FETIH'in geri kalan HER ŞEY aynen kalacak.**

### 2. FETIH TypeScript Araçlarını Ekle

```bash
mkdir -p /home/ara/Desktop/fetih/tools
cd /home/ara/Desktop/fetih/tools
npm init -y

# CTF araçları
cp -r /home/ara/Desktop/seth-github/seth-main/src/tools/ctf ./

# OSINT + Git  
cp -r /home/ara/Desktop/seth-github/seth-main/src/tools/osint ./
cp -r /home/ara/Desktop/seth-github/seth-main/src/tools/git ./

# Bireysel araçlar
cp /home/ara/Desktop/seth-github/seth-main/src/tools/agent-spawn.ts .
cp /home/ara/Desktop/seth-github/seth-main/src/tools/agent-memory.ts .
cp /home/ara/Desktop/seth-github/seth-main/src/tools/ask-user.ts .
cp /home/ara/Desktop/seth-github/seth-main/src/tools/fetih-engine.ts .
```

### 3. MCP Bridge (FETIH → FETIH)

FETIH'te MCP zaten var. Tek yapman gereken: FETIH TypeScript araçlarını bir **MCP server** olarak expose etmek.

```typescript
// bridge/mcp-server.ts
import { MCPServer } from '@anthropic-ai/mcp';
import { CTFAraclari } from '../tools/ctf';
import { OSINTAraclari } from '../tools/osint';

const server = new MCPServer({
  name: 'fetih-tools',
  tools: [
    ...CTFAraclari,
    ...OSINTAraclari,
  ]
});

server.listen(5001);
```

Sonra FETIH'in `~/.fetih/config.yaml` dosyasına şu satırı ekle:

```yaml
mcp_servers:
  fetih-tools:
    command: node
    args: ["/home/ara/Desktop/fetih/bridge/mcp-server.js"]
```

FETIH MCP tool'u bu server'daki tüm tool'ları otomatik keşfeder. **Sıfır kod!**

### 4. FETIH Plugin Sistemini Ekle

`/home/ara/Desktop/seth-github/seth-main/src/plugin/index.ts` dosyasını `bridge/plugin.ts` olarak kopyala. MCP server'a plugin yönetim tool'larını da ekle.

---

## KISIM 4: KULLANIM

```bash
# 1. FETIH'i başlat (Python)
cd /home/ara/Desktop/fetih
source .venv/bin/activate
python cli.py

# 2. MCP bridge'i başlat (TypeScript — ayrı terminal)
cd /home/ara/Desktop/fetih
node bridge/mcp-server.js

# 3. Telegram'dan veya CLI'dan kullan
# "10.0.0.1'de 80 portunu tara" → FETIH → MCP → CTF aracı
# "bu hash'i kır" → FETIH → MCP → CTF aracı
# "ornek.com'u araştır" → FETIH → MCP → OSINT aracı
```

---

## KISIM 5: ÖZET

| Parça | Ne Olacak? | Dil |
|-------|-----------|-----|
| FETIH core | **Aynen kalır** | Python |
| 30+ provider | **Aynen kalır** | Python |
| Telegram/Discord | **Aynen kalır** | Python |
| Skills, Memory, Cron | **Aynen kalır** | Python |
| CTF araçları | **Eklenecek** (MCP) | TypeScript |
| OSINT araçları | **Eklenecek** (MCP) | TypeScript |
| Plugin sistemi | **Eklenecek** (MCP) | TypeScript |
| Web panel | **Yok** ❌ | - |
| Terminal permission | **Yok** ❌ | - |
| Sandbox | **Yok** ❌ | - |

---

## KISIM 6: BAŞARI KRİTERLERİ

- [ ] FETIH (Python) CLI çalışıyor
- [ ] `--provider deepseek` çalışıyor
- [ ] `--provider anthropic` çalışıyor
- [ ] Telegram bot çalışıyor
- [ ] MCP bridge başlıyor
- [ ] `"10.0.0.1'i tara"` → CTF aracı çalışıyor
- [ ] `"ornek.com'u araştır"` → OSINT aracı çalışıyor
- [ ] Plugin yüklenebiliyor
