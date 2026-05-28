# ⚔ FETIH REST API

FETIH AI Agent için HTTP REST API sunucusu. Tüm becerileri, ayarları ve operasyonları tek bir HTTP arayüzünden yönetin.

**Port:** `1453` | **Framework:** FastAPI + Uvicorn | **Doküman:** Swagger UI

---

## 🚀 Hızlı Başlatma

```bash
# Sunucuyu başlat
python3 -m api.server --port 1453

# Veya environment variable ile
FETIH_API_PORT=1453 python3 -m api.server
```

Sunucu başladıktan sonra:

```
⚔  FETIH API Server
Port     : 1453
Docs     : http://127.0.0.1:1453/api/docs
Health   : http://127.0.0.1:1453/api/v1/health
```

---

## 📡 Endpoint Kataloğu (69 endpoint)

### 💬 Chat & Agent (6)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `POST` | `/api/v1/chat` | Prompt gönder, tam yanıt al |
| `POST` | `/api/v1/chat/stream` | SSE streaming sohbet |
| `POST` | `/api/v1/chat/background` | Arkaplanda çalıştır |
| `GET` | `/api/v1/chat/tasks` | Arkaplan görevlerini listele |
| `GET` | `/api/v1/chat/tasks/{id}` | Görev durumunu sorgula |
| `DELETE` | `/api/v1/chat/tasks/{id}` | Görevi iptal et |

### 🤖 Model Yönetimi (8)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/models` | Modelleri listele |
| `POST` | `/api/v1/models/switch` | Model değiştir |
| `GET` | `/api/v1/models/params` | Parametreleri getir |
| `POST` | `/api/v1/models/params` | Parametreleri güncelle |
| `GET` | `/api/v1/models/providers` | Provider'ları listele |
| `POST` | `/api/v1/models/providers` | Custom provider ekle |
| `DELETE` | `/api/v1/models/providers/{slug}` | Custom provider sil |

### 📋 Session Yönetimi (8)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/sessions` | Session'ları listele |
| `POST` | `/api/v1/sessions` | Yeni session oluştur |
| `GET` | `/api/v1/sessions/{id}` | Session detayı |
| `GET` | `/api/v1/sessions/{id}/history` | Mesaj geçmişi |
| `PUT` | `/api/v1/sessions/{id}` | Session güncelle |
| `DELETE` | `/api/v1/sessions/{id}` | Session sil |
| `POST` | `/api/v1/sessions/{id}/export` | Dışa aktar (json/markdown) |

### 🧠 Skill Yönetimi (7)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/skills` | Skill'leri listele |
| `GET` | `/api/v1/skills/categories` | Kategori listesi + sayıları |
| `GET` | `/api/v1/skills/{name}` | Skill detayı |
| `GET` | `/api/v1/skills/{name}/raw` | Ham SKILL.md içeriği |
| `POST` | `/api/v1/skills/search` | Gelişmiş arama |
| `POST` | `/api/v1/skills/reload` | Cache yenile |

### 🔧 Tool Yönetimi (5)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/tools` | Tool'ları listele |
| `POST` | `/api/v1/tools/enable` | Tool aktifleştir |
| `POST` | `/api/v1/tools/disable` | Tool deaktif et |
| `GET` | `/api/v1/tools/available` | Kullanılabilir tool'lar |
| `GET` | `/api/v1/tools/{name}/schema` | Tool JSON şeması |

### ⚙️ Konfigürasyon (6)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/config` | Tüm konfigürasyon |
| `GET` | `/api/v1/config/{key}` | Tek değer getir |
| `PUT` | `/api/v1/config/{key}` | Değer güncelle |
| `PATCH` | `/api/v1/config` | Çoklu güncelleme |
| `GET` | `/api/v1/config/env` | .env değerleri |
| `PUT` | `/api/v1/config/env/{key}` | .env güncelle |
| `POST` | `/api/v1/config/reload` | Yeniden yükle |

### 🌐 Gateway (7)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/gateway/status` | Durum |
| `POST` | `/api/v1/gateway/start` | Başlat |
| `POST` | `/api/v1/gateway/stop` | Durdur |
| `POST` | `/api/v1/gateway/restart` | Yeniden başlat |
| `GET` | `/api/v1/gateway/platforms` | Platform durumları |
| `POST` | `/api/v1/gateway/platforms/{name}/pause` | Platform duraklat |
| `POST` | `/api/v1/gateway/platforms/{name}/resume` | Platform devam ettir |

### 👤 Profil Yönetimi (4)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/profiles` | Profil listesi |
| `POST` | `/api/v1/profiles` | Yeni profil |
| `POST` | `/api/v1/profiles/{name}/activate` | Profil değiştir |
| `DELETE` | `/api/v1/profiles/{name}` | Profil sil |

### 📁 Dosya Yönetimi (5)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `POST` | `/api/v1/files/upload` | Dosya yükle |
| `GET` | `/api/v1/files` | Dosyaları listele |
| `GET` | `/api/v1/files/{id}` | Dosya bilgisi |
| `GET` | `/api/v1/files/{id}/download` | Dosyayı indir |
| `DELETE` | `/api/v1/files/{id}` | Dosya sil |

### 🔌 Plugin (3)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/plugins` | Plugin listesi |
| `POST` | `/api/v1/plugins/install` | Plugin yükle |
| `DELETE` | `/api/v1/plugins/{name}` | Plugin kaldır |

### ⏰ Cron (4)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/cron` | Görev listesi |
| `POST` | `/api/v1/cron` | Yeni görev |
| `PUT` | `/api/v1/cron/{id}` | Görev güncelle |
| `DELETE` | `/api/v1/cron/{id}` | Görev sil |
| `POST` | `/api/v1/cron/{id}/trigger` | Hemen çalıştır |

### 🖥️ Sistem (4)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/status` | Sistem durumu |
| `GET` | `/api/v1/version` | Sürüm bilgisi |
| `GET` | `/api/v1/usage` | Kullanım istatistikleri |

---

## 🔐 Kimlik Doğrulama

API key tanımlandığında tüm isteklerde `Authorization` header'ı gerekir:

```bash
# .env dosyasına ekleyin
FETIH_API_KEY="sizin-guclu-api-keyiniz"

# İsteklerde kullanım
curl -H "Authorization: Bearer sizin-guclu-api-keyiniz" \
  http://127.0.0.1:1453/api/v1/health
```

API key tanımlanmamışsa auth'suz erişime izin verilir (development modu).

---

## 📝 Örnek Kullanımlar

### curl ile

```bash
# Health check
curl http://127.0.0.1:1453/api/v1/health

# Model değiştir
curl -X POST http://127.0.0.1:1453/api/v1/models/switch \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-opus-4-5","provider":"anthropic"}'

# Skill ara
curl "http://127.0.0.1:1453/api/v1/skills?search=malware&limit=5"

# Session oluştur ve prompt gönder
SESSION=$(curl -s -X POST http://127.0.0.1:1453/api/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{"title":"Guvenlik Analizi"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

curl -X POST http://127.0.0.1:1453/api/v1/chat \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"Loglarda anomali var mi kontrol et\",\"session_id\":\"$SESSION\"}"

# Konfigürasyon güncelle
curl -X PATCH http://127.0.0.1:1453/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{"updates":{"model":"claude-sonnet-4-6","gateway.auth.mode":"token"}}'

# Dosya yükle
curl -X POST http://127.0.0.1:1453/api/v1/files/upload \
  -F "file=@ornek_dosya.pdf"

# Cron görevi ekle (her pazartesi 09:00)
curl -X POST http://127.0.0.1:1453/api/v1/cron \
  -H "Content-Type: application/json" \
  -d '{"schedule":"0 9 * * 1","prompt":"Haftalik guvenlik raporu olustur"}'
```

### Python ile

```python
import requests

BASE = "http://127.0.0.1:1453/api/v1"

# Health check
r = requests.get(f"{BASE}/health")
print(r.json()["status"])  # "ok"

# Skill ara
r = requests.get(f"{BASE}/skills", params={"search": "XSS", "limit": 5})
for skill in r.json()["skills"]:
    print(f"  - {skill['name']} ({skill['category']})")

# Model değiştir
r = requests.post(f"{BASE}/models/switch", json={
    "model": "claude-haiku-4-5",
    "provider": "anthropic"
})
print(r.json())

# Prompt gönder (streaming)
r = requests.post(f"{BASE}/chat/stream", json={
    "message": "Python'da REST API yaz",
    "model": "claude-sonnet-4-6",
    "max_iterations": 10
}, stream=True)

for line in r.iter_lines():
    if line:
        print(line.decode())
```

### JavaScript ile

```javascript
const BASE = "http://127.0.0.1:1453/api/v1";

// Skill listesi
const skills = await fetch(`${BASE}/skills?limit=5`)
  .then(r => r.json());
console.log(`Toplam: ${skills.total} skill`);

// Session oluştur
const session = await fetch(`${BASE}/sessions`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ title: "JS Testi" })
}).then(r => r.json());
console.log(`Session: ${session.id}`);

// Prompt gönder
const response = await fetch(`${BASE}/chat`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    message: "Fibonacci dizisini hesapla",
    session_id: session.id,
    model: "claude-sonnet-4-6"
  })
}).then(r => r.json());
console.log(response.response);
```

---

## 🗂️ Dizin Yapısı

```
api/
├── __init__.py
├── server.py              # FastAPI uygulaması (ana giriş)
├── auth.py                # API key doğrulama
├── models/
│   ├── __init__.py
│   └── schemas.py         # Pydantic request/response modelleri
├── routes/
│   ├── __init__.py
│   ├── chat.py            # Chat & agent endpoint'leri
│   ├── config.py          # Konfigürasyon yönetimi
│   ├── cron_routes.py     # Zamanlanmış görevler
│   ├── deps.py            # Ortak bağımlılıklar (agent, config)
│   ├── files.py           # Dosya upload/download
│   ├── gateway.py         # Gateway yönetimi
│   ├── models.py          # Model/provider yönetimi
│   ├── plugins.py         # Plugin yönetimi
│   ├── profiles.py        # Profil yönetimi
│   ├── sessions.py        # Session CRUD
│   ├── skills.py          # Skill listeleme/arama
│   ├── system_routes.py   # Health, status, version
│   └── tools.py           # Tool yönetimi
└── README.md              # Bu dosya
```

---

## ⚙️ Environment Variables

| Değişken | Varsayılan | Açıklama |
|----------|-----------|----------|
| `FETIH_API_PORT` | `1453` | Sunucu portu |
| `FETIH_API_HOST` | `127.0.0.1` | Bind adresi |
| `FETIH_API_KEY` | *(boş)* | API key (boşsa auth'suz) |
| `FETIH_HOME` | `~/.fetih` | FETIH konfigürasyon dizini |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `DEEPSEEK_API_KEY` | — | DeepSeek API key |
| `GEMINI_API_KEY` | — | Google Gemini API key |

---

> ⚔ **FETIH AI Agent** — https://github.com/MustafaKemal0146/fetih
