# Kod Kalitesi Denetimi — cli.py, commands.py, run_agent.py, prompt_builder.py

> Tarih: 2026-05-29 · Kapsam: dead code, kullanılmayan import, hata handling,
> komut alias çakışmaları, prompt format tutarlılığı. **Breaking change yok.**

## Özet

Dört hedef dosya (toplam ~22K satır) tarandı. **Kritik kusur bulunmadı.** Kod
tabanı genel olarak iyi yapılandırılmış; "sessiz" exception handler'ların çoğu
bilinçli, belgelenmiş fallback desenleri. Aşağıda bulgular ve bu PR'da uygulanan
düşük riskli düzeltmeler listelenmiştir.

---

## 1. `cli.py` (~14.6K satır)

| Bulgu | Durum |
|-------|-------|
| Kullanılmayan top-level import | **Bulunamadı** |
| Dead code / çağrılmayan fonksiyon | **Bulunamadı** |
| Yinelenen `def` adı (shadowing) | **Bulunamadı** |
| Bare `except:` (tipsiz) | **Bulunamadı** — hepsi `except Exception:` |
| `except Exception: pass` desenleri | Bilinçli defensive fallback'ler (örn. bootstrap import, opsiyonel display özellikleri). Davranış doğru — **aksiyon yok** |

**Sonuç:** Aksiyon gerekmiyor.

## 2. `fetih_cli/commands.py` (~1.8K satır)

- 76 `CommandDef` kaydı ve 40+ alias tarandı.
- **Yinelenen alias yok, çakışan alias→komut eşlemesi yok, kayıtsız referans
  verilen komut yok.** (örn. `reset→new`, `fork→branch`, `bg`/`btw`→`background`
  benzersiz eşleniyor.)

**Sonuç:** Temiz, aksiyon gerekmiyor.

## 3. `run_agent.py` (~4.1K satır)

Hata handling'in çoğu bilinçli ("best-effort" temizlik) ve belgeli. En zor
debug edilebilir nokta: çocuk-süreç/kaynak temizliği kademeli `except: pass`
blokları (`_evict_*` ve `close()`) — başarısızlık zinciri kayboluyordu.

**Bu PR'da uygulanan (güvenli, davranış değiştirmeyen):**
- `release_clients`/cache-evict ve `close()` içindeki tüm sessiz temizlik
  handler'larına `logger.debug(...)` eklendi. Davranış aynı (hatalar yine
  yutuluyor), ama artık DEBUG seviyesinde izlenebilir.

**Rapor (değiştirilmedi):** rate-limit header parse, config yükleyiciler,
memory provider shutdown gibi diğer `except: pass` noktaları docstring'lerinde
"strictly best-effort" olarak belgeli; instrumentation eklenebilir ama
zorunlu değil.

## 4. `agent/prompt_builder.py` (~1.5K satır)

- **Bulgu (~1255):** `<available_skills>` bloğunda implicit string birleştirme
  ile `+` operatörü karışık kullanılıyor:
  ```python
  "<available_skills>\n"
  + "\n".join(index_lines) + "\n"
  "</available_skills>\n"
  ```
- **Durum: SADECE RAPOR — değiştirilmedi.** Çalışıyor ve doğru. Yeniden
  biçimlendirme, üretilen prompt metnini değiştirme riski taşır (model
  davranışını etkileyebilir) → breaking-change politikası gereği dokunulmadı.
- Yinelenen fonksiyon tanımı, bare except veya TODO/FIXME bulunmadı.

---

## Ek gözlem: ruff PLW1514 (repo geneli)

Repo'nun bloklayan lint kuralı `PLW1514` (encoding'siz `open()`). Bu denetim
sırasında `main`'de **10** pre-existing ihlal tespit edildi (`api/`,
`fetih_cli/tool_installer.py`). Bunların `api/routes/` altındaki 5 tanesi ilgili
API PR'ında giderildi; kalanlar ayrı bir temizlikte ele alınabilir.

## Doğrulama

- `python -m py_compile run_agent.py` → OK
- `ruff check run_agent.py` → yeni sorun yok
- `python -c "import run_agent"` → OK
