# FETIH'e Katkıda Bulunma

FETIH'e katkıda bulunmak istediğin için teşekkürler! Bu rehber geliştirme ortamını kurmanı, mimariyi anlamanı ve PR'ını merge ettirmeni sağlar.

---

## Katkı Öncelikleri

Katkıları şu sırayla değerlendiriyoruz:

1. **Hata düzeltmeleri** — çökmeler, yanlış davranış, veri kaybı. Her zaman en yüksek öncelik.
2. **Platform uyumluluğu** — macOS, farklı Linux dağıtımları, WSL2. FETIH her yerde çalışmalı.
3. **Güvenlik iyileştirmeleri** — shell injection, prompt injection, path traversal, privilege escalation.
4. **Performans ve sağlamlık** — retry logic, hata yönetimi, graceful degradation.
5. **Yeni skill'ler** — yalnızca geniş kitleye yararlı olanlar.
6. **Yeni araçlar** — nadiren gerekli. Çoğu yetenek skill olarak eklenmeli.
7. **Dokümantasyon** — düzeltmeler, açıklamalar, yeni örnekler.

---

## Skill mi, Araç mı?

En sık sorulan soru budur. Cevap neredeyse her zaman **skill**'dir.

### Skill yap:
- Yetenek, talimatlar + shell komutları + mevcut araçlarla ifade edilebiliyorsa
- Harici bir CLI veya API'yi sarmalıyorsa
- Özel Python entegrasyonu gerektirmiyorsa
- Örnekler: arXiv arama, git iş akışları, Docker yönetimi, PDF işleme

### Araç yap:
- Python'da doğrudan sistem erişimi gerekiyorsa (dosya izleme, ağ soketi vb.)
- Mevcut araçları birleştirerek verimli uygulanamıyorsa
- Durum yönetimi gerektiriyorsa (örn. çalışan bir süreç takibi)

---

## Geliştirme Ortamı

```bash
git clone https://github.com/MustafaKemal0146/fetih.git
cd fetih
uv sync --extra all --extra dev
source .venv/bin/activate
fetih --version
```

### Testleri Çalıştır

```bash
pytest tests/ -q --ignore=tests/integration --ignore=tests/e2e
```

### Linting

```bash
ruff check .
ruff format .
```

---

## PR Göndermeden Önce

- [ ] Testler geçiyor (`pytest tests/ -q`)
- [ ] Lint temiz (`ruff check .`)
- [ ] Yeni özellik için test yazdın
- [ ] Commit mesajı açıklayıcı

---

## Commit Mesajı Formatı

```
tür: kısa açıklama

Uzun açıklama (gerekirse)
```

Türler: `fix`, `feat`, `docs`, `refactor`, `test`, `ci`, `chore`

Örnek: `fix: gateway telegram mesajlarında encoding hatası düzeltildi`

---

## Soru veya Sorun

[Issue aç](https://github.com/MustafaKemal0146/fetih/issues) veya [Discussion başlat](https://github.com/MustafaKemal0146/fetih/discussions).
