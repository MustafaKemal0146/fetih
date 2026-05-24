# FETIH Güvenlik Politikası

Bu belge FETIH'in güven modelini, güvenlik sınırlarını ve zafiyet bildirimi sürecini tanımlar.

---

## 1. Zafiyet Bildirimi

Güvenlik açıklarını **kamuya açık issue olarak açma.** Bunun yerine özel olarak bildir:

- [GitHub Security Advisories](https://github.com/MustafaKemal0146/fetih/security/advisories/new) üzerinden özel bildiri

**FETIH bir bug bounty programı yürütmemektedir.**

### İyi bir rapor şunları içerir:

- Kısa açıklama ve ciddiyet değerlendirmesi
- Etkilenen bileşen (dosya yolu ve satır aralığı, örn. `tools/bash_tool.py:45-60`)
- Ortam bilgisi (`fetih --version`, commit SHA, işletim sistemi, Python versiyonu)
- `main` branch veya son sürümde üretilebilir adımlar

---

## 2. Kapsam

### Kapsam dahilinde:

- **Shell komut enjeksiyonu** — kullanıcı girdisinin kabuk komutlarına enjekte edilmesi
- **Prompt enjeksiyonu** — harici içeriğin ajan davranışını değiştirmesi
- **Path traversal** — izin verilmeyen dosyalara erişim
- **Kimlik bilgisi sızıntısı** — API anahtarları veya token'ların açığa çıkması
- **Gateway güvenliği** — yetkisiz kullanıcıların bot komutlarına erişmesi

### Kapsam dışı:

- Kötü niyetli bir AI modeli çıktısından kaynaklanan sorunlar
- Kullanıcının kendi sistematik araçlar ile kendi sistemine verdiği zarar
- Sosyal mühendislik saldırıları

---

## 3. Güvenlik Modeli

FETIH yerel çalışan bir araçtır. Temel güven sınırı şudur:

> **Güvenilmeyen içerik (web sayfaları, dosyalar, API yanıtları) ajan talimatlarını değiştirmemeli.**

Araçlar kullanıcı adına çalışır — izinler kullanıcı tarafından `fetih config` ile yapılandırılır.

---

## 4. Desteklenen Sürümler

| Sürüm | Destek |
|-------|--------|
| Son sürüm (PyPI) | Aktif |
| Eski sürümler | Yalnızca kritik düzeltmeler |

---

## 5. Açıklama Süreci

1. Özel bildirim al
2. 7 gün içinde yanıt ver
3. Düzeltme geliştir ve test et
4. Yamayı yayımla
5. Bildirici ile koordineli olarak kamuoyuna duyur

Katkın için teşekkürler.
