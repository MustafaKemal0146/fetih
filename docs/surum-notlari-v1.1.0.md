## 🪟 FETIH v1.1.0 — Windows Masaüstü Uygulaması (Deneysel)

Bu sürümün ana yeniliği: **FETIH artık bir Windows masaüstü uygulaması olarak da geliyor.** Terminale bağlı kalmadan, çift tıklamayla açılan native bir pencere.

> ⚠️ **Deneysel / test modu.** Masaüstü uygulaması **erken erişim** aşamasındadır. Günlük kullanım için birincil arayüz hâlâ CLI'dır. Masaüstü uygulamasını denemeni istiyoruz, ama kararsızlıkları normal karşıla — ve lütfen bize bildir.

### 🪟 Windows Masaüstü Uygulaması

- **Native WinUI 3 penceresi** — .NET 10 üzerinde, kendi kendine yeten paketleme
- **Taşınabilir sürüm:** `dist\win-x64\fetih.cmd` — Python kurulu olmayan makinede de çalışır
- **Kurulum paketi:** Inno Setup ile `Fetih-Setup-1.1.0-win-x64.exe`
- Sohbet arayüzü, oturum listesi, model seçimi ve araç çağrısı görünümü
- Uygulama kapanırken arka planda yetim süreç bırakmaz (Job Object ile süreç ağacı takibi)

### 🧪 Bu Sürümde Bilinenler

Deneysel olduğu için bazı şeyler pürüzlü olabilir:

- Uzun oturumlarda arayüz yavaşlayabilir
- Bazı slash komutları masaüstünde henüz karşılıksız
- Pencere yeniden boyutlandırmada yerleşim ara sıra bozulabilir
- Windows dışı platformlarda masaüstü uygulaması **yok** (şimdilik yalnızca Windows)

**Bir sorunla karşılaşırsan:** [issue aç](https://github.com/MustafaKemal0146/fetih/issues/new). Yanına şunları eklersen çok daha hızlı bakarız:
- Windows sürümü
- Ne yaptığın ve ne olmasını beklediğin
- Hata çıktısı / ekran görüntüsü
- Mümkünse `%LOCALAPPDATA%\Fetih\logs` altındaki günlükler

### 🧩 TUI Ağ Geçidi

- **`tui_gateway` modülü eklendi** — stdio üzerinden satır ayrımlı JSON-RPC konuşan oturum köprüsü. Masaüstü uygulaması bu köprüyü kullanıyor.
- Tamamlama (`complete.slash`, `complete.path`), oturum yaşam döngüsü, yapılandırma ve model metotları
- Bu modül eksik olduğu için daha önce toplanamayan testler artık çalışıyor

### 🔒 Lisans

- **Lisans GPL-3.0-only olarak netleştirildi.** Depodaki tüm sürüm bildirimleri (`pyproject.toml`, ACP registry manifesti, REST API) artık aynı lisansı gösteriyor.
- Kısaca: kaynağı inceleyebilir, değiştirebilir, dağıtabilirsin. Değiştirilmiş bir sürümü dağıtırsan kaynak kodu da aynı lisansla paylaşmak zorundasın. Yalnızca kendin/kuruluşun içinde kullanırsan kaynak açma yükümlülüğü doğmaz.

### 🔧 Düzeltmeler

- **Taşınabilir sürüm açılışta çöküyordu** — `dotnet publish` XAML/PRI kaynak paketlemesini atlıyordu, uygulama "Cannot locate resource" ile kapanıyordu. Düzeltildi.
- Masaüstü köprüsü kapanışta yetim süreç bırakıyordu, giderildi.

### 📦 Kurulum

**Masaüstü uygulaması (Windows):**

```
Releases sayfasından Fetih-Setup-1.1.0-win-x64.exe indir ve çalıştır
```

Taşınabilir sürüm istiyorsan kurulum gerekmez — arşivi açıp `fetih.cmd` dosyasına çift tıkla.

**CLI:**

```bash
pip install --upgrade fetih-agent
# veya
git pull && pip install -e .
```

### 🔗 Bağlantılar

- Landing: https://mustafakemal0146.github.io/fetih/
- Karşılaştır: https://github.com/MustafaKemal0146/fetih/compare/v1.0.2...v1.1.0
- Sorun bildir: https://github.com/MustafaKemal0146/fetih/issues
- Lisans: GPL-3.0

---

**Özetle:** Masaüstü uygulaması geldi ama deneysel. CLI yerini koruyor. Dene, kır, bize söyle.
