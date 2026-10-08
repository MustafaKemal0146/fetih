# FETİH Masaüstü v1.3.0

Bu sürüm masaüstü uygulamasını güvenlik, kararlılık, performans ve görünüm
açısından baştan sağlamlaştırır.

## 🔒 Güvenlik
- **Komut onay akışı:** Ajanın çalıştıracağı tehlikeli komutlar artık sohbette
  **izin kartı** olarak çıkıyor — *bir kez / bu oturum / her zaman / reddet*.
  Bir siber güvenlik aracı için çekirdek özellik.
- **Güncelleme doğrulaması:** İndirilen güncelleme SHA-256 ile doğrulanıyor;
  eşleşmezse iptal.
- **Gizli bilgi redaksiyonu:** Loglarda ve destek raporlarında token/anahtar
  gibi veriler maskeleniyor.

## ✨ Yenilikler
- **Otomatik sohbet başlıkları:** İlk mesajdan sonra kısa, anlamlı başlık
  üretiliyor.
- **Yenilenmiş cevap görünümü:** Asistan yanıtları avatar + saydam geniş kart
  düzeninde.
- **Yapısal uygulama günlüğü:** Döngüsel, gizli-bilgi maskeli; tanılama
  paketine dahil.
- **Ctrl+Enter ile gönder** (Enter = gönder, Shift+Enter = yeni satır).

## ⚡ Performans
- **Soğuk başlangıç hızlandırıldı:** İlk mesajın uzun bekleme süresi, açılışta
  arka plan ısıtmasıyla büyük ölçüde giderildi.
- **Akış titremesi giderildi:** Yazı akarken ekranın "yenilenme" hissi kayboldu.
- **Otomatik yeniden bağlanma:** Köprü koparsa üstel beklemeyle kendi kendine
  bağlanır.
- **Uzun sohbetler:** Transkript tavanı + SQLite WAL ile daha akıcı.

## 🐛 Düzeltmeler
- **Türkçe karakter bozulması** (ş/ğ/İ, emoji) giderildi.
- **"Durdur" düğmesi** artık turu gerçekten durduruyor.
- **Sayfa geçişinde sohbetin sıfırlanması** düzeldi.
- **Hayalet Python süreçleri** kalmıyor; ikinci açılışta artıklar temizleniyor.
- **Skill sayısı** sorusu yanıtlanabiliyor (ajan kendi yeteneklerini sayabiliyor).

## 🧰 Altyapı
- Masaüstü için PR'da derleme + test çalıştıran CI; kurulumda tek-çalışma kilidi.

---

Kurulum: GitHub Releases'teki installer (`.exe`) ya da taşınabilir zip. İmzasız
olduğundan ilk açılışta SmartScreen uyarısı çıkabilir (Daha fazla bilgi → Yine
de çalıştır).
