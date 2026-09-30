# FETİH ChatPage — Claude Tarzı Aktivite Satırı ve UX İyileştirmeleri Manuel Test Kontrol Listesi
# FETİH ChatPage — Claude-Style Activity Lines & UX Improvements Manual Test Checklist

Bu doküman, FETİH masaüstü uygulamasında (WinUI 3 / Windows App SDK) Claude tarzı düşünce/aktivite satırları, alttaki dönen "çalışıyor" göstergesi ve UX düzeltmelerinin doğrulanması için hazırlanmış 12 adımlı manuel test rehberidir.

---

## Test Ortamı Hazırlığı / Test Environment Setup

1. **Köprü Sunucusunu Başlatın (Gerçek LLM veya --fake-model) / Start Bridge Server (Real LLM or --fake-model):**
   - **Seçenek A (Deterministik Sahte Model ile - Gerçek LLM gerektirmez / With Fake Model):**
     ```powershell
     $env:FETIH_BRIDGE_TOKEN = "test_token"
     .\.venv\Scripts\python.exe -m fetih_desktop_bridge --port 8765 --token test_token --fake-model
     ```
   - **Seçenek B (Gerçek LLM / Real LLM):**
     ```powershell
     $env:FETIH_BRIDGE_TOKEN = "test_token"
     .\.venv\Scripts\python.exe -m fetih_desktop_bridge --port 8765 --token test_token
     ```

2. **FETİH Masaüstü Uygulamasını Çalıştırın / Launch FETİH Desktop App:**
   - Manuel başlatılan köprüye bağlanmak için:
     ```powershell
     $env:FETIH_BRIDGE_URL = "ws://127.0.0.1:8765"
     $env:FETIH_BRIDGE_TOKEN = "test_token"
     dotnet run --project apps/windows/Fetih.Desktop/Fetih.Desktop.csproj
     ```
   - Veya uygulamanın köprüyü sahte modelle kendi başlatması için tek satır:
     ```powershell
     $env:FETIH_FAKE_MODEL = "1"
     dotnet run --project apps/windows/Fetih.Desktop/Fetih.Desktop.csproj
     ```

---

## 12 Adımlı Test Kontrol Listesi / 12-Step Test Checklist

### 1. Düşünce Sırasında Tek Satırlık Başlık ve Akış Metni
### 1. Single-Line Header and Streaming Thought During Reasoning
- **Eylem / Action:** Sohbet kutusuna karmaşık bir soru yazın (örn. *"Masaüstünde test adında bir klasör oluştur ve içine bir index.html yaz"*).
- **Beklenen Durum / Expected State:**
  - Tek satırlık bir aktivite bloğu belirir.
  - İlk 15 karaktere kadar "Düşünülüyor…" ("Thinking…") yazar.
  - 15 karakteri aşıp ilk cümle tamamlandığında başlık tek satırlık anlamlı bir özete kilitlenir (sıçrama yapmaz).
  - Sağ tarafta canlı saniye sayacı ("X sn" / "X s") artar.
- **Ekran Görüntüsü / Screenshot:** Düşünce akışı devam ederken başlık ve sayaç görünümü.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 2. Araç Çalışırken Gösterim
### 2. Running Tool Indication
- **Eylem / Action:** Model bir araç (tool) çağırdığında (örn. `terminal`, `write_file`).
- **Beklenen Durum / Expected State:**
  - Aktivite başlığı "Komut çalıştırılıyor (terminal)…" ("Running terminal…") şeklinde güncellenir.
  - Süre sayacı çalışmaya devam eder.
- **Ekran Görüntüsü / Screenshot:** Araç çalıştırma anındaki aktivite satırı.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 3. Düşünce Bitip Yanıt Başladığında Grubun Kapanması
### 3. Activity Group Completion & Chevron State on Final Response
- **Eylem / Action:** Düşünce ve araç çağrıları tamamlanıp asıl ajan yanıtı (markdown baloncuğu) akmaya başladığında.
- **Beklenen Durum / Expected State:**
  - Aktivite bloğunun solunda yeşil onay ikonu (`Segoe Fluent Icons` checkmark) belirir.
  - Özet metni formatlanır: `[Etiket] · [X işlem] · [Y sn]` (araç yoksa yalnızca `[Etiket] · [Y sn]`).
  - Chevron simgesi sağa bakar (`>`).
  - Düşünce bloğu varsayılan olarak kapalıdır; ajan metni altında temiz bir balon olarak belirir.
- **Ekran Görüntüsü / Screenshot:** Tamamlanmış özet satırı ve altındaki ajan yanıtı.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 4. Satıra Tıklayarak Düşünce Geçmişini Açma
### 4. Click to Expand Activity Details
- **Eylem / Action:** Tamamlanmış veya sürmekte olan aktivite satırının herhangi bir yerine tıklayın.
- **Beklenen Durum / Expected State:**
  - Chevron 90 derece dönerek aşağı bakar (`v`).
  - Satırın hemen altında solunda 2px dikey çizgi olan genişletilmiş bölüm açılır.
  - İçeride tam düşünce metni ve çalıştırılan araç kartları (girdileri ve çıktıları) sıralanır.
  - Maksimum yükseklik 320px ile sınırlıdır; uzun düşüncelerde dikey kaydırma çubuğu belirir.
  - Fare tekerleği iç kaydırma bittiğinde üst sayfayı kaydırmaya devam eder.
- **Ekran Görüntüsü / Screenshot:** Açık durumdaki düşünce geçmişi ve 2px sol çizgi.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 5. Satıra Tekrar Tıklayarak Kapatma
### 5. Click Again to Collapse
- **Eylem / Action:** Genişletilmiş durumdaki aktivite başlık satırına tekrar tıklayın.
- **Beklenen Durum / Expected State:**
  - Bölüm pürüzsüzce kapanır, chevron tekrar sağa (`>`) döner.
  - Kullanıcı manuel açtıktan sonra bir sonraki akış başladığında satır kendiliğinden kapanmaz (kullanıcı kontrolü korunur).
- **Ekran Görüntüsü / Screenshot:** Tekrar kapatılmış satır görünümü.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 6. Alttaki "Çalışıyor" Göstergesi
### 6. Bottom Rotating Working Indicator
- **Eylem / Action:** Kullanıcı mesaj gönderir ve yanıt beklenir.
- **Beklenen Durum / Expected State:**
  - Sohbet listesinin en altında, mesaj balonlarının dışında sol hizalı (ajan mesajı girintisiyle uyumlu `Margin="30,8,0,16"`) dönen bir gösterge ve yanında "Çalışıyor…" ("Working…") metni belirir.
  - Mesajlar koleksiyonuna sahte mesaj eklenmez; `Messages.Count` değişmez.
  - Ajan yanıtı tamamlandığında gösterge yumuşakça durur ve 150 ms debounce sonrası görünmez olur (`Visibility = Collapsed`).
- **Ekran Görüntüsü / Screenshot:** Yanıt üretilirken en altta görünen dönen gösterge.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 7. Durdur Butonuna Basıldığında Akışın Durması
### 7. Cancel / Stop Button Behavior
- **Eylem / Action:** Model düşünürken veya araç çalıştırırken sağ alttaki kırmızı kare "Durdur" butonuna tıklayın.
- **Beklenen Durum / Expected State:**
  - Akış anında kesilir.
  - Dönen alttaki gösterge kaybolur.
  - Aktivite özetine "durduruldu" ("stopped") rozeti eklenir (örn: `Talebi inceliyor · 1 işlem · durduruldu · 8 sn`).
  - Aktivite başlığındaki durum glifi durdurulma sembolüne (`\uE71A`) dönüşür.
  - Gönder butonu tekrar aktif olur.
- **Ekran Görüntüsü / Screenshot:** Durdurulan aktivite grubu ve aktif gönder butonu.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 8. Hata Durumunda Gösterim
### 8. Tool Error Indication
- **Eylem / Action:** Hata veren bir işlem tetikleyin (örn. var olmayan bir komut veya reddedilen yetki).
- **Beklenen Durum / Expected State:**
  - Aktivite başlığı sarı/kırmızı uyarı glifine (`\uE7BA`) dönüşür.
  - Özet metninde hata adedi belirtilir: `[Etiket] · [X işlem] · 1 hata · [Y sn]` ("1 error").
- **Ekran Görüntüsü / Screenshot:** Hata durumunu gösteren özet satırı.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 9. Çoklu Araç Çağrılarında Sayaç Doğrulaması
### 9. Multiple Tools Counter Verification
- **Eylem / Action:** Modelin art arda birden fazla araç çağırmasını sağlayın (örn. 3 dosya okuma ve 1 komut çalıştırma).
- **Beklenen Durum / Expected State:**
  - Tüm araçlar tek bir aktivite bloğu içinde toplanır.
  - Özet satırında "4 işlem" ("4 actions") ifadesi doğru adetle gösterilir.
- **Ekran Görüntüsü / Screenshot:** Çoklu işlem sayacını içeren özet satırı.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 10. Geçmiş Oturum Yüklendiğinde Süre Tutarlılığı
### 10. Legacy & Saved Session Loading Consistency
- **Eylem / Action:** Sol menüdeki sohbet geçmişinden önce eski bir oturumu, ardından yeni kaydedilmiş bir oturumu seçin.
- **Beklenen Durum / Expected State:**
  - Eski kayıtlı oturumlarda süre bilgisi (`duration_ms`) yoksa başlıkta "0 sn" gösterilmez; doğrudan `[Etiket] · [X işlem]` şeklinde temiz görünür.
  - Yeni sistemle kaydedilmiş oturumlarda süre doğru bir şekilde yüklenir (`12 sn`, `1 dk 5 sn` vb.).
- **Ekran Görüntüsü / Screenshot:** Yüklenen geçmiş oturumdaki aktivite satırları.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 11. Ctrl+N ile Yeni Sohbet Açıldığında Kısayol Tooltip'i
### 11. Ctrl+N Accelerator Tooltip Clearance
- **Eylem / Action:** Klavye kısayoluyla `Ctrl + N` tuşlarına basın.
- **Beklenen Durum / Expected State:**
  - Yeni boş sohbet açılır.
  - Gönder butonunun üzerinde veya ekranın herhangi bir yerinde asılı kalan "Ctrl+N" tooltip'i görünmez (`KeyboardAcceleratorPlacementMode="Hidden"` devrededir).
- **Ekran Görüntüsü / Screenshot:** Yeni açılan sohbet ve temiz giriş alanı.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

### 12. Dil Değiştirildiğinde (TR <-> EN) Anında Güncelleme
### 12. Instant Language Switch (TR <-> EN)
- **Eylem / Action:** Sol alttaki Ayarlar (Settings) menüsünden dili Türkçe'den İngilizce'ye ve tekrar Türkçe'ye değiştirin.
- **Beklenen Durum / Expected State:**
  - Durum çubuğunda "Connected Connected" gibi çift metin kalmaz.
  - Giriş kutusu yerelleştirme metni eksiksizdir (`chat.prompt_placeholder` anahtarı yerine doğru metin görünür).
  - Aktivite başlıkları ve birimleri anında dile uyarlanır (`sn` <-> `s`, `işlem` <-> `actions`, `hata` <-> `error`, `durduruldu` <-> `stopped`).
- **Ekran Görüntüsü / Screenshot:** İngilizce ve Türkçe arayüzdeki aktivite ve durum çubuğu görünümleri.
- [ ] Başarılı / Passed | [ ] Başarısız / Failed

---

## Test Sonucu Özeti / Test Result Summary

| Toplam Test / Total Tests | Başarılı / Passed | Başarısız / Failed | Notlar / Notes |
|:---:|:---:|:---:|:---|
| 12 | [ ] | [ ] | |

**Testi Gerçekleştiren / Tester:**  
**Tarih / Date:**  
