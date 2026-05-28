# CTF Hint Seviyeleri Detaylı Rehberi

## Level 1: Nudge (Genel Yönlendirme)

**Amaç:** Kullanıcıya challenge'ın doğasını anlatmak ama çözümü kendisinin bulmasını sağlamak.

**Ne zaman verilir:** `/hint` komutuyla.

**İçerik:**
- Challenge kategorisi
- Genel yaklaşım stratejisi
- Hangi tür zafiyet/teknik aranmalı
- İlk bakılacak yer

**Yasaklar:**
- Spesifik komutlar
- Kesin çözüm adımları
- Tool isimleri

## Level 2: Direction (Teknik Yön)

**Amaç:** Kullanıcıya hangi spesifik tekniği/aracı kullanacağını söylemek.

**Ne zaman verilir:** `/hint more` komutuyla.

**İçerik:**
- Kullanılacak tool
- Denenecek payload/teknik
- Analiz edilecek spesifik alan
- Beklenen davranış

**Yasaklar:**
- Tam komut satırı (kısaltılmış olabilir)
- Flag konumu
- Final çözüm

## Level 3: Solution (Çözüm Yolu)

**Amaç:** Tam çözüm yolunu adım adım anlatmak.

**Ne zaman verilir:** `/hint solution` komutuyla.

**İçerik:**
- Adım adım çözüm
- Komutlar (tam veya parametreleri maskelenmiş)
- Beklenen çıktılar
- Flag formatı

**Yasaklar:**
- Flag'in kendisi (asla!)
- Sadece flag'i yazıp geçmek

## Kategori Bazlı İpucu Şablonları

### Web
- Level 1: "Bu bir [XSS/SQLi/CSRF/SSRF/LFI/...] challenge'ı. [Input/Header/Cookie] alanlarına odaklan."
- Level 2: "[Parametre] alanına [payload] dene. [Tool] ile test edebilirsin."
- Level 3: "[Tool] kullanarak [spesifik komut]. Sonuçta [beklenen çıktı] görmelisin."

### Reverse Engineering
- Level 1: "Binary [stripped/packed/obfuscated]. [Ghidra/IDA/x64dbg] ile analiz et."
- Level 2: "[Fonksiyon adı] fonksiyonuna bak. [Register/değişken] önemli."
- Level 3: "[Adresteki] check'i patch'le/NOP'la. Alternatif olarak [çözüm yolu]."

### Cryptography
- Level 1: "[Base64/Hex/XOR/AES/RSA] kullanılmış olabilir. Şifreli metnin yapısını analiz et."
- Level 2: "Anahtar uzunluğu [N] byte. [Tool] ile brute-force/frekans analizi yap."
- Level 3: "Anahtar [değer]. [Tool] ile: `[komut]`. Çıktıda flag formatını ara."

### Forensics
- Level 1: "Dosya [PCAP/image/memory dump/disk image]. [Wireshark/Volatility/Autopsy] ile incele."
- Level 2: "[Protokol/offset/timeline] bölgesine odaklan. Şüpheli [paket/process/dosya] var."
- Level 3: "[Spesifik konum]'daki veriyi [tool] ile extract et: `[komut]`"

### Pwn/Binary Exploitation
- Level 1: "Buffer overflow var. [checksec] ile korumaları kontrol et."
- Level 2: "Offset [N]'de EIP/RIP kontrolü var. [ROPgadget/one_gadget] ile gadget ara."
- Level 3: "Exploit: `[pwntools script özeti]`. Remote: `[connect komutu]`"

## Yaygın Tuzaklar ve Kör Noktalar

1. **Overthinking:** Bazen çözüm sandığından basittir. Temel kontrolleri atlama.
2. **Tool fixation:** Tek bir tool'a takılıp kalma. Aynı işi yapan alternatif tool'lar var.
3. **Category bias:** Web sandığın şey crypto olabilir. Challenge'ı yeniden sınıflandırmayı dene.
4. **Hint ignorance:** Challenge açıklamasındaki ipuçlarını gözden kaçırma.
5. **Encoding layers:** Birden fazla encoding katmanı olabilir (base64 → hex → rot13).
6. **Steganography blindness:** Görüntü/dosya içinde gizli veri olabilir. Her zaman strings/hexdump yap.
