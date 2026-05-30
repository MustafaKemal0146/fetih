"""Oturum başlangıcında gösterilen rastgele ipuçları."""

import random


TIPS = [
    # --- Slash Komutları ---
    "/background <mesaj> (takma adı /bg veya /btw) görevi ayrı oturumda çalıştırır, mevcut oturum serbest kalır.",
    "/branch mevcut oturumu çatallayarak ilerlemeyi kaybetmeden farklı bir yön denenmesini sağlar.",
    "/compress sohbet bağlamını manuel olarak sıkıştırır.",
    "/rollback dosya sistemi kontrol noktalarını listeler; ajanın değiştirdiği dosyaları önceki haline getirir.",
    "/rollback diff 2, 2. kontrol noktasından bu yana yapılan değişiklikleri geri yüklemeden önizler.",
    "/rollback 2 src/dosya.py, belirli bir kontrol noktasından tek dosyayı geri yükler.",
    "/title \"projem\" oturumuna isim verir; daha sonra /resume veya fetih -c ile devam edilebilir.",
    "/resume önceden adlandırılmış bir oturumu kaldığı yerden devam ettirir.",
    "/queue <mesaj> mevcut turu kesmeden bir sonraki tura mesaj kuyruğa alır.",
    "/undo konuşmadan son kullanıcı/asistan alışverişini kaldırır.",
    "/retry son mesajı yeniden gönderir; ajanın cevabı yeterince iyi olmadığında kullanışlıdır.",
    "/verbose araç ilerleme gösterimini döngüsel değiştirir: kapalı → yeni → tümü → ayrıntılı.",
    "/reasoning high modelin düşünme derinliğini artırır. /reasoning show muhakemeyi görüntüler.",
    "/fast öncelikli işlemeyi açıp kapatır, daha hızlı API yanıtları sağlar (sağlayıcıya bağlı).",
    "/yolo oturumun geri kalanı için tüm tehlikeli komut onay istemlerini atlar.",
    "/model oturum ortasında model değiştirmeyi sağlar; /model sonnet veya /model gpt-5 dene.",
    "/model --global varsayılan modeli kalıcı olarak değiştirir.",
    "/personality pirate eğlenceli bir kişilik ayarlar; kawaii'den shakespeare'e 14 yerleşik seçenek var.",
    "/theme veya /skin CLI temasını değiştirir; red, green, gold veya heaven dene.",
    "/statusbar model, token, bağlam doluluk %, maliyet ve süreyi gösteren kalıcı çubuğu açıp kapatır.",
    "/tools disable browser mevcut oturum için tarayıcı araçlarını geçici kaldırır.",
    "/browser connect tarayıcı araçlarını çalışan Chrome örneğine CDP ile bağlar.",
    "/plugins yüklü eklentileri ve durumlarını listeler.",
    "/cron zamanlanmış görevleri yönetir; herhangi bir platforma tekrarlayan mesajlar kurulabilir.",
    "/reload-mcp yeniden başlatmadan MCP sunucu yapılandırmasını yeniden yükler.",
    "/usage token kullanımını, maliyet dökümünü ve oturum süresini gösterir.",
    "/insights son 30 günün kullanım analizlerini gösterir.",
    "/paste panosunu görüntü için kontrol eder ve bir sonraki mesaja ekler.",
    "/profile hangi profilin etkin olduğunu ve ana dizinini gösterir.",
    "/config mevcut yapılandırmayı bir bakışta gösterir.",
    "/stop ajan tarafından başlatılan tüm çalışan arka plan süreçlerini sonlandırır.",

    # --- @ Bağlam Referansları ---
    "@file:yol/dosya.py dosya içeriğini doğrudan mesajına ekler.",
    "@file:main.py:10-50 yalnızca 10-50. satırları ekler.",
    "@folder:src/ dizin ağaç listesini ekler.",
    "@diff hazırlanmamış git değişikliklerini mesaja ekler.",
    "@staged hazırlanmış git değişikliklerini (git diff --staged) ekler.",
    "@git:5 tam yamalarıyla birlikte son 5 commit'i ekler.",
    "@url:https://example.com bir web sayfasının içeriğini çekip ekler.",
    "@ yazmak dosya sistemi yolu tamamlamayı tetikler; herhangi bir dosyaya etkileşimli gidilebilir.",
    "Birden fazla referansı birleştir: \"@file:main.py ve @file:test.py tutarlılık için incele.\"",

    # --- Kısayol Tuşları ---
    "Alt+Enter çok satırlı giriş için satır sonu ekler. (Windows Terminal Alt+Enter'ı yakalar; Ctrl+Enter kullan.)",
    "Ctrl+C ajanı keser. 2 saniye içinde çift bas ve zorla çık.",
    "Ctrl+Z FETIH'i arka plana askıya alır; devam ettirmek için terminalde fg çalıştır.",
    "Tab otomatik öneri metnini kabul eder veya slash komutlarını otomatik tamamlar.",
    "Ajan çalışırken yeni mesaj yazarak kesintiye uğrat ve yönlendir.",
    "Alt+V panodan bir görüntüyü konuşmaya yapıştırır.",
    "5+ satır yapıştırmak otomatik olarak dosyaya kaydeder ve yerine kompakt referans ekler.",

    # --- CLI Bayrakları ---
    "fetih -c en son CLI oturumunu devam ettirir. fetih -c \"proje adı\" başlığa göre devam ettirir.",
    "fetih -w izole bir git çalışma ağacı oluşturur; paralel ajan iş akışları için mükemmel.",
    "fetih -w -q \"#42 sorununu düzelt\" çalışma ağacı izolasyonunu tek seferlik sorgu ile birleştirir.",
    "fetih chat -t web,terminal odaklanmış bir oturum için yalnızca belirli araç setlerini etkinleştirir.",
    "fetih chat -s github-pr-workflow başlatmada bir yetenek önceden yükler.",
    "fetih chat -q \"sorgu\" tek etkileşimsiz sorgu çalıştırıp çıkar.",
    "fetih chat --max-turns 200 tur başına varsayılan 90 yineleme sınırını geçersiz kılar.",
    "fetih chat --checkpoints her yıkıcı dosya değişikliğinden önce dosya sistemi anlık görüntülerini etkinleştirir.",
    "fetih --yolo tüm oturum için tüm tehlikeli komut onay istemlerini atlar.",
    "fetih chat --source telegram oturumu fetih sessions listesinde filtrelemek için etiketler.",
    "fetih -p work chat varsayılanı değiştirmeden belirli bir profil altında çalışır.",

    # --- CLI Alt Komutları ---
    "fetih doctor --fix yapılandırma ve bağımlılık sorunlarını teşhis eder ve otomatik onarır.",
    "fetih dump kompakt bir kurulum özeti çıkarır; hata raporları için harika.",
    "fetih config set ANAHTAR DEĞER sırları .env'e ve geri kalanını config.yaml'a otomatik yönlendirir.",
    "fetih config edit, config.yaml'ı varsayılan düzenleyicide açar.",
    "fetih config check eksik veya eski yapılandırma seçeneklerini tarar.",
    "fetih sessions browse arama özellikli etkileşimli oturum seçici açar.",
    "fetih sessions stats platforma ve veritabanı boyutuna göre oturum sayılarını gösterir.",
    "fetih sessions prune --older-than 30 eski oturumları temizler.",
    "fetih skills search react --source skills-sh, skills.sh genel dizininde arar.",
    "fetih skills check yüklü hub yeteneklerini güncel güncellemeler için tarar.",
    "fetih skills tap add kuruluşum/skills-repo özel bir GitHub yetenek kaynağı ekler.",
    "fetih skills snapshot export setup.json yetenek yapılandırmanı yedekleme için dışa aktarır.",
    "fetih mcp add github --command npx komut satırından MCP sunucuları ekler.",
    "fetih mcp serve, FETIH'i diğer ajanlar için MCP sunucusu olarak çalıştırır.",
    "fetih auth add kimlik havuzu rotasyonu için birden fazla API anahtarı eklemeyi sağlar.",
    "fetih completion bash >> ~/.bashrc tüm komutlar için sekme tamamlamayı etkinleştirir.",
    "fetih logs -f agent.log'u gerçek zamanlı takip eder. --level WARNING --since 1h çıktıyı filtreler.",
    "fetih backup tüm FETIH ana dizininin zip yedeğini oluşturur.",
    "fetih profile create coder kendi komutu haline gelen izole bir profil oluşturur.",
    "fetih profile create work --clone mevcut yapılandırma ve anahtarlarını yeni profile kopyalar.",
    "fetih update yeni paket yetenekleri TÜM profillere otomatik olarak eşitler.",
    "fetih gateway install FETIH'i sistem servisi olarak kurar (systemd/launchd).",
    "fetih memory setup harici bellek sağlayıcısı yapılandırmayı sağlar (Honcho, Mem0 vb.).",
    "fetih webhook subscribe HMAC doğrulamalı olay güdümlü webhook rotaları oluşturur.",
    "Tasarruf et: fetih tools kullanılmayan araçları devre dışı bırakır, fetih skills config yetenekleri kısaltır.",
    "/reasoning low veya /reasoning minimal düşünme derinliğini varsayılanın altına indirir; daha hızlı, ucuz yanıtlar.",
    "fetih models görüntü ve sıkıştırma görevlerini daha ucuz modellere yönlendirir; token maliyetini %85+ azaltır.",

    # --- Yapılandırma ---
    "config.yaml'da display.bell_on_complete: true ayarla; uzun görevler bittiğinde zil sesi duyulur.",
    "display.streaming: true ayarla; model oluştururken token'lar gerçek zamanlı görünür.",
    "display.show_reasoning: true ayarla; modelin düşünce zinciri muhakemesi izlenir.",
    "display.compact: true ayarla; çıktıda boşluk azaltılır, daha yoğun bilgi alınır.",
    "display.busy_input_mode: queue ayarla, mesajları kesmek yerine kuyruğa al; veya /steer ile enjekte et.",
    "display.resume_display: minimal ayarla; oturum devam ettirmede tam konuşma özetini atla.",
    "compression.threshold: 0.50 ayarla; otomatik sıkıştırmanın ne zaman tetikleneceğini kontrol et.",
    "agent.max_turns: 200 ayarla; ajan tur başına daha fazla araç çağrısı adımı atabilir.",
    "file_read_max_chars: 200000 ayarla; read_file çağrısı başına maksimum içeriği artır.",
    "approvals.mode: smart ayarla; LLM güvenli komutları otomatik onaylar, tehlikelileri reddeder.",
    "config.yaml'da fallback_model ayarla; yedek sağlayıcıya otomatik geçiş yapılır.",
    "privacy.redact_pii: true ayarla; LLM'e göndermeden önce kullanıcı ID'leri hashlenir.",
    "browser.record_sessions: true ayarla; tarayıcı oturumları WebM video olarak otomatik kaydedilir.",
    "config.yaml'da worktree: true ayarla; her zaman git çalışma ağacı oluşturulur (fetih -w ile aynı).",
    "security.website_blocklist.enabled: true ayarla; belirli alan adları web araçlarından engellenir.",
    "cron.wrap_response: false ayarla; ham ajan çıktısı cron başlık/altbilgi olmadan teslim edilir.",
    "FETIH_TIMEZONE, sunucu saat dilimini herhangi bir IANA saat dilimi dizesiyle geçersiz kılar.",
    "config.yaml'da ortam değişkeni ikamesi çalışır: ${DEĞİŞKEN_ADI} sözdizimini kullan.",
    "config.yaml'daki hızlı komutlar, sıfır token kullanımıyla anında kabuk komutları çalıştırır.",
    "Özel kişilikler config.yaml'da agent.personalities altında tanımlanabilir.",
    "provider_routing, OpenRouter sağlayıcı sıralamasını, beyaz ve kara listeyi kontrol eder.",

    # --- Araçlar & Yetenekler ---
    "execute_code, FETIH araçlarını programatik olarak çağıran Python betikleri çalıştırır; sonuçlar bağlam dışında.",
    "delegate_task varsayılan olarak 3'e kadar eşzamanlı alt ajan başlatır (delegation.max_concurrent_children).",
    "web_extract PDF URL'lerinde çalışır; herhangi bir PDF bağlantısı geç ve markdown'a dönüştürülür.",
    "search_files, ripgrep destekli ve grep'ten daha hızlıdır; terminal grep yerine kullan.",
    "patch, 9 bulanık eşleme stratejisi kullanır; küçük boşluk farklılıkları düzenlemeleri bozmaz.",
    "patch, tek bir çağrıda toplu çok dosyalı düzenlemeler için V4A formatını destekler.",
    "read_file, bir dosya bulunamadığında benzer dosya adları önerir.",
    "read_file otomatik yinelenenleri kaldırır; değişmemiş dosyayı yeniden okumak hafif taslak döndürür.",
    "browser_vision ekran görüntüsü alır ve yapay zeka ile analiz eder; CAPTCHA ve görsel içerik için çalışır.",
    "browser_console sayfa bağlamında JavaScript ifadelerini değerlendirebilir.",
    "image_generate, FLUX 2 Pro ve otomatik 2x büyütme ile görüntüler oluşturur.",
    "text_to_speech metni sese dönüştürür; Telegram'da sesli baloncuklar olarak oynatılır.",
    "send_message oturum içinden bağlı herhangi bir mesajlaşma platformuna ulaşabilir.",
    "Todo aracı, oturum boyunca karmaşık çok adımlı görevleri takip etmeye yardımcı olur.",
    "session_search TÜM geçmiş konuşmalar genelinde tam metin araması yapar.",
    "Ajan tercihleri, düzeltmeleri ve ortam gerçeklerini otomatik olarak belleğe kaydeder.",
    "mixture_of_agents, zor problemleri 4 öncü LLM aracılığıyla işbirliği içinde yönlendirir.",
    "Terminal komutları, uzun süren görevler için notify_on_complete ile arka plan modunu destekler.",
    "Terminal arka plan süreçleri, belirli çıktı satırlarında uyarı vermek için watch_patterns'i destekler.",
    "Terminal aracı 6 arka ucu destekler: yerel, Docker, SSH, Modal, Daytona ve Singularity.",

    # --- Profiller ---
    "Her profil kendi yapılandırma, API anahtarları, bellek, oturumlar, yetenekler ve cron işlerine sahiptir.",
    "Profil adları kabuk komutları olur; 'fetih profile create coder' 'coder' komutunu oluşturur.",
    "fetih profile export coder -o yedek.tar.gz taşınabilir profil arşivi oluşturur.",
    "İki profil yanlışlıkla bir bot tokenı paylaşırsa, ikinci ağ geçidi açık hatayla engellenir.",

    # --- Oturumlar ---
    "Oturumlar ilk alışverişten sonra otomatik olarak açıklayıcı başlıklar oluşturur; manuel adlandırmaya gerek yok.",
    "Oturum başlıkları soy zincirini destekler: \"projem\" → \"projem #2\" → \"projem #3\".",
    "Çıkarken FETIH, oturum kimliği ve istatistiklerle devam komutunu yazdırır.",
    "fetih sessions export yedek.jsonl tüm oturumları yedekleme veya analiz için dışa aktarır.",
    "fetih -r OTURUM_KİMLİĞİ herhangi bir geçmiş oturumu kimliğiyle devam ettirir.",

    # --- Bellek ---
    "Bellek donmuş anlık görüntüdür; değişiklikler yalnızca bir sonraki oturum başlangıcında görünür.",
    "Bellek girişleri, istem enjeksiyonu ve sızdırma kalıpları için otomatik taranır.",
    "Ajanın iki bellek deposu var: kişisel notlar (~2200 karakter) ve kullanıcı profili (~1375 karakter).",
    "Ajana verdiğin düzeltmeler (\"hayır, böyle yap\") genellikle otomatik olarak belleğe kaydedilir.",

    # --- Yetenekler ---
    "GitHub, yaratıcı, mlops, verimlilik, araştırma ve daha fazlasını kapsayan 80+ paket yetenek.",
    "Yüklü her yetenek otomatik olarak slash komutuna dönüşür; hepsini görmek için / yaz.",
    "fetih skills install official/security/1password depodan isteğe bağlı yetenekler yükler.",
    "Yetenekler belirli işletim sistemi platformlarıyla kısıtlanabilir; bazıları yalnızca macOS veya Linux'ta yüklenir.",
    "config.yaml'daki skills.external_dirs, özel dizinlerden yetenek yüklemeye izin verir.",
    "Ajan, skill_manage kullanarak prosedürel bellek olarak kendi yeteneklerini oluşturabilir.",
    "Plan yeteneği, aktif çalışma alanında .fetih/plans/ altına markdown planları kaydeder.",

    # --- Cron & Zamanlama ---
    "Cron işleri yetenek ekleyebilir: fetih cron add --skill blogwatcher \"Yeni gönderileri kontrol et\".",
    "Cron teslimat hedefleri telegram, discord, slack, e-posta, sms ve 12'den fazla platformu içerir.",
    "Cron yanıtı [SILENT] ile başlarsa teslimat bastırılır; yalnızca izleme işleri için kullanışlı.",
    "Cron göreceli gecikmeleri (30d), aralıkları (her 2s), cron ifadelerini ve ISO zaman damgalarını destekler.",
    "Cron işleri tamamen yeni ajan oturumlarında çalışır; istemler öz içerikli olmalıdır.",

    # --- Ses ---
    "faster-whisper kuruluysa ses modu sıfır API anahtarıyla çalışır (ücretsiz yerel konuşmadan metne).",
    "Beş TTS sağlayıcısı mevcut: Edge TTS (ücretsiz), ElevenLabs, OpenAI, NeuTTS (ücretsiz yerel), MiniMax.",
    "/voice on CLI'da ses modunu etkinleştirir. Ctrl+B, bas-konuş kaydını açıp kapatır.",
    "Akışlı TTS, cümleler oluşturuldukça oynatır; tam yanıt için beklenmez.",
    "Telegram, Discord, WhatsApp ve Slack'teki sesli mesajlar otomatik olarak metne dönüştürülür.",

    # --- Ağ Geçidi & Mesajlaşma ---
    "FETIH 21 mesajlaşma platformunda çalışır: Telegram, Discord, Slack, WhatsApp, Signal, Matrix ve daha fazlası.",
    "fetih gateway install, önyüklemede başlayan sistem servisi olarak kurar.",
    "DingTalk Akış Modunu kullanır; webhook veya genel URL gerekmez.",
    "BlueBubbles, yerel macOS sunucusu aracılığıyla iMessage'ı FETIH'e getirir.",
    "Webhook rotaları HMAC doğrulama, hız sınırlama ve olay filtrelemeyi destekler.",
    "API sunucusu, Open WebUI ve LibreChat ile uyumlu OpenAI uyumlu uç nokta sunar.",
    "Discord sesli kanal modu: bot VC'ye katılır, konuşmayı metne çevirir ve yanıt verir.",
    "group_sessions_per_user: true, grup sohbetlerinde her kişiye kendi oturumunu verir.",
    "/sethome bir sohbeti cron iş teslimatları için ana kanal olarak işaretler.",
    "Ağ geçidi, etkinlik dışı zaman aşımlarını destekler; aktif ajanlar süresiz çalışabilir.",

    # --- Güvenlik ---
    "Tehlikeli komut onayının 4 kademesi var: bir kez, oturum, her zaman (kalıcı izin listesi), reddet.",
    "Akıllı onay modu, güvenli komutları otomatik onaylamak ve tehlikelileri işaretlemek için LLM kullanır.",
    "SSRF koruması özel ağları, geri döngüyü, bağlantı-yerel ve bulut meta veri adreslerini engeller.",
    "Tirith ön yürütme taraması homograf URL sahteciliğini ve yorumlayıcı boru kalıplarını algılar.",
    "MCP alt süreçleri filtrelenmiş ortam alır; yalnızca güvenli sistem değişkenleri geçer.",
    "Bağlam dosyaları (.fetih.md, AGENTS.md) yüklemeden önce istem enjeksiyonu için güvenlik taramasından geçirilir.",
    "config.yaml'daki command_allowlist belirli kabuk komut kalıplarını kalıcı olarak onaylar.",

    # --- Bağlam & Sıkıştırma ---
    "Bağlam eşiğe ulaştığında otomatik sıkıştırılır; anılar temizlenir ve geçmiş özetlenir.",
    "Bağlam doldukça durum çubuğu sarıya, ardından turuncuya, ardından kırmızıya döner.",
    "~/.fetih/SOUL.md ajanın birincil kimliğidir; davranışı şekillendirmek için özelleştir.",
    "FETIH, proje bağlamını .fetih.md, AGENTS.md, CLAUDE.md veya .cursorrules'dan yükler (ilk eşleşme).",
    "Alt dizin AGENTS.md dosyaları, ajan klasörlere girdikçe aşamalı olarak keşfedilir.",
    "Bağlam dosyaları, akıllı baş/kuyruk kısaltmasıyla 20.000 karakterle sınırlıdır.",

    # --- Tarayıcı ---
    "Beş tarayıcı sağlayıcısı: yerel Chromium, Browserbase, Browser Use, Camofox ve Firecrawl.",
    "Camofox algılama önleme tarayıcısıdır; C++ parmak izi sahteciliği olan Firefox çatalı.",
    "browser_navigate otomatik sayfa anlık görüntüsü döndürür; sonrasında browser_snapshot'a gerek yok.",
    "annotate=true ile browser_vision, etkileşimli öğelere numaralı etiketler ekler.",

    # --- MCP ---
    "MCP sunucuları config.yaml'da yapılandırılır; hem stdio hem de HTTP taşımacılığı desteklenir.",
    "Sunucu başına araç filtreleme: tools.include beyaz listeye, tools.exclude belirli araçları kara listeye alır.",
    "MCP sunucuları çalışma zamanında araç setleri otomatik oluşturur; fetih tools platforma göre açıp kapatabilir.",
    "MCP OAuth desteği: auth: oauth, PKCE ile tarayıcı tabanlı yetkilendirmeyi etkinleştirir.",

    # --- Kontrol Noktaları & Geri Alma ---
    "Hiçbir dosya değiştirilmediğinde kontrol noktalarının sıfır ek yükü var; varsayılan olarak etkin.",
    "Geri almayı geri alabilmek için geri alma öncesi anlık görüntü otomatik kaydedilir.",
    "/rollback aynı zamanda konuşma turunu da geri alır; ajan geri alınan değişiklikleri hatırlamaz.",
    "Kontrol noktaları ~/.fetih/checkpoints/'daki gölge depoları kullanır; projenin .git'ine asla dokunulmaz.",

    # --- Toplu İşlem & Veri ---
    "batch_runner.py, eğitim verisi üretimi için yüzlerce istemi paralel olarak işler.",
    "fetih chat -Q programatik kullanım için sessiz modu etkinleştirir; başlık ve döndüreci bastırır.",
    "Yörünge kaydetme (--save-trajectories), model eğitimi için tam araç kullanım izlerini yakalar.",

    # --- Eklentiler ---
    "Üç eklenti türü: genel (araçlar/kancalar), bellek sağlayıcıları ve bağlam motorları.",
    "fetih plugins install sahip/repo, eklentileri doğrudan GitHub'dan yükler.",
    "8 harici bellek sağlayıcısı mevcut: Honcho, OpenViking, Mem0, Hindsight ve daha fazlası.",
    "Eklenti kancaları pre/post_tool_call, pre/post_llm_call ve transform_terminal_output içerir.",

    # --- Çeşitli ---
    "İstem önbelleğe alma (Anthropic), önbelleğe alınmış sistem istemi öneklerini yeniden kullanarak maliyeti azaltır.",
    "Ajan, arka plan iş parçacığında otomatik olarak oturum başlıkları oluşturur; sıfır gecikme etkisi.",
    "Akıllı model yönlendirme, basit sorguları daha ucuz bir modele otomatik yönlendirebilir.",
    "Slash komutları önek eşleştirmeyi destekler: /h, /help'e çözümlenir; /mod, /model'e.",
    "Terminale dosya yolu sürüklemek görüntüleri otomatik ekler veya bağlam olarak gönderir.",
    ".worktreeinclude, çalışma ağaçlarına kopyalanacak gitignore edilmiş dosyaları listeler.",
    "fetih acp, FETIH'i VS Code, Zed ve JetBrains entegrasyonu için ACP sunucusu olarak çalıştırır.",
    "Özel sağlayıcılar: config.yaml'da custom_providers altına adlandırılmış uç noktaları kaydet.",
    "FETIH_EPHEMERAL_SYSTEM_PROMPT, hiç geçmişe kaydedilmeyen bir sistem istemi ekler.",
    "credential_pool_strategies, fill_first, round_robin, least_used ve rastgele rotasyonu destekler.",
    "fetih login, Nous ve OpenAI Codex sağlayıcıları için OAuth tabanlı kimlik doğrulamayı destekler.",
    "API sunucusu, sunucu tarafı durumuyla hem Sohbet Tamamlamaları hem de Yanıtlar API'sini destekler.",
    "config'de tool_preview_length: 0, döndürücünün etkinlik akışında tam dosya yollarını gösterir.",
    "fetih status --deep tüm bileşenler genelinde daha derin tanısal kontroller çalıştırır.",

    # --- Gizli Özellikler & İleri Düzey Kullanım ---
    "Cron işleri Python betiği ekleyebilir (--script); stdout'u bağlam olarak isteme enjekte edilir.",
    "Cron betikleri ~/.fetih/scripts/'de bulunur ve ajandan önce çalışır; veri toplama hatları için mükemmel.",
    "config.yaml'daki prefill_messages_file, her API çağrısına az sayıda örnek ekler; geçmişe kaydedilmez.",
    "SOUL.md, ajanın varsayılan kimliğini tamamen değiştirir; FETIH'i kendine göre yapmak için yeniden yaz.",
    "SOUL.md ilk çalıştırmada varsayılan kişilikle tohumlanır. Özelleştirmek için ~/.fetih/SOUL.md'yi düzenle.",
    "/compress <odak konusu> özet bütçesinin %60-70'ini konuna ayırır ve geri kalanını agresif kısaltır.",
    "İkinci ve sonraki sıkıştırmalarda sıkıştırıcı, sıfırdan başlamak yerine önceki özeti günceller.",
    "Ağ geçidi oturumu sıfırlamadan önce FETIH, önemli gerçekleri arka planda otomatik belleğe aktarır.",
    "config.yaml'da network.force_ipv4: true, bozuk IPv6'lı sunuculardaki takılmaları düzeltir.",
    "Terminal aracı yaygın çıkış kodlarına açıklama ekler: grep'in 1 döndürmesi = 'Eşleşme bulunamadı'.",
    "Başarısız ön plan terminal komutları üstel geri alma ile 3 kez otomatik yeniden dener (2s, 4s, 8s).",
    "Yalnız sudo komutları, .env'den SUDO_PASSWORD'ü boru hattına bağlayacak şekilde otomatik yeniden yazılır.",
    "execute_code yerleşik yardımcılara sahip: toleranslı ayrıştırma için json_parse() ve retry().",
    "execute_code'un 7 korumalı alan aracı (web_search, terminal, okuma/yazma/arama/yama) RPC kullanır; bağlama girmez.",
    "Aynı dosya bölgesini 3+ kez okumak uyarı tetikler. 4+ okumada döngüleri önlemek için kesin bloke edilir.",
    "write_file ve patch, son okumadan beri dosyanın harici değiştirilip değiştirilmediğini tespit eder.",
    "V4A yama formatı Dosya Ekle, Dosya Sil ve Dosya Taşı yönergelerini destekler; yalnızca Güncelle değil.",
    "MCP sunucuları örnekleme yoluyla LLM tamamlamaları geri isteyebilir; ajan sunucu için araç haline gelir.",
    "MCP sunucuları, yeniden başlatma olmadan otomatik araç yeniden kaydını tetiklemek için bildirim gönderir.",
    "acp_command: 'claude' ile delegate_task, herhangi bir platformdan Claude Code'u alt ajan olarak başlatır.",
    "Delegasyonun kalp atışı iş parçacığı var; alt ajan etkinliği üst ajana yayılarak zaman aşımlarını önler.",
    "Sağlayıcı HTTP 402 döndürdüğünde, yardımcı istemci otomatik olarak bir sonrakine geçer.",
    "agent.tool_use_enforcement, araç çağırmak yerine eylemleri tanımlayan modelleri yönlendirir.",
    "agent.restart_drain_timeout (varsayılan 60s), çalışan ajanlara ağ geçidi yeniden başlatmadan önce bitirme fırsatı verir.",
    "agent.api_max_retries (varsayılan 3), ajanın başarısız API çağrısını kaç kez yeniden deneyeceğini kontrol eder.",
    "Ağ geçidi, AIAgent örneklerini oturum başına önbelleğe alır; bu önbelleği yok etmek istem önbelleğini bozar.",
    "Herhangi bir web sitesi /.well-known/skills/index.json aracılığıyla yetenekler sunabilir; skills hub otomatik keşfeder.",
    "~/.fetih/skills/.hub/audit.log'daki skills denetim günlüğü her yükleme ve kaldırma işlemini takip eder.",
    "Eski git çalışma ağaçları otomatik temizlenir: itilmemiş commit'i olmayan 24-72 saat eskiler budanır.",
    "Her profil FETIH_HOME/home/'da kendi alt süreç HOME'una sahip; izole git, ssh, npm, gh yapılandırmaları.",
    "FETIH_HOME_MODE ortam değişkeni (sekizli, örn. 0701), web sunucusu geçişi için dizin izinleri ayarlar.",
    "Konteyner modu: FETIH_HOME'a .container-mode yerleştir ve host CLI otomatik konteynere geçer.",
    "Ctrl+C'nin 5 öncelik kademesi var: kaydı iptal et → istemleri iptal et → seçiciyi iptal et → ajanı kes → çık.",
    "Ajan çalışması sırasındaki her kesinti, zaman damgalarıyla ~/.fetih/interrupt_debug.log'a kaydedilir.",
    "BROWSER_CDP_URL, tarayıcı araçlarını çalışan herhangi bir Chrome'a bağlar; WebSocket, HTTP veya host:port kabul eder.",
    "BROWSERBASE_ADVANCED_STEALTH=true, özel Chromium ile gelişmiş algılama önlemeyi etkinleştirir.",
    "CLI, 80 sütundan dar terminallerde otomatik olarak kompakt moda geçer.",
    "Hızlı komutlar iki türü destekler: exec (doğrudan kabuk komutu) ve alias (başka komuta yönlendir).",
    "config'deki delegation.model ve delegation.provider, alt ajanları daha ucuz modellere yönlendirir.",
    "delegation.reasoning_effort, alt ajanlar için düşünme derinliğini bağımsız olarak kontrol eder.",
    "config.yaml'daki display.platforms, platform başına görüntü geçersiz kılmalarına izin verir.",
    "config'deki human_delay.mode, insan yazma hızını simüle eder; yapılandırılabilir min_ms/max_ms aralığı.",
    "Yapılandırma sürüm geçişleri yüklemede otomatik çalışır; yeni anahtarlar manuel müdahale olmadan görünür.",
    "GPT ve Codex modelleri, araç disiplini ve zorunlu araç kullanımı için özel sistem istemi rehberliği alır.",
    "Gemini modelleri, mutlak yollar, paralel araç çağrıları ve etkileşimsiz komutlar için özel yönergeler alır.",
    "context.engine, alternatif bağlam yönetim stratejileri için bir eklenti adına ayarlanabilir.",
    "8000 tokenden fazla tarayıcı sayfaları, ajana döndürülmeden önce yardımcı LLM tarafından otomatik özetlenir.",
    "Sıkıştırıcı ucuz ön geçiş yapar: 200 karakterden fazla araç çıktıları LLM çalışmadan önce yer tutucularla değiştirilir.",
    "Sıkıştırma başarısız olduğunda, API'yi zorlamaktan kaçınmak için daha fazla deneme 10 dakika duraklatılır.",
    "Uzun tehlikeli komutlar (>70 karakter), onay isteminde önce tam metni görmek için 'görüntüle' seçeneği alır.",
    "Ses kaydı sırasında mikrofon RMS seviyelerine göre ▁▂▃▄▅▆▇ çubukları gösterilir.",
    "Profil adları mevcut PATH ikilileriyle çakışamaz; 'fetih profile create ls' reddedilir.",
    "fetih profile create backup --clone-all her şeyi kopyalar (yapılandırma, anahtarlar, SOUL.md, anılar, yetenekler).",
    "Ses kaydı tuşu, config.yaml'daki voice.record_key aracılığıyla yapılandırılabilir; yalnızca Ctrl+B değil.",
    ".cursorrules ve .cursor/rules/*.mdc dosyaları otomatik algılanır ve proje bağlamı olarak yüklenir.",
    "Bağlam dosyaları 10'dan fazla istem enjeksiyonu kalıbını destekler; görünmez Unicode, 'talimatları yoksay'.",
    "GPT-5 ve Codex, mesaj formatında 'system' yerine 'developer' rolü kullanır.",
    "Görev başına yardımcı geçersiz kılmalar: config.yaml'da auxiliary.vision.provider, auxiliary.compression.model vb.",
    "Yardımcı istemci 'main'i sağlayıcı takma adı olarak değerlendirir; gerçek birincil sağlayıcıya çözümlenir.",
    "fetih claw migrate --dry-run, herhangi bir şey yazmadan OpenClaw geçişini önizler.",
    "Tırnak işaretleri veya kaçış boşluklarıyla yapıştırılan dosya yolları otomatik olarak işlenir.",
    "Slash komutları hiçbir zaman büyük yapıştırma çöküşünü tetiklemez; büyük bağımsız değişkenlerle çalışır.",
    "Ajan yürütmesi sırasında yazılan slash komutları kesinti mantığını atlayarak anında çalışır.",
    "FETIH_DEV=1, yerel geliştirme için konteyner modu algılamayı atlar.",
    "Her MCP sunucusu, fetih tools aracılığıyla bağımsız açılıp kapatılabilen kendi araç setine sahip.",
    "Config'deki MCP ${ENV_VAR} yer tutucuları sunucu başlatılırken çözümlenir; ~/.fetih/.env dahil.",
    "Güvenilir depolardan gelen yetenekler 'güvenilir' güvenlik seviyesi alır; topluluk yetenekleri ekstra taranır.",
    "~/.fetih/skills/.hub/quarantine/'daki karantina, güvenlik incelemesi bekleyen yetenekleri tutar.",

    # --- Gelişmiş Slash Komutları ---
    "/steer <istem> bir sonraki araç çağrısından sonra not ekler; görevi kesmeden yönlendir.",
    "/goal <metin> kalıcı döngü hedefi belirler; bir yargıç tamamlandı diyene kadar FETIH tur tur devam eder.",
    "/snapshot create [etiket] FETIH yapılandırmasının tam durum anlık görüntüsünü kaydeder; /snapshot restore ile geri alınır.",
    "/copy [N] son asistan yanıtını panoya kopyalar veya numarayla sondan N'incisini kopyalar.",
    "/redraw tam UI yeniden çizimini zorlar; tmux yeniden boyutlandırma sonrası terminal kaymasını düzeltir.",
    "/agents (takma adı /tasks) mevcut oturumdaki aktif ajanları ve arka plan görevlerini gösterir.",
    "/footer, model, araç sayıları ve tur zamanlamasını gösteren son yanıtlardaki altbilgiyi açıp kapatır.",
    "/busy queue|steer|interrupt, FETIH çalışırken Enter'a basmanın ne yapacağını kontrol eder.",
    "/topic Telegram DM'lerinde çok oturumlu konu modunu etkinleştirir; /topic <id> geçmiş oturumları geri yükler.",
    "/approve session|always, seçtiğin güven kapsamıyla bekleyen tehlikeli komutu çalıştırır; /deny reddeder.",
    "/restart, aktif çalışmalar boşaltıldıktan sonra ağ geçidini düzgünce yeniden başlatır.",
    "/kanban boards switch <slug>, sohbet içinden aktif Kanban panosunu değiştirir.",
    "/reload, ~/.fetih/.env'yi çalışan oturuma yeniden yükler; yeniden başlatmadan yeni API anahtarları alınır.",

    # --- Cron (ajansız & betikler) ---
    "no_agent=True ile cronjob, zamanlamaya göre betik çalıştırır ve stdout'unu doğrudan gönderir; sıfır token.",
    "Boş cron betiği stdout'u sessiz çalışma anlamına gelir; hiçbir şey teslim edilmez, eşik izleyiciler için mükemmel.",
    "FETIH_CRON_MAX_PARALLEL (varsayılan 4), anlık artışlar anahtarlarını doyurmasın diye cron işi sayısını sınırlar.",

    # --- Ağ Geçidi Kancaları ---
    "Ağ geçidi kancaları, HOOK.yaml + handler.py ile ~/.fetih/hooks/<ad>/ altında bulunur; işleyici 'handle' olmalıdır.",
    "Kanca olayları gateway:startup, session:start, agent:step ve command:* joker karakter aboneliklerini içerir.",
    "~/.fetih/BOOT.md kontrol listesi bırak; gateway:startup kancası her önyüklemede tek seferlik ajan olarak çalıştırır.",

    # --- Küratör ---
    "fetih curator run --dry-run, küratörün herhangi bir şeyi değiştirmeden ne arşivleyeceğini önizler.",
    "fetih curator pin <yetenek>, bir yeteneği hem otomatik arşivlemeye hem de skill_manage aracına karşı korur.",
    "fetih curator rollback, yetenekleri çalışma öncesi anlık görüntüden geri yükler; yedekler .curator_backups/'ta.",

    # --- Kimlik Havuzları & Yönlendirme ---
    "fetih auth reset <sağlayıcı>, kimlik havuzundaki tüm bekleme sürelerini ve tükenme bayraklarını temizler.",
    "credential_pool_strategies.<sağlayıcı>: round_robin, fill_first yerine anahtarları eşit şekilde döndürür.",
    "use_gateway: true, araç başına web, görüntü, tts veya tarayıcıyı Nous aboneliğin üzerinden yönlendirir.",
    "provider_routing.data_collection: deny, OpenRouter'da veri depolayan sağlayıcıları dışlar.",
    "provider_routing.require_parameters: true, yalnızca isteğindeki her parametreyi destekleyen sağlayıcılara yönlendirir.",

    # --- TUI & Gösterge Paneli ---
    "FETIH_TUI_RESUME=1, başlatmada en son TUI oturumuna otomatik yeniden bağlanır; SSH düşmelerinden sonra kullanışlı.",
    "FETIH_TUI_THEME=light|dark|<hex>, COLORFGBG ayarlamayan terminallerde TUI temasını zorlar.",
    "TUI'da Ctrl+G veya Ctrl+X Ctrl+E, uzun çok satırlı istemler için giriş tamponunu $EDITOR'da açar.",
    "TUI, LaTeX'i satır içi işler; $E=mc^2$ ham TeX yerine Unicode matematiğe dönüşür.",

    # --- Ortam Değişkenleri & Yapılandırma Kapıları ---
    "display.tool_progress_command: true, mesajlaşma platformlarında /verbose'u sunar; varsayılan olarak yalnızca CLI'da.",
    "FETIH_BACKGROUND_NOTIFICATIONS=result, yalnızca arka plan görevleri bittiğinde bildirir.",
    "FETIH_WRITE_SAFE_ROOT, write_file ve patch'i bir dizin önekiyle kısıtlar; dışarıdaki yazmalar onay gerektirir.",
    "FETIH_IGNORE_RULES, AGENTS.md, SOUL.md, .cursorrules, bellek ve önceden yüklenmiş yeteneklerin enjeksiyonunu atlar.",
    "FETIH_ACCEPT_HOOKS, config.yaml'da bildirilen görülmemiş kabuk kancalarını TTY istemi olmadan otomatik onaylar.",
    "auxiliary.goal_judge.model, /goal yargıcını döngü maliyetini sıfıra yakın tutmak için ucuz hızlı modele yönlendirir.",
    "Kontrol noktaları, yavaş git işlemlerini önlemek için 50.000'den fazla dosyası olan dizinleri atlar.",

    # --- TTS ---
    "tts.provider: piper, CPU'da 44 dilli yerel TTS çalıştırır; sesler ~/.fetih/cache/piper-voices/'a otomatik indirilir.",
    "tts.providers.<ad>.type: command, {input_path} ve {output_path} yer tutucularıyla CLI TTS motoruna bağlanır.",

    # --- API Sunucusu & Proxy ---
    "API_SERVER_ENABLED=true, Open WebUI ve LibreChat için ağ geçidinin yanında OpenAI uyumlu uç nokta çalıştırır.",
    "GATEWAY_PROXY_URL, platform G/Ç yerel, ajan çalışması uzak API sunucusuna devredilen bölünmüş kurulum çalıştırır.",

    # --- Platforma Özgü ---
    "MATRIX_DEVICE_ID, E2EE için kararlı cihaz kimliği sabitler; olmadan her başlatmada anahtarlar döner.",
    "TELEGRAM_WEBHOOK_URL ayarlandığında TELEGRAM_WEBHOOK_SECRET gereklidir; openssl rand -hex 32 ile üret.",

    # --- Toplu İşlem ---
    "batch_runner.py --resume, tamamlanmış istemleri metne göre eşleştirir; veri seti yeniden sıralamaları bitmiş işi yeniden çalıştırmaz.",

    # --- Daha Az Bilinen Slash Komutları ---
    "/new yerinde yeni oturum başlatır (takma adı /reset); yeni oturum kimliği, temiz geçmiş, CLI açık kalır.",
    "/clear terminal ekranını siler VE yeni oturum başlatır; görsel sıfırlama için tek kısayol.",
    "/history, CLI'dan çıkmadan mevcut konuşmayı satır içinde yazdırır; hızlı yeniden okuma için kullanışlı.",
    "/save oturumu sonlandırmadan mevcut konuşmayı diske yazar.",
    "/status oturum bilgilerini bir bakışta gösterir: kimlik, başlık, model, token kullanımı ve geçen süre.",
    "/image <yol> yapıştırma veya sürükle-bırak olmadan bir sonraki istem için yerel görüntü dosyası ekler.",
    "/platforms, ağ geçidi ve mesajlaşma platformu bağlantı durumunu doğrudan sohbet içinden gösterir.",
    "/commands tam slash komutu + yüklü yetenek listesini sayfalandırır; sekme tamamlamasız platformlarda kullanışlı.",
    "/toolsets -t/--toolsets'in ne kabul ettiğini bilmek için mevcut tüm araç setlerini listeler.",
    "/gquota, sağlayıcı aktif olduğunda ilerleme çubuklarıyla Google Gemini Code Assist kota kullanımını gösterir.",
    "/voice tts, yalnızca TTS modunu açıp kapatır; ajan yüksek sesle yanıtlar ama sen hala yazarsın.",
    "/reload-skills, yeniden başlatmadan yeni yeteneklerin görünmesi için ~/.fetih/skills/'i yeniden tarar.",
    "/indicator kaomoji|emoji|unicode|ascii, ajan çalışmaları sırasında TUI meşgul göstergesi stilini seçer.",
    "/debug bir destek paketi (sistem bilgisi + günlükler) yükler ve paylaşılabilir bağlantılar döndürür.",

    # --- CLI Alt Komutları & Bayrakları ---
    "fetih -z \"<istem>\" en saf tek seferlik çalıştırma: stdout'ta son yanıt, başka hiçbir şey; betiklerde pipe için ideal.",
    "fetih chat --pass-session-id, ajanın kendine referans verebilmesi için oturum kimliğini sistem istemine ekler.",
    "fetih chat --image yol/resim.png, ayrı yükleme adımı olmadan tek -q sorgusuna yerel görüntü ekler.",
    "fetih chat --ignore-user-config, ~/.fetih/config.yaml'ı atlar; tekrarlanabilir hata raporları ve CI çalışmaları için.",
    "fetih chat --source tool, programatik sohbetleri etiketler, fetih sessions listesini karmaşıklaştırmazlar.",
    "fetih dump --show-keys, daha derin destek hata ayıklaması için düzenlenmiş API anahtarı parmak izlerini içerir.",
    "fetih sessions rename <KİMLİK> \"yeni başlık\" herhangi bir geçmiş oturumu yeniden adlandırır.",
    "fetih import, sessions export veya profile export tarafından üretilen oturum veya profil arşivini geri yükler.",
    "fetih fallback, fallback_model zincirini etkileşimli olarak yönetir; config.yaml'ı elle düzenlemeye gerek yok.",
    "fetih pairing, DM eşleştirme tokenını döndürür; rotasyondan sonra ilk mesaj gönderen bot erişimini alır.",
    "fetih setup, yeni kullanıcıları sağlayıcı, anahtarlar ve platform bağlantısı konusunda etkileşimli yönlendirir.",
    "fetih status --deep, her bileşen genelinde tam sağlık taraması çalıştırır; düz fetih status hızlı görünümdür.",

    # --- Ajan Davranışı Ortam Değişkenleri ---
    "FETIH_AGENT_TIMEOUT=0, çalışan ajan için ağ geçidi hareketsizlik öldürmesini devre dışı bırakır; uzun araştırma için.",
    "FETIH_ENABLE_PROJECT_PLUGINS=1, ./.fetih/plugins/'den repo-yerel eklentileri otomatik yükler; güven kapılı.",
    "FETIH_DISABLE_FILE_STATE_GUARD=1, patch ve write_file üzerindeki 'dosya değişti' korumasını kapatır.",
    "FETIH_ALLOW_PRIVATE_URLS=true, web araçlarının localhost ve özel ağlara erişmesine izin verir; ağ geçidinde kapalı.",
    "FETIH_OPTIONAL_SKILLS=ad1,ad2, profil başına ilk çalışmada ekstra isteğe bağlı katalog yeteneklerini otomatik yükler.",
    "FETIH_BUNDLED_SKILLS, özel paket yetenek ağacını işaret eder; Homebrew ve Nix paketleme tarafından kullanılır.",
    "FETIH_DUMP_REQUEST_STDOUT=1, her API istek yükünü günlük dosyaları yerine stdout'a döker.",
    "FETIH_OAUTH_TRACE=1, sağlayıcı kimlik doğrulamasını hata ayıklamak için OAuth token değişimi denemelerini günlüğe kaydeder.",
    "FETIH_STREAM_RETRIES (varsayılan 3), geçici ağ hatalarında akış ortası yeniden bağlantı denemelerini kontrol eder.",

    # --- Ağ Geçidi Davranışı Ortam Değişkenleri ---
    "FETIH_GATEWAY_BUSY_ACK_ENABLED=false, kullanıcı meşgul ajana mesaj gönderdiğinde onay mesajlarını susturur.",
    "FETIH_AGENT_NOTIFY_INTERVAL (varsayılan 180s), ağ geçidinin uzun turlarda ne sıklıkla ilerleme bildireceğini ayarlar.",
    "FETIH_RESTART_DRAIN_TIMEOUT (varsayılan 900s), /restart'ın zorlamadan önce çalışmaları ne kadar beklediğini sınırlar.",
    "FETIH_CHECKPOINT_TIMEOUT (varsayılan 30s), dosya sistemi kontrol noktası oluşturmayı sınırlar; büyük monorepolarda artır.",

    # --- Yardımcı Görevler & Görüntü Üretimi ---
    "config.yaml'daki image_gen.model, FAL modelini seçer: flux-2/klein, gpt-image-2, nano-banana-pro ve daha fazlası.",
    "image_gen.provider, görüntü üretimini varsayılan yerine bir eklenti üzerinden yönlendirir (OpenAI Images, FAL).",
    "AUXILIARY_VISION_BASE_URL + AUXILIARY_VISION_API_KEY, görüntü analizini herhangi bir OpenAI uyumlu uç noktaya yönlendirir.",

    # --- Güvenlik ---
    "security.tirith_fail_open: false, tirith tarayıcısı hata verdiğinde FETIH'in komutları engellemesini sağlar.",
    "TIRITH_FAIL_OPEN ortam değişkeni, tirith_fail_open yapılandırmasını geçersiz kılar; config.yaml'sız hızlı geçiş.",

    # --- Oturumlar & Kaynak Etiketleri ---
    "--source tool sohbetleri fetih sessions listesinden varsayılan olarak hariç tutulur; görmek için --source'u açıkça ayarla.",
    "Oturum kimlikleri zaman damgası öneklidir (20250305_091523_abcd); ls ve jq'da sıralama doğal çalışır.",

    # --- Çeşitli ---
    "API_SERVER_MODEL_NAME, /v1/models'daki model adını özelleştirir; çok profilli Open WebUI kurulumları için gerekli.",
]


def get_random_tip(exclude_recent: int = 0) -> str:
    """Rastgele bir ipucu döndür."""
    return random.choice(TIPS)
