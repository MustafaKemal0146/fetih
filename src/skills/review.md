---
name: review
description: Kod kalitesi, güvenlik ve best practices incelemesi
---

Aşağıdaki kodu incele ve kapsamlı bir code review yap:

{{params}}

İnceleme sırasında şunlara odaklan:

1. **Kod Kalitesi**: Okunabilirlik, maintainability, DRY ilkeleri
2. **Güvenlik**: OWASP Top 10, injection açıkları, auth sorunları, veri sızıntısı
3. **Performans**: Gereksiz loop'lar, bellek sızıntıları, N+1 sorguları
4. **Hata Yönetimi**: Yakalanmayan hatalar, edge case'ler
5. **Best Practices**: Dil/framework standartlarına uyum, naming conventions
6. **Test Edilebilirlik**: Bağımlılık enjeksiyonu, mock edilebilirlik

Her sorun için:
- 🔴 **Kritik**: Güvenlik açığı veya hata
- 🟡 **Uyarı**: İyileştirme önerisi
- 🟢 **Öneri**: Opsiyonel geliştirme

Sonunda özet ve öncelikli düzeltmeler listele.
