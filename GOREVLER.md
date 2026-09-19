# TLN Cybersecurity Challenge — Görev Listesi

> Hackathon: 19-20 Eylül 2026 · Bugün: 12 Eylül 2026
> Kaynak proje: Sentinel-Agent (mevcut kod üzerine inşa ediyoruz)

Sorumluluklar Serhat ve Görkem arasında eşit süreye gelecek şekilde paylaştırıldı.
Kim önce hangi görevi alırsa alsın fark etmez — atamalar değiştirilebilir, önemli olan toplam yükün dengeli kalması.

---

## Aşama 1 — Hackathon öncesi hazırlık (12-18 Eylül)

Bu aşamadaki işler mevcut fonksiyonelliği kanıtlamak/görünür kılmak içindir, yeni özellik eklemek değil.

1. **Docker içinde test suite doğrulama** — `docker compose run --rm sentinel pytest -q` çalıştır, tüm testlerin gerçekten yeşil olduğunu doğrula, çıkan gerçek hataları düzelt. *(Sorumlu: Serhat · ~1.5 saat)*

2. **Juice Shop'a karşı uçtan uca canlı tarama koşumu** — `scripts/run_scan.py` ile gerçek bir tarama yap, en az bir `CONFIRMED` IDOR/BFLA bulgusu üret, çıktısını (JSON rapor + repro-curl) kaydet. *(Sorumlu: Görkem · ~2.5 saat)*

3. **Tek komutluk demo scripti** — `docker compose up` (veya tek bir `make demo` / script) ile Juice Shop'u ayağa kaldırıp otomatik tarama başlatan ve hazır rapor üreten akışı kur. Amaç: jürinin kurulum sürtünmesi yaşamadan projeyi deneyebilmesi. *(Sorumlu: Serhat · ~3.5 saat)*

4. **HTML rapor görüntüleyici — tasarım/frontend** — mevcut JSON rapor çıktısını okuyup bulgu listesi + evidence detayını (request/response diff, leaked-marker vurgusu, repro-curl) gösteren statik bir sayfa tasarla ve oluştur. *(Sorumlu: Serhat · ~3.5 saat)*

5. **HTML rapor görüntüleyici — veri bağlama ve son rötuş** — 4 numaralı sayfayı gerçek rapor verisiyle (2 numaralı koşumdan çıkan) doldur, kenar durumlarını (INCONCLUSIVE, çoklu bulgu) kontrol et, küçük görsel düzeltmeler yap. *(Sorumlu: Görkem · ~3.5 saat)*

6. **README güncelleme** — durumu "erken geliştirme"den çıkar, tek-komut demo talimatını ve dashboard ekran görüntüsünü ekle. *(Sorumlu: Görkem · ~1 saat)*

7. **Devpost başvuru metni taslağı** — problem/çözüm anlatısı, OWASP API Security Top 10 #1 (BOLA) ile ilişkilendirme, kullanılan teknolojiler listesi, prior-work şeffaflık cümlesi (mevcut kod üzerine hackathon'da eklenenler). *(Sorumlu: Serhat · ~1.5 saat)*

8. **AI araçları açıklama metni** — hem yapım sürecinde (Claude Code) hem çalışma zamanında (Gemini/Ollama ile hipotez üretimi) AI kullanımını ayrı ayrı anlatan kısa metin. *(Sorumlu: Görkem · ~0.5 saat)*

**Aşama 1 toplam:** Serhat ~10 saat · Görkem ~7.5 saat — dengesizliği Aşama 2'de kapatıyoruz.

---

## Aşama 2 — Hackathon penceresi (19-20 Eylül)

Bu aşamadaki işler "hackathon sırasında eklendi" diye açıkça işaretlenecek — uyumluluk için önemli.

9. **Yeni özellik: state-changing (PUT/DELETE) authz testi — oracle mantığı** — DESIGN.md'de v1 olarak planlanmış; `PolicyEngine` + yeni oracle mantığını yaz (mevcut IDOR oracle'ı örnek alınarak, `Oracle` ABC'sinden türet). *(Sorumlu: Görkem · ~3 saat)*

10. **Yeni özellik: state-changing authz testi — testler + policy entegrasyonu** — 9 numaralı oracle için `tests/` altında network'süz unit testler yaz, `destructive_tests` flag'ini `PolicyEngine.authorize`'a bağla, Juice Shop'a karşı doğrula. *(Sorumlu: Serhat · ~3 saat)*

11. **Demo videosu — senaryo** — ≤5 dakikalık video için senaryo yaz: problem → mimari (LLM planlar, kod kanıtlar) → canlı koşum → dashboard'da bulgu gösterimi → etki → tech stack. *(Sorumlu: Serhat · ~1 saat)*

12. **Demo videosu — çekim ve kurgu** — 11 numaralı senaryoya göre ekran kaydı al, kurgula, ≤5 dakikaya indir. *(Sorumlu: Görkem · ~2.5 saat)*

13. **Devpost submission sayfasını doldurma ve son kontrol** — proje adı, açıklama, teknoloji listesi, demo linki, video, AI açıklaması — hepsini Devpost formuna işle, birlikte son okuma yap. *(Sorumlu: Serhat + Görkem birlikte · ~1 saat)*

**Aşama 2 toplam:** Serhat ~5 saat · Görkem ~5.5 saat (+ ortak ~1 saat).

---

## Toplam yük

| | Aşama 1 | Aşama 2 | Toplam |
|---|---|---|---|
| **Serhat** | ~10 saat | ~5 saat | **~15 saat** |
| **Görkem** | ~7.5 saat | ~5.5 saat | **~13 saat** |
| **Ortak** | — | ~1 saat | **~1 saat** |

Genel toplam: ~29 saat aktif iş, iki kişiye dengeli dağıtılmış.
