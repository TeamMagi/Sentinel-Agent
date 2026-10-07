# Demo Videosu — Senaryo (≤5 dakika)

> Görev 11 taslağı. Çekim (Görev 12) bu senaryoya göre yapılır; süreler kabaca, kurguda ayarlanır.
> Ekranda gösterilecek her adım gerçek, çalışan komuttur — `make demo` bugün itibariyle uçtan uca doğrulandı.

---

## 0. Açılış kartı (0:00–0:10) — ~10 sn

Ekranda: proje adı + tek cümlelik tanım.

> **"Sentinel-Agent — AI destekli bir pentest ajanı ki her bulgusunu kanıtlıyor."**

Sunucu (voice-over): "Access control açıkları — IDOR, BOLA — OWASP API Top 10'da bir numara. Ama
klasik tarayıcılar bunu bulamıyor çünkü 'kimin nesi kimde' sorusunu anlamıyor. Biz de bunu, LLM'in
akıl yürüttüğü ama kararı asla LLM'in vermediği bir sistemle çözdük."

## 1. Problem (0:10–0:45) — ~35 sn

Ekranda: OWASP API Security Top 10 listesi (statik görsel/slayt), #1 BOLA vurgulu.

- BOLA/IDOR nedir, tek cümle örnek: "/api/orders/42 yerine /api/orders/43 dene, başkasının
  siparişini gör."
- Sorun: "AI pentest ajanı" demoların çoğu — model hedefe saldırıyor, sonra 'buldum' diyor. Kanıt
  yok, tekrar-üretilebilirlik yok, false-positive riski yüksek.

## 2. Mimari (0:45–1:45) — ~60 sn

Ekranda: DESIGN.md'deki akış diyagramı (README'deki ASCII şemanın görsel versiyonu):

```
recon → hipotez (LLM) → authorize(scope) → replay(actor) → oracle → finding → report
                              │                  │             │
                        güvenlik kapısı     tek choke point   3 kontrol + leaked-marker
```

Anlatım:
- "LLM burada yalnızca *ne test edelim* sorusuna cevap veriyor — endpoint listesine bakıp 'bu id
  parametresi obje-seviyesi yetki testi için aday' diyor."
- "Ama saldırıyı LLM yapmıyor. Her istek `Replayer` denen tek noktadan geçiyor — kimlik enjeksiyonu,
  scope kontrolü, rate limit hep orada."
- "`CONFIRMED` kararını hep kod veriyor: positive control + negative control + baseline kararlılığı
  geçmeden, ve kurbanın verisi saldırganın cevabında **gerçekten** görünmeden asla."
- Kısa ekran: `PolicyEngine.authorize` kodundan bir kesit (scope reddi örneği) — "yıkıcı istekler
  bile `destructive_tests` bayrağı açık olmadan asla gönderilmiyor."

## 3. Canlı koşum (1:45–3:15) — ~90 sn

Ekran kaydı, gerçek terminal:

```bash
make demo
```

- Terminalde akan loglar hızlandırılmış gösterilebilir (Juice Shop ayağa kalkıyor, kalibrasyon
  hesapları oluşturuluyor, tarama koşuyor).
- Çıktı satırına vurgu: `[done] 6 bulgu · 1 CONFIRMED · runs/run-.../`
- Anlatım: "Tek komut: hedefi ayağa kaldırıyor, iki test hesabı açıyor, taramayı koşuyor. Sıfırdan
  kanıtlı bulguya iki dakikadan kısa sürede."

## 4. Dashboard'da bulgu gösterimi (3:15–4:15) — ~60 sn

Ekran: `report.html` tarayıcıda açık.

- Bulgu listesi → `CONFIRMED` IDOR'a tıkla.
- Vurgulanacaklar:
  - Positive/negative/baseline kontrol rozetleri (yeşil tik'ler).
  - Request/response diff — kurbanın sepetindeki ürün bilgisinin saldırganın cevabında göründüğü
    satır (leaked-marker vurgusu).
  - Kopyalanabilir repro-curl (token'ın redaksiyonlu göründüğü nokta özellikle gösterilsin —
    "gerçek token asla loga/rapora yazılmıyor").
- Tek cümle: "Bu ekran, jürinin veya bir güvenlik ekibinin manuel doğrulayabileceği tam kanıt seti."

*(Opsiyonel, süre izin verirse +15 sn: hackathon'da eklenen state-changing authz oracle'ın
`INCONCLUSIVE→CONFIRMED` geçişini `destructive_tests` bayrağıyla göster — "yazma/silme yetkisini de
aynı disiplinle test ediyoruz.")*

## 5. Etki (4:15–4:40) — ~25 sn

- "Sıfır yanlış-pozitif hedefiyle tasarlandı: kanıt yoksa `CONFIRMED` yok."
- "LLM tamamen kapatılsa (`--llm none`) bile araç deterministik olarak çalışmaya, kanıt üretmeye
  devam ediyor — AI yalnızca kapsam ve açıklama kalitesini artırıyor, güvenliğin temeli değil."

## 6. Tech stack + kapanış (4:40–5:00) — ~20 sn

Ekranda: `Built with` şeridi (Python 3.11 · httpx · Pydantic · pytest · Gemini/Ollama/Anthropic ·
Docker · OWASP Juice Shop).

> Kapanış kartı: proje adı + repo/Devpost linki.

---

## Çekim notları

- Terminal yazı boyutu büyük tutulsun (screen-recording okunabilirlik).
- `make demo` koşumu önceden bir kez "prova" edilsin (Docker image cache'lensin) ki kayıtta
  Playwright/Chromium indirme süresi görünmesin — kurguda gerekirse hızlandır.
- Rapor sayfasında açık/koyu tema ikisi de gösterilebilir (kısa geçiş) — görsel çeşitlilik için.
- Ses kaydı ayrı yapılıp kurguda senkronlanabilir; script yukarıdaki metin birebir okunabilir.
