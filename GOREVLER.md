# Görev Listesi — TLN Cybersecurity Challenge 2026 (19–20 Eylül)

> **Kaynak:** [`sentinel-agent-yapilacaklar.txt`](sentinel-agent-yapilacaklar.txt) (30 madde + teknik
> öncelik notu). Bu dosya o listeyi **Serhat ve Görkem arasında paylaştırır**; maddelerin özgün
> numaraları (1–30, T1–T4) korunur ki iki dosya birbirine referans verebilsin.
>
> Kurallar: **[CLAUDE.md](CLAUDE.md)** (Türkçe/imzasız commit, `pytest -q` yeşil kalmadan merge yok)
> · mimari: **[DESIGN.md](DESIGN.md)**.

## Öncelik (kaynak dosyadan)

| Aralık | Anlamı |
|---|---|
| **1–9** | Pazarlık payı yok — mutlaka yapılacak |
| **10–15** | En çok puan getirecek kısım (**UX bir puanlama kriteri** ve şu an en zayıf eksen) |
| **16–30** | Konumlandırma, tutarlılık, teslim cilası |
| **T1–T4** | 48 saatlik teknik öncelik sırası (kaynak dosyanın EK NOT'u) |

## ⛔ İhlal edilemez kural (kaynak dosyanın UYARI'sı)

**Verdict tarafına fallback KOYMAYIN.** Oracle emin olamadığında `INCONCLUSIVE` demesi bir eksiklik
değil, projenin **en güçlü tarafıdır**. "Emin olamadım, o zaman LIKELY diyeyim" gibi bir gevşeme
precision'ı kaybettirir ve tüm tezi çökertir. Bu, CLAUDE.md §5'teki değişmezlerin üstünde tutulur.

---

## Yük dağılımı (dengeli — 26.0 / 26.5 saat)

| | A Temizlik | B Dil | C UX | D Konum | E Tutarlılık | F Teslim | T Teknik | Toplam |
|---|---|---|---|---|---|---|---|---|
| **Görkem** | 1,2,3,4 (3.5) | 6 (4.0) | 10,11,13 (3.5) | 16,17,18,19 (4.5) | 20,21,22,23 (2.5) | — | T3,T4 (8.0) | **26.0 s** |
| **Serhat** | 5 (1.0) | 7,8,9 (5.0) | 12,14,15 (6.0) | — | — | 24–30 (6.5) | T1,T2 (8.0) | **26.5 s** |

**Paylaştırma mantığı:** README'ye dokunan **bütün** maddeler (1,2,3,4,6,10,11,13,16–19) tek kişide
(Görkem) toplandı — yarışma penceresinde iki kişinin aynı dosyada çakışması en pahalı hatadır.
Serhat kod/UX yolunu (demo, panel, config üretimi), video/teslim paketini ve **kritik yol olan dikey
dilimi** (T1–T2) alır.

**Önerilen sıra:** T1 → T2 (proje bunlarsız ayakta değil) → 1–9 (pazarlık payı yok) → 10–15 (en çok
puan) → T3/T4 → 16–30.

---

## A) Dışarıya çıkmadan önce temizlenecekler

### [x] 1. Benchmark tablosunu README'den çıkar · *(Görkem · ~1s)*
"Canlı koşum, 2026-09-16", 3 hedef / 31 vaka, precision %100, FP-rate %0, TP/FN/FP/TN dağılımı —
**hepsi**. **Metodoloji anlatımı KALSIN** (vulnerable↔hardened ikiz mantığı, etiketlerin gerçek HTTP
davranışından konması, FP kapanı olarak negatif vakalar); **rakam gitsin**. Gerçek koşum çıkınca geri
konur; o zaman en güçlü koz olur.

### [x] 2. Badge'lerden test sayısını sil · *(Görkem · ~0.5s)*
**Durum:** README satır 10 → `tests-541 passing`; proje yapısındaki "(276 test)" ile çelişiyor ve
her koşumda eskiyor. Badge tamamen kalkacak.

### [x] 3. Tarihli / sürümlü iddiaları gözden geçir · *(Görkem · ~1.5s)*
`OWASP Juice Shop (v20.2.0)`, `VAmPI (vulnerable=1)`, `crAPI (main)` sürüm etiketleri **ve**
"VAmPI e-posta güncelleme yalnızca kendi hesabını değiştirir", "crAPI mechanic_report POST = 405"
gibi gözlem cümleleri de birer **ölçüm iddiasıdır**. Gerçekten koşulana kadar dursun.

### [x] 4. `make demo` çıktı örneğini kaldır · *(Görkem · ~0.5s)*
`[done] 6 bulgu · 1 CONFIRMED · runs/run-.../` satırı gerçek bir demo çıktısı gibi duruyor. Gerçek
çıktı alınana kadar çıkarılmalı.

### [ ] 5. Ekran görüntülerini kontrol et · *(Serhat · ~1s)*
**Durum:** `docs/web-ui-bulgu.png` ve `docs/web-ui-tarama.png` **dosya olarak VAR** (kırık resim yok).
Kalan iş: görüntülerin **güncel arayüzü** gösterdiğini doğrulamak; göstermiyorsa yenilemek.

---

## B) Dil

### [x] 6. README **İNGİLİZCE** olacak · *(Görkem · ~4s)*
Jüri Amazon, U.S. Bank, Corteva, Blue Cross Blue Shield tarafından; hiçbiri Türkçe okumayacak.
Bu maddeyi 10/11/13/16/17/18/19 ile **tek geçişte** yap (README'yi iki kez yazma).

### [ ] 7. Demo videosu İngilizce (ya da İngilizce altyazılı) · *(Serhat · ~3s)*
**5 dakika sınırı var.** İçerik kurgusu için bkz. madde 24–25.

### [ ] 8. Devpost submission metni İngilizce · *(Serhat · ~1.5s)*
Proje adı, açıklama, kullanılan teknolojiler.

### [ ] 9. Takım içi Türkçe kalabilir · *(Serhat · ~0.5s)*
Commit mesajları, `CLAUDE.md`, `DESIGN.md` Türkçe kalır — bunlar jüriye gitmiyor. Tek iş: bu ayrımı
`CLAUDE.md §2`'ye bir cümleyle yazıp karar netleşsin (juri-yüzü İngilizce / takım-içi Türkçe).

---

## C) Kurulum ve kullanıcı deneyimi

> Puanlama kriteri: *"How intuitive, accessible, and practical is the solution for its intended
> users?"* — **şu an en zayıf eksen.** Bu blok en çok puan getiren bloktur.

### [x] 10. README'nin ilk ekranı `make demo` + panel ekran görüntüsü olsun · *(Görkem · ~1.5s)*
Şu an okuyan önce Docker, WSL2 ve üç YAML dosyası görüyor.

### [x] 11. "Neden WSL2 + Docker" bölümünü README'den çıkar · *(Görkem · ~1s)*
`docs/gelistirme-ortami.md`'ye taşı (**dosya henüz yok, oluşturulacak**); OneDrive tuzağı notu da
oraya. Doğru bilgi ama okuyana "bu araç zor" diyor.

### [x] 12. `cp config/*.example.yaml` adımlarını demo yolundan kaldır · *(Serhat · ~2.5s)*
**Durum:** `make demo` zaten `scripts/bootstrap_demo.py` ile kendi config'ini
(`runs/demo/config/{scope,actors,endpoints}.yaml`) üretiyor — kullanıcı hiçbir dosya kopyalamıyor.
"🚀 Tek komutla demo" bölümünde de `cp` adımı yok. Doğrulandı (gerçek `make demo` koşumuyla).

### [x] 13. Web panelini ön kapı yap, CLI'ı ikinci bölüme al · *(Görkem · ~1s)*
Şu an tersi. README yapısıyla birlikte (madde 6/10) yapılır.

### [x] 14. Panel ilk açılışta örnek scope üretsin · *(Serhat · ~2s)*
`scripts/serve_ui.py`'a `_bootstrap_example_scope` eklendi: `--scope` dosyası yokken yanındaki
`*.example.yaml`'ı kopyalayıp örnek scope'u kendisi oluşturur (var olan bir scope'u asla ezmez).
Uçtan uca doğrulandı: boş `config/`'ta panel açılıp `/api/scan` artık 503 değil 400 (geçersiz
istek) dönüyor — scope kilitli. `tests/test_serve_ui.py` eklendi.

### [ ] 15. Jürinin hiçbir şey kurmadan görebileceği bir şey bırak · *(Serhat · ~1.5s)*
Barındırılmış panel olmasa bile **tek dosyalık `report.html`'i repoya koymak yeter** — jüri indirip
açar, kanıtı görür. (Redaksiyonlu, gerçek bir koşumdan.)

---

## D) Konumlandırma · *(tamamı Görkem — README sahipliği)*

### [x] 16. Özgünlük iddiasını daralt · *(Görkem · ~1.5s)*
Differential authorization testing yeni değil: **Burp Autorize, AuthMatrix** ve README'de kendi
referans verdiğiniz **AuthProbe**. Yeni olan üç şeyi öne al:
1. deterministik **leaked-marker** ile verdict,
2. **kurcalamaya-dayanıklı imzalı kanıt paketi**,
3. **MCP** üzerinden başka ajanlara **kanıt motoru** olmak.

### [x] 17. Dedektör tablolarını README'nin dibine indir · *(Görkem · ~1s)*
12 oracle + 20 dedektör listesi "bu ZAP klonu mu?" sorusunu davet ediyor ve gerçek farkı gömüyor.

### [x] 18. Etki hikâyesini son kullanıcıya bağla · *(Görkem · ~1s)*
Jürinin tema örnekleri tüketici tarafında (phishing, siber zorbalık, gizlilik); sizinki geliştirici
aracı. **IDOR'un sıradan insanların sipariş / sağlık / mesaj verisinin sızma yolu olduğunu** somut
bir ihlal örneğiyle **bir paragrafta** anlat.

### [x] 19. Kapsam sprawl'ını kes · *(Görkem · ~1s)*
Agent-security oracle'ları, template ekosistemi, sürüm bütünlüğü doğrulama, holdout → **vizyon
dosyasında kalsın**; README'de "yol haritası" başlığı altında **tek satır** olsun.

---

## E) İç tutarlılık · *(tamamı Görkem)*

### [x] 20. `UntrustedToActionOracle` çelişkisini gider · *(Görkem · ~0.5s)*
**Durum (doğrulandı):** README **satır 113** oracle tablosunda **uygulanmış** olarak listeli,
**satır 147** agent-predicate tablosunda "*(yol haritasında)*" diyor. **Gerçek durum: UYGULANDI**
(AS-3 bitti → `src/pentestai/oracle/untrusted_to_action.py`). → **satır 147 düzeltilecek**,
satır 113 kalacak.

### [x] 21. Model isimlerini doğrula · *(Görkem · ~0.5s)*
`qwen3.8:27b` (README 299/375/384/392 + `config/llm.example.yaml`) ve `gemini-3.6-flash`.
**Var olmayan model adı, model tarafını bilen bir jüride kötü durur** — `ollama list` çıktısıyla ve
sağlayıcı dokümanıyla birebir doğrula.

### [x] 22. Kod-dışı referansları kontrol et · *(Görkem · ~1s)*
`DESIGN.md §5`, `docs/rakip-analizi-agent-security-2026-09.md`, `docs/sozluk.md`, `SECURITY.md`,
`LICENSE §5`. **Durum:** bu beşinin hepsi artık **VAR** (`docs/sozluk.md` AS-9 ile eklendi) —
`scripts/verify_release.py` yerel Markdown linklerini zaten kontrol ediyor, kırık link yok.
Kalan iş: **bölüm numaralarının** (`DESIGN.md §5`, `LICENSE §5`) gerçekten o bölüme denk geldiğini
doğrulamak. Olmayan dosyaya/bölüme link vermeyin.

### [x] 23. "Stage 0 / 1 / 2" tablosunu gerçekleşenle eşle · *(Görkem · ~0.5s)*
Yarışma sonunda Stage 0 bitmişse tabloda öyle görünsün.

---

## F) Sunum ve teslim · *(tamamı Serhat)*

### [ ] 24. Demo videosu üç kare üstüne kurulsun · *(Serhat · ~2.5s)*
1. Zafiyetli hedefte **CONFIRMED** — kanıt + repro-curl ekranda.
2. Sağlamlaştırılmış ikizde **REJECTED** — yanlış alarm yok.
3. `--llm none` ile **aynı sonuç** — tezin ispatı.

> **İkinci kare birincisinden değerli:** "buldum" diyen her demo var; **"bulmadığım yerde de
> bulmadım"** diyen demo yok.

### [ ] 25. Videoda jürinin istediği beş başlık sırayla geçsin · *(Serhat · ~1s)*
problem / çözüm / nasıl çalışıyor / teknoloji / kimin işine yarar.

### [ ] 26. AI kullanım beyanı · *(Serhat · ~1s)*
**Zorunlu** — hangi araçlar, nasıl kullanıldı. Şart "katılımcı gönderdiği işi açıklayabilmeli" diyor;
**jüri kod sorabilir**. (Mevcut `docs/AI_DISCLOSURE.md` temel alınabilir.)

### [ ] 27. Jüriye link bırak · *(Serhat · ~0.5s)*
GitHub reposu yeter; **canlı barındırma zorunlu değil**.

### [ ] 28. Ödül hedefini netleştir · *(Serhat · ~0.5s)*
**Grand Prize / Best Cybersecurity Solution.** "Best Beginner Project" sizin kategoriniz değil,
oraya oynamayın.

### [ ] 29. Commit geçmişi Cuma 10:00 EDT sonrasında başlasın · *(Serhat · ~0.5s)*
Vizyon dosyası ayrı dursun; **kod yarışma penceresinde yazılsın**. Bu bir teslim kuralı — nasıl
uygulanacağına (yeni repo / yeni dal) karar verip yazıya dök.

### [ ] 30. Etik / kapsam uyarısı README'de kalsın · *(Serhat · ~0.5s)*
Pentest aracı için jüri bunu arar; **sizde iyi yazılmış** — silinmesin, İngilizce'ye taşınırken de
korunsun.

---

## G) Teknik öncelik sırası (48 saat) — kaynak dosyanın EK NOT'u

### [x] T1. Dikey dilim · *(Serhat · ~6s)* — **kritik yol**
İki aktör oturumu → scope/policy kapısı → **tek replay noktası** → `IdorOracle` → leaked-marker
verdict → evidence + tek rapor.
**Kabul:** Juice Shop'ta **tek bir gerçek CONFIRMED** çıkarsa proje ayakta.
**Doğrulandı:** gerçek `make demo` koşumu — `27 bulgu · 4 CONFIRMED`, `runs/run-20260918-100903-64fa82/`.

### [x] T2. Hardened ikiz · *(Serhat · ~2s)* — **ilk günün işi**
Aynı oracle'ın, yetkilendirmesi düzgün bir endpoint'te **REJECTED** demesi.
**Kabul:** aynı oracle, aynı koşum, iki hedef → biri CONFIRMED biri REJECTED.
**Doğrulandı:** `python -m scripts.bench_guard` — `[idor-basket] idor: vulnerable=CONFIRMED
hardened=REJECTED · 0-FP OK · recall OK` (+ `idor-public-trap`, `bfla-admin`). Ayrıca bu koşumda
Windows konsolunda (`cp125x`) `✅` karakteri yüzünden çöken bir encoding hatası bulunup düzeltildi
(`scripts/bench_guard.py`).

### [x] T3. LLM'siz hipotez üretimi (kapsam genişletme) · *(Görkem · ~5s)*
- path şablonundan çıkarım (`{id}`, `{uid}` segmentleri)
- OpenAPI/HAR'dan tip bilgisi (integer/uuid parametreler)
- bootstrap crawl'dan öğrenilen **id havuzu**
- yanıt şemasından otomatik **leaked-marker adayı**

**Kabul:** `--llm none` ile hipotez üretimi çalışır (madde 24'ün üçüncü karesi buna dayanır).

### [x] T4. Küçük ama **GERÇEK** benchmark · *(Görkem · ~3s)*
Juice Shop üstünde **5–6 etiketli vaka**, yarısı pozitif yarısı negatif.
**Küçük ve gerçek, büyük ve boştan iyidir.** (Madde 1'de çıkarılan tablonun yerine bu konur.)

---

## Arşiv — önceki görev dalgaları

Bu dosyanın önceki içeriği (RK-1…RK-14 ve AS-1…AS-9 dalgaları) yarışma listesine yer açmak için
kaldırıldı. Kayıp yok:

- **Tamamlananlar** git geçmişinde ve kodda duruyor: RK turu **27/27 Serhat + 27/27 Görkem**;
  AS turu da **bitti** — Görkem AS-2/AS-4/AS-5/AS-7, Serhat AS-1/AS-3/AS-6/AS-9.
- **Açık kalan tek madde:** ortak, açık uçlu **AS-8** (Go-Explore / evrimsel hipotez araması) —
  yarışma sonrasına ertelendi.
- **Madde 19 gereği** agent-security oracle'ları, template ekosistemi, sürüm bütünlüğü doğrulama ve
  holdout **kodda kalır ama README'de öne çıkarılmaz**: vizyon dosyasına taşınıp README'de tek
  satırlık "yol haritası" olurlar.
- Gerekçe/kıyas dokümanları yerinde: [rakip analizi](docs/rakip-analizi-2026-09.md) ·
  [agent-security kıyası](docs/rakip-analizi-agent-security-2026-09.md) · [ROADMAP](ROADMAP.md) ·
  [kalite artığı](GOREVLER_Q.md) · [Tier C](TIER_C.md).
