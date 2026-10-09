# Görev Listesi — Galeri Rakip Analizi Eylem Planı (2026-09-21)

> **Kaynak:** [`docs/rakip-analizi-tln-galeri-2026-09-21.md`](docs/rakip-analizi-tln-galeri-2026-09-21.md)
> (91 Devpost gönderimi + en yakın 8 rakibin derin incelemesi). Bu dosya, o belgenin **eyleme
> dönüştürülebilir** maddelerini **Serhat ↔ Görkem** arasında **efor bazında eşit** paylaştırır.
> Madde numaraları analizin **§3 tablosu** (#1–#15) ve **§6** ile birebir eşleşir ki iki belge
> birbirine referans verebilsin.
>
> Kurallar: **[CLAUDE.md](CLAUDE.md)** (Türkçe/imzasız commit, `pytest -q` yeşil kalmadan merge yok)
> · mimari: **[DESIGN.md](DESIGN.md)** · korunacak kenar (moat): analiz **§5**.

## Öncelik (analiz §3'ten)

| Grup | Anlamı |
|---|---|
| **A · P0** | Kod-dışı, hemen — sunum/anlatı. En yüksek getiri, sıfır kod riski. |
| **B · P1** | Hızlı kazançlar (kod). Küçük yüzey, yüksek etki. |
| **C · P2** | Orta kod lifti — yeni detector/oracle/gate. |
| **D · P3** | Büyük lift — ekosistem entegrasyonu, öğrenen bileşenler. |

## ⛔ İhlal edilemez kural

**Verdict tarafına fallback KOYMAYIN.** Oracle emin olamadığında `INCONCLUSIVE` demesi bir eksiklik
değil, projenin **en güçlü tarafıdır**. "Emin olamadım, o zaman LIKELY diyeyim" gibi bir gevşeme
precision'ı kaybettirir ve tüm tezi çökertir. Bu, CLAUDE.md §5'teki değişmezlerin üstünde tutulur.
Aşağıdaki remediation/verify/functional-regression maddeleri (#7, #8) **verdict merdivenini
gevşetmeden** eklenecek: yeni bir kanıt, mevcut dört-kademeyi zenginleştirir, kısayol açmaz.

---

## Yük dağılımı (dengeli — efor bazında)

| | A Anlatı (P0) | B Kod (P1) | C Kod (P2) | D Kod (P3) | Efor toplamı |
|---|---|---|---|---|---|
| **Görkem** | #1, #3, #4, §6-5 (4.0) | #6, #7 (5.0) | #8, #9, #10, #11 (12.5) | — | **≈ 21.5 s** |
| **Serhat** | #2, §6-1b, §6-4 (2.5) | #5 (2.5) | #12 (3.5) | #13, #14, #15 (12.5) | **≈ 21.0 s** |

> Saatler analiz §3'ün efor sütunundan türetilmiştir (Düşük≈1.0 · Düşük-Orta≈1.5 · Orta≈2.5 ·
> Orta-Yüksek≈3.5 · Yüksek≈5.0). Denge **madde sayısıyla değil eforla** kurulur (Görkem 10, Serhat 8
> madde; efor 21.5/21.0). İş bölmeleri **DESIGN.md §7 bağımlılık yönüne** göre ayrıldı.

**Paylaştırma mantığı (katman sahipliğiyle):**
- **Görkem** = README/deck anlatısı + **oracle / detector / verdict / evidence** katmanı (proof-bundle
  bayatlaması, remediation-verify verdict'i, causal-lineage oracle, entropy detector, MCP-manifest
  detektörü). Bu, Görkem'in T3 (LLM'siz hipotez/detector) ve T4 (benchmark) sahipliğiyle örtüşür.
- **Serhat** = video/Devpost teslim paketi + **report/webui / net / policy** katmanı (yapıştırılabilir
  remediation prompt UI'si, manifest-deviation policy kapısı, nuclei ingestion, pasif URL on-ramp,
  immunity-memory). Bu, Serhat'ın T1/T2 (dikey dilim: scope/policy) ve panel/demo sahipliğiyle örtüşür.

**Önerilen sıra:** A (P0, kod-dışı — hemen ve bedava) → B (P1 hızlı kazançlar) → C (P2) → D (P3).

---

## A) Anlatı / sunum — P0 · *(kod-dışı, hemen)* · [analiz §6 + §3 #1–#4]

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
### [ ] #1. Anlatıyı "klasik API + ajan-çağı yetki, ikisini de KANITLA" diye çerçevele · *(Görkem · efor: Düşük)*
Kaynak: ChainBreak/Ranger/Pramaan kümesinin varlığı · katman: README + deck.
Sahip olduğumuz dört predicate (CONFUSED_DEPUTY, DESTRUCTIVE_WRITE, EXFILTRATION,
UNTRUSTED_TO_ACTION) README/deck'te bir cümleyle öne çıksın; deck IDOR/BOLA'yı öne, ajan tarafını
dipnota atmayı bıraksın. Innovation puanının toplandığı yere taşır.

### [ ] #2. "intended vs claimed vs actual" çerçevesini rapor/sunuma al · *(Serhat · efor: Düşük)*
Kaynak: Ranger · katman: report/video anlatısı.
Ajanın *ne yapmak istediği*, *ne iddia ettiği*, *ne gerçekten olduğu* ayrımını rapor/video diline
işle. Bedava, kod gerektirmez, jüriye çok satar.

### [ ] #3. "evidence-first, model gets no vote" + "trajectory/lineage" dilini vurgula · *(Görkem · efor: Düşük)*
Kaynak: HORCRUX / ChainBreak · katman: README + deck.
Jürinin ödüllendirdiği dili kullan: "reproducible offline", "measured not claimed". Bunları benchmark
slaytı + proof-bundle slaytıyla eşle.

### [ ] #4. Ranger kontrastı: "biz hedefi kanıtlıyoruz, meta-değerlendirmiyoruz" · *(Görkem · efor: Düşük)*
Kaynak: Ranger · katman: deck + README.
"Ranger ajanın davranışını değerlendirir; Sentinel hedefin zafiyetini kanıtlar — biz daha zor ispatı
yapıyoruz, üstelik aynı Juice Shop üzerinde." Güçlü, net konumlandırma.

### [ ] §6-1b. Devpost yazımı + videoda ajan-güvenliğini yükselt · *(Serhat · efor: Düşük)*
Kaynak: analiz §6.1 · katman: Devpost/video teslim.
Dört predicate'i Devpost açıklamasında ve video anlatısında görünür kıl (#1'in teslim-yüzü karşılığı).

### [ ] §6-4. Devpost linkini gerçek adrese çevir · *(Serhat · efor: Düşük)*
Kaynak: analiz §6.4 · katman: Devpost/deck.
Deck'te placeholder `[devpost.com/software/…]` görülüyordu — gerçek gönderim adresiyle değiştir.

### [ ] §6-5. "Herkes kanıt diyor; biz ÖLÇTÜK" slaytı · *(Görkem · efor: Düşük)*
Kaynak: analiz §6.5 · katman: benchmark slaytı (T4 sahipliği).
Kanıt-temelli küme kalabalık; farkı *ölçülmüş sayılar* (precision/recall + 0-FP tuzak) yaratıyor. En
ayrıştırıcı slayt bu.

---

## B) Kod — P1 · *(hızlı kazançlar)* · [analiz §3 #5–#7]

### [x] 6. README **İNGİLİZCE** olacak · *(Görkem · ~4s)*
Jüri Amazon, U.S. Bank, Corteva, Blue Cross Blue Shield tarafından; hiçbiri Türkçe okumayacak.
Bu maddeyi 10/11/13/16/17/18/19 ile **tek geçişte** yap (README'yi iki kez yazma).
### [x] #5. Yapıştırılabilir "AI-ready remediation prompt" · *(Serhat · efor: Orta)*
Kaynak: Synk · katman: report/webui.
Remediation düzyazısını, geliştirme ortamına (Lovable/Cursor vb.) yapıştırılabilir somut bir prompt'a
çevir. Küçük yüzey, yüksek UX getirisi.

### [ ] #6. Proof-bundle "bayatlama" (hedef değişince yeniden-ispat işareti) · *(Görkem · efor: Orta)*
Kaynak: Crucible · katman: evidence.
Bundle zaten SHA-256 ile mühürlü; hedef yanıtı değişince bundle "yeniden-ispat gerekiyor" işaretine
geçsin (girdi hash'i tutup karşılaştır). Verdict'e dokunmaz, kanıtın güncelliğini ölçer.

### [ ] #7. Remediation doğrulama döngüsü + "failed-repair" verdict · *(Görkem · efor: Orta)*
Kaynak: Crucible · katman: oracle/report.
Önerilen düzeltmeyi uygulayıp yeniden tarayınca zafiyet kapanıyor mu? "failed-repair" durumu, mevcut
dört-kademeli merdiveni **gevşetmeden** zenginleştirir (⛔ kuralına dikkat).

---

## C) Kod — P2 · *(orta lift)* · [analiz §3 #8–#12]

### [ ] #8. Fonksiyonel-regresyon kontrolü (düzeltme işlevi bozuyor mu) · *(Görkem · efor: Orta-Yüksek)*
Kaynak: Crucible · katman: oracle/verify (#7 ile eşleşir).
Güvenlik düzeltmesi işlevi (ör. ödeme/format) bozabilir; "exploit bloklandı MI **VE** işlev hâlâ
çalışıyor MU" çift kontrolü. #7'nin doğal devamı, aynı kişide.

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
### [ ] #9. Causal lineage graph — çok-adımlı BOLA + UntrustedToAction · *(Görkem · efor: Yüksek)*
Kaynak: ChainBreak · katman: oracle.
Veri hassasiyeti + köken + hedef izleyen nedensel köken grafiği; çok-adımlı BOLA ve
`UntrustedToActionOracle` için güçlü temel. En büyük P2 kalemi.

### [ ] #10. Entropy-temelli sır detektörü (yeni detector) · *(Görkem · efor: Düşük-Orta)*
Kaynak: SentinelZero · katman: detector.
Shannon entropy ile sır/token tespiti — ucuz, deterministik, mevcut detector ailesine bir alt sınıf
olarak oturur (Open/Closed).

### [ ] #11. MCP tool-manifest tarama (hedefin MCP'sini denetle) · *(Görkem · efor: Orta)*
Kaynak: SentinelZero/Pramaan · katman: detector/oracle.
Biz MCP'yi *sunucu* olarak sunuyoruz; *hedefin* MCP tool şemasındaki tehlikeli execution
örüntülerini tarayan detektör, ajan-güvenliği kapsamımızı genişletir.

### [x] #12. manifest-deviation gate (ajan-izi: bildirilen ↔ gözlemlenen akış) · *(Serhat · efor: Orta-Yüksek)*
Kaynak: HIVE · katman: policy/oracle.
"İhlal yalnızca bildirilen mimariden sapınca sayılır" kapısı — bizim scope/policy kapımızın
davranışsal karşılığı. Serhat'ın T1 dikey dilim (scope/policy) sahipliğine oturur.

---

## D) Kod — P3 · *(büyük lift)* · [analiz §3 #13–#15]

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
### [x] #13. Dış araç ingestion (özellikle nuclei template'leri) · *(Serhat · efor: Yüksek)*
Kaynak: HORCRUX · katman: net/recon.
Dış araç çıktılarını (öncelikle **nuclei template** ekosistemi) recon/hypothesis'e besle. En büyük
kapsama getirisi; deterministik sonuç otoriter, AI yardımcı ilkesi korunur.

### [x] #14. Hafif "URL ver, pasif tara" on-ramp (auth'suz detektörler) · *(Serhat · efor: Orta)*
Kaynak: Synk · katman: net/webui.
Auth gerektirmeyen pasif detektörler için (exposure/info-leak/headers/CVE) URL-ver-tara hafif giriş
yolu. Friction sorununa kısmi çare — **pivot değil**, on-ramp (analiz §4'e uygun).

### [x] #15. "immunity memory" / öğrenilen imza kütüphanesi · *(Serhat · efor: Yüksek)*
Kaynak: HIVE · katman: hypothesis/store.
Soyut zafiyet örüntülerini hatırlayan imza kütüphanesi; hypothesis üretimini besler. Açık uçlu, en
belirsiz kalem — en sona.

---

## Ne ALMAYACAĞIZ (analiz §4 — kimse bu maddelere sapmasın)

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
- **Tüketici scam/phishing pivotu** — kalabalık, türev, tezi sulandırır.
- **ZK-proof / W3C Verifiable Credentials ağırlığı** (Pramaan) — maliyet çok yüksek; leaked-marker +
  SHA-256 bundle zaten yeterli.
- **Tam sıfır-config / tarayıcı-eklentisi pivotu** — erişim-kontrol testi kimlik ister. Hafif on-ramp
  (#14) evet, pivot hayır.
- **Çoklu-ajan "tartışma" gösterisi** (PARALLAX tarzı) — "kod karar verir" ilkesiyle gerginlik yaratır.

---

## Arşiv — önceki görev dalgası

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
Bu dosyanın önceki içeriği (yarışma penceresi listesi: A–G blokları, maddeler **1–30** ve **T1–T4**;
ondan önceki RK-1…RK-14 ve AS-1…AS-9 dalgaları) galeri-analizi eylem planına yer açmak için
kaldırıldı — **kayıp yok, git geçmişinde ve kodda duruyor**. Referanslar yerinde:
[genel rakip analizi](docs/rakip-analizi-2026-09.md) ·
[agent-security kıyası](docs/rakip-analizi-agent-security-2026-09.md) ·
[galeri analizi](docs/rakip-analizi-tln-galeri-2026-09-21.md) · [ROADMAP](ROADMAP.md) · [DESIGN.md](DESIGN.md).
