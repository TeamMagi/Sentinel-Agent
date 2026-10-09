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

### [ ] #5. Yapıştırılabilir "AI-ready remediation prompt" · *(Serhat · efor: Orta)*
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

### [ ] #12. manifest-deviation gate (ajan-izi: bildirilen ↔ gözlemlenen akış) · *(Serhat · efor: Orta-Yüksek)*
Kaynak: HIVE · katman: policy/oracle.
"İhlal yalnızca bildirilen mimariden sapınca sayılır" kapısı — bizim scope/policy kapımızın
davranışsal karşılığı. Serhat'ın T1 dikey dilim (scope/policy) sahipliğine oturur.

---

## D) Kod — P3 · *(büyük lift)* · [analiz §3 #13–#15]

### [ ] #13. Dış araç ingestion (özellikle nuclei template'leri) · *(Serhat · efor: Yüksek)*
Kaynak: HORCRUX · katman: net/recon.
Dış araç çıktılarını (öncelikle **nuclei template** ekosistemi) recon/hypothesis'e besle. En büyük
kapsama getirisi; deterministik sonuç otoriter, AI yardımcı ilkesi korunur.

### [ ] #14. Hafif "URL ver, pasif tara" on-ramp (auth'suz detektörler) · *(Serhat · efor: Orta)*
Kaynak: Synk · katman: net/webui.
Auth gerektirmeyen pasif detektörler için (exposure/info-leak/headers/CVE) URL-ver-tara hafif giriş
yolu. Friction sorununa kısmi çare — **pivot değil**, on-ramp (analiz §4'e uygun).

### [ ] #15. "immunity memory" / öğrenilen imza kütüphanesi · *(Serhat · efor: Yüksek)*
Kaynak: HIVE · katman: hypothesis/store.
Soyut zafiyet örüntülerini hatırlayan imza kütüphanesi; hypothesis üretimini besler. Açık uçlu, en
belirsiz kalem — en sona.

---

## Ne ALMAYACAĞIZ (analiz §4 — kimse bu maddelere sapmasın)

- **Tüketici scam/phishing pivotu** — kalabalık, türev, tezi sulandırır.
- **ZK-proof / W3C Verifiable Credentials ağırlığı** (Pramaan) — maliyet çok yüksek; leaked-marker +
  SHA-256 bundle zaten yeterli.
- **Tam sıfır-config / tarayıcı-eklentisi pivotu** — erişim-kontrol testi kimlik ister. Hafif on-ramp
  (#14) evet, pivot hayır.
- **Çoklu-ajan "tartışma" gösterisi** (PARALLAX tarzı) — "kod karar verir" ilkesiyle gerginlik yaratır.

---

## Arşiv — önceki görev dalgası

Bu dosyanın önceki içeriği (yarışma penceresi listesi: A–G blokları, maddeler **1–30** ve **T1–T4**;
ondan önceki RK-1…RK-14 ve AS-1…AS-9 dalgaları) galeri-analizi eylem planına yer açmak için
kaldırıldı — **kayıp yok, git geçmişinde ve kodda duruyor**. Referanslar yerinde:
[genel rakip analizi](docs/rakip-analizi-2026-09.md) ·
[agent-security kıyası](docs/rakip-analizi-agent-security-2026-09.md) ·
[galeri analizi](docs/rakip-analizi-tln-galeri-2026-09-21.md) · [ROADMAP](ROADMAP.md) · [DESIGN.md](DESIGN.md).
