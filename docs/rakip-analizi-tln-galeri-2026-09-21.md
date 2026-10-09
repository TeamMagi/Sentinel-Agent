# TLN Cybersecurity Challenge 2026 — Galeri Rakip Analizi ve İlham Çıkarımı

> **Kapsam:** Bu belge, birlikte yarıştığımız **gerçek Devpost gönderimlerini** (91 proje) inceler ve
> Sentinel-Agent için hangi fikirlerin mantıklı, alınabilir/ilham verici olduğunu önceliklendirir.
> Genel pazar manzarası için [rakip-analizi-2026-09.md], çok-adımlı ajan saldırıları için
> [rakip-analizi-agent-security-2026-09.md]. Bu ikisiyle çakışmaz; onları tamamlar.
>
> Tarih: 2026-09-21 · Kaynak: TLN Cybersecurity Challenge project-gallery + 8 rakibin detay sayfası.
> **Not:** Bu bir analiz belgesidir; hiçbir kod değişikliği içermez. "Kod gerektiren" fikirler
> yarışma sonrası yol haritasına aittir, açıkça öyle işaretlenmiştir.

---

## 0. Yönetici özeti (üç kritik bulgu)

1. **Tezimiz kazanıyor — ama artık ayırt edici değil, kalabalık.** En güçlü ~8 rakibin çekirdek
   felsefesi bizimkinin aynısı: *kanıt-temelli, deterministik, tekrar-oynatılabilir, kararı kod
   verir, LLM oy vermez.* ChainBreak "güvenlik bir tool-call özelliği değil, bir yörünge
   özelliğidir" diyor; Ranger "ajanlar kanıtlamadan başarı iddia ediyor" diyor; Crucible SHA-256'lı
   tekrar-oynatılabilir kanıt üretiyor; HIVE "byte-özdeş ledger replay" yapıyor. Bu, yaklaşımımızı
   **doğruluyor** (jüri bunu ödüllendiriyor) ama aynı zamanda "kanıt" ekseninde **tek başına
   olmadığımızı** gösteriyor.

2. **Üst küme AI-AJAN güvenliğine kaymış — ve bizim bu yeteneğimiz zaten var ama gizli.**
   En yenilikçi/görünür projelerin çoğu ajan-çağı güvenliği (ChainBreak, HIVE, Ranger, Pramaan,
   SentinelZero, AgentGate, VEIL, TrapScan, ChainBreak). "Innovation" puanı orada toplanıyor.
   Bizde `UntrustedToActionOracle` + dört ajan predicate'i (CONFUSED_DEPUTY, DESTRUCTIVE_WRITE,
   EXFILTRATION, UNTRUSTED_TO_ACTION) **zaten var** — ama deck/README/video HTTP IDOR/BOLA'yı öne
   çıkarıyor, ajan tarafını dipnota atıyor. **En yüksek getirili, kod-gerektirmeyen hamle:
   anlatıyı "hem klasik API yetki + hem ajan-çağı yetki, ikisini de KANITLA" olarak yeniden
   çerçevelemek.** (Bkz. §6.)

3. **Erişilebilirlik/friction bizim en zayıf yanımız, ve rakipler burada bizi geçiyor.** Synk "URL
   ver → tara → düz-dille açıkla → yapıştırılabilir düzeltme promptu → yeniden tara" döngüsüyle
   uzman olmayan kullanıcıya hitap ediyor. Bizim aracımız iki hesap + YAML scope + Docker istiyor.
   Jüri kriteri "intended users için erişilebilirlik" olduğundan bu bir gerçek puan kaybı. Tam
   sıfır-config bizde mümkün değil (erişim-kontrol testi doğası gereği kimlik ister) ama daha
   yumuşak bir on-ramp mümkün. (Bkz. §7.)

---

## 1. Alanın haritası — 91 proje, altı kova

| Kova | ~Adet | Örnekler | Bize etkisi |
|---|---|---|---|
| **Ajan runtime güvenliği / prompt-injection** | ~12 | ChainBreak, HIVE, VEIL, AgentGate, AgentZero, TrapScan, SentinelZero, Ranger, Pramaan | **En güçlü rakip küme.** Innovation'ı topluyor. Bizim gizli yeteneğimizle örtüşüyor. |
| **Kanıt / replay / audit temelli** | ~6 | Crucible, Ranger, HIVE, Rouge, Pramaan | **Tezimizle bire bir.** Doğrular + kalabalıklaştırır. |
| **Supply-chain / "vibe-coded app" güvenliği** | ~5 | Sentinel(pkg), SlopGuard, Crucible, Synk, VibeGuard | UX/erişilebilirlik dersleri burada. |
| **Malware / dosya analizi** | ~5 | MalGuard, Glassbox, Sudarshan, PARALLAX | Bizden uzak; sunum fikirleri (PARALLAX çoklu-ajan tartışma). |
| **Scam / phishing triyaj** (tüketici) | ~30+ | ScamShield ×4, PhishLens ×2, NETRA, GoPhish… | Kalabalık, türev, bize alakasız. Ödül için ciddi rakip değil. |
| **Tema-dışı / zayıf** | ~8 | baby-sleep, ambulans, genomik, sınav koçu | "Impact & Relevance"ten düşük alır. |

**Sonuç:** Gerçek rekabet ilk iki kovadaki ~15 ciddi projeyle. İlham da oradan gelmeli.

---

## 2. Bize en yakın 8 rakip — derin inceleme

Her biri için: **fikir · yaklaşım · gerçekten yeni olan · bizim için ders.**

### 2.1 ChainBreak — "Runtime Security Invariants for AI Agents"
- **Fikir:** Tek tek zararsız ama zincirlenince veri sızdıran ajan tool-call dizilerini yakalamak.
- **Yaklaşım:** *Causal lineage graph* (veri hassasiyeti + köken + hedef), saf-Python deterministik
  değişmezler (<0.2ms), **dual-track** (korumasız baseline ↔ korumalı çalıştırma karşılaştırması),
  fail-closed (bilinmeyen tool = engelle). 44 pytest, %100 saldırı yakalama, 0 FP.
- **Gerçekten yeni:** "Güvenlik nokta değil **yörünge** özelliğidir." Point-in-time → trajectory kayması.
- **Bizim için ders:** (a) "dual-track baseline↔protected" bizim positive/negative/baseline
  kontrolümüzün ajan-izi karşılığı — anlatıda bunu vurgulayabiliriz. (b) *Causal lineage graph*,
  çok-adımlı BOLA ve `UntrustedToActionOracle` için güçlü bir kod-yol-haritası fikri. (c) Onların
  "0.2ms saf-Python, LLM yok" cümlesi bizim "kod karar verir" cümlemizle aynı — biz daha erken ve
  daha geniş yapıyoruz, bunu kıyasla göstermeliyiz.

### 2.2 Ranger — "Fact-based security evaluation for AI agents"
- **Fikir:** Güvenlik ajanları kanıtlamadan "buldum/başardım" diyebilir; Ranger bunu **gözlemlenen
  kanıtla** ölçer. "Ajanın ne yapmak *istediği*, ne *iddia ettiği*, ne *gerçekten olduğu*" üçlüsünü ayırır.
- **Yaklaşım:** Observation gateway (HTTP trafiğini yakalar) + DB observer → `events.jsonl` →
  evaluation engine (kaydı senaryo hedefine karşı **replay** eder) → dashboard. **Hedef: OWASP Juice Shop** (bizimle aynı).
- **Gerçekten yeni:** *Yeteneği güvenlikten ayırmak* — hedefi tamamlarken sınır ihlal eden ajanı yakalamak.
- **Bizim için ders (ÇOK YÜKSEK):** (a) **"intended vs claimed vs actual" çerçevesi** bizim
  raporlama/anlatımızı keskinleştirir — bedava, kod gerektirmez, jüriye çok satar. (b) Ranger bir
  **meta-değerlendirici** (ajanı yargılar); biz **hedefi** yargılıyoruz (gerçek IDOR'u kanıtlıyoruz).
  Aynı Juice Shop'u kullanıyoruz → sunumda net kontrast: *"Ranger ajanın davranışını değerlendirir;
  Sentinel hedefin zafiyetini kanıtlar — biz daha zor olan ispatı yapıyoruz."* Bu, güçlü bir konumlandırma.

### 2.3 Crucible — "Replayable Security Checks"
- **Fikir:** npm audit uyarılarını izole ortamda **yeniden üretip** düzeltmenin işe yarayıp
  yaramadığını doğrulamak.
- **Yaklaşım:** TS compiler API (çağrı noktaları) + Docker izolasyon + **çift doğrulama: exploit
  bloklandı MI VE işlev hâlâ çalışıyor MU** + açık verdict (reproduced / failed-repair / inconclusive).
  Kanıt girdilerinin SHA-256'sını tutar; **izlenen dosya değişince kanıt "bayatlar"** ve yeniden
  doğrulama ister.
- **Gerçekten yeni:** (a) **Fonksiyonel kontrol ile güvenlik kontrolünü birlikte koşmak** — "güvenlik
  düzeltmesi" para formatını bozabilir; bunu gösteriyor. (b) **Kanıt bayatlaması** (girdi değişince otomatik geçersiz).
- **Bizim için ders (YÜKSEK):** (a) Bizim proof-bundle'ımız SHA-256 ile mühürlü; **bayatlama**
  fikrini ekleyebiliriz: hedef yanıtı değişince bundle "yeniden-ispat gerekiyor" işaretine geçsin.
  (b) **Remediation'ı doğrulama döngüsü**: düzeltme önerimizi uygulayıp yeniden tarayınca kapanıyor
  mu? "failed-repair" verdict'i bizde de anlamlı. (c) Onların verdict trichotomy'si bizim dört-kademeli
  merdivenimizi doğruluyor — moat değil ama güven verici.

### 2.4 HIVE — "Security for what happens between agents"
- **Fikir:** Her ajan yetkisi içinde kalırken bileşke davranışın yetkisiz veri akışı yaratması
  ("hiçbir üyenin gönderilmediği yere varan popülasyon").
- **Yaklaşım:** Append-only ledger'dan davranış grafiği → *detect → contain → verify* → **manifest-
  deviation gate** (ihlal yalnızca *bildirilen mimariden sapınca* sayılır) → deterministik Python, LLM yok.
  **Byte-özdeş ledger replay**, "immunity memory" (soyut zafiyet örüntülerini hatırlar).
- **Gerçekten yeni:** Kompozisyon güvenliği + "sadece bildirilen mimariden sapma ihlaldir" kapısı.
- **Bizim için ders:** (a) **manifest-deviation gate**, bizim scope/policy kapımızın davranışsal
  karşılığı — ajan-izi hedeflerinde "bildirilen izinli akış ↔ gözlemlenen akış" farkı = bulgu. (b)
  "immunity memory" = öğrenilen imza kütüphanesi → hypothesis üretimini besler (yol haritası).

### 2.5 SentinelZero — "Zero-Trust API & MCP Security Auditor"
- **Fikir:** Ajan/MCP sunucu kodunu **dağıtımdan önce** deterministik tarayıp MCP-özgü riskleri bulmak.
- **Yaklaşım:** Python AST analizi + **Shannon entropy** ile sır tespiti + MCP tool-manifest'te tehlikeli
  execution örüntüleri (shell injection) + otomatik remediation (sırrı env'e çıkaran unified diff).
  **SARIF 2.1.0** (bizde de var), ~1.26ms tarama, %100 test.
- **Gerçekten yeni:** "İlk açık-kaynak MCP tool blast-radius denetleyicisi" iddiası + statik/AST hız.
- **Bizim için ders:** (a) **Entropy-temelli sır detektörü** ucuz, deterministik, bizim detector
  ailesine oturur (yol haritası). (b) **MCP-manifest tarama**: biz MCP'yi *sunucu* olarak sunuyoruz;
  *hedefin* MCP tool şemasını tarayan bir detektör ajan-güvenliği kapsamımızı genişletir. (c) Onlar
  **statik** (kod okur); biz **dinamik/differential** (canlı iki-aktör) — bu bizim üstünlüğümüz, kıyasla göster.

### 2.6 Pramaan — "Active security scanning & validation for A2A networks"
- **Fikir:** Agent-to-agent etkileşimlerini **yürütmeden önce** doğrulayan yönetişim katmanı.
- **Yaklaşım:** 16-katmanlı mimari — W3C Verifiable Credentials (kimlik), delegation-chain + ZK-proof
  policy, prompt-injection/replay/anomali savunması, **quorum-tabanlı trust receipts**, tamper-evident
  audit log, DeepTeam ile otomatik red-team. "Sentinel" bileşeni A2A + MCP tarar, exposed tool bulur.
- **Gerçekten yeni:** Sürekli doğrulama (kimlik+yetki+niyet+davranış+uyum) + Proof-of-Authority.
- **Bizim için ders:** (a) **"trust receipt" per-karar** fikri bizim proof-bundle'ı zenginleştirir
  (her verdict için imzalı makbuz). (b) **DeepTeam otomatik red-team** entegrasyonu — dış red-team
  motorunu hipotez kaynağı olarak kullanma fikri (yol haritası). (c) ZK-proof/VC bizim için **fazla
  ağır** — almayacağız (§4).

### 2.7 HORCRUX — "Offensive-security orchestration platform"
- **Fikir:** Dağınık recon/vuln araçlarını (ffuf, httpx, nikto, nmap, nuclei, OpenVAS, SearchSploit,
  WhatWeb) tek kalıcı soruşturma ortamında birleştirmek.
- **Yaklaşım:** Araçları *değiştirmez*, çıktılarını **kanıt-öncelikli AI yorumu** ile birleştirir:
  deterministik araç sonuçları otoriter, AI sadece bağlam/öneri. Kalıcı attack-surface modeli, hipotez
  takibi, kapsama boşluğu tespiti, "sıradaki adım" önerisi. Python + Pydantic + Typer + Rich.
- **Gerçekten yeni:** Orkestrasyon katmanı + "deterministik sonuç otoriter, AI yardımcı" (bizim ilkemiz!).
- **Bizim için ders:** (a) Felsefeleri bizimkiyle **birebir aynı** ("evidence-first, AI supporting")
  — bu, jürinin bu çerçeveyi sevdiğinin ikinci kanıtı; anlatımızda güvenle kullan. (b) **Dış araç
  ingestion** (özellikle **nuclei template**'leri) bizim recon/hypothesis'i besleyebilir (yol haritası,
  yüksek kapsama getirisi). (c) `--loop` orkestratörümüz zaten "sıradaki adım" mantığında — kıyasla
  öne çıkar.

### 2.8 Synk — "Security rescue suite for vibe-coded apps"
- **Fikir:** AI ile hızla üretilen (Lovable vb.) uygulamaları dağıtımdan sonra tarayıp düzeltmek.
- **Yaklaşım:** URL ver → canlı yüzeyi crawl → güvenlik/sağlık kontrolleri → **düz-dil açıklama** →
  **"AI-ready remediation prompt"** (Lovable'a yapıştırılır) → yeniden tara. Firecrawl + TypeScript.
- **Gerçekten yeni:** Güvenlik raporunu **AI geliştirme ortamına yapıştırılabilir prompt'a** çevirmek +
  erişilebilirlik-öncelikli tasarım + "Build→Scan→Understand→Fix→Rescan" döngüsü.
- **Bizim için ders (UX):** (a) **Yapıştırılabilir remediation prompt** fikri bizim remediation
  düzyazımızı somut aksiyona çevirir — küçük, yüksek etkili UX eki (yol haritası). (b) **"URL ver,
  tara" hafif on-ramp** bizim friction sorunumuza kısmi çare (auth gerektirmeyen pasif detektörler
  için mümkün: exposure/info-leak/headers/CVE). (c) Düz-dil + skor sunumu jüri "UX" kriterine hitap eder.

---

## 3. Mantıklı fikirler — önceliklendirilmiş ilham tablosu

| # | Fikir | Kaynak | Bize uyar mı | Efor | Kod? | Öncelik |
|---|---|---|---|---|---|---|
| 1 | Anlatıyı "klasik API + ajan-çağı yetki, ikisini de KANITLA" diye çerçevele | ChainBreak/Ranger/Pramaan kümesinin varlığı | Evet — yeteneğimiz zaten var | Düşük | **Hayır** | **P0** |
| 2 | "intended vs claimed vs actual" çerçevesini rapor/sunuma al | Ranger | Evet | Düşük | Hayır | **P0** |
| 3 | "evidence-first, AI supporting" + "trajectory property" dilini vurgula | HORCRUX / ChainBreak | Evet | Düşük | Hayır | **P0** |
| 4 | Ranger kontrastı: "biz hedefi kanıtlıyoruz, meta-değerlendirmiyoruz" | Ranger | Evet | Düşük | Hayır | **P1** |
| 5 | Yapıştırılabilir "AI-ready remediation prompt" | Synk | Evet | Orta | Evet | P1 |
| 6 | Proof-bundle "bayatlama" (hedef değişince yeniden-ispat işareti) | Crucible | Evet | Orta | Evet | P1 |
| 7 | Remediation doğrulama döngüsü + "failed-repair" verdict | Crucible | Evet | Orta | Evet | P1 |
| 8 | Fonksiyonel-regresyon kontrolü (düzeltme işlevi bozuyor mu) | Crucible | Kısmen | Orta-Yüksek | Evet | P2 |
| 9 | Causal lineage graph — çok-adımlı BOLA + UntrustedToAction | ChainBreak | Evet | Yüksek | Evet | P2 |
| 10 | Entropy-temelli sır detektörü (yeni detector) | SentinelZero | Evet | Düşük-Orta | Evet | P2 |
| 11 | MCP tool-manifest tarama (hedefin MCP'sini denetle) | SentinelZero/Pramaan | Evet | Orta | Evet | P2 |
| 12 | manifest-deviation gate (ajan-izi: bildirilen↔gözlemlenen akış) | HIVE | Evet | Orta-Yüksek | Evet | P2 |
| 13 | Dış araç ingestion (özellikle nuclei template'leri) | HORCRUX | Evet | Yüksek | Evet | P3 |
| 14 | Hafif "URL ver, pasif tara" on-ramp (auth'suz detektörler) | Synk | Kısmen | Orta | Evet | P3 |
| 15 | "immunity memory" / öğrenilen imza kütüphanesi | HIVE | Belki | Yüksek | Evet | P3 |

**P0 = kod-dışı, hemen (sunum/anlatı).** P1–P3 = yarışma sonrası yol haritası, artan efor.

---

## 4. Ne ALMAYACAĞIZ (ve neden)

- **Tüketici scam/phishing pivotu** — kalabalık, türev, tezimizi sulandırır; moat'ımız kanıt-temelli
  yetki testi, oraya kaymak intihar.
- **ZK-proof / W3C Verifiable Credentials ağırlığı** (Pramaan) — mühendislik maliyeti çok yüksek,
  bizim kanıt modelimiz (leaked-marker + SHA-256 bundle) zaten yeterli ve daha anlaşılır.
- **Tam sıfır-config / tarayıcı-eklentisi pivotu** — erişim-kontrol testi doğası gereği kimlik ister;
  derinliğimizi feda etmeden tam sıfır-config olamayız. Hafif on-ramp (#14) evet, pivot hayır.
- **Deepfake / genel içerik-güvenliği** — alakasız.
- **Çoklu-ajan "tartışma" gösterisi** (PARALLAX tarzı) — LLM yüzeyini artırır, "kod karar verir"
  ilkemizle gerginlik yaratır; wow-faktörü var ama moat değil, şimdilik hayır.

---

## 5. Moat — bu güçlü kümede bile bizde olan, onlarda olmayan

Kanıt/replay kümesi güçlü ama **hiçbiri tam olarak bizim yaptığımızı yapmıyor:**

- **Ranger** ajanı *değerlendirir* (meta); IDOR'u kendisi *bulmaz/kanıtlamaz*.
- **ChainBreak / HIVE** ajan *yörüngesini* korur (savunma, runtime); hedef uygulamada IDOR avlamaz.
- **SentinelZero** *statik* (AST + MCP manifest); canlı iki-aktör differential yok.
- **Crucible** npm-vuln *yeniden üretir*; kimlikli cross-user veri sızıntısı kanıtlamaz.
- **HORCRUX** mevcut araçları *orkestre eder*; kendi deterministik oracle'ı yok.
- **Pramaan** A2A *yönetişimi*; klasik web/API IDOR/BOLA hedefi değil.

**Bizim tekelimiz:** *canlı, kimlikli bir hedefte, iki gerçek oturumlu aktörle, leaked-marker ile
cross-user veri sızıntısını KANITLAMAK; bunu çevrimdışı yeniden-ispatlanabilir mühürlü bundle'a
koymak; ve etiketli hedeflerde ölçülmüş precision/recall ile göstermek.* Bu kümede kimse bu üçlüyü
birden yapmıyor. **Sunumda korunacak kenar budur.** (Ayrıntılı moat: [rakip-analizi-2026-09.md] §6.)

---

## 6. Kod-dışı, hemen yapılabilir hamleler (kod dondu, bunlar anlatı/sunum)

1. **Devpost yazımı + video anlatısında ajan-güvenliğini yükselt.** Zaten sahip olduğumuz dört
   predicate'i (CONFUSED_DEPUTY, DESTRUCTIVE_WRITE, EXFILTRATION, UNTRUSTED_TO_ACTION) bir cümleyle
   öne çıkar: *"Sadece klasik API yetki açıklarını değil, ajan-çağı yetki açıklarını da aynı
   deterministik disiplinle kanıtlıyoruz."* Bu, Innovation puanının toplandığı yere bizi taşır.
2. **Ranger kontrastını kullan.** "Ranger ajanın davranışını değerlendirir; Sentinel hedefin
   zafiyetini kanıtlar — biz daha zor ispatı yapıyoruz, üstelik aynı Juice Shop üzerinde."
3. **Rakiplerin diliyle konuş (çünkü jüri o dili ödüllendiriyor):** "trajectory/lineage", "measured
   not claimed", "evidence-first, model gets no vote", "reproducible offline". Bunları benchmark
   slaytı + proof-bundle slaytıyla eşle.
4. **Devpost linkini gerçek adrese çevir** (deck'te placeholder `[devpost.com/software/…]` görülüyordu).
5. **"Neredeyse herkes kanıt diyor; biz ölçtük" vurgusu.** Kanıt-temelli küme kalabalık; farkı
   *ölçülmüş sayılar* (precision/recall + 0-FP tuzak) yaratıyor — bu bizim en ayrıştırıcı slaytımız.

---

## 7. Yol haritası fikirleri (kod, yarışma sonrası — ROADMAP'e ek)

Öncelik sırasıyla (detay §3 tablosu):

- **P1 — hızlı kazançlar:** Synk-tarzı yapıştırılabilir remediation prompt (#5); Crucible-tarzı
  proof-bundle bayatlaması (#6) ve remediation doğrulama + "failed-repair" verdict (#7).
- **P2 — orta:** SentinelZero entropy sır detektörü (#10) ve MCP-manifest tarayıcı (#11); ChainBreak
  causal-lineage graph ile çok-adımlı BOLA (#9); HIVE manifest-deviation gate (#12); Crucible
  fonksiyonel-regresyon kontrolü (#8).
- **P3 — büyük lift:** HORCRUX-tarzı dış araç ingestion, özellikle **nuclei template** ekosistemi
  (#13) — en büyük kapsama getirisi; hafif "URL ver, pasif tara" on-ramp (#14); HIVE immunity-memory
  imza kütüphanesi (#15).

> Bu maddeler mevcut mimariye Open/Closed ile oturur: yeni detector/oracle = yeni alt sınıf; UX ekleri
> `report`/`webui` katmanında; ingestion `net`/recon'da. Bağımlılık yönü (models→policy→net→oracle→…)
> korunur. (Bkz. [DESIGN.md] §7.)

---

## 8. Kaynakça

- TLN Cybersecurity Challenge — project gallery (91 proje, 5 kriter, 10 jüri, 6 ödül).
- ChainBreak — https://devpost.com/software/chainbreak-runtime-security-invariants-for-ai-agents
- Ranger — https://devpost.com/software/ranger-lbc1zt
- Crucible — https://devpost.com/software/crucible-replayable-security-checks
- HIVE — https://devpost.com/software/hive-security-for-what-happens-between-agents
- SentinelZero — https://devpost.com/software/sentinelzero
- Pramaan — https://devpost.com/software/pramaan-ecqvtf
- HORCRUX — https://devpost.com/software/horcrux-offensive-security-orchestration-platform
- Synk — https://devpost.com/software/synk-un7q9e
- İlgili iç belgeler: [rakip-analizi-2026-09.md], [rakip-analizi-agent-security-2026-09.md], [DESIGN.md].
