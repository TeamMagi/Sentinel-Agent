# Görev Listesi — Ürünleştirme Dalgaları (rakip-kıyas sonrası)

> Bağlam: **MVP + Tier A + Tier B** (IDOR/BOLA, BFLA, BOPLA, injection ailesi, SSRF/XXE/RFI,
> CSRF, stored-XSS, session-lifecycle, exposure, info-leak, rate-limit, CVE/default-creds,
> server-side) **tamamlandı ve canlı doğrulandı.** Ardından **kalite turu Q1–Q3** (CWE/OWASP +
> deterministik severity · SARIF/CI · benchmark harness'i) bitti. Bu dosya artık, rakip/kıyas
> araştırması sonrası çıkan **ürünleştirme yol haritasının** (bkz. **[ROADMAP.md](ROADMAP.md)**)
> görevlerini Serhat ve Görkem arasında paylaştırır.
>
> Mimari/stil: **[DESIGN.md](DESIGN.md)** + **[CLAUDE.md](CLAUDE.md)** · Kalite turu artığı (Q4/Q5):
> **[GOREVLER_Q.md](GOREVLER_Q.md)** · Mimariye uymayan breadth: **[TIER_C.md](TIER_C.md)**.

Sorumluluklar **toplam yük eşit** olacak şekilde paylaştırıldı (**Serhat 30s / Görkem 31s**).
Atamalar değiştirilebilir — önemli olan yükün dengeli kalması. Görev gerekçeleri, kaynak makale
eşlemesi ve kabul kriterlerinin uzun hali **[ROADMAP.md](ROADMAP.md)**'de.

---

## Tamamlananlar (temizlendi)

- ✅ **Tier A** (A1–A6): access-control genişletmeleri, injection oracle, response-inspection,
  exposure, info-leak, user-enum + JWT.
- ✅ **Tier B** (B1–B8): write altyapısı + mass-assignment/file-upload/CSRF, timing (blind),
  stored-XSS + session, rate-limit/burst, recon/wordlist + GraphQL, OOB + SSRF/XXE/RFI,
  CVE + default-creds, server-side (prototype-pollution/cache-poisoning).
- ✅ **Kalite turu Q1–Q3**: CWE/OWASP + deterministik severity · SARIF + `--fail-on` + GitHub
  action · benchmark harness'i (Juice Shop'ta precision %100 / recall %100 canlı doğrulandı).
- ✅ **Ek düzeltmeler**: redaction'da kaçışlı-tırnak JSON bug'ı · `unauthorized_access`
  public-endpoint false-positive'i.

---

## Ortak ilkeler (her görev için — CLAUDE.md §3, §5, §6)

- **Değişmezler korunur:** LLM ağa dokunmaz · CONFIRMED'i yalnız kod verir (deterministik kanıt) ·
  kontroller geçmeden verdict yok · redaction zorunlu · scope kapısı her istekte. Yeni "canlı"
  yazma adımları `destructive_tests` + scope kapısı arkasında.
- **OOP + DI + Open/Closed:** yeni motor/entegrasyon constructor'dan enjekte edilir; mevcut
  sınıflar değiştirilmeden genişletilir.
- **Network'süz testler** (`httpx.MockTransport`/`respx`) her yol için; `pytest -q` yeşil olmadan
  merge yok. Uygun görevlerde **canlı kalibrasyon** (Juice Shop / VAmPI / crAPI).

---

## Dalga 1 — Güven derinleştirme *(en yüksek getiri)*

### R-A1 — Canary planting · *(Sorumlu: Serhat · ~7s)* ✅ tamamlandı
Tarama öncesi kurban hesabına **benzersiz işaret verisi** ek (B1 write kapısını kullanır); saldırgan
cevabında belirirse tartışmasız leaked-marker. **Kabul:** Juice Shop'ta canary'li IDOR'da FP=0,
marker canary değeriyle eşleşiyor. *(Kaynak: MAPTA, AuthProbe)*

### R-D1 — Per-role coverage + profil-etiketli bulgu · *(Sorumlu: Serhat · ~3s)* ✅ tamamlandı
Raporda "hangi aktör hangi endpoint'e ulaştı" tablosu; her bulgu keşfeden aktörle etiketli
("found as user_A"). **Kabul:** per-rol kapsam tablosu + profil etiketi raporda. *(Kaynak: Escape, StackHawk)*

### R-A3 — Çok-hedefli benchmark · *(Sorumlu: Görkem · ~8s)*
VAmPI + crAPI + Juice Shop; AuthProbe'un "vulnerable↔hardened ikiz, 0-FP" metodolojisi; advisory
metni gizlenir. **Kabul:** ≥3 hedef, ≥30 etiketli vaka, precision/recall/FP tablosu README'de.
*(Kaynak: AuthProbe, appsecsanta)*

### R-B1 — 2×2 yetki matrisi + çift-yönlü test · *(Sorumlu: Görkem · ~4s)*
(own/peer obje) × (own/higher rol) matrisi; A→B kadar B→A da test (asimetrik izolasyon).
**Kabul:** her iki yön test ediliyor, matris raporda, asimetrik sızıntı yakalanıyor. *(Kaynak: StingrAI)*

---

## Dalga 2 — Benimsenme + kanıt

### R-C1 — Baseline + diff modu · *(Sorumlu: Serhat · ~5s)* ✅ tamamlandı
Bilinen FP'ler baseline'da bastırılır, yalnız **yeni bulgu** raporlanır; "no silent drops"
(bastırılan sebebiyle raporda kalır). **Kabul:** `--baseline` ile yalnız yeni bulgular gate'ler.
*(Kaynak: Snyk, ZAP, p1-triage)*

### R-D2 — Dedup (`CWE+endpoint+param`) + agreement bump · *(Sorumlu: Serhat · ~3s)* ✅ tamamlandı
Rule-id değil kök-nedene göre grupla; `sources[]` izini koru; çok sinyal aynı bulguyu derse
confidence↑. SARIF fingerprint ile uyumlu. **Kabul:** aynı kök-neden tek grup. *(Kaynak: p1-triage)*

### R-A2 — Replay edilebilir kanıt paketi · *(Sorumlu: Görkem · ~5s)*
Her CONFIRMED bulguya tam istek/yanıt fixture'ı + çevrimdışı yeniden-ispat scripti. **Kabul:**
`runs/<id>/proof/<fid>.json` + `replay.py` bulguyu ağsız yeniden ispatlıyor. *(Kaynak: XBOW, Shannon, MAPTA)*

### R-C2 — LLM FP-triyajı (`likely_fp`) · *(Sorumlu: Görkem · ~4s)*
Yerel Ollama; verdict+confidence+reason döner; **asla silmez**, `likely_fp` işaretler; hata → `unreviewed`.
**Kabul:** LLM kapalıyken davranış aynı; açıkken etiket eklenir, verdict değişmez (§5). *(Kaynak: p1-triage)*

---

## Dalga 3 — Konumlandırma + olgunluk

### R-C3 — MCP tool-server · *(Sorumlu: Serhat · ~6s)* ✅ tamamlandı
`Replayer` + oracle'lar tipli **MCP araçları** olarak açılır → diğer ajanlar (Claude Code) Sentinel'i
"deterministik hâkim" olarak çağırır. **Kabul:** `sentinel-mcp` authorize→replay→oracle'ı tipli araç
olarak sunuyor. *(Kaynak: appsecsanta, strix)*

### R-D3 — Olgunluk paketi · *(Sorumlu: Serhat · ~6s)* ✅ tamamlandı
Kurulabilir CLI (`sentinel scan`), scan modları (quick/standard/deep), CVSS/EPSS, budget-tabanlı
erken durdurma (~40 çağrı / $0.30 / 300s). **Kabul:** `pip install` → `sentinel scan …`; modlar
bütçeyi ölçekliyor. *(Kaynak: StackHawk, strix, MAPTA, appsecsanta)*

### R-B2 — ID varyasyonu + iç-içe/dolaylı referans · *(Sorumlu: Görkem · ~5s)*
int & UUID; sadece URL'de değil gövde/ikinci-el lookup'taki obje id'leri. **Kabul:** gövdedeki obje
id'sinde IDOR CONFIRMED testi geçiyor. *(Kaynak: StingrAI)*

### R-B3 — Scalar inference / feedback-driven keşif · *(Sorumlu: Görkem · ~5s)*
Yanıtlardan veri ilişkisini çıkarıp `own_object_ids`'i otomatik bootstrap. **Kabul:** id'ler elle
verilmeden bulunabiliyor (Juice Shop). *(Kaynak: Escape)*

---

## Toplam yük (dengeli — 30/31)

| | Dalga 1 | Dalga 2 | Dalga 3 | Toplam |
|---|---|---|---|---|
| **Serhat** | R-A1(7) + R-D1(3) = 10 | R-C1(5) + R-D2(3) = 8 | R-C3(6) + R-D3(6) = 12 | **30 saat** |
| **Görkem** | R-A3(8) + R-B1(4) = 12 | R-A2(5) + R-C2(4) = 9 | R-B2(5) + R-B3(5) = 10 | **31 saat** |

**Önerilen sıra:** Dalga 1 önce (canary + benchmark + matris güven iddiasını rakiplerin ötesine
taşır) → Dalga 2 (CI benimsenmesi) → Dalga 3 (konumlandırma + olgunluk). Tier C, Dalga 1–2
oturmadan başlamaz.
