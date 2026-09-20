# Görev Listesi — Rakip-Kıyas İkinci Dalga (2026-09)

> Bağlam: **MVP + Tier A + Tier B**, **kalite turu Q1–Q3** ve **ürünleştirme yol haritasının
> (ROADMAP) tüm ana maddeleri** (canary, proof-pack, çok-hedefli benchmark, baseline, LLM FP-triyaj,
> MCP, per-role coverage, dedup, olgunluk paketi) **tamamlandı ve canlı doğrulandı** (437 test yeşil).
> Bu dosya artık **yeni rakip/benzer-proje araştırmasından** (bkz.
> **[docs/rakip-analizi-2026-09.md](docs/rakip-analizi-2026-09.md)**) çıkan görevleri Serhat ve
> Görkem arasında paylaştırır.
>
> Mimari/stil: **[DESIGN.md](DESIGN.md)** + **[CLAUDE.md](CLAUDE.md)** · uzun kıyas/gerekçe:
> **[docs/rakip-analizi-2026-09.md](docs/rakip-analizi-2026-09.md)** + **[ROADMAP.md](ROADMAP.md)** ·
> kalite artığı: **[GOREVLER_Q.md](GOREVLER_Q.md)** · mimariye uymayan breadth: **[TIER_C.md](TIER_C.md)**.

Sorumluluklar **toplam yük eşit** olacak şekilde paylaştırıldı (**Serhat 27s / Görkem 27s**).
Atamalar değiştirilebilir — önemli olan yükün dengeli kalması.

---

## Tamamlananlar (temizlendi)

- ✅ **Tier A** (A1–A6): access-control genişletmeleri, injection oracle, response-inspection,
  exposure, info-leak, user-enum + JWT.
- ✅ **Tier B** (B1–B8): write altyapısı + mass-assignment/file-upload/CSRF, timing (blind),
  stored-XSS + session, rate-limit/burst, recon/wordlist + GraphQL, OOB + SSRF/XXE/RFI,
  CVE + default-creds, server-side (prototype-pollution/cache-poisoning).
- ✅ **Kalite turu Q1–Q3**: CWE/OWASP + deterministik severity · SARIF + `--fail-on` + GitHub
  action · benchmark harness'i.
- ✅ **ROADMAP Dalga 1–3 (rakip-kıyas ürünleştirme) — hepsi bitti:**
  - **R-A1** Canary planting (`oracle/canary.py`) · **R-A2** Replay edilebilir kanıt paketi
    (`evidence/proof.py` + `scripts/replay.py` + `runs/<id>/proof/<fid>.json`) · **R-A3** Çok-hedefli
    benchmark (`scripts/benchmark.py` — **3 hedef / 31 vaka / precision %100 · recall %61.5 · FP %0**).
  - **R-C1** Baseline + diff (`report/baseline.py`, `--baseline`) · **R-C2** LLM FP-triyaj
    (`triage.py`, `--triage-fp`, `likely_fp`) · **R-C3** MCP tool-server (`mcpserver.py`, `sentinel-mcp`).
  - **R-D1** Per-role coverage (`report/coverage.py`) · **R-D2** Dedup + agreement bump
    (`report/dedup.py`) · **R-D3** Olgunluk paketi (kurulabilir `sentinel scan` + scan-mode + CVSS/EPSS).
- 🟡 **Kısmen biten — kalan dilim aşağıda yeni göreve taşındı:**
  - **R-B1** 2×2 matris **raporu** (`report/matrix.py`, asimetrik izolasyon tespiti) hazır → kalan
    **çift-yönlü oracle koşumu** → **RK-4**.
  - **R-B2** UUID/id-şekli altyapısı (`orchestrator/idtools.py`) hazır → kalan **iç-içe/dolaylı id** → **RK-6**.
  - **R-B3** feedback bootstrap izi (`scanner.py`/`recon/crawl.py`) var → kalan **scalar inference** → **RK-5**.
- ✅ **Ek düzeltmeler**: redaction'da kaçışlı-tırnak JSON bug'ı · `unauthorized_access`
  public-endpoint false-positive'i · LLM erişilemezse deterministik yol · proof-replay redaksiyon tutarlılığı.

---

## Ortak ilkeler (her görev için — CLAUDE.md §3, §5, §6)

- **Değişmezler korunur:** LLM ağa dokunmaz · CONFIRMED'i yalnız kod verir (deterministik kanıt) ·
  kontroller geçmeden verdict yok · redaction zorunlu · scope kapısı her istekte. Yeni "canlı"
  yazma adımları `destructive_tests` + scope kapısı arkasında.
- **OOP + DI + Open/Closed:** yeni motor/entegrasyon constructor'dan enjekte edilir; mevcut
  sınıflar değiştirilmeden **yeni sınıf** olarak genişletilir.
- **Network'süz testler** (`httpx.MockTransport`/`respx`) her yol için; `pytest -q` yeşil olmadan
  merge yok. Uygun görevlerde **canlı kalibrasyon** (Juice Shop / VAmPI / crAPI).

---

## Dalga 1 — Güven + kanıt motoru *(en yüksek getiri)*

### RK-1 — Write→verify→restore→verify güvenli-yazma döngüsü · *(Sorumlu: Serhat · ~6s)*
`StateChangingOracle`'a güvenli-yazma protokolü: operatör-onaylı test değeri **yaz** → yazıldığını
**doğrula** → **geri al** → geri alındığını **doğrula**; yarıda kalırsa `recovery_state` kaydet;
state-changing'de otomatik retry yasak (§10.11). `CanaryPlanter` ile birleşir. **Kabul:** Juice
Shop'ta güvenli yazma-authz testi çalışır, mutasyon her koşumda geri alınır, ağsız testte
restore-doğrulama yolu kapsanır. *(Kaynak: OpenBOLA)*

### RK-2 — JUnit XML + CSV reporter'ları · *(Sorumlu: Görkem · ~3s)*
Mevcut `Reporter` ABC'sine iki alt sınıf: `report/render_junit.py` (CI test-paneli) +
`report/render_csv.py` (resource-capability matrisi). Verdict/veri değişmez, redaction korunur.
**Kabul:** `runs/<id>/` altında `junit.xml` + `report.csv`; GitHub/GitLab test sekmesi bulguları
gösteriyor; ağsız render testi geçiyor. *(Kaynak: OpenBOLA, StackHawk)*

### RK-3 — GraphQL BOLA oracle'ı (verdict üreten) · *(Sorumlu: Serhat · ~5s)*
`recon/graphql.py` aday sorgu üretiyor ama verdict vermiyor. `GraphqlBolaOracle`: iki aktörle
`build_query()` gövdesini koşup leaked-marker/differential uygular (verdict yalnız Oracle'dan).
**Kabul:** GraphQL hedefte `id`-argümanlı sorguda CONFIRMED/REJECTED yolu ayrı ayrı test edilir.
*(Kaynak: Escape)*

### RK-4 — Çift-yönlü 2×2 yetki matrisi (oracle koşumu) · *(Sorumlu: Serhat · ~4s)*
R-B1'in kalan dilimi: `report/matrix.py` raporu hazır; scanner artık (own/peer obje)×(own/higher rol)
için **A→B kadar B→A** koşsun → asimetrik izolasyon gerçek koşumla yakalanır. **Kabul:** iki yön de
test ediliyor, matris raporda dolu, tek-yön sızıntı işaretleniyor. *(Kaynak: AuthMatrix, StingrAI)*

### RK-9 — İmzalı taşınabilir kanıt-paketi (proof bundle) · *(Sorumlu: Görkem · ~4s)*
Mevcut `proof/<fid>.json`'ın üstüne **imzalı/hash'li, çevrimdışı yeniden-ispatlanabilir** bundle
(repro script + bütünlük hash'i) → bulgu bir güvenlik ekibine/bug-bounty'ye **değiştirilemez
kanıtla** teslim edilir. **Kabul:** bundle üretiliyor, hash doğrulanınca `scripts/replay.py` ağsız
PROVEN veriyor, tahrifte FAILED. *(Kaynak: XBOW, Shannon; net-yeni)*

---

## Dalga 2 — Kapsam / recall derinleştirme

### RK-5 — Scalar inference / feedback-driven keşif · *(Sorumlu: Görkem · ~5s)*
R-B3'ü tamamla: yanıtlardan obje ilişkilerini çıkarıp `own_object_ids`'i **elle vermeden** bootstrap
(kurulum gerektiren BOLA FN'lerini azaltır). **Kabul:** Juice Shop'ta id'ler config'te verilmeden
bulunabiliyor; ağsız çıkarım testi geçiyor. *(Kaynak: Escape)*

### RK-6 — İç-içe / dolaylı id + UUID varyasyonu · *(Sorumlu: Görkem · ~5s)*
R-B2'yi tamamla: yalnız URL'de değil **gövde/ikinci-el lookup'taki** obje id'leri; int **ve** UUID.
`resource_key` çakışması (sürümlü path'ler) da burada çözülür. **Kabul:** gövdedeki obje id'sinde
IDOR CONFIRMED testi geçiyor; UUID id yolu kapsanıyor. *(Kaynak: StingrAI)*

### RK-8 — Provider adapter'ları (modern backend keşfi) · *(Sorumlu: Serhat · ~5s)*
`recon/` altında opsiyonel adaptörler: Hasura / Supabase / PostgREST / Firebase trafiğinden
**normalize envanter** → own-object bootstrap'ı güçlendirir. Adaptör etiketi yalnız gözlenen
kanıtı tanımlar (protokol iddiası değil). **Kabul:** en az bir backend için gözlenen trafikten
endpoint/obje envanteri çıkarılıyor; ağsız test. *(Kaynak: OpenBOLA)*

---

## Dalga 3 — Benimsenme / konumlandırma / gizlilik

### RK-7 — Raporda opak handle'lar · *(Sorumlu: Serhat · ~2s)*
Aktör adı/id yerine opak takma-ad (`identity-1`, `obj-7f…`) — redaksiyonun üstüne bir gizlilik
katmanı (rapor paylaşılınca kimlik sızmaz). **Kabul:** rapor/HTML'de gerçek aktör adı/ham id yok,
eşleme tablosu yalnız yerelde. *(Kaynak: OpenBOLA)*

### RK-10 — "0-FP negative-twin" regresyon paketi · *(Sorumlu: Görkem · ~4s)*
Benchmark'taki "vulnerable↔hardened ikiz" setini **CI regresyon paketi** olarak ürünleştir →
kullanıcı kendi pipeline'ında "FP hâlâ 0 mı?" diye koşar. **Kabul:** `make bench-guard` (veya CI
job) negatif-ikiz vakalarında yanlış CONFIRMED çıkarsa kırmızıya döner. *(Kaynak: AuthProbe; net-yeni)*

### RK-11 — Air-gap / gizlilik modu · *(Sorumlu: Serhat · ~3s)*
`--offline`/gizlilik modu: dışa **hiç** ağ yok (hedef dışı), telemetri yok; LLM yalnız yerel Ollama'ya
izinli. "Hedef verisi makineden çıkmaz" garantisini resmîleştir. **Kabul:** modda bulut LLM/dış istek
denemesi bloklanıp loglanıyor; ağsız test kanıtlıyor. *(Kaynak: Akto, OpenBOLA; net-yeni)*

### RK-12 — Nuclei-tarzı topluluk template ekosistemi · *(Sorumlu: Görkem · ~6s)*
Dedektör ailesini bir **YAML template formatına** aç → topluluk yeni imza/misconfig ekler, çekirdek
kod değişmeden breadth büyür. `detector/` bir `TemplateDetector` ile template yükler. **Kabul:** en
az bir dedektör template'ten sürülüyor; kötü template güvenle eleniyor (tarama çökmez); ağsız test.
*(Kaynak: Nuclei; net-yeni)*

### RK-13 — MCP "deterministik hâkim" konumlandırma · *(Sorumlu: Serhat · ~2s)*
MCP tool-server bizde var ama pazarlanmıyor; sektörde en hızlı büyüyen kalıp ve rakiplerde yok.
README/demo'ya "diğer AI ajanlarının kanıt motoru" hikâyesi + bir **"Claude Code + sentinel-mcp"**
örnek akışı ekle. **Kabul:** çalışan örnek akış + docs bölümü; kod değişmez (doküman/demo).
*(Kaynak: strix, appsecsanta)*

---

## Dalga 4 — Stretch *(açık uçlu — Dalga 1–3 oturunca)*

### RK-14 — Çok-ajan planner-executor + rol uzmanlaşması · *(Ortak · açık uçlu)*
`--scouts` paralel var; üstüne **planner→executor→verifier** rol ayrımı + task-graph (çok-ajan >
tek-ajan 4.3×). CHECKMATE dersi: uzun-ufuklu planlamayı LLM yerine **deterministik planlayıcıya** ver.
Efor açık uçlu → yük dengesine sayılmaz; Dalga 1–2 bitmeden başlanmaz. *(Kaynak: HPTSA/MAPTA, CHECKMATE)*

---

## Toplam yük (dengeli — 27/27)

| | Dalga 1 | Dalga 2 | Dalga 3 | Toplam |
|---|---|---|---|---|
| **Serhat** | RK-1(6) + RK-3(5) + RK-4(4) = 15 | RK-8(5) = 5 | RK-7(2) + RK-11(3) + RK-13(2) = 7 | **27 saat** |
| **Görkem** | RK-2(3) + RK-9(4) = 7 | RK-5(5) + RK-6(5) = 10 | RK-10(4) + RK-12(6) = 10 | **27 saat** |

**Önerilen sıra:** Dalga 1 önce (write-restore güvenlik döngüsü + JUnit/CSV CI çıktıları + GraphQL
BOLA verdict güven/benimsenme iddiasını rakiplerin ötesine taşır) → Dalga 2 (recall/kapsam) → Dalga 3
(konumlandırma + gizlilik). RK-14 (çok-ajan) ancak Dalga 1–2 oturunca. Tier C, bunların hepsinden sonra.
