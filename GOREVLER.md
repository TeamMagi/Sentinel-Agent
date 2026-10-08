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
> **agent-security kıyası: [docs/rakip-analizi-agent-security-2026-09.md](docs/rakip-analizi-agent-security-2026-09.md)** ·
> kalite artığı: **[GOREVLER_Q.md](GOREVLER_Q.md)** · mimariye uymayan breadth: **[TIER_C.md](TIER_C.md)**.

Sorumluluklar **toplam yük eşit** olacak şekilde paylaştırılır. Atamalar değiştirilebilir —
önemli olan yükün dengeli kalması.

> **Durum (2026-09-17):** **RK turu bitti** — Serhat (RK-1, RK-3, RK-4, RK-8, RK-7, RK-11,
> RK-13 — 27s) ve Görkem (RK-2, RK-5, RK-6, RK-9, RK-10, RK-12 — 27s) görevlerinin **tamamı**
> tamamlandı. Yeni tur: **Dalga 5–6 (AS-1…AS-9)** — Kaggle "AI Agent Security" çözümlerinin
> incelenmesinden çıkan görevler (**Serhat 17s / Görkem 17s**).

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

- ✅ **Görkem — ikinci dalga (RK) tamamlandı** (473 test yeşil):
  - **RK-2** JUnit XML + CSV reporter'ları (`report/render_junit.py`, `report/render_csv.py`) →
    `runs/<id>/junit.xml` + `report.csv` (redaction'lı; verdict→test sonucu, kaynak-yetenek matrisi).
  - **RK-9** İmzalı/hash'li taşınabilir kanıt-paketi (`evidence/proof.py::build_bundle/verify_bundle`,
    `proof/<id>.bundle.json`, `scripts/replay.py` bundle desteği, `SENTINEL_PROOF_KEY` ile HMAC imza).
  - **RK-5** Scalar inference / feedback-driven keşif (`orchestrator/idtools.py::infer_resource_ids`
    + `recon/crawl.py::feedback_bootstrap`, scanner'a bağlı; ağsız test yeşil).
  - **RK-6** İç-içe/dolaylı id + UUID + gövde/header konumu (`models.Endpoint.with_id`) ve **sürümlü
    path resource_key çakışması** (`Endpoint.resource_key` sürüm segmentini atlar).
  - **RK-10** 0-FP negatif-ikiz regresyon paketi (`bench/twins.py`, `scripts/bench_guard.py`,
    `make bench-guard`, CI `bench-guard` işi) — hardened ikizde yanlış CONFIRMED → kırmızı.
  - **RK-12** Nuclei-tarzı YAML template ekosistemi (`detector/template.py::TemplateDetector`,
    `templates/*.yaml`, `--templates` bayrağı) — kötü template güvenle elenir, tarama çökmez.

- ✅ **Devir notu (`yapılacaklar.md`) kapandı ve dosya silindi** — zorunlu maddelerinin hepsi bitti:
  4 dalın `develop`'a merge'i, **bloke olan `origin` push'u**, `config/*/` git-ignore ve §7'deki
  **sürümlü-path `resource_key` çakışması** (RK-6 ile kalıcı çözüldü). Ortam notları (docker
  `sg docker -c`, juice-shop reset tuzağı, Ollama) README/DESIGN ve oturum hafızasında duruyor.
  **Devrolan tek açık madde — recall FN'leri (opsiyonel):** (a) `excessive_data_exposure`/
  `mass_assignment` yalnız id-taşıyan veya PUT/PATCH/DELETE endpoint'lerde hipotez üretiyor →
  id-siz (`/users/v1/_debug`) ve POST (`register`) vakaları kaçıyor; (b) crAPI SSRF/NoSQLi
  **gövde-parametresi** testi read-only kapsamda çalışmıyor. İkisi de Dalga 2 (recall/kapsam)
  ruhunda; ayrı görev olarak açılabilir.

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

### ✅ RK-1 — Write→verify→restore→verify güvenli-yazma döngüsü · *(Sorumlu: Serhat · ~6s)* — **tamamlandı**
`StateChangingOracle.run()` artık mutasyon tespit edilince (verdict'ten bağımsız) kurbanın
objesini kendi session'ıyla eski haline döndürüp okuyarak doğruluyor (`_restore_if_mutated`).
DELETE'te otomatik geri alma yok (kaynağı yeniden yaratacak genel yol yok) → `Evidence.
recovery_state`'e orijinal gövde kaydediliyor; PUT/PATCH/POST'ta restore yazması/doğrulaması
başarısız olursa da aynı şekilde. `CanaryPlanter.generate_value()` ile birleşti: canary_planter
enjekte edilirse sabit sentinel (8931) yerine paylaşılan rastgele/tahmin-edilemez değer
kullanılıyor. `tests/test_oracle_state_change.py`: restore-başarı, DELETE recovery_state,
restore-hatası ve canary-entegrasyonu yolları ağsız kapsandı. *(Kaynak: OpenBOLA)*

### ✅ RK-2 — JUnit XML + CSV reporter'ları · *(Sorumlu: Görkem · ~3s)* — **tamamlandı**
Mevcut `Reporter` ABC'sine iki alt sınıf: `report/render_junit.py` (CI test-paneli) +
`report/render_csv.py` (resource-capability matrisi). Verdict/veri değişmez, redaction korunur.
**Kabul:** `runs/<id>/` altında `junit.xml` + `report.csv`; GitHub/GitLab test sekmesi bulguları
gösteriyor; ağsız render testi geçiyor. *(Kaynak: OpenBOLA, StackHawk)*

### ✅ RK-3 — GraphQL BOLA oracle'ı (verdict üreten) · *(Sorumlu: Serhat · ~5s)* — **tamamlandı**
`oracle/graphql_bola.GraphqlBolaOracle`: `recon/graphql.py`'nin bulduğu (field, id_arg)
adaylarını iki aktörle koşup IdorOracle'la aynı 3-kontrol + leaked-marker disiplinini uygular.
GraphQL'e özgü "erişim yok" biçimlerini (HTTP 200 + `errors` ya da `data.<field>: null`) status
koduna güvenmeden tanır; sorgu GET+`?query=` ile gider (introspection'daki desenle aynı —
salt-okunur, `destructive_tests` gerektirmez). `Scanner.discover_more` bulunan adayları otomatik
test ediyor. `tests/test_oracle_graphql_bola.py` (5 test) + `classify.py`'ye `graphql_bola`
eklendi (eksikti, düzeltildi). *(Kaynak: Escape)*

### ✅ RK-4 — Çift-yönlü 2×2 yetki matrisi (oracle koşumu) · *(Sorumlu: Serhat · ~4s)* — **tamamlandı**
Doğrulandı: `Scanner.run_hypotheses`'ın `idor`/`state_change_authz`/`method_bypass`/`stored_xss`
dispatch döngüleri (her victim × her attacker, kendisi hariç) **zaten** A→B kadar B→A'yı koşuyordu
— eksik olan, `report/matrix.py`'nin bunu gerçek (stub değil) oracle kararlarıyla uçtan uca
doğrulayan bir testti. `tests/test_scanner_matrix.py`: asimetrik ownership-check'li (yalnızca
B'nin objesi korunuyor) sahte API → `run_hypotheses` gerçekten iki yönü de koşuyor (B→A CONFIRMED,
A→B REJECTED) → `build_auth_matrix` asimetrik izolasyonu gerçek bulgulardan yakalıyor → Markdown
raporda görünüyor. *(Kaynak: AuthMatrix, StingrAI)*

### ✅ RK-9 — İmzalı taşınabilir kanıt-paketi (proof bundle) · *(Sorumlu: Görkem · ~4s)* — **tamamlandı**
Mevcut `proof/<fid>.json`'ın üstüne **imzalı/hash'li, çevrimdışı yeniden-ispatlanabilir** bundle
(repro script + bütünlük hash'i) → bulgu bir güvenlik ekibine/bug-bounty'ye **değiştirilemez
kanıtla** teslim edilir. **Kabul:** bundle üretiliyor, hash doğrulanınca `scripts/replay.py` ağsız
PROVEN veriyor, tahrifte FAILED. *(Kaynak: XBOW, Shannon; net-yeni)*

---

## Dalga 2 — Kapsam / recall derinleştirme

### ✅ RK-5 — Scalar inference / feedback-driven keşif · *(Sorumlu: Görkem · ~5s)* — **tamamlandı**
R-B3'ü tamamla: yanıtlardan obje ilişkilerini çıkarıp `own_object_ids`'i **elle vermeden** bootstrap
(kurulum gerektiren BOLA FN'lerini azaltır). **Kabul:** Juice Shop'ta id'ler config'te verilmeden
bulunabiliyor; ağsız çıkarım testi geçiyor. *(Kaynak: Escape)*

### ✅ RK-6 — İç-içe / dolaylı id + UUID varyasyonu · *(Sorumlu: Görkem · ~5s)* — **tamamlandı**
R-B2'yi tamamla: yalnız URL'de değil **gövde/ikinci-el lookup'taki** obje id'leri; int **ve** UUID.
`resource_key` çakışması (sürümlü path'ler) da burada çözülür. **Kabul:** gövdedeki obje id'sinde
IDOR CONFIRMED testi geçiyor; UUID id yolu kapsanıyor. *(Kaynak: StingrAI)*

### ✅ RK-8 — Provider adapter'ları (modern backend keşfi) · *(Sorumlu: Serhat · ~5s)* — **tamamlandı**
`recon/providers.py`: `ProviderAdapter` (ABC) + `PostgrestAdapter`/`SupabaseAdapter`/
`HasuraAdapter`/`FirebaseAdapter`. Her biri yalnızca GERÇEKTEN gözlenen bir imza (OpenAPI
şeması, GoTrue health, Hasura `/v1/version` şekli, Firebase RTDB host+`.json`) varsa evidence
döner; PostgREST/Supabase tablo envanterini kendi şemasından okur (tahmin değil).
`Scanner.discover_more` bulunan envanteri endpoint listesine ekliyor. `tests/
test_recon_providers.py` (10 test, ağsız). *(Kaynak: OpenBOLA)*

---

## Dalga 3 — Benimsenme / konumlandırma / gizlilik

### ✅ RK-7 — Raporda opak handle'lar · *(Sorumlu: Serhat · ~2s)* — **tamamlandı**
`report/anonymize.HandleAnonymizer`: aktör adlarını `identity-N`'e, bilinen kaynak id'lerini
`obj-<hash6>`'a çevirir (kelime-sınırı korumalı regex — kısa id'ler alakasız sayılara
karışmaz); eşleme yalnızca bellekte, hiçbir yere yazılmaz. `Scanner.save(anon_handles=True)`
(CLI `--anon-handles`) yalnızca Markdown/HTML'e uygular — `findings.json`/SARIF/proof gerçek
veriyle kalır (CI/replay bozulmaz). HtmlReporter'ın gömdüğü yapısal `json_body` de ayrıca
temizlendi. `tests/test_report_anonymize.py` + `tests/test_scanner_anon.py` (uçtan uca).
*(Kaynak: OpenBOLA)*

### ✅ RK-10 — "0-FP negative-twin" regresyon paketi · *(Sorumlu: Görkem · ~4s)* — **tamamlandı**
Benchmark'taki "vulnerable↔hardened ikiz" setini **CI regresyon paketi** olarak ürünleştir →
kullanıcı kendi pipeline'ında "FP hâlâ 0 mı?" diye koşar. **Kabul:** `make bench-guard` (veya CI
job) negatif-ikiz vakalarında yanlış CONFIRMED çıkarsa kırmızıya döner. *(Kaynak: AuthProbe; net-yeni)*

### ✅ RK-11 — Air-gap / gizlilik modu · *(Sorumlu: Serhat · ~3s)* — **tamamlandı**
`airgap.AirgapPolicy` (saf karar kapısı — `PolicyEngine.authorize` gibi): CLI `--offline`
verilince `_build_llm` bulut sağlayıcıyı (gemini/anthropic) istemci kurulmadan ÖNCE
`AirgapViolation` ile reddeder + loglar (fail-closed); yalnızca yerel Ollama/LLM'siz koşuma
izin verir. Asıl sızıntı yüzeyi LLM client'ların kendi httpx/SDK bağlantısıydı (Replayer/
PolicyEngine'den hiç geçmiyor) — hedefe giden trafik zaten scope'la sınırlıydı. Telemetri kod
tabanında hiç yoktu (arandı, doğrulandı) — bayrak bu boşluğu resmîleştiriyor. `tests/
test_airgap.py` (9 test, ağsız). *(Kaynak: Akto, OpenBOLA; net-yeni)*

### ✅ RK-12 — Nuclei-tarzı topluluk template ekosistemi · *(Sorumlu: Görkem · ~6s)* — **tamamlandı**
Dedektör ailesini bir **YAML template formatına** aç → topluluk yeni imza/misconfig ekler, çekirdek
kod değişmeden breadth büyür. `detector/` bir `TemplateDetector` ile template yükler. **Kabul:** en
az bir dedektör template'ten sürülüyor; kötü template güvenle eleniyor (tarama çökmez); ağsız test.
*(Kaynak: Nuclei; net-yeni)*

### ✅ RK-13 — MCP "deterministik hâkim" konumlandırma · *(Sorumlu: Serhat · ~2s)* — **tamamlandı**
README'nin MCP tool-server bölümüne konumlandırma anlatısı (XBOW/Strix tarzı ajanik araçların
zero-FP garantisi veremediği yer) + çalışan bir **"Claude Code + sentinel-mcp"** örnek akışı
eklendi (`claude mcp add` / `.mcp.json` + `list_actors`→`run_oracle` örnek diyaloğu). Kod
değişmedi, yalnızca doküman. *(Kaynak: strix, appsecsanta)*

---

## Dalga 5 — Agent-security: yeni saldırı yüzeyi *(Kaggle kıyasından)*

> Gerekçe ve kaynak inceleme: **[docs/rakip-analizi-agent-security-2026-09.md](docs/rakip-analizi-agent-security-2026-09.md)**.
> Kaggle "AI Agent Security – Multi-Step Tool Attacks" yarışmasının **dört güvenlik predicate'i**
> (EXFILTRATION · UNTRUSTED_TO_ACTION · DESTRUCTIVE_WRITE · CONFUSED_DEPUTY) bize **ölçülebilir ve
> deterministik kanıtlanabilir** yeni bir yüzey açıyor. Bizde zaten LLM + **MCP tool-server** +
> canary + redaction var; predicate'ler mevcut sınıflar DEĞİŞTİRİLMEDEN yeni `Oracle` alt sınıfları
> olarak eklenir (Open/Closed).
>
> **Etik/scope (CLAUDE.md §10):** yalnızca sahibi olunan veya açık yazılı yetki verilen ajan/MCP
> hedefleri; `UNTRUSTED_TO_ACTION` + `DESTRUCTIVE_WRITE` **`destructive_tests` + scope kapısı**
> arkasında; canary sırlar sentetik, redaction zorunlu.

### AS-1 — Agent hedef adaptörü + `AgentOracle` soyut tabanı · *(Sorumlu: Serhat · ~5s)*
Sentinel'i bir LLM-ajan/MCP hedefine bağlayan adaptör: ajanın **trace**'inden tipli modeller
(`ToolCall`, `AgentTrace` — çağrı adı, argümanlar, çıktının **kaynağı**) + `AgentOracle(ABC)`.
Diğer üç predicate oracle'ı bunun üstüne kurulur. Tüm ajan trafiği `Replayer`/scope kapısından
geçer; LLM ağa dokunmaz (değişmez §5.1). **Kabul:** sahte ajan trace'iyle ağsız test; yeni predicate
eklemek çekirdeği değiştirmiyor; scope dışı tool çağrısı reddedilip loglanıyor. *(Kaynak: yarışma SDK'sı)*

### AS-2 — `ConfusedDeputyOracle` + `DestructiveWriteOracle` · *(Sorumlu: Görkem · ~5s)*
**CD:** açık kullanıcı niyeti olmadan yan-etkili tool-call (ör. `email.send`) tetiklendi mi.
**DW:** `fs.write`/`fs.delete` korumalı kaynağı hedefliyor mu. Verdict yalnız deterministik trace
kanıtıyla; DW yalnızca `destructive_tests` açıkken. **Kabul:** her iki oracle için CONFIRMED ve
REJECTED yolları ayrı ağsız test; kullanıcı aksiyonu **açıkça istediğinde** CD REJECTED (FP kapanı).
*(Kaynak: predicate CONFUSED_DEPUTY / DESTRUCTIVE_WRITE)*

### AS-3 — `UntrustedToActionOracle` (prompt-injection → aksiyon) · *(Sorumlu: Serhat · ~6s)*
**Benign kullanıcı + saldırgan kontrolündeki dış içerik** tehdit modeli (1. çözümün kapanışta
önerdiği ayrım): güvenilmez içeriğe (`web.search`/`email.read`/tool çıktısı) gömülü yönerge
ayrıcalıklı bir aksiyonu tetikliyor mu. **Kaynak-izleme** (hangi güvenilmez çıktı hangi aksiyonu
besledi) kanıt olarak kaydedilir. **Kabul:** enjeksiyon→aksiyon zinciri CONFIRMED; aynı aksiyonu
kullanıcı kendi istediğinde REJECTED; ağsız test. *(Kaynak: predicate UNTRUSTED_TO_ACTION; Agent-Sentry)*

### AS-4 — `ExfiltrationOracle` + canary sır · *(Sorumlu: Görkem · ~5s)*
`CanaryPlanter` (R-A1) mantığını ajana taşı: sentetik `SECRET_MARKER` canary'si dışarı giden çağrıda
(ör. `http.post` gövdesi) görünüyor mu — **geri-döndürülebilir encode** (base64/hex/url) varyantları
dahil. Canary rapora/evidence'a ham yazılmaz. **Kabul:** düz **ve** encode edilmiş sızıntı CONFIRMED;
sır dışarı çıkmadığında REJECTED; redaction testi; ağsız. *(Kaynak: predicate EXFILTRATION)*

---

## Dalga 6 — Metodoloji ve olgunluk

### AS-5 — Holdout hedef + genelleme raporu · *(Sorumlu: Görkem · ~4s)*
Yarışmanın **public ↔ private guardrail** ayrımının karşılığı: bugün 3 benchmark hedefinin **hepsini**
kalibre ediyoruz, hiçbiri "dokunmadığımız" holdout değil → overfit'i ölçemiyoruz. `suite.yaml`'a
`holdout: true` işaretli hedef(ler) ekle; rapor **kalibre ↔ holdout** metriklerini AYRI tablolarda
versin. **Kabul:** holdout hedefli suite değerlendirmesi; rapor iki tabloyu ayrı gösteriyor; ağsız
değerlendirme testi. *(Kaynak: yarışma private-LB mimarisi)*

### AS-6 — Robustluk marjı (drift'e dayanıklı CONFIRMED) · *(Sorumlu: Serhat · ~3s)*
1. çözümün skoru 44.5→46.5 yapan dersi: **kıl payı geçen kanıt, ortam değişince kaybolur** (llama.cpp
sürümü logitleri 2'ye kadar kaydırıyordu). Bizde karşılığı: oracle kararın **ne kadar rahat**
verildiğini raporlasın (kaç owner-private marker sızdı, baseline'dan ayrışma miktarı); düşük marjlı
CONFIRMED'ler raporda **işaretlensin** (verdict değişmez). **Kabul:** `Evidence`'a marj alanı; düşük
marj raporda görünür; marj hesabı ağsız testlerle kapsanıyor. *(Kaynak: 1. çözüm — margin > +5)*

### AS-7 — Sürüm bütünlüğü: dosya manifesti + `verify_release` · *(Sorumlu: Görkem · ~3s)*
RK-9'u (bulgu bazlı imzalı bundle) **repo/sürüm düzeyine** taşı: yayımlanan artefaktların hash
manifesti + `scripts/verify_release.py` — **ağsız, hedefsiz, yalnız stdlib** ile manifest/JSON/rapor
aritmetiğini ve yerel doküman linklerini doğrular. **Kabul:** `python -m scripts.verify_release`
ağsız çalışıp temizde 0, bozulmuş artefaktta non-zero döner; ağsız test. *(Kaynak: 5. çözüm — provenance)*

### AS-9 — Ops olgunluğu: ruff + terimler sözlüğü + `experiments/` düzeni · *(Sorumlu: Serhat · ~3s)*
Depoda **fiilen linter yok**. `ruff` (`E,W,F,I,UP,B,SIM`) + `make lint` + CI lint işi; `docs/sozluk.md`
(oracle/detector/marker/verdict/canary/holdout… terim birliği); benchmark koşuları için
`experiments/<ad>/` düzeni (tek doğruluk kaynağı: değerlendirilen konfig = koşulan konfig).
**Kabul:** `make lint` temiz; sözlük README/DESIGN'dan linkli; CI'da lint kapısı var.
*(Kaynak: 3. repo — harness/ops disiplini)*

---

## Stretch — açık uçlu *(Dalga 5–6 oturunca)*

### AS-8 — Arşiv-güdümlü (Go-Explore) + evrimsel hipotez araması · *(Ortak · açık uçlu)*
Yarışmanın önerdiği arama aileleri (novelty search, trace-guided mutation, **Go-Explore** tarzı
"umut verici durumu arşivle, oradan devam et") ve 1. çözümün **GCG öncesi evrimsel sıcak-başlatması**
("semantik gen": ifade, sıra, layout) bizim hipotez üreticimize uyarlanır: endpoint/id/param
adaylarını geri beslemeyle mutasyona sok, çeşitliliği koru. Efor açık uçlu → **yük dengesine
sayılmaz**; RK-14 ile birlikte ele alınır. *(Kaynak: 1. çözüm + yarışma "önerilen yaklaşımlar")*

### RK-14 — Çok-ajan planner-executor + rol uzmanlaşması · *(Ortak · açık uçlu)*
`--scouts` paralel var; üstüne **planner→executor→verifier** rol ayrımı + task-graph (çok-ajan >
tek-ajan 4.3×). CHECKMATE dersi: uzun-ufuklu planlamayı LLM yerine **deterministik planlayıcıya** ver.
Efor açık uçlu → yük dengesine sayılmaz; Dalga 1–2 bitmeden başlanmaz. *(Kaynak: HPTSA/MAPTA, CHECKMATE)*

---

## Toplam yük

### Biten tur — RK (Dalga 1–3): 27/27 ✅

| | Dalga 1 | Dalga 2 | Dalga 3 | Toplam |
|---|---|---|---|---|
| **Serhat** ✅ | RK-1(6) + RK-3(5) + RK-4(4) = 15 | RK-8(5) = 5 | RK-7(2) + RK-11(3) + RK-13(2) = 7 | **27 saat — bitti** |
| **Görkem** ✅ | RK-2(3) + RK-9(4) = 7 | RK-5(5) + RK-6(5) = 10 | RK-10(4) + RK-12(6) = 10 | **27 saat — bitti** |

### Yeni tur — AS (Dalga 5–6, agent-security kıyasından): **dengeli 17/17**

| | Dalga 5 (agent-security) | Dalga 6 (metodoloji) | Toplam |
|---|---|---|---|
| **Serhat** | AS-1(5) + AS-3(6) = 11 | AS-6(3) + AS-9(3) = 6 | **17 saat** |
| **Görkem** | AS-2(5) + AS-4(5) = 10 | AS-5(4) + AS-7(3) = 7 | **17 saat** |

**Önerilen sıra:** **AS-1 önce** (adaptör + `AgentOracle` tabanı; AS-2/AS-3/AS-4 ona bağlı) → sonra
predicate oracle'ları paralel (AS-2 ‖ AS-3 ‖ AS-4) → Dalga 6 metodoloji (AS-5 holdout ile
benchmark'ın genelleme körlüğü kapanır; AS-6/AS-7/AS-9 bağımsız, her an alınabilir). Stretch'ler
(**AS-8**, **RK-14**) ancak Dalga 5–6 oturunca; Tier C hepsinden sonra.
