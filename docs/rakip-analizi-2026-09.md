# Rakip / Benzer Proje Araştırması ve Kıyas Raporu

> **Tarih:** 2026-09-16 · **Kapsam:** Sentinel-Agent'a benzer, web'de paylaşılan ücretli/ücretsiz
> projelerin taranması, bizimle karşılaştırılması ve "ne alabiliriz / ne ekleyebiliriz" önerileri.
> **İlişki:** Bu rapor [ROADMAP.md](../ROADMAP.md)'in kıyas bölümünü **güncel web araştırmasıyla
> tazeler**; ROADMAP'te "boşluk" olarak listelenen birçok madde (canary, baseline, MCP, per-role
> coverage, dedup, çok-hedefli benchmark, kurulabilir CLI) **bu tarihte kapandı** — aşağıdaki tablo
> güncel durumu yansıtır. Değişmez tez korunur: *LLM akıl yürütür, deterministik motor kanıtlar.*

---

## 0. Yönetici özeti

Sentinel-Agent'ın oturduğu alan artık "meraklı proje" değil, **olgun bir kategori**: Mart 2026
itibarıyla ~70 açık kaynak AI-pentest ajanı var (2023'te 5'ten az). Bizim tam yaptığımız işin —
**çok-aktörlü, kanıt-temelli, deterministik BOLA/IDOR doğrulaması** — birebir karşılığı olan
projeler bu yıl belirginleşti. En yakın ikiz **OpenBOLA** (Apache-2.0); akademik referans
**AuthProbe**; klasik pratisyen araçları **Autorize / AuthMatrix** (Burp eklentileri); ticari
API-DAST cephesi **Escape / Akto / StackHawk**; ve otonom AI ajanları **XBOW / Strix / PentestGPT**.

**Ana bulgu:** Sentinel'in temel mimari tezi (*"CONFIRMED kararını yalnız kod verir, LLM oy
kullanamaz"*) sektörün gittiği yönle **birebir örtüşüyor** ve hatta ondan katı. Bağımsız araştırma
(appsecsanta 2026, CHECKMATE, ARTEMIS) net söylüyor: kazanan formül *breadth* (daha çok zafiyet tipi)
değil, **güven + benchmark + benimsenme**; ve "LLM'i uzun-ufuklu planlamaya sokma, deterministik
motora bırak" yaklaşımı ölçülebilir biçimde daha iyi/ucuz/hızlı. Bizim bütün mimarimiz bunun üstüne
kurulu — yani **doğru bahsi oynuyoruz**.

**Nerede öndeyiz:** verdict'i kesinlikle kodun vermesi, leaked-marker + **canary** kanıtı, write-verb
+ BFLA + BOPLA + mass-assignment kapsamı (akademik SOTA'dan geniş), LLM-opsiyonel + yerel Ollama +
zorunlu redaction (gizlilik), **MCP tool-server** (en hızlı büyüyen kalıp), sıfır-bağımlılık Web UI.

**Nerede açığız (bu raporun asıl değeri):** (1) OpenBOLA'nın **write→verify→restore→verify** mutasyon
güvenlik döngüsü bizde yok; (2) **JUnit XML / CSV** CI çıktıları eksik; (3) **GraphQL BOLA oracle'ı**
henüz aday üretiyor, verdict vermiyor; (4) **çift-yönlü 2×2 yetki matrisi** ve iç-içe/dolaylı id
kapsamı kısmi; (5) recall %61.5 — read-only kapsamın ulaşamadığı yazma-metodu vakaları; (6) benchmark
yüzeyi 3 hedef — sektör ölçütü daha geniş (XBOW 104 web-CTF). Bunların hepsi somut, mimarimize oturan,
düşük-riskli eklemeler (detay §5–§6).

---

## 1. Pazar manzarası — beş kova

Sentinel'in rakip yüzeyi tek bir ürün değil; birbirini kesen beş kategoriden oluşuyor.

### Kova 1 — Deterministik BOLA/IDOR doğrulayıcıları (**en yakın rakipler**)

| Proje | Tür / Lisans | Bizimle örtüşme | Not |
|---|---|---|---|
| **OpenBOLA** | Açık kaynak (Apache-2.0), yerel-öncelikli | **≈%90 — neredeyse ikiz** | "Authorization-first, deterministic BOLA/IDOR validation." Choke-point executor, çok-kimlikli ownership kanıtı, redaction, HAR import, SARIF/JUnit/CSV, AI-sandbox. Aşağıda ayrıntı. |
| **AuthProbe** (arXiv) | Akademik, black-box | Yüksek (yalnız okuma) | OpenAPI-güdümlü, iki+ kimlik, "vulnerable↔hardened ikiz, 0-FP" metodolojisi. Bizim benchmark yaklaşımımızın kaynağı. Read-only. |
| **Bola Security Test Gate** (Arvanta) | Açık kaynak, "CI gate" | Orta | Gerçek trafikten hesap-değiştirme + kanıt-temelli bulgu; CI kapısı odaklı. Belgeleme sınırlı. |

**Ders:** Bu kova bizim tam alanımız ve 2026'da kalabalıklaştı. Farkımız artık "bu işi yapıyoruz"
değil, **"bu işi en katı determinizm + en geniş kapsam + gizlilik ile yapıyoruz"** olmalı.

### Kova 2 — Klasik differential-auth araçları (pratisyen standardı)

| Proje | Nasıl çalışır | Sınırı |
|---|---|---|
| **Autorize** (Burp) | Her isteği otomatik olarak düşük-yetkili + anonim oturumla **replay** eder; yanıt benzerliğine göre `Bypassed! / Enforced! / Is enforced???` etiketler | Proxy-güdümlü (manuel gezinti gerekir); kanıt = yanıt benzerliği, **leaked-marker ispatı yok**; FP triyajı insana kalır |
| **AuthMatrix** (Burp) | Kullanıcı × rol × istek **matrisi** elle tanımlanır, tek tıkla tüm kombinasyonlar koşulur, renk-kodlu sonuç | Ağır **ön-konfigürasyon**; varsayılan tespit "HTTP 200" (kırılgan); regex-fail modunda FP riski |
| AuthScope / diğer Burp eklentileri | Benzer replay/karşılaştırma varyantları | Yarı-otomatik, kanıt paketi zayıf |

**Ders:** Autorize'ın **her isteği otomatik replay** ergonomisi ve AuthMatrix'in **tam rol×istek
matrisi** güçlü fikirler. Biz differential'i yapıyoruz ama (a) çift-yönlü/2×2 matrisi henüz kısmi,
(b) "HAR/proxy'den yakala → hepsini otomatik test et" akışımız var ama pazarlanmıyor.

### Kova 3 — Ticari API-DAST ürünleri (benimsenme çıtası)

| Ürün | Güç | Zayıf | Bizden ders |
|---|---|---|---|
| **Escape** | AI-destekli fuzzing, **GraphQL** + iş-mantığı (BSLT), FP < %3.7, çok-adımlı login | Ücretli/kapalı; ağır | GraphQL BOLA derinliği + feedback-driven keşif (scalar inference) |
| **Akto** | MIT çekirdek, **sürekli API envanteri**, CI/CD iş-mantığı testleri, self-hosted/air-gap | Runtime-trafik odaklı | Sürekli/trafik-beslemeli mod; air-gap konumlandırması (bizde de var) |
| **StackHawk** | Developer-first, **her PR'da** koşar, en düşük sürtünme CI | ZAP tabanlı; **BOLA/IDOR elle konfig, otomatik yüzeye çıkmaz** | PR-başına CI ergonomisi; ama tam bizim boşluğumuz onların zayıfı |
| **42Crunch** | OpenAPI **statik** audit, GitHub Actions build-fail | Runtime yok | Tasarım-fazı OpenAPI denetimi (tamamlayıcı) |

**Ders:** Ticari ürünlerin ortak tezi bizim README'mizin tezi: *"Tarayıcılar BOLA'yı kaçırır, çünkü
kimin neyi sahiplendiğini bilemez."* Onların benimsenme kozları — **her PR'da koşma, baseline/diff,
per-role coverage, zengin CI çıktıları** — bizde ya var (baseline, coverage) ya da ucuz eklenir
(JUnit XML). Onların ölçek kozu (sürekli envanter) bizim mimarimize daha büyük bir iş.

### Kova 4 — Açık kaynak API tarayıcıları (tamamlayıcı ekosistem)

**ZAP** (endüstri-standart DAST, Automation Framework), **Nuclei** (11.000+ topluluk template'i, BOLA
template'leri dahil), **mitmproxy** (manuel authz testi), **Schemathesis/RESTler** (stateful/property
fuzzing → çok-adımlı authz), **Bearer** (SAST, eksik auth-middleware). Bunlar rakip değil, **entegre
edilebilecek** kaynaklar — özellikle Nuclei'nin **template ekosistemi** dedektör ailemiz için ilham.

### Kova 5 — Otonom AI-pentest ajanları (üst-kategori)

| Ajan | Konum | Bizden fark / ders |
|---|---|---|
| **XBOW** | HackerOne #1; ARTEMIS'te 8000-host ağda 10 OSCP insanının 9'unu geçti | Geniş otonomi; ama "zero-FP garanti edemeyiz" der → **bizim LLM-oy-kullanamaz garantimiz daha katı** |
| **Strix** | Açık kaynak, "her bug'ı ispatlar", HTTP-proxy + tarayıcı + exploit env | Bağımsız testlerde **çalışmayı bitirip işini ispatlaması** övülüyor → bizim proof/replay hattımızla aynı ruh; referans/öğretmen |
| **PentestGPT** | ~12.5k yıldız, USENIX'24; Reasoning/Generation/Parsing modülleri; Ollama dahil çok-sağlayıcı | Çok-sağlayıcı + yerel-model deseni bizimkiyle aynı; ajan mimarisi olgun |
| **MAPTA / HPTSA / VulnBot / D-CIPHER** | Çok-ajanlı planner-executor | **Çok-ajan > tek-ajan (4.3×)**; task-graph/rol uzmanlaşması → bizim `--scouts`/`pipeline`'ı derinleştirme yönü |
| **CHECKMATE** | Hibrit: LLM **PDDL** yazar → klasik planlayıcı çözer | Claude Code native ajanından **%20 daha başarılı, %50 daha hızlı, daha ucuz** → "LLM'i uzun planlamaya sokma" tezimizin kanıtı |
| **xOffense** | Qwen3-32B fine-tune | **Fine-tuned mid-size model, GPT-4'ü geçiyor** → bizim Ollama/yerel yönümüzü doğrular |

**Ders (appsecsanta 2026, en kritik):** Lab→gerçek uçurumu acımasız — bir-günlük CVE'de advisory
metniyle **%87**, metin çıkınca **%7**; otonom (ipuçsuz) **%21**; zor HackTheBox **≈%0**. Yani "ajanı
hedefe sal, buldum desin" demoları gerçekte çöküyor. Bizim **ipuçsuz + kanıt-zorunlu** duruşumuz tam
da bu uçurumun doğru tarafında. Ayrıca **iş-mantığı açıkları kritik zafiyetlerin %70'i** ve ajanların
kör noktası — bunu bilerek kapsam-dışı bırakmamız stratejik olarak savunulabilir.

---

## 2. En yakın ikiz: OpenBOLA — ayrıntılı kıyas

OpenBOLA, Sentinel'in çekirdeğiyle şaşırtıcı derecede örtüşür; bu yüzden en öğretici karşılaştırma.

**Ortak DNA (ikimizde de var):**
- Authorization-first, **deterministik** executor tek choke-point; LLM ağa dokunamaz (AI yalnız
  redakte/sanitize bağlam görür, sonda öneri verir).
- Çok-kimlikli **ownership kanıtı**: yanıt gövdesi tek başına sahiplik kanıtı sayılmaz; create/response
  yapısal kaydı gerekir (bizde `own_object_ids` bootstrap + leaked-marker).
- **Verdict sınıfları**: protected / BOLA / inconclusive / skipped ≈ bizim REJECTED / CONFIRMED /
  INCONCLUSIVE / (test edilmedi).
- **Redaction**: kimlik bilgileri şifreli in-memory, log/rapora ham yazılmaz; HAR import'ta yapısal
  redaksiyon.
- Scope kapısı her istekte; redirect'lerde bile yeniden doğrulama (bizde IP-pinning + authorize).
- **SARIF** + CI çıkışı, Apache/açık kaynak.

**OpenBOLA'da olup bizde eksik/zayıf olan (→ almalıyız):**
1. **Write→verify→restore→verify mutasyon döngüsü.** Yıkıcı yazma (POST/PUT/PATCH/DELETE) için:
   operatör onayı → test değeri yaz → yazıldığını doğrula → **geri al** → geri alındığını doğrula;
   yarıda kalırsa kurtarma durumu kaydedilir; **otomatik retry yasak**. Bizde `StateChangingOracle` +
   `CanaryPlanter` var ama **restore/reversal döngüsü yok** (kod teyidi: `state_change.py`'de
   restore/revert yok). Bu, yazma-authz testini güvenli açmanın anahtarı.
2. **Zengin CI çıktıları:** HTML + CSV (**resource-capability matrisi**) + JSON + Markdown + **JUnit
   XML** + SARIF (6 format). Bizde JSON/MD/HTML/SARIF var; **JUnit XML ve CSV yok** (kod teyidi).
3. **Opak handle'lar:** raporda gerçek kullanıcı adı/id yerine opak takma-ad (redaksiyonun ötesinde
   gizlilik). Bizde redaction var ama aktör adları görünür.
4. **Provider adapter'ları:** Hasura / Supabase / PostgREST / Firebase trafiğinden **normalize
   envanter** — own-object bootstrap'ı güçlendirir.
5. **Kriptografik scope bağlama:** scope dosyası yüklendikten sonra takas edilemez (bütünlük).
6. **Etkileşimli TUI:** argümansız çalışınca terminal arayüzü (bizde Web UI + CLI — TUI şart değil).

**Bizde olup OpenBOLA'da olmayan (→ korumalı üstünlük):**
- **Canary planting** (aktif işaret ekme) — tartışmasız leaked-marker.
- **Çok daha geniş oracle/dedektör ailesi**: BFLA, BOPLA, mass-assignment, stored-XSS, injection,
  timing, CSRF, method-bypass, unauthorized-access + 12 dedektör (exposure, CVE, info-leak,
  rate-limit, JWT, CORS, SSRF/XXE, prototype-pollution...). OpenBOLA yalnız BOLA/IDOR.
- **LLM-güdümlü hipotez + enrichment** (opsiyonel, verdict'i değiştirmez) + **çok-sağlayıcı** (Anthropic
  / Gemini / Ollama).
- **MCP tool-server** — başka ajanların "deterministik hâkim"i.
- **Self-improving pivot** (`--loop`) + **paralel scout** (`--agent --scouts`).

---

## 3. Güncel kıyas tablosu (2026-09)

Durum: ✅ var · 🟡 kısmi · ⬜ yok

| Yetenek | **Sentinel** | OpenBOLA | AuthProbe | Autorize/AuthMatrix | Escape/Akto | StackHawk | AI ajanları (XBOW/Strix) |
|---|---|---|---|---|---|---|---|
| Differential çok-aktörlü BOLA/IDOR | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| BFLA (dikey yetki) | ✅ | ⬜ | ⬜ | 🟡 | ✅ | ✅ | 🟡 |
| Write-verb (state-change / mass-assign / stored-XSS) | ✅ | 🟡 (BOLA-write) | ⬜ | 🟡 (manuel) | ✅ | 🟡 | ✅ |
| **Verdict'i KOD verir (LLM oy kullanamaz)** | ✅✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | 🟡 |
| Leaked-marker **+ canary** kanıtı | ✅✅ | 🟡 (marker) | ✅ | 🟡 | ✅ | 🟡 | 🟡 |
| **Write→verify→restore→verify güvenlik döngüsü** | ⬜ | ✅ | ⬜ | ⬜ | 🟡 | ⬜ | 🟡 |
| Geniş oracle/dedektör ailesi (injection/CVE/misconfig…) | ✅✅ | ⬜ | ⬜ | ⬜ | ✅ | 🟡 | ✅ |
| LLM-opsiyonel (kural-only çalışır) | ✅ | ✅ | — | ✅ | ⬜ | ✅ | ⬜ |
| Yerel model (Ollama) / air-gap | ✅ | 🟡 | — | — | 🟡 (Akto) | ⬜ | 🟡 |
| Çıktıda PII/sır redaction + opak handle | ✅ / ⬜ opak | ✅ / ✅ | 🟡 | ⬜ | 🟡 | 🟡 | ⬜ |
| OpenAPI/HAR/GraphQL-güdümlü keşif | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | 🟡 |
| **GraphQL BOLA oracle** (verdict) | 🟡 (aday üretir) | 🟡 | ⬜ | ⬜ | ✅ | 🟡 | 🟡 |
| Çok-hedefli benchmark (precision/recall/FP) | ✅ (3 hedef, %100/%61.5/%0) | 🟡 | ✅ | ⬜ | 🟡 | ⬜ | ✅✅ |
| Replay edilebilir kanıt/PoC paketi | ✅ (proof + repro-curl) | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | ✅✅ |
| SARIF / CI entegrasyonu | ✅ | ✅ | ⬜ | ⬜ | ✅ | ✅ | 🟡 |
| **JUnit XML / CSV çıktısı** | ⬜ | ✅ | ⬜ | ⬜ | 🟡 | ✅ | ⬜ |
| Baseline / diff (yalnız yeni bulgu) | ✅ | 🟡 | ⬜ | ⬜ | ✅ | ✅ | 🟡 |
| Per-role coverage raporu | ✅ | ✅ (matris) | ⬜ | 🟡 | ✅ | 🟡 | ⬜ |
| Dedup + agreement-based confidence | ✅ | 🟡 | ⬜ | ⬜ | ✅ | 🟡 | 🟡 |
| **Çift-yönlü 2×2 yetki matrisi + iç-içe id** | 🟡 | 🟡 | 🟡 | ✅ (AuthMatrix) | ✅ | 🟡 | 🟡 |
| MCP tool-server (ajan-entegre) | ✅ | ⬜ | ⬜ | ⬜ | 🟡 | ⬜ | ✅ |
| Sürekli/trafik-beslemeli API envanteri | ⬜ | 🟡 | ⬜ | ⬜ | ✅ (Akto) | 🟡 | ⬜ |
| Web UI / kontrol paneli | ✅ (stdlib) | 🟡 (TUI) | ⬜ | (Burp GUI) | ✅ | ✅ | 🟡 |

**Okuma:** Sentinel, bu tablonun **en dolu satırlı** aracı — özellikle "verdict'i kod verir + geniş
kapsam + LLM-opsiyonel + yerel + MCP" bileşimi başka hiçbir tek üründe bir arada yok. Kalan ⬜/🟡'ler
(write-restore döngüsü, JUnit/CSV, GraphQL BOLA verdict, 2×2 matris, sürekli envanter) somut ve
kapatılabilir.

---

## 4. Onlardan ne **alabiliriz** (adopt) — öncelikli, mimarimize oturan

Her madde CLAUDE.md §5 değişmezlerini korur (verdict yalnız kod; redaction; scope kapısı; kontrolsüz
verdict yok) ve Open/Closed ile **yeni sınıf** olarak eklenir.

### Yüksek getiri / düşük risk (önce bunlar)

1. **Write→verify→restore→verify mutasyon döngüsü** *(kaynak: OpenBOLA)*
   `StateChangingOracle`'a güvenli-yazma protokolü: operatör-onaylı test değeri yaz → yazıldığını
   doğrula → **geri al** → geri alındığını doğrula; yarıda kalırsa `recovery_state` kaydet; otomatik
   retry yasak (zaten §10.11'de state-changing retry kapalı). `CanaryPlanter` ile birleşir. → yazma-
   authz testini **güvenle** açar, recall'ı POST/PUT/DELETE vakalarında yükseltir. *Efor: ~6s.*

2. **JUnit XML + CSV reporter'ları** *(kaynak: OpenBOLA, StackHawk)*
   `report/render_junit.py` (CI test-paneli) + `report/render_csv.py` (resource-capability matrisi).
   Mevcut `Reporter` ABC'sine iki alt sınıf; verdict/veri değişmez. → CI benimsenmesi için en ucuz
   yüksek-değerli adım (Jenkins/GitLab/GitHub test sekmesi bulguları gösterir). *Efor: ~3s.*

3. **GraphQL BOLA oracle'ı (verdict üreten)** *(kaynak: Escape)*
   `recon/graphql.py` zaten aday sorgu üretiyor ama verdict vermiyor. `GraphqlBolaOracle`: iki aktörle
   `build_query()` gövdesini koşup leaked-marker/differential uygular. → GraphQL hedeflerde recall +
   Escape'in en güçlü olduğu yüzeyde paritenin başlangıcı. *Efor: ~5s.*

4. **Çift-yönlü 2×2 yetki matrisi tamamlama** *(kaynak: AuthMatrix, StingrAI)* — ROADMAP R-B1
   (own/peer obje) × (own/higher rol); A→B kadar B→A; asimetrik izolasyon yakalanır; matris raporda.
   `report/matrix.py` var, döngüyü çift-yön koşacak şekilde tamamla. *Efor: ~4s.*

### Orta getiri

5. **Opak handle'lar raporda** *(kaynak: OpenBOLA)* — aktör adı/id yerine `identity-1`/`obj-7f…`;
   redaksiyonun üstüne bir gizlilik katmanı (rapor paylaşılınca kimlik sızmaz). *Efor: ~2s.*

6. **Feedback-driven / scalar inference keşfi** *(kaynak: Escape)* — ROADMAP R-B3. Yanıtlardan obje
   ilişkilerini çıkarıp `own_object_ids`'i elle vermeden bootstrap. Recall'ın "kurulum gerektiren
   BOLA" FN'lerini azaltır. *Efor: ~5s.*

7. **Provider adapter'ları** *(kaynak: OpenBOLA)* — Hasura/Supabase/PostgREST/Firebase trafiğinden
   normalize envanter; modern backend'lerde otomatik keşif. `recon/` altında opsiyonel adaptörler.
   *Efor: ~5s.*

8. **İç-içe / dolaylı id + UUID varyasyonu** *(kaynak: StingrAI)* — ROADMAP R-B2. Gövde/ikinci-el
   lookup'taki id'ler; int **ve** UUID. `resource_key` çakışması (yapılacaklar §7) de burada çözülür.
   *Efor: ~5s.*

### Stratejik / daha büyük lift

9. **Çok-ajanlı planner-executor + rol uzmanlaşması** *(kaynak: HPTSA/MAPTA/VulnBot, 4.3×)* — ROADMAP
   2.3. `--scouts` paralel var; üstüne **planner→executor→verifier** rol ayrımı + task-graph. CHECKMATE
   dersi: uzun-ufuklu planlamayı LLM yerine **deterministik planlayıcıya** ver (bizim tezimizle bire bir).
   *Efor: açık uçlu.*

10. **Benchmark yüzeyini genişlet** *(kaynak: XBOW 104 web-CTF, AuthProbe)* — 3 hedef → daha fazla;
    recall'ı yazma-metodu kapsamıyla (madde 1) yükselt; "advisory metnini gizle" disiplinini koru.
    *Efor: ~6s + hedef kurulumu.*

---

## 5. Ne **ekleyebiliriz** (net-yeni fikirler — kimsede tam yok)

Rakiplerden kopya değil, bizim kenarımızı büyüten özgün eklemeler:

- **"Deterministik hâkim" olarak konumlandırma (MCP'yi pazarla).** MCP tool-server bizde **var** ama
  sektörde en hızlı büyüyen kalıp ve rakiplerde yok. XBOW/Strix "zero-FP garanti edemeyiz" derken,
  Sentinel'i **onların verdict-doğrulayıcısı** olarak sunmak boş bir niş. → README/demo'da "diğer
  AI ajanlarının kanıt motoru" hikâyesini öne çıkar; bir "Claude Code + sentinel-mcp" örnek akışı ekle.

- **Kanıt-paketi imzalama / taşınabilir PoC bundle.** `proof/<fid>.json` var; üstüne **imzalı,
  çevrimdışı yeniden-ispatlanabilir** bir bundle (hash + repro script) → bulgu bir güvenlik ekibine
  ya da bug-bounty'ye **değiştirilemez kanıtla** teslim edilir. Kimsede standart değil.

- **FP-kapanı (negative twin) kütüphanesi ürünleştirme.** Benchmark'ta kullandığımız "vulnerable↔
  hardened ikiz" setini bir **regresyon paketi** olarak paketle → kullanıcı kendi CI'ında "0-FP hâlâ
   0 mu?" diye koşar. AuthProbe metodolojisini üründe operasyonelleştirmek.

- **Air-gap / gizlilik rozeti.** Akto self-hosted diyor ama biz **LLM'siz de tam çalışıyoruz** +
  Ollama yerel. "Hedef verisi makineden çıkmaz" garantisini ölçülü bir **gizlilik moduyla** (dışa hiç
  ağ yok, telemetri yok — OpenBOLA'nın "no telemetry"si gibi) resmîleştir ve pazarla.

- **Nuclei-tarzı topluluk template ekosistemi (dedektörler için).** 12 dedektörümüzü bir **YAML
  template formatına** aç → topluluk yeni imza/misconfig ekler, çekirdek kod değişmeden breadth büyür.
  Uzun vadeli benimsenme çarpanı.

---

## 6. Korumamız gereken kenarlar (moat) — vurguyu kaybetme

Araştırma bunların **gerçek farklılaştırıcı** olduğunu doğruluyor; demolarda/README'de öne çıkar:

1. **LLM oy kullanamaz garantisi** — XBOW/MAPTA "zero-FP garanti edemeyiz" derken bizim değişmezimiz
   daha katı. Sektörün en güvenilir cümlesi bu.
2. **Kanıt-zorunlu determinizm** — appsecsanta'nın "%87→%7 advisory uçurumu" tam bizim reddettiğimiz
   demo tuzağı. "İpucu yok, kanıt var" duruşu doğrulanmış strateji.
3. **Kapsam genişliği + write-verb** — AuthProbe read-only, StackHawk elle-konfig; biz akademik SOTA'dan
   geniş.
4. **LLM-opsiyonel + yerel + redaction** — "mimari > model ölçeği; fine-tuned mid-size kazanıyor"
   (xOffense/CHECKMATE) bizim yönümüzü doğruluyor.
5. **MCP + Web UI + reproducible curl/proof** — benimsenme ve ajan-entegrasyon kolaylığı.

---

## 7. Öneri — dalga planı (ROADMAP'e ek)

| Öncelik | Madde | Kaynak | Getiri | Efor |
|---|---|---|---|---|
| **1** | Write→verify→restore→verify (madde 4.1) | OpenBOLA | Güvenli yazma-authz + recall | ~6s |
| **1** | JUnit XML + CSV reporter (4.2) | OpenBOLA/StackHawk | CI benimsenme | ~3s |
| **2** | GraphQL BOLA oracle (4.3) | Escape | GraphQL recall | ~5s |
| **2** | Çift-yönlü 2×2 matris (4.4) | AuthMatrix | Kapsam derinliği | ~4s |
| **3** | MCP "deterministik hâkim" konumlandırma (§5) | strix/appsecsanta | Niş sahiplenme | ~2s (doküman) |
| **3** | Scalar inference + iç-içe id (4.6, 4.8) | Escape/StingrAI | Recall FN azalt | ~10s |
| **4** | Çok-ajan planner-executor (4.9) | HPTSA/CHECKMATE | Otonomi | açık uçlu |

**Tek cümlelik sonuç:** Sentinel doğru bahsi oynuyor ve bu alandaki en dolu-özellikli tek araçlardan
biri; kısa vadede en yüksek getiri **write-restore güvenlik döngüsü + JUnit/CSV CI çıktıları +
GraphQL BOLA verdict**'inde; orta vadede **MCP'yi "AI ajanlarının deterministik hâkimi" olarak
pazarlamak** ve **çift-yönlü matris + scalar inference** ile kapsam/recall'ı derinleştirmekte.

---

## 8. Kaynakça

- OpenBOLA — Authorization-first, deterministic BOLA/IDOR validation: <https://github.com/LeonardSEO/OpenBOLA>
- AuthProbe: Multi-Identity BOLA Detection (arXiv): <https://arxiv.org/html/2607.20574v1>
- Bola Security Test Gate (Arvanta): <https://www.arvantacyber.com/bola-security-test-gate/>
- AI Pentesting Agents 2026 (appsecsanta — 6 kalıp, 39+ araç): <https://appsecsanta.com/research/ai-pentesting-agents-2026>
- 7 Best Open Source API Security Tools 2026 (appsecsanta): <https://appsecsanta.com/api-security-tools/best-open-source-api-security-tools>
- Best DAST Tools for APIs 2026 (appsecsanta): <https://appsecsanta.com/dast-tools/dast-tools-for-apis>
- Escape vs StackHawk / DAST karşılaştırması: <https://escape.tech/blog/top-dast-tools/>
- StackHawk — API security testing tools 2026: <https://www.stackhawk.com/blog/api-security-testing-tools/>
- AuthMatrix (Burp eklentisi): <https://github.com/SecurityInnovation/AuthMatrix>
- Autorize (Burp eklentisi): <https://github.com/PortSwigger/autorize>
- Strix — açık kaynak AI pentester (bağımsız inceleme): <https://protego.me/blog/strix-ai-pentester-honest-review>
- PentestGPT (açık kaynak agentic framework): <https://github.com/GreyDGL/PentestGPT>
- 10 Best Open Source Agentic Pentesting Tools 2026 (Strobes): <https://strobes.co/blog/open-source-agentic-pentesting-tools/>
- Nuclei / ZAP / mitmproxy / Schemathesis (Kova 4) — yukarıdaki appsecsanta listesinden.
