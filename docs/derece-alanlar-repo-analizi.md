# Ek Repo Analizleri (2. tur) — İlham/Rakip İnceleme

> **Amaç:** Yeni gönderilen repoları tek tek inceleyip Sentinel-Agent'ın
> **eksiklerini/öğrenebileceklerini** biriktirmek. Hedef aracı "kullanmak" değil; **kendimizi ve
> projeyi geliştirmek.**
>
> **Yöntem:** Her repo bir bölüm. Her bölümde: *Ne yapıyor · Öne çıkanlar · Bizde eksik olan ·
> Sentinel'e nasıl eklenir (hangi modül/sınıf) · Almayacaklarımız · Tek cümlelik ders.* Bu belge
> **analizdir; kod değiştirmez.**
>
> **Önemli çerçeve:** Sentinel-Agent, access-control (IDOR/BOLA/BFLA) + ajan-çağı yetki ekseninde
> teknik olarak derin (onlarca oracle, deterministik CONFIRMED, replay, actor izolasyonu, redaction,
> scope gate, benchmark holdout, self-eval, hash-zincirli kanıt, counterfactual, SARIF, web UI).
> Yeni repolar farklı problem alanlarında olabilir; ders çoğunlukla **"kanıtı inandırıcı sunma"** ve
> **karşıt dersler** olacak — bunu her repoda ayırt edeceğiz.
>
> **Not (git geçmişi):** Bu dosyanın önceki içeriği — TLN Cybersecurity Challenge 2026 dereceye
> girenlerinin (TRACE X · NoScam · SlopGuard · ChainBreak · CyberShield) analizi + A–U görev
> tracker'ı — bu turda yerini yeni repolara bıraktı ama **git geçmişinde duruyor** (`git log --
> follow docs/derece-alanlar-repo-analizi.md`; en son tam sürüm commit `975aec1` civarı). O turun
> tüm görevleri (A–U) **tamamlandı ve kodda mevcut** (eval/ · hash-zincir · counterfactual · lineage
> · verdict-invariance · prompt-injection sertleştirme · composite Action · MITRE/blast-radius vb.).

---

## Repo 1 — `pradeepkumar-ai-byte/VaxGuard` = **VaxGuard**

**Link:** https://github.com/pradeepkumar-ai-byte/VaxGuard
**Tür:** Üretim LLM'leri için "otonom yapay bağışıklık sistemi" — prompt-injection/jailbreak/veri-
sızdırma vb. 6 saldırı vektörüne karşı hem **tarayıcı (diagnostic)** hem **runtime savunma
middleware'i (vaccine)**. *(Bizden farklı alan: LLM-uygulama güvenliği, access-control değil.)*
**Yığın:** Python 3.10+ · FastAPI · SQLAlchemy (SQLite/PostgreSQL) · Click CLI · Groq LPU
(`qwen/qwen3-benzeri`) · vanilla HTML/CSS/JS "glassmorphism" dashboard + WebSocket telemetri · pytest.

### 1.1 Ne yapıyor (kısaca)
İki katman: (1) **Diagnostic engine** — bir LLM'i 6 taksonomideki (`data/attacks.yaml`) saldırılarla
tarar, 0–100 "Global Immunity Score" hesaplar; (2) **Vaccine generator** — self-reflective
Generate→Critique→Refine zinciriyle savunma prompt'ları üretir, "immune memory" (TF-IDF centroid
drift) ile zero-day anomali yakalayıp otomatik "aşı" konuşlandırır. Canlı WebSocket dashboard +
CLI + REST + Docker + GitHub Actions CI.

### 1.2 Öne çıkanlar (jüriyi etkileyen)
1. **Çok-yüzeyli, düşük-friction dağıtım:** CLI (`vaxguard serve/scan`) · REST API · WebSocket canlı
   telemetri · Docker · CI. Erişilebilirlik güçlü (SlopGuard/ChainBreak ile aynı sinyal).
2. **Canlı telemetri dashboard'u:** `ws://…/ws/stream` üzerinden `THREAT_DETECTED` /
   `AUTO_IMMUNITY_DEPLOYED` / `SCAN_COMPLETED` olayları; immunity gauge + 6 eksen radar + canlı
   sandbox. Tarama **sürerken** görsel akış — güçlü demo kartı.
3. **Tek headline metrik:** 0–100 "Global Immunity Score" — jüri/karar-verici için tek bakışta duruş.
4. **Yayınlanmış benchmark tablosu** (`RESULTS.md`, 50 adversarial vektör): overall %78→%6 breach,
   benign-FPR %0. Kategori kırılımı verilmiş.
5. **Dürüst limitations:** benign-FPR'nin **%0 olmasının "fazla mükemmel/overfit işareti"**
   olabileceğini, güven aralığı/ablation olmadığını, test modellerinin açıklanmadığını **kendisi**
   yazmış → dürüstlük vitrini (TRACE X ile aynı sinyal).
6. **Kısmi deterministik/LLM ayrımı:** regex/heuristik + TF-IDF (deterministik) ile LLM'i ayırmış.

### 1.3 Bizde EKSİK / zayıf olanlar (bu repodan çıkan)
- ⚠️ **Canlı, akış-tabanlı telemetri yok.** Web UI'miz tarama ilerlemesini gösteriyor ama VaxGuard
  gibi olay-bazlı **WebSocket canlı akış** (her tespit anında event) ve radar/gauge görselleştirmesi
  yok. Sunum/demo değeri olan bir vitrin farkı (kod-orta).
- ⚠️ **Tek "duruş skoru" (headline) yok.** Bizde CONFIRMED/LIKELY/… sayaçları var ama VaxGuard'ın
  0–100 "Immunity Score" gibi **tek bakışta özet** bir rakam yok. (S — blast-radius ile birleşebilir;
  ama bizde bunu *advisory* tutmak şart — verdict'i asla ezmemeli.)
- ✅ **Tekrar güçlenen:** dürüst limitations + yayınlanmış metrik (bizde artık `eval/` + Kısıtlar
  bölümüyle var) ve çok-yüzeyli erişilebilirlik (CLI/API/CI + composite Action ile karşılandı).

### 1.4 KARŞIT DERS (en değerli çıktı) — tezimizi doğruluyor
- ❗ **VaxGuard breach verdict'ini "LLM-as-a-judge"a bırakıyor** → karar **non-deterministik**.
  Üstüne benign-FPR %0 "fazla mükemmel" (kendi limitation'ı). Bu tam olarak bizim **YAPMADIĞIMIZ**
  şey: Sentinel'de verdict'i **kod** verir, LLM oy vermez (verdict-invariance testiyle *kanıtlı*),
  ve near-miss disiplinli `eval/` FP-rate %0'ı **etikete** dayandırır, LLM yargısına değil.
  → **Slayt/anlatı kartı:** *"Rakipler saldırıyı LLM'e yargılatıyor; biz kararı deterministik
  kanıta bağlıyoruz — 'evidence-first, model gets no vote'."*
- ❗ **VaxGuard bir savunma/enforcement middleware'i** (ChainBreak gibi); biz **bulucu/kanıtlayıcı**yız.
  Onların "aşı üret + trafiği filtrele" rolünü almayız.

### 1.5 Sentinel'e nasıl eklenir — mimariye uyumlu, invariant'ları bozmadan
| # | Öneri | Nereye (modül/sınıf) | Not | Öncelik |
|---|---|---|---|---|
| V1 | **Canlı tarama telemetrisi**: web UI'ya tarama sürerken olay akışı (bulgu bulundukça) | `webui/` (SSE/WebSocket veya polling) + `scan_manager` event'leri | Sunum/demo değeri; verdict'i etkilemez, salt görüntüleme | 🟡 Orta |
| V2 | **Tek "duruş özeti" rozeti**: CONFIRMED/severity dağılımından türeyen advisory skor | `report/` (+ `classify`/`impact` ile) | S ile birleşir; **advisory**, verdict'i asla ezmez | 🟢 Düşük |
| V3 | **Karşıt-ders anlatısı**: "model oy vermez" farkını deck/README'de VaxGuard-tarzı LLM-judge'a karşı vurgula | doküman | Kod yok; en yüksek getirili sunum hamlesi | 🟢 Düşük |

### 1.6 Bu repodan ALMAYACAKLARIMIZ (kapsam dışı)
- **LLM-as-a-judge breach classification** — bizim tezimize aykırı (verdict'i kod verir), ALINMAZ.
- **Vaccine synthesis (Generate→Critique→Refine), auto-immunity aşı konuşlandırma, TF-IDF prompt-
  drift, prompt-injection savunma middleware'i** — hepsi VaxGuard'ın LLM-uygulama-savunması domain'ine
  ait; access-control bulucu/kanıtlayıcı aracımıza taşınmaz (scope-creep + enforcement rolü).
- **Groq/tek-sağlayıcı bağımlılığı** — bizde LLM opsiyonel ve çok-sağlayıcı; değişmez.

### 1.7 Tek cümlelik ders
> VaxGuard **karşıt bir örnek**: erişilebilirlik ve dürüst-limitation'da güçlü ama güvenlik
> kararını **LLM'e yargılatıyor** — Sentinel'in "kararı deterministik kanıt verir, model oy vermez"
> tezini *tersinden* doğruluyor; alacağımız tek somut şey **canlı telemetri vitrini** ve bu **karşıt
> anlatı**, motoru değil.

---

## Repo 2 — `abhisheksinghyadav0004-ux/CyberSentinel-AI` = **CyberSentinel-AI**

**Link:** https://github.com/abhisheksinghyadav0004-ux/CyberSentinel-AI
**Tür:** SOC analisti için ağ-trafiği triyaj panosu — canlı paket metadata'sı + yüklenen CSV ağ
loglarını "soruşturmaya-hazır uyarılara" çevirir. *(Bizden çok farklı alan: network SOC monitoring;
üstelik olgunluk düşük — portfolyo/öğrenme projesi, 2 commit.)*
**Yığın:** Python (Flask) · Scapy (paket yakalama) · JS/HTML/CSS + Chart.js pano · **LLM YOK** ·
DB yok (in-memory / tarayıcı localStorage).

### 2.1 Ne yapıyor (kısaca)
Scapy ile canlı paket yakalar ya da CSV log yükler; kural-tabanlı eşiklerle (ör. 5 sn'de tek
kaynaktan ≥30 paket = Medium, ≥80 = Critical; >1500 bayt = Medium) uyarı üretir, yerel IOC
watchlist'e eşler, Chart.js panosunda protokol dağılımı/trafik trendi gösterir. Uyarı yaşam-döngüsü
(New/Investigating/Resolved) + analist notları (tarayıcıda saklı) + JSON export.

### 2.2 Öne çıkanlar
1. **Tamamen deterministik, kural-tabanlı tespit** — LLM yok; kararı eşikler + analist verir.
   (İsimde "AI" var ama AI yok; dürüstlük açısından README bunu gizlemiyor.)
2. **MITRE ATT&CK eşlemesi entegre** (T1583 / T1046 / T1498) — bulguları taksonomiye bağlıyor.
3. **Veri-minimizasyonu:** "yalnızca analiz için gereken metadata saklanır; kimlik bilgileri ve ham
   payload'lar hariç" — redaction/gizlilik disiplininin akrabası.
4. **Açık limitations:** "IOC watchlist yereldir/demo amaçlıdır", "eşikler gerçek ortama göre
   ayarlanmalı", "üretim için değil, öğrenme/portfolyo" — dürüst sınır beyanı.
5. **Analist triyaj iş-akışı:** uyarı durumu (New/Investigating/Resolved) + not + severity filtresi.
6. **Canlı pano:** auto-update Chart.js (protokol dağılımı, trafik trendi) — VaxGuard'daki canlı
   telemetri temasını tekrar ediyor.

### 2.3 Bizde EKSİK / zayıf olanlar (bu repodan çıkan — yeni olanlar)
- ⚠️ **Bulgu triyaj yaşam-döngüsü zayıf.** Web UI'de bulguları görüyoruz ama VaxGuard/CyberSentinel
  gibi durum makinesi (New/Investigating/Resolved) + kalıcı analist notu (koşumlar arası) belirgin
  değil. Bir güvenlik ekibinin "bunu inceledim/kapattım" akışı. (Salt sunum/iş-akışı katmanı.)
- ✅ **Tekrar güçlenen:** MITRE ATT&CK eşlemesi (bizde T ile eklendi — 2. kez doğrulandı),
  redaction/veri-minimizasyonu (bizde §5 kural 5), açık limitations (bizde Kısıtlar), canlı pano
  (V1 ile örtüşür — 2. kez çıktı).

### 2.4 KARŞIT DERS — olgunluk/rigor farkı
- ❗ **Test yok, metrik yok, FP disiplini yok, kalıcı depolama yok.** "AI" ismi taşıyan ama ne AI ne
  ölçüm içeren bir projeye karşı bizim farkımız net: **deterministik kanıt + ölçülmüş/tekrar-
  üretilebilir eval (875 test, `eval/` FP-rate %0, benchmark holdout)**. CyberShield dersinin (sayısı
  olmayan dürüstlük yetmez) daha uç bir hali. Anlatıda "rigor" farkını güçlendirir.

### 2.5 Sentinel'e nasıl eklenir
| # | Öneri | Nereye (modül/sınıf) | Not | Öncelik |
|---|---|---|---|---|
| W1 | **Bulgu triyaj durumu + notu**: New/Investigating/Resolved + kalıcı analist notu | `webui/` (+ `runs/` yanında hafif durum dosyası) | Salt iş-akışı katmanı; verdict'e dokunmaz; opsiyonel | 🟢 Düşük |

*(MITRE eşlemesi zaten T ile eklendi; canlı pano V1 ile kapsanıyor — yeni madde açmadık.)*

### 2.6 Bu repodan ALMAYACAKLARIMIZ (kapsam dışı)
Scapy paket yakalama, ağ-trafiği/IOC watchlist mantığı, protokol-dağılımı görselleştirmesi, network-
SOC domain'i — access-control bulucu/kanıtlayıcı aracımıza taşınmaz. In-memory/localStorage depolama
modelini de almayız (bizde `runs/` + kanıt defteri var).

### 2.7 Tek cümlelik ders
> CyberSentinel-AI, "AI" adı taşıyan ama AI'sız + testsiz + metriksiz bir portfolyo projesi —
> bizim **rigor** farkımızı (deterministik kanıt + ölçülmüş eval) tersinden vurguluyor; alacağımız
> tek somut şey opsiyonel bir **analist triyaj-durumu** iş akışı, ve MITRE eşlemesinin (zaten yaptık)
> bir kez daha doğru yol olduğu.

---

## Repo 3 — `vimalspaceton618-afk/Talos` = **Talos / AgentGuard** ⭐ (bu turun bize en yakını)

**Link:** https://github.com/vimalspaceton618-afk/Talos
**Tür:** AI ajanları için **local-first güvenlik firewall proxy'si** — indirect prompt-injection
(inbound) + veri sızıntısı (outbound DLP) tespiti, risk-tabanlı policy + karantina + HITL. *(Alan
bize yakın: ajan-güvenliği; ama rol farkı kritik — ChainBreak/VaxGuard gibi bir **savunma/
enforcement proxy'si**, biz **bulucu/kanıtlayıcı**yız.)*
**Yığın:** Python 3.11+ · FastAPI (HITL API :8000) · Streamlit ops dashboard (:8501) · React+Vite
command center (:3000) · SQLite · **LLM dokümanda belirtilmemiş** (kural/istatistik-tabanlı görünüyor).

### 3.1 Ne yapıyor (kısaca)
Ajanın önüne bir proxy koyar: gelen içerikte indirect prompt-injection tarar (`inbound_scanner`),
giden veride DLP yapar (`outbound_dlp`), risk skoruna göre `policy_engine` ile karar verir, şüpheli
istekleri **karantinaya** alır, insan (HITL) panodan inceler. Mock-agent test ortamı + red-team
regresyon paketi + GitHub Actions CI (`security-regression.yml`).

### 3.2 Öne çıkanlar
1. **Deterministik, kural-tabanlı karar** (LLM'e yargı yok gibi) — bizim tezimizle **hizalı**
   (VaxGuard'ın LLM-judge'una zıt; bu repo bizim tarafımızda).
2. **CI'da red-team regresyon + deterministik yerel fixture'lar** (`security-regression.yml`,
   benchmark JSON artefaktları **30 gün** saklanıyor) — bizim `bench-guard`/`eval` + CI desenimizin
   birebir akrabası; artefakt-saklama/trend fikri güzel.
3. **İki-yönlü ajan koruması**: inbound (injection) + outbound (DLP) — kavramsal olarak bizim
   **UNTRUSTED_TO_ACTION** (inbound→action) + **EXFILTRATION** (outbound canary) predicate'lerimizle
   birebir örtüşür.
4. **HITL + karantina**: belirsizi insana bırakma — bizim INCONCLUSIVE/insan-doğrulaması ruhuyla aynı.
5. **Çok-yüzey**: API + Streamlit + React + CLI script'leri + pip-installable.

### 3.3 Bizde EKSİK / zayıf olanlar (bu repodan çıkan)
- ⚠️ **CI'da eval/benchmark sonucunu artefakt olarak saklama/trend zayıf.** Bizim CI'ımız SARIF +
  `runs/` yüklüyor ve `bench-guard`/`verify_release` koşuyor; ama `eval/results.json`'ı zamanla
  saklanan bir **artefakt + basit trend** olarak yayınlamıyoruz. Talos benchmark JSON'ını 30 gün
  saklıyor — "sayı zamanla nasıl gidiyor" görünür oluyor.
- ✅ **Tekrar güçlenen / doğrulanan:** deterministik-karar (bizim tezimiz, VaxGuard'a zıt),
  red-team regresyon + deterministik fixture (bizde `bench/twins` + `eval/`), inbound/outbound ajan
  koruması (bizde predicate olarak **zaten var** — Talos bunları *korur*, biz *kanıtlarız*),
  HITL/belirsizi-insana (bizde INCONCLUSIVE).

### 3.4 KONUMLANDIRMA / KARŞIT DERS
- ❗ **Guard vs Prover (3. kez):** ChainBreak + VaxGuard + Talos — hepsi ajanı **koruyan** runtime
  guard/proxy. Sentinel farkı: hedef ajanın bu saldırılara **açık olup olmadığını KANITLAR**.
  Anlatı kartı: *"AgentGuard ajanı korur; Sentinel hedefin indirect-injection/exfiltration'a açık
  olduğunu deterministik kanıtla gösterir — biz savunmayı değil, açığı ispatlarız."*
- ❗ **Deterministik ama ölçülmemiş:** Talos bizim gibi deterministik ama **yayınlanmış metrik /
  FP disiplini / taksonomi eşlemesi yok**. Bizde `eval/` (FP-rate %0, near-miss) + CWE/OWASP/MITRE
  var → aynı felsefede daha ölçülü olmak farkımız.

### 3.5 Sentinel'e nasıl eklenir
| # | Öneri | Nereye (modül/sınıf) | Not | Öncelik |
|---|---|---|---|---|
| X1 | **CI'da eval/benchmark artefaktı + trend**: `eval/results.json` + benchmark özetini saklanan artefakt olarak yayınla (zamanla FP-rate/recall gidişi) | `.github/workflows/sentinel.yml` (upload-artifact/retention) | Var olanı vitrine çıkarmak; kod ~yok | 🟢 Düşük |

*(inbound/outbound ajan koruması bizde predicate olarak zaten var; guard/enforcement rolünü ALMAYIZ.)*

### 3.6 Bu repodan ALMAYACAKLARIMIZ (kapsam dışı)
Firewall/proxy enforcement rolü (araya girip blokla/karantinaya al), inbound/outbound **savunma**
middleware'i, risk-skoru-ile-otomatik-blok — hepsi Talos'un *koruma* domain'ine ait. Biz hedefin
açığını **kanıtlarız**, trafiği filtrelemeyiz (ChainBreak/VaxGuard için de aynı sınır).

### 3.7 Tek cümlelik ders
> Talos, bizim tarafımızda (deterministik) duran ama **koruyan** bir ajan-firewall'u; dersi üç katlı:
> (1) "guard değil, prover'ız" konumlandırmasını 3. kez netleştir, (2) deterministik olup da
> **ölçmemenin** eksikliğini bizim `eval/`+taksonomimiz kapatıyor, (3) tek somut alınacak **CI eval
> artefaktı/trend** (X1).

---

## Toplu "Yapılacaklar" (yeni tur — her repo sonrası güncellenir)

- [x] (V1) Canlı tarama telemetrisi (web UI olay akışı) · *kaynak: VaxGuard (+CyberSentinel)* · 🟡 — scanner `on_phase` callback (opsiyonel, verdict'i etkilemez) → ScannerRunner her faz bitince '[faz] N bulgu · M CONFIRMED' akıtıyor; scan-status progress'te canlı görünür
- [x] (V2) Tek "duruş özeti" advisory rozeti (S ile birleşir) · *kaynak: VaxGuard* · 🟢 — `report/posture.py` (0-100 advisory skor + grade, yalnız CONFIRMED sayılır, 'güvenli demez'); markdown rapor başlığında + web UI done payload'ında
- [x] (V3) "Model oy vermez" karşıt-ders anlatısı (deck/README) · *kaynak: VaxGuard* · 🟢 — README 'Neyle farklı?'ya 'prover değil guard' + 'evidence-first, model gets no vote' bloğu eklendi (test_verdict_invariance referanslı)
- [x] (W1) Bulgu triyaj durumu (New/Investigating/Resolved) + kalıcı analist notu · *kaynak: CyberSentinel* · 🟢 — `report/triage_state.py` (runs/<id>/triage.json) + web UI GET/POST /api/runs/<id>/triage (traversal-korumalı); `tests/test_triage_state.py` (8)
- [x] (X1) CI'da eval/benchmark artefaktı + trend (FP-rate/recall gidişi) · *kaynak: Talos* · 🟢 — sentinel.yml test job'ı self-eval'i koşup `eval/results.json`'ı 90 gün saklanan artefakt olarak yüklüyor

**Tekrarlayan sinyaller:**
- **Guard vs Prover (3/3 ajan-güvenlik repo):** ChainBreak + VaxGuard + Talos hepsi ajanı *koruyan*
  runtime guard/proxy; Sentinel farkı hedefin **açık olduğunu kanıtlamak** → en net konumlandırma kartı.
- **Erişilebilirlik/çok-yüzey + canlı pano** (CLI/API/CI/dashboard) — her repoda çıktı; bizde
  CLI/MCP/web UI + composite Action var, eksik olan **canlı telemetri** (V1).
- **Dürüst limitations + yayınlanmış/ölçülmüş metrik** — "olmazsa-olmaz"; bizde `eval/` + Kısıtlar
  var. Talos deterministik ama ölçmemiş; VaxGuard ölçmüş ama LLM'e yargılatmış; CyberSentinel ne test
  ne metrik → **deterministik + ölçülmüş + kararı kod verir** üçlüsünü aynı anda yapan biziz.
- **MITRE ATT&CK eşlemesi** — birden çok repoda; bizde T ile eklendi → doğru yolda.

---

# 🎯 SENTEZ VE EYLEM (2. tur — 3 repo)

## Ana teşhis (tek paragraf)
Bu turdaki 3 reponun **hiçbiri access-control ekseninde bizden derin değil** ve **hiçbiri yeni bir
zafiyet tipi/motor gerektirmiyor**. Üçü de ya farklı alan (VaxGuard: LLM-uygulama savunması;
CyberSentinel: network SOC) ya da farklı **rol** (Talos: ajan-firewall/guard). En büyük değer
**konumlandırma ve doğrulama**: (1) "guard değil, prover'ız" farkı 3 ajan-güvenlik reposuyla üst
üste netleşti; (2) "kararı kod verir, model oy vermez" tezimiz VaxGuard'ın LLM-judge'una **karşıt**
olarak parlıyor; (3) "deterministik **ve** ölçülmüş **ve** kararı kod verir" üçlüsünü aynı anda yapan
tek proje biziz (Talos ölçmüyor, VaxGuard LLM'e yargılatıyor, CyberSentinel ne test ne metrik).
Somut kod işi az ve hepsi 🟢/🟡 cila; çekirdeğe eklenecek yeni yetenek yok.

## Örüntü tablosu — hangi ders kaç repoda?
| Ders | VaxGuard | CyberSentinel | Talos | Sinyal |
|---|:-:|:-:|:-:|---|
| Guard/enforcement rolü (biz: prover) | ✅ | — | ✅ | **konumlandırma: prover farkı** |
| Deterministik karar (LLM oy vermez) | ❌ (LLM-judge) | ✅ | ✅ | tezimiz doğru; VaxGuard karşıt örnek |
| Yayınlanmış/ölçülmüş metrik | ✅ | ❌ | ❌ | bizde `eval/` var → fark |
| Açık limitations | ✅ | ✅ | — | olmazsa-olmaz (bizde Kısıtlar) |
| MITRE ATT&CK eşlemesi | ⚠️ | ✅ | ❌ | bizde T ile var |
| Canlı pano/telemetri | ✅ | ✅ | ✅ | **3/3 — eksiğimiz (V1)** |
| Çok-yüzey erişim (CLI/API/CI/dash) | ✅ | ⚠️ | ✅ | bizde var (+Action) |

## Kendimize ne katacağız — önceliklendirilmiş
**A) Kod GEREKTİRMEYEN (hemen, en yüksek getiri)**
- **V3 — Konumlandırma/anlatı:** README/DESIGN'e iki net cümle: *"Guard değil, prover'ız"* (hedefin
  açık olduğunu kanıtlarız, trafiği filtrelemeyiz) + *"evidence-first, model gets no vote"* (VaxGuard-
  tarzı LLM-judge'a karşı). 3 repo bunu doğruladı → sıfır-risk, yüksek getiri.

**B) Küçük kod (cila; istenirse)**
- **X1 — CI eval artefaktı/trend:** `eval/results.json`'ı CI'da saklanan artefakt yap (zamanla
  FP-rate/recall gidişi). Neredeyse bedava, jüriye "sayı zamanla korunuyor" der. (Talos deseni.)
- **V1 — Canlı tarama telemetrisi:** web UI'de tarama sürerken bulgu-akışı (SSE/polling). 3/3 repoda
  görülen tek gerçek UX eksiğimiz; demo değeri yüksek, orta iş.
- **W1 — Bulgu triyaj durumu + notu:** New/Investigating/Resolved + kalıcı analist notu (web UI).
  Küçük iş-akışı katmanı; verdict'e dokunmaz.
- **V2 — Advisory "duruş özeti" rozeti:** severity dağılımından tek skor; **S ile birleştir**,
  advisory tut (verdict'i asla ezmesin). Düşük öncelik.

**C) YAPMAYACAKLARIMIZ (net):** LLM-as-judge (VaxGuard), vaccine/auto-immunity, firewall/proxy
enforcement + karantina (Talos/ChainBreak/VaxGuard), Scapy/network-SOC (CyberSentinel). Hepsi ya
tezimize aykırı ya da başka domain → scope-creep.

## Öneri (eğer 2 şey yapılacaksa)
1. **V3 (anlatı)** — kod yok, en yüksek getiri, 3 repo doğruladı.
2. **X1 (CI eval artefaktı)** — neredeyse bedava, ölçülmüşlük vitrinini güçlendirir.
> V1/W1 demo cilası isteğe bağlı; çekirdek zaten güçlü.
