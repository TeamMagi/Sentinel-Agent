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

## Toplu "Yapılacaklar" (yeni tur — her repo sonrası güncellenir)

- [ ] (V1) Canlı tarama telemetrisi (web UI olay akışı) · *kaynak: VaxGuard* · 🟡
- [ ] (V2) Tek "duruş özeti" advisory rozeti (S ile birleşir) · *kaynak: VaxGuard* · 🟢
- [ ] (V3) "Model oy vermez" karşıt-ders anlatısı (deck/README) · *kaynak: VaxGuard* · 🟢

**Tekrarlayan sinyaller:**
- **Erişilebilirlik/çok-yüzey** (CLI/API/CI/dashboard) — yine çıktı; bizde CLI/MCP/web UI + composite
  Action ile karşılandı, eksik olan **canlı telemetri**.
- **Dürüst limitations + yayınlanmış metrik** — yine "olmazsa-olmaz"; bizde `eval/` + Kısıtlar var.
- **Karşıt ders:** LLM-as-judge (VaxGuard) vs evidence-first (biz) — anlatıda kullanılacak en net fark.

> **Sıradaki repolar:** gönderildikçe bu dosyaya Repo 2, Repo 3… olarak eklenecek ve sentez
> güncellenecek.
