# Dereceye Girenlerin Repo Analizi — Repo Repo İnceleme

> **Amaç:** TLN Cybersecurity Challenge 2026'da dereceye giren projelerin repolarını tek tek
> inceleyip, Sentinel-Agent'ın **eksiklerini/öğrenebileceklerini** biriktirmek. Hedef aracı
> "kullanmak" değil; **kendimizi ve projeyi geliştirmek + GitHub profilini güçlendirmek.**
>
> **Yöntem:** Her repo bir bölüm. Her bölümde: *Ne yapıyor · Öne çıkanlar · Bizde eksik olan ·
> Sentinel'e nasıl eklenir (hangi modül/sınıf) · Öncelik.* Bu belge **analizdir; kod değiştirmez.**
>
> **Önemli çerçeve:** Sentinel-Agent, access-control (IDOR/BOLA/BFLA) ekseninde teknik olarak
> zaten derin (onlarca oracle, deterministik CONFIRMED, replay, actor izolasyonu, redaction,
> scope gate, benchmark holdout, SARIF, web UI). Rakiplerin çoğu **farklı problem alanında**.
> Dolayısıyla buradan alınacak ders çoğunlukla **"yeni zafiyet tipi" değil, "kanıtı jüriye
> inandırıcı sunma disiplini"** olacak. Bunu her repoda ayırt edeceğiz.

---

## Repo 1 — `rakeshselvaraj0108/TLN` = **TRACE X**

**Link:** https://github.com/rakeshselvaraj0108/TLN
**Tür:** Finansal siber suç ("dijital tutuklama" dolandırıcılığı) soruşturma iş tezgâhı (full-stack).
**Yığın:** Python 3.12 + FastAPI + SQLite(WAL) + XGBoost/scikit-learn (backend) · Next.js 14 + React
+ d3 + CesiumJS (frontend) · Claude API (opt-in) / Ollama (local) / deterministik fallback.

### 1.1 Ne yapıyor (kısaca)
Telekom/banka/sosyal/kamera/kayıt gibi **çok kaynaklı kanıtı** içeri alır, kimlikleri kişilere
çözer (union-find entity resolution), alanlar-arası örüntüleri yakalar (call→debit, fan-out, SIM
rotation), her varlığı **kalibre edilmiş ML** ile puanlar, ve tüm iddiaları **tamper-evident kayda**
karşı doğrulayıp insana sunar. Temel ilke bizimkiyle **birebir aynı ruhu taşıyor:**
*"Skor bir insan için ipucudur, asla karar değildir."*

### 1.2 Neden dereceye girmiş — jüriyi etkileyen 6 şey
Alan olarak bizden uzak ama **sunum ve kanıt disiplini** açısından tam da jürinin ödüllendirdiği
şeyleri yapmış:

1. **"Truth Gate" — halüsinasyon önleyici doğrulayıcı + self-eval.** Her cümleyi otomatik
   doğrular ve verdict verir: `VERIFIED / FABRICATED / TAMPERED / UNSUPPORTED / UNCITED`. Dahası,
   **elle etiketlenmiş 9 tuzağa** (2 uydurma, 1 tahrif, 2 desteksiz, 2 geçmesi gereken doğru, 2
   dürüst ret) karşı üretim doğrulayıcısını çalıştırıp **%100 (9/9) doğruluk** yayınlamış.
2. **Hash-zincirli (SHA-256, append-only) kanıt defteri + canlı "tamper drill" butonu.** ₺480.000'i
   ₺1'e bozup entegrite kontrolünün canlı yakalamasını izletiyor. `GET /integrity/verify` 2.119
   kaydı yeniden hash'leyip zinciri yeniden yürüyor.
3. **Dürüst, ölçülmüş metrikler.** ROC-AUC 0.998, ECE 0.0123, PR-AUC 0.994, precision@thr 0.944,
   recall 0.981 — **ve benchmark recall'ının 0.50 olduğunu (12 planted fraud'un 6'sını kaçırıyor)
   saklamadan yayınlamış.** Bu dürüstlük jüride puan.
4. **Exculpatory ("aklayıcı") motor.** Sonuca varmadan önce **masum senaryoları** test ediyor
   (istikrarlı karşı taraf = tedarikçi ödemesi; sabit alıcı = rutin havale; uzun ömürlü paylaşımlı
   telefon = burner değil). Skoru düşürür ama sıfırlamaz (max 0.6 indirim) → final yine insana.
5. **Açık "Kısıtlar" (§16) bölümü.** Sentetik veri, 0.50 recall, tamper-evident ≠ tamper-proof,
   demo auth, feature approximation'ları... zayıflıkları **kendisi listelemiş.**
6. **Tek-komut kanıtlanabilirlik + reproducibility.** `pytest -q` (51 test), `parity.py --all`
   (573 fixture replay), `ml.train` (bit-bit yeniden üretilebilir). Jüri "iddiaları kendim
   doğrulayabiliyorum" diyebiliyor.

### 1.3 Bizde EKSİK / zayıf olanlar (bu repodan çıkan)
Sentinel zaten deterministik CONFIRMED, replay, redaction, controls (positive/negative/stability)
yapıyor — ama **jüriye gösterilebilir "kanıt-güvenilirliği artefaktları"** eksik:

- ❌ **Doğrulayıcı self-eval harness'i yok.** Bizim `verifier`/CONFIRMED mantığımızı **planted
  true-positive + planted false-positive fixture'larına** karşı çalıştırıp "FP oranı %0, TP recall
  %X" diye **yayınlanan bir sayı** üretmiyoruz. TRACE X'in en güçlü kartı buydu.
- ❌ **Hash-zincirli evidence + görünür entegrite doğrulaması yok** (proof bundle var ama
  append-only SHA-256 zinciri + `integrity/verify` + "tamper drill" demo yok).
- ❌ **Yayınlanmış dürüst benchmark metrik tablosu yok.** `bench/twins.py` + `benchmark_holdout`
  altyapısı var ama README'de precision/recall/FP-rate + "neyi kaçırıyoruz" tablosu öne çıkmıyor.
- ❌ **Açık "Kısıtlar/Limitations" bölümü zayıf.** Dürüstlük vitrini eksik.
- ⚠️ **"Exculpatory" adımı örtük.** Bizde negative-control var ama TRACE X gibi *"önce masum
  açıklamayı çürütmeye çalış, çürütemezsen CONFIRMED verme"* diye **açıkça çerçevelenmiş** ve
  raporda gösterilen bir aşama değil.
- ⚠️ **Tek-komut "her şeyi kanıtla" akışı** parçalı (pytest + benchmark ayrı ayrı).

### 1.4 Sentinel'e nasıl eklenir — mimariye uyumlu, invariant'ları bozmadan
Hepsi mevcut katmanlı yapıya (`models → policy → net → oracle → auth → evidence → report`) ve
güvenlik değişmezlerine (LLM ağa dokunmaz, CONFIRMED'i kod verir, actor izolasyonu) **sadık**:

| # | Öneri | Nereye (modül/sınıf) | Not | Öncelik |
|---|---|---|---|---|
| A | **Verifier self-eval harness**: planted TP + FP fixture seti → CONFIRMED mantığını çalıştır → `FP=0`, `TP-recall=X%` sayısı yayınla | `bench/` + yeni `bench/selfeval.py`; fixture'lar `respx`/`MockTransport` ile | Network'süz; jüriye "yalancı çıktı üretmiyoruz" kanıtı. **En yüksek getiri.** | 🔴 Yüksek |
| B | **Hash-zincirli evidence + `integrity verify` + tamper-drill** | `evidence/store.py` + `evidence/proof.py` (`EvidenceStore`'a SHA-256 append-only chain) | CONFIRMED'i etkilemez; sadece kanıtın tahrif edilmediğini ispatlar | 🔴 Yüksek |
| C | **Dürüst benchmark metrik tablosu** README'ye (precision/recall/FP-rate + "kaçırdıklarımız") | `bench/suite.py` çıktısını `report/` üzerinden README'ye; sayıyı CI üretsin | Zaten var olan `benchmark_holdout`'u vitrine çıkarmak | 🔴 Yüksek |
| D | **Açık "Kısıtlar" bölümü** README + DESIGN'e | doküman | Kod yok; sadece dürüstlük vitrini | 🟡 Orta |
| E | **Exculpatory adımını açık aşama yap**: oracle CONFIRMED vermeden önce "benign açıklama" hipotezlerini deterministik ele → rapora "elenen masum senaryolar" satırı | `oracle/base.py` kontrol hattı + `report/` | Var olan negative-control'ü yeniden çerçevele + rapora yansıt | 🟡 Orta |
| F | **Tek komut "prove"**: `make prove` = tests + benchmark + selfeval + integrity, tek çıktı | `Makefile` + `scripts/` | Jüri deneyimini kolaylaştırır | 🟡 Orta |

### 1.5 Bu repodan ALMAYACAKLARIMIZ (kapsam dışı)
- Union-find **entity resolution**, **call→debit / fan-out / SIM rotation** detektörleri, **XGBoost
  skorlama/kalibrasyon**, **CesiumJS harita** — bunlar TRACE X'in domain'ine (fraud investigation)
  ait. Access-control aracımıza doğrudan taşınmaz; taklit etmek scope-creep olur.
- ML kalibrasyon (ROC-AUC/ECE) bize **birebir** uymaz çünkü biz ML skoru değil **deterministik
  kanıt** veriyoruz. Ama "planted set üzerinde precision/recall yayınla" fikri (A/C) uyar.

### 1.6 Tek cümlelik ders
> TRACE X bizden **daha iyi zafiyet bulduğu için değil**, **bulduğunu jüriye daha inandırıcı
> kanıtladığı ve dürüstçe sınırlarını gösterdiği için** dereceye girmiş. Bizim teknik derinliğimiz
> var; eksik olan **kanıt-güvenilirliği vitrini** (self-eval, hash-chain, dürüst metrik, limitasyon).

---

## Repo 2 — `Aditya-galaxy/noscam` = **NoScam**

**Link:** https://github.com/Aditya-galaxy/noscam
**Tür:** Yetkilendirme-dolandırıcılığı önleme geçidi (kurbanı sahte ödeme onaylamaya kandırmayı
engeller). Full-stack: Chrome MV3 eklentisi + servis + telefon onay arayüzü + Android.
**Yığın:** Python 3 (servis) · Chrome MV3 (HTML/CSS/JS) · Android · opsiyonel Gemini API
(yalnızca öğüt cümlesi) · pytest (110+ test).

### 2.1 Ne yapıyor (kısaca)
Kötü site tespit etmeye çalışmaz; **güvenilmez kanalların geri-alınamaz finansal işlemleri
onaylamasını** engeller. Mesaj provenance'ını (link'e mı tıklandı, URL elle mi yazıldı) izler,
saf-fonksiyon policy engine ile 3 karar verir (`allowed / held / refused`), ikinci-cihaz onayı
ister, ve her kararı **SHA-256 hash-chain**'e yazar. Felsefe **bizimkiyle örtüşüyor:** deterministik
motor karar verir, LLM sadece açıklar.

### 2.2 Neden dereceye girmiş — jüriyi etkileyen şeyler
1. **LLM'i KARAR DIŞINA itmiş ve bunu TEST ile kanıtlamış.** Disposition, model çağrılmadan
   *önce* belirleniyor; **testler model ne dönerse dönsün sonucun aynı kaldığını doğruluyor.**
   Model link/markup dönerse reddediliyor. Güvenilmez girdi (payee adı, hostname) modele gitmeden
   **truncate + label** ediliyor (prompt-injection sertleştirmesi).
2. **Saf-fonksiyon policy engine + truth table.** `service/policy.py` deterministik; 110+ testin
   bir kısmı doğrudan **truth-table** ve **approval-replay** testleri.
3. **SHA-256 hash-chain denetim izi** — TRACE X ile *aynı desen.* (İki winner de bunu yapmış.)
4. **Dürüst scorecard:** `Scams stopped 16/16 · ordinary left alone 10/14 · slowed 4/14 ·
   refused 0/14`. Yani **false-positive/friction'ı saklamadan** sayı olarak vermiş.
5. **Gerçek canlı sayfaya karşı regresyon:** Wikimedia bağış sayfasına karşı test — "meşru akışta
   yanlış alarm vermiyoruz" kanıtı.
6. **Açık "Limitations" bölümü** (OS-seviyesi koruma yok, kullanıcı isterse hep aşabilir, vb.).
7. **SSRF önleme** link checker'da; sayfa servise erişemiyor (loopback-only, closed shadow DOM).

### 2.3 Bizde EKSİK / zayıf olanlar (bu repodan çıkan — TRACE X ile çakışmayanlar)
- ❌ **"LLM kararı değiştiremez" invariant'ını KANITLAYAN test yok.** Biz bunu *ilke* olarak
  söylüyoruz (CONFIRMED'i kod verir) ama NoScam gibi *"modele rastgele/kötü niyetli çıktı ver,
  verdict değişmiyor"* diye **açık bir test** ile göstermiyoruz. Ucuz ama çok inandırıcı.
- ❌ **Policy truth-table testi / belgesi zayıf.** `PolicyEngine.authorize` var ama her disposition
  yolunu kapsayan **belgelenmiş truth table** vitrinde değil.
- ⚠️ **Güvenilmez girdinin LLM'e label/truncate edilerek verilmesi** netleştirilmemiş. Yanıt
  gövdeleri (attacker-controlled olabilir) prompt'a girerken prompt-injection sertleştirmesi açık
  değil. (Bizim agent-security oracle'larımız var ama *kendi LLM prompt hattımızın* sertleştirmesi
  ayrı konu.)
- ⚠️ **Gerçek benign uygulamaya karşı "sıfır yanlış CONFIRMED" regresyonu yok.** Biz juice-shop'ta
  kalibre ediyoruz ama "meşru bir uygulamada hiç false-positive üretmiyoruz" diye ayrı bir
  negative-control regresyon seti yok.
- ✅ **Doğrulanan ortak desenler (TRACE X'te de vardı, tekrar güçleniyor):** hash-chain evidence
  (B), dürüst scorecard/metrik (C), açık limitations (D). *İki winner de yaptığına göre bunlar
  "olmazsa-olmaz" sinyali.*

### 2.4 Sentinel'e nasıl eklenir
| # | Öneri | Nereye (modül/sınıf) | Not | Öncelik |
|---|---|---|---|---|
| G | **Verdict-invariance testi**: LLM istemcisine adversarial/rastgele çıktı enjekte et → CONFIRMED/verdict değişmiyor diye assert et | `tests/test_llm_actions.py` / yeni `tests/test_verdict_invariance.py`; sahte LLM client | En ucuz, en inandırıcı invariant kanıtı. **"LLM oy vermez"i test edilebilir yap.** | 🔴 Yüksek |
| H | **Policy truth-table**: her disposition yolunu belgele + testle | `policy/authorize.py` + `tests/test_authorize.py` + DESIGN'e tablo | Var olanı vitrine çıkarmak | 🟡 Orta |
| I | **Prompt-injection sertleştirmesi**: yanıt gövdesi/başlıkları LLM'e girmeden label+truncate | `llm/prompts.py` (+ `net/normalize.py` ile redaction hattı) | LLM ağa dokunmuyor ama *okuduğu içerik* attacker-controlled → sertleştir | 🟡 Orta |
| J | **Benign-app negative-control regresyonu**: meşru bir hedefte "0 CONFIRMED" ispatı | `bench/` (yeni benign fixture seti) | (A) self-eval ile birleştirilebilir | 🟡 Orta |

### 2.5 Bu repodan ALMAYACAKLARIMIZ (kapsam dışı)
İkinci-cihaz onayı, Chrome MV3 eklentisi, closed shadow DOM, ödeme-cap/cooling period, UPI decode,
Android interception — hepsi NoScam'in ödeme-koruma domain'ine ait. Access-control aracına taşınmaz.
(SSRF önleme fikri bizde `net` katmanında zaten scope-gate ile örtülü; ayrıca eklenmez.)

### 2.6 Tek cümlelik ders
> NoScam bizimle **aynı tezi paylaşıyor** ama farkı: *ilkeyi test ile kanıtlıyor* (LLM kararı
> değiştiremez → test), *friction'ı dürüstçe sayıyor* (scorecard), ve *gerçek meşru sayfada yanlış
> alarm vermediğini gösteriyor*. Bizde ilkeler var; **kanıtlayan testler + dürüst sayılar** eksik.

---

## Repo 3 — `alizahh-7/SlopGuard-` = **SlopGuard**

**Link:** https://github.com/alizahh-7/SlopGuard-
**Tür:** Tedarik-zinciri güvenliği — "slopsquatting" (AI'ın uydurduğu paket adlarını saldırganın
kaydedip malware koyması) önleme. Full-stack + çok yüzeyli dağıtım.
**Yığın:** Python 3.10+ / FastAPI (backend) · React 19 + Vite + Tailwind (frontend) · PyPI/npm/OSV
(read-only) · pytest (125 test) · Vercel deploy.

### 3.1 Ne yapıyor (kısaca)
AI kod asistanının önerdiği paketleri kurmadan önce tarar: import/requirements/package.json çıkarır,
registry metadata'sını (kod indirmeden/çalıştırmadan) sorgular, **deterministik belgelenmiş
kurallarla** skorlar, ve paket-başına verdict + kanıt + öneri verir. Felsefe bizimkiyle aynı:
*deterministik, belgeli kurallar; tutarlı sonuç; "güvenli" iddia etmek yerine sinyal raporla.*

### 3.2 Neden dereceye girmiş — jüriyi etkileyen şeyler
1. **Çok-yüzeyli, düşük-friction dağıtım:** Web (yapıştır-tara) · **CLI (exit-code'lu)** ·
   **GitHub Action (CI/CD'ye düşer)** · **MCP server (üretim anında asistana açılır)** · REST API.
   Uzman-olmayan da, CI da, AI asistanı da kullanabiliyor. **Erişilebilirlik puanı burada.**
2. **Aksiyon alınabilir çıktı:** "Safe Install" (flagged paketleri çıkaran komut üretir) + "Fix"
   (version pin'leri koruyarak düzelten diff üretir). Sadece raporlamıyor, **çözüm veriyor.**
3. **Çalıştırılabilir eval artefaktı:** `eval/labeled.json` (70 etiketli vaka) + `evaluate.py` →
   "no FP, no FN" — **ama dürüstçe** "küçük, yazar-derlemesi set, gerçek-dünya doğruluğu değil"
   diyor. Hatta AI benchmark'ının **yetersiz tamamlandığını (12/360) saklamadan** yayınlamış.
4. **Sağlam verdict taksonomisi + `UNKNOWN` disiplini:** `OK/REVIEW/RISKY/BLOCK/UNKNOWN`; yetersiz
   veri → `UNKNOWN`, **asla risk/phantom iddiası değil.** "Güvenli demiyoruz, sinyal raporluyoruz."
5. **İyi-huylu servis:** read-only, request body loglanmıyor, rate-limit (429), input validation
   (422), timeout, CORS allowlist. Güvenlik-bilinçli mühendislik.
6. **Açık "Limitations" + "Next Steps"** (yalnız PyPI/npm, metadata-tabanlı, küçük eval seti…).

### 3.3 Bizde EKSİK / zayıf olanlar (bu repodan çıkan — yeni olanlar)
- ❌ **CI/CD entegrasyonu (GitHub Action) yok.** SARIF çıktımız var (CI-dostu!) ama Sentinel'i bir
  pipeline'a "düşürüp exit-code ile kapı yapan" hazır bir GitHub Action paketi yok. En düşük
  frictionlu adoption yolu bu.
- ❌ **Aksiyon-alınabilir remediation çıktısı zayıf.** Bulguyu raporluyoruz ama "bunu şöyle düzelt"
  (yapıştırılabilir mitigation/fix ipucu) her bulguya iliştirilmiyor.
- ❌ **Çalıştırılabilir, versiyonlu eval artefaktı yok.** `bench/` altyapısı var ama SlopGuard gibi
  *"`eval/labeled.json` + `evaluate.py` → herkes çalıştırır, FP/FN sayısını yeniden üretir"* diye
  temiz, tek-dosya bir kanıt artefaktımız yok. **Bu, A/C/J maddelerinin somut/çalıştırılabilir
  hâli** — onları "artefakt" seviyesine yükseltmeliyiz.
- ⚠️ **`INCONCLUSIVE` disiplinini vitrine çıkarmıyoruz.** Bizde INCONCLUSIVE verdict var ama
  "yetersiz veri asla CONFIRMED'e şişmez, biz güvenli demeyiz sadece kanıt raporlarız" çerçevesi
  README'de öne çıkmıyor. (SlopGuard'ın `UNKNOWN` disiplini tam bu.)
- ✅ **Tekrar güçlenen:** dürüst eval + açık limitations (C/D). *Üçüncü winner de yaptı.*
- ♻️ **Erişilebilirlik teması yine çıktı:** Eski `rakip-analizi-tln-galeri` belgesi de "en zayıf
  yanımız friction/erişilebilirlik" demişti (Synk örneği). SlopGuard bunu **doğruluyor** →
  çok-yüzeyli, düşük-friction on-ramp gerçek bir puan ekseni.

### 3.4 Sentinel'e nasıl eklenir
| # | Öneri | Nereye (modül/sınıf) | Not | Öncelik |
|---|---|---|---|---|
| K | **GitHub Action + exit-code gating**: SARIF çıktısını CI'da kapıya bağla | `.github/actions/` + `scripts/` + var olan SARIF reporter | SARIF zaten var → sarmalayıcı iş. Düşük-friction adoption. | 🔴 Yüksek |
| L | **Bulgu-başına remediation ipucu**: her verdict'e "nasıl düzeltilir" satırı | `report/` (Reporter alt sınıfları) + oracle metadata | Sadece raporlama katmanı; motoru etkilemez | 🟡 Orta |
| M | **Çalıştırılabilir eval artefaktı**: `eval/labeled.json` + `eval/evaluate.py` → FP/FN yayınla | yeni `eval/` (A/C/J'yi tek somut artefakta bağla) | Jüri "kendim çalıştırıp doğruladım" der. **A+C+J'nin çıktısı.** | 🔴 Yüksek |
| N | **`INCONCLUSIVE` disiplinini belgele + çerçeve**: "güvenli demeyiz, kanıt raporlarız" | `oracle/base.py` + README | Var olanı vitrine çıkarmak; kod ~yok | 🟢 Düşük |

### 3.5 Bu repodan ALMAYACAKLARIMIZ (kapsam dışı)
Slopsquatting/paket-registry mantığı (PyPI/npm/OSV sorgu, typosquat, alias tablosu), Vercel deploy,
React frontend detayları — SlopGuard'ın tedarik-zinciri domain'ine ait. Access-control aracına
taşınmaz. ("Fix diff üretme" fikrini L'de *hafif* biçimde alıyoruz; paket-fix mantığını değil.)

### 3.6 Tek cümlelik ders
> SlopGuard bizden **daha akıllı tespit yaptığı için değil**, *herkesin kolayca kullanabildiği*
> (web/CLI/Action/MCP), *aksiyon veren* (fix/safe-install), ve *herkesin çalıştırıp doğrulayabildiği
> eval'i olan* (labeled.json + evaluate.py) bir paket olduğu için dereceye girmiş. Bizim eksiğimiz
> **paketleme/erişilebilirlik + çalıştırılabilir kanıt artefaktı.**

---

## Repo 4 — `hashmessi/ChainBreak` = **ChainBreak** ⭐ (bize en yakın)

**Link:** https://github.com/hashmessi/ChainBreak
**Tür:** AI-ajan runtime güvenliği — otonom ajanda **çok-adımlı (trajectory) veri sızdırma**
önleme. Middleware olarak tool-call'ları araya girip *birikimli yörüngeyi* değerlendirir.
**Yığın:** Python 3.10+ / FastAPI + OpenRouter LLM (deterministik fallback classifier ile) ·
React 18 + Vite (frontend) · Docker/Render/Vercel/Heroku · pytest (44 test).

### 4.1 Ne yapıyor (kısaca)
Tek tek zararsız ama zincirlenince sızıntıya dönen adımları yakalar: *"her adım tek başına
zararsız ve standart izin kontrolünü geçer; ama otonom yörüngede biriken durum yetkisiz context
exfiltration'a yol açar."* LLM classifier her adımdan semantik öznitelik (intent, sensitivity,
destination) çıkarır; birikimli **state manager** nedensel soy-ağacını (`triggered_by:
[step_indices]`) tutar; deterministik **invariant engine** yörünge güvenlik kontratını ihlal
ediyor mu diye karar verip **egress'ten önce** bloklar.

### 4.2 Neden dereceye girmiş — ve neden bizim gizli yeteneğimizle örtüşüyor
1. **Felsefe BİREBİR bizim tezimiz:** *"semantik yorum (LLM) ile deterministik uygulama (saf
   Python) ayrımı → güvenlik kararında zero hallucination, classifier güvenine bağımsız fail-closed
   garanti."* Bu tam olarak "LLM akıl yürütür, motor kanıtlar" ilkemiz. **Jüri bunu ödüllendirmiş.**
2. **Trajectory-level analiz (per-step değil):** Birikimli durum + nedensel lineage. Yani
   "innovation" ekseninde farkı burada. Bizim EXFILTRATION predicate'imiz var ama **birikimli
   yörünge + lineage** boyutu bizde ne kadar derin? (Bkz. §4.3.)
3. **İsimlendirilmiş, belgeli 4 invariant (birinci-sınıf kontrat):** `SENSITIVE_DATA_BOUNDARY`,
   `SECRET_BOUNDARY`, `PRIVILEGE_BOUNDARY`, `TRAJECTORY_ESCALATION`. Bizim 4 predicate'imizle
   neredeyse örtüşüyor — ama onlar bunları **vitrine koymuş.**
4. **Counterfactual "dual-track" kanıt:** Korumasız baseline vs korumalı yürütme **yan yana**,
   adım-adım lineage ile. Görsel, ikna edici, "işte fark bu" diyen bir kanıt sunumu.
5. **Fail-closed mimari:** Belirsizlik → blokla; bilinmeyen tool → HOLD.
6. **Dürüst benchmark taksonomisi:** 20 senaryo → 6 attack(BLOCK) · 5 safe(ALLOW) · **4 near-miss
   (ALLOW!)** · 3 failure(HOLD) · 2 unknown(HOLD). **%100 detection, %100 prevention, %0 false
   block.** *"near-miss" kategorisi = saldırıya benzeyen ama masum akışları KASITLI olarak
   flag'lememe disiplini.*
7. **Performans metriği:** invariant başına <0.15ms — ölçülmüş, yayınlanmış.

### 4.3 Bizde EKSİK / zayıf olanlar (bu repodan çıkan — en değerli grup)
- ❗ **Anlatı hatası (tekrar doğrulandı):** Bizim ajan-çağı yetki yeteneğimiz **var** ama
  README/deck IDOR/BOLA'yı öne çıkarıp bunu dipnota atıyor. ChainBreak sadece bunu yapıp dereceye
  girmiş. **Anlatıyı "klasik API yetki + ajan-çağı trajectory yetki, ikisini de KANITLA" olarak
  yeniden çerçevelemek** en yüksek getirili, kod-gerektirmeyen hamle. *(Eski galeri analizi de
  aynısını söylemişti — üçüncü kez doğrulandı.)*
- ❓ **Trajectory-level birikimli analiz + lineage derinliği belirsiz.** Bizim EXFILTRATION
  predicate'imiz per-action mı, yoksa ChainBreak gibi *birikimli yörünge + `triggered_by` nedensel
  soy-ağacı* mı izliyor? Eğer per-action ise, **gerçek bir yetenek boşluğu** var. (Kontrol edilmeli;
  `world_model.py` + `agent/exfiltration.py`.)
- ❌ **Counterfactual dual-track görsel kanıt yok.** Bizde positive/negative control + replay **var**
  ama "korumasız baseline vs kontrollü sonuç" **yan yana, adım-lineage'lı** bir sunumu yok.
  Var olan malzemeyi güçlü bir kanıt-vitrinine dönüştürme fırsatı.
- ⚠️ **Ajan invariant'ları isimlendirilip belgelenmemiş.** 4 predicate'imiz var ama ChainBreak gibi
  "birinci-sınıf, isimli, belgeli güvenlik kontratı" olarak sunulmuyor.
- ⚠️ **"Near-miss" benchmark kategorisi yok.** J maddesini keskinleştirir: sadece benign değil,
  *saldırıya benzeyen-ama-masum* vakaları da flag'lemediğimizi ispatlamalıyız.
- ✅ **Tekrar güçlenen:** LLM-semantik / deterministik-uygula ayrımı (çekirdek tezimiz) —
  ChainBreak "zero hallucination" çerçevesiyle bunu doğruluyor; bu ifadeyi biz de kullanmalıyız.

### 4.4 Sentinel'e nasıl eklenir
| # | Öneri | Nereye (modül/sınıf) | Not | Öncelik |
|---|---|---|---|---|
| O | **Trajectory-level exfiltration + nedensel lineage** (`triggered_by` step indices) — per-action'dan birikimli-yörüngeye | `orchestrator/world_model.py` + `agent/exfiltration.py` + `oracle/untrusted_to_action.py` | Önce mevcut derinliği KONTROL et; eksikse gerçek yetenek ekle | 🔴 Yüksek |
| P | **Counterfactual dual-track kanıt** (baseline-savunmasız vs kontrollü, yan yana + lineage) rapora/UI'ya | `report/` + web UI + var olan control/replay | Yeni motor yok; var olan control+replay'i vitrine çevir | 🔴 Yüksek |
| Q | **Ajan invariant'larını isimlendir + belgele** (4 predicate → birinci-sınıf kontrat) + anlatıyı yeniden çerçevele | `models/immunity.py` + README/DESIGN + deck/video | Kod ~yok; en yüksek getirili sunum hamlesi | 🔴 Yüksek |
| R | **"Near-miss" benchmark kategorisi** (saldırı-benzeri-ama-masum → flag'leme) | `bench/` (J/M ile birleşir) | FP disiplinini keskinleştirir | 🟡 Orta |

### 4.5 Bu repodan ALMAYACAKLARIMIZ (kapsam dışı)
ChainBreak bir *savunma* middleware'i (runtime guard); biz *bulucu/kanıtlayıcı* araçyız. Onların
"tool-call'ı araya girip blokla" enforcement modelini olduğu gibi almayız — biz hedef ajanın bu
trajectory saldırılarına **açık olup olmadığını test ederiz.** Yani ChainBreak'in *senaryolarını*
(attack/near-miss taksonomisi) ve *sunumunu* alırız; enforcement-gate rolünü değil.

### 4.6 Tek cümlelik ders
> ChainBreak, bizde **zaten var olan ama gizlediğimiz** ajan-çağı yetki yeteneğini *tek başına öne
> çıkarıp* dereceye girmiş. Dersimiz üç katlı: (1) anlatıyı ajan-yetkiyi de içerecek şekilde yeniden
> çerçevele (Q), (2) trajectory+lineage derinliğini kontrol et/tamamla (O), (3) baseline-vs-kontrol
> counterfactual'ı görsel kanıta çevir (P).

---

## Repo 5 — `Ansh87/CyberShield` = **CyberShield**

**Link:** https://github.com/Ansh87/CyberShield
**Tür:** AI destekli tehdit sınıflandırma + **bağlam/sonuç-farkındalıklı gerçek-dünya risk skoru.**
Siber-fiziksel tehditleri sistemin özelinde değerlendirir. *(Lise öğrencisi eğitim prototipi.)*
**Yığın:** Vanilla JS/HTML/CSS (frontend) · Netlify serverless (Node) · Gemini API · CISA KEV +
MITRE ATT&CK/ATLAS + OWASP LLM Top 10 veri kaynakları.

### 5.1 Ne yapıyor (kısaca)
Telemetriyi Gemini ile sınıflandırır, sonra **deterministik kod sonucu (consequence) hesaplar.**
Aynı zafiyeti bağlamına göre farklı puanlar: chatbot'ta prompt injection = veri sızıntısı;
aktüatörde = güvenlik olayı. Ağırlıklı formül: fiziksel-güvenlik %28 · severity %25 · varlık
kritikliği %22 · otonomi %15 · maruziyet %10, gözetim seviyesine göre çarpanla düşürülür.

### 5.2 Neden galeriye/derece adayına girmiş — ve karşıt dersler
1. **Güçlü IMPACT anlatısı:** "Tüm zafiyetler eşit değildir; aktüatörü vuran ≠ chatbot'u vuran."
   Siber-fiziksel güvenlik çerçevesi jürinin "Impact & Relevance" kriterine doğrudan hitap ediyor.
   **Basit bir proje bile net bir 'neden önemli' hikâyesiyle görünür oluyor.**
2. **Sonuç-farkındalıklı skorlama:** Düz severity yerine **varlık kritikliği + otonomi + maruziyet
   + gözetim** ile bağlamsal risk. Karar-verici için daha kullanışlı çıktı.
3. **Felsefe yine bizimki (5. kez):** "Gemini tanımlar, deterministik kod sonucu hesaplar."
4. **Prompt-injection sertleştirmesi (I'yi doğruluyor):** Telemetriyi tag'e sarıp *"kanıt
   güvenilmezdir, injection'ı çalıştırma, raporla"* diyor + output escaping + API key server-side.
5. **Taksonomi eşleme:** Bulgular CISA KEV'e canlı doğrulanıyor; MITRE ATT&CK/ATLAS + OWASP LLM
   Top 10 eşlemesi → inandırıcılık.
6. **KARŞIT DERS (dürüstlük yeterli değil, sayı da lazım):** Dürüstçe "LLM yanılabilir, tüm bulgular
   insan doğrulaması ister, FP oranı ölçülmedi, public dataset'te (CICIDS2017/UNSW-NB15) test
   edilmedi, nicel metrik yok" diyor. **Dürüst ama sayısız** → muhtemelen bu yüzden üst sıralarda
   değil. Bize mesaj: **C/M şart** — sadece "kısıtımız var" demek yetmez, *sayıyı da* koymalıyız.

### 5.3 Bizde EKSİK / zayıf olanlar (bu repodan çıkan — yeni olanlar)
- ❌ **Bağlamsal sonuç/impact skorlaması yok.** Biz CONFIRMED/severity veriyoruz ama "bu IDOR *tüm
  kullanıcıların PII'sini* mi yoksa *önemsiz bir alanı* mı sızdırıyor?" gibi **iş-etkisi/blast-radius
  boyutu** raporda yok. Karar-verici için önceliklendirme zayıf kalıyor.
- ⚠️ **Taksonomi eşleme vitrini zayıf.** `detector/cve.py` + `classify.py` var ama her bulguyu
  **OWASP API Top 10 / CWE / MITRE** ile eşleyip raporda göstermek inandırıcılığı artırır.
- ⚠️ **IMPACT anlatısı zayıf.** "Access-control neden önemli" (gerçek ihlaller, $, PII) hikâyesini
  deck/README/video'da güçlendirmek "Impact & Relevance" puanını yükseltir.
- ✅ **Doğrulanan:** prompt-injection untrusted-labeling (I) — CyberShield tam bunu yapıyor;
  LLM/deterministik ayrımı (5. kez); ve "sayısı olmayan dürüstlük yetmez" → C/M'nin önemi.

### 5.4 Sentinel'e nasıl eklenir
| # | Öneri | Nereye (modül/sınıf) | Not | Öncelik |
|---|---|---|---|---|
| S | **Bağlamsal sonuç/impact skoru**: bulguya blast-radius/veri-hassasiyeti/varlık-kritikliği boyutu | `report/` + `classify.py` (+ opsiyonel scope config'te asset criticality) | CONFIRMED'i etkilemez; önceliklendirme katmanı | 🟡 Orta |
| T | **Taksonomi eşleme**: her bulgu → OWASP API Top 10 / CWE / MITRE ATT&CK | `classify.py` + `report/` | İnandırıcılık; kısmen var olabilir, vitrine çıkar | 🟡 Orta |
| U | **IMPACT anlatısı**: "access-control neden önemli" (gerçek vaka/$/PII) deck/README/video | doküman | Kod yok; "Impact & Relevance" puanı | 🟡 Orta |

### 5.5 Bu repodan ALMAYACAKLARIMIZ (kapsam dışı)
Siber-fiziksel/aktüatör telemetri sınıflandırması, Gemini-bağımlı sınıflandırma, prose text-box
ingestion, Netlify serverless mimarisi — CyberShield'in domain'ine/olgunluk seviyesine ait.
Skorlama *fikrini* (S) alıyoruz, siber-fiziksel modelini değil.

### 5.6 Tek cümlelik ders
> CyberShield teknik olarak en hafif proje ama **net bir impact hikâyesiyle** görünür olmuş; asıl
> dersi ise *karşıt*: dürüstçe "metriğimiz yok" demek, dürüst *ve* ölçülmüş rakiplerin gerisinde
> bırakıyor → bizim **sayıya sahip olmamız** (C/M) şart, sadece kısıt beyanı yetmez.

---

## Toplu "Yapılacaklar" (biriken — her repo sonrası güncellenir)

- [ ] (A) Verifier self-eval harness — planted TP/FP → yayınlanan FP/recall sayısı  · *kaynak: TRACE X* · 🔴
- [x] (B) Hash-zincirli evidence + integrity verify + tamper-drill · *kaynak: TRACE X* · 🔴 — `evidence/ledger.py` (append-only, prev_hash zincirli defter) + `EvidenceStore` her koşumda `proof/ledger.jsonl` yazar + `scripts/integrity.py` (`verify` zinciri+proof'ları yeniden hash'ler, `--drill` canlı tamper-drill); `tests/test_ledger.py` (8). Verdict'i etkilemez.
- [x] (C) Dürüst benchmark metrik tablosu (README) · *kaynak: TRACE X* · 🔴 — README §"Çok-hedefli benchmark"te zaten var (precision/recall/FP-rate + "neyi kaçırıyoruz")
- [x] (D) Açık "Kısıtlar" bölümü (README/DESIGN) · *kaynak: TRACE X* · 🟡 — README'ye "⚠️ Kısıtlar (dürüst sınırlar)" bölümü eklendi
- [ ] (E) Exculpatory adımını açık kontrol aşaması yap · *kaynak: TRACE X* · 🟡
- [x] (F) Tek komut `make prove` · *kaynak: TRACE X* · 🟡 — `make prove` = pytest + self-eval + bench-guard + verify_release (ağsız, ilk kırılan kapıda durur); `make eval` de eklendi
- [x] (G) Verdict-invariance testi — LLM ne dönerse dönsün verdict aynı · *kaynak: NoScam* · 🔴 — `tests/test_verdict_invariance.py` (5): adversarial LLM (demote/escalate/injection/çöp/patlama) → verdict+severity SABİT, yalnızca severity_suggested/impact değişir; Hypothesis'te verdict alanı yok
- [x] (H) Policy truth-table (belge + test) · *kaynak: NoScam* · 🟡 — `tests/test_authorize_truth_table.py` (12 satır + kapsama testi, parametrize) + DESIGN.md §10.5'e belgelenmiş truth-table (tek kaynak, drift koruması)
- [x] (I) Prompt-injection sertleştirmesi — yanıt içeriği LLM'e label+truncate · *kaynak: NoScam* · 🟡 — `llm/prompts.py` `wrap_untrusted()`: fence-breakout nötrleme (içerikteki `<<UNTRUSTED_DATA>>`/rol etiketleri) + truncation (MAX 8000); 4 build_* metodu buradan geçer; `tests/test_prompt_hardening.py` (6). (Fence + "veri, talimat değil" zaten vardı; eksik olan kaçış+kırpma eklendi.)
- [ ] (J) Benign-app negative-control regresyonu (0 CONFIRMED ispatı) · *kaynak: NoScam* · 🟡

- [x] (K) GitHub Action + exit-code gating (SARIF'i CI kapısına bağla) · *kaynak: SlopGuard* · 🔴 — workflow zaten SARIF+`--fail-on` yapıyordu; eksik olan tekrar-kullanılabilir composite `.github/actions/sentinel-scan/action.yml` eklendi (başka repolar `uses:` ile çağırır, `sentinel scan` CLI'ıyla). README'de örnek kullanım.
- [x] (L) Bulgu-başına remediation ipucu (raporda "nasıl düzeltilir") · *kaynak: SlopGuard* · 🟡 — remediation kataloğu `webui`→`report/remediation.py`'ye taşındı (tek kaynak, webui shim), markdown rapor her REJECTED-olmayan bulguya deterministik fix + OWASP linki iliştirir; `tests/test_report_remediation.py` (4)
- [x] (M) Çalıştırılabilir eval artefaktı `eval/labeled.json`+`evaluate.py` (A+C+J'yi somutlaştırır) · *kaynak: SlopGuard* · 🔴 — `eval/` (labeled.json + evaluate.py + results.{json,md}) + `src/pentestai/bench/eval.py` + `tests/test_eval.py`; 8 vaka, GERÇEK oracle, ağsız → precision %100 / recall %100 / **FP-rate %0**; A(self-eval)+C(metrik)+J(benign)+R(near-miss) tek artefaktta
- [x] (N) `INCONCLUSIVE` disiplinini belgele/çerçevele ("güvenli demeyiz") · *kaynak: SlopGuard* · 🟢 — README verdict merdivenine "Güvenli demeyiz, kanıt raporlarız" çerçevesi eklendi

- [x] (O) Trajectory-level exfiltration + nedensel lineage (`triggered_by`) · *kaynak: ChainBreak* · 🔴 — `agent/lineage.py` (data-flow taint: önceki adımın çıktısı sonrakinin argümanında → `triggered_by`) + `ToolCall.triggered_by` alanı + `ExfiltrationOracle` çok-adımlı sızıntıda nedensel zincir kanıtı üretir (okuma→sızdırma); `tests/test_lineage.py` (6). Verdict'i etkilemez. **Not:** untrusted_to_action zaten kaynak-izleme (1-adım lineage) yapıyor.
- [x] (P) Counterfactual dual-track kanıt (baseline vs kontrollü, yan yana) · *kaynak: ChainBreak* · 🔴 — `report/counterfactual.py`: "Yetkili (baseline) ↔ Kontrolsüz (saldırı)" yörüngeleri yan yana + nedensel lineage (sahip okur→saldırgan erişir→deterministik fark), REDAKTE; markdown rapora bağlandı (`render_md`). HTML/web UI zaten iki yörüngeyi payload'da taşıyor.
- [~] (Q) Ajan invariant'larını isimlendir/belgele + anlatıyı yeniden çerçevele · *kaynak: ChainBreak (+eski galeri)* · 🔴 — README'de 5 predicate "isimli, birinci-sınıf güvenlik kontratı" olarak çerçevelendi, bayat predicate tablosu düzeltildi (UNTRUSTED_TO_ACTION artık "implemented"), "zero hallucination" + "klasik API + ajan-çağı yetki, ikisini de KANITLA" dili eklendi. **Kalan:** deck/video/Devpost anlatısı
- [x] (R) "Near-miss" benchmark kategorisi (saldırı-benzeri-ama-masum) · *kaynak: ChainBreak* · 🟡 — M'ye dahil: session-scoped id + public-by-design near-miss vakaları (`SessionScopedIdorNearMiss` + `PublicEndpointTwin`), ikisi de doğru şekilde CONFIRMED DEĞİL
- [x] (S) Bağlamsal sonuç/impact skoru (blast-radius/veri-hassasiyeti) · *kaynak: CyberShield* · 🟡 — `report/impact.py`: deterministik heuristik blast-radius (çapraz-kullanıcı/auth'suz) + operasyon (read/write-delete); markdown rapora 'Bağlamsal etki (heuristik)' satırı; severity'yi etkilemez; `tests/test_mitre_impact.py` (9)
- [x] (T) Taksonomi eşleme (OWASP API Top 10 / CWE / MITRE) raporda · *kaynak: CyberShield* · 🟡 — CWE+OWASP zaten tam; MITRE ATT&CK eşlemesi (`classify.MITRE_ATTACK` + `Finding.mitre`, yaklaşık/dürüst) eklendi, markdown Classification satırında görünür
- [~] (U) IMPACT anlatısı (access-control neden önemli) deck/README/video · *kaynak: CyberShield* · 🟡 — README "Neden önemli?" bloğu güçlendirildi (mass-PII/account-takeover, "kanıtlar, tahmin etmez"). **Kalan:** deck/video

**Tekrarlayan sinyaller (birden çok repoda):**
- **Anlatıyı ajan-çağı yetkiye de çevir** (Q) — ChainBreak *tek başına bunu yapıp* dereceye girdi;
  eski galeri analizi de aynısını demiş → **en yüksek getirili, kod-gerektirmeyen hamle.**
- **LLM-semantik / deterministik-uygula ayrımı** — çekirdek tezimiz; ChainBreak "zero hallucination"
  çerçevesiyle doğruladı. Bu ifadeyi biz de kullanmalıyız.
- **Hash-chain evidence** (B) — TRACE X + NoScam → "olmazsa-olmaz".
- **Dürüst metrik + açık limitations** (C, D) — 4 winner'da da var → "olmazsa-olmaz".
- **Erişilebilirlik/friction** (K + eski galeri) — tekrar tekrar çıkan zayıf yanımız.
- **Çalıştırılabilir eval + near-miss disiplini** (M+R = A+C+J'nin somut hâli) — jüri "kendim
  doğruladım" diyebilmeli; sadece "yakaladık" değil "yanlış alarm vermedik" de ispatlanmalı.

---

# 🎯 SENTEZ VE EYLEM PLANI (5 repo bittikten sonra)

## Ana teşhis (tek paragraf)
5 dereceye giren projenin **hiçbiri access-control ekseninde bizden teknik olarak daha derin
değil.** Sentinel-Agent zaten onlarca oracle, deterministik CONFIRMED, replay, actor izolasyonu,
redaction, scope gate, SARIF, benchmark holdout, MCP server ve web UI'ye sahip. **Kaybettiğimiz yer
teknik derinlik değil; üç eksen:** (1) **konumlandırma/anlatı** — sahip olduğumuz ajan-çağı yetki
yeteneğini gizliyoruz; (2) **kanıt-vitrini** — bulduğumuzu jüriye "kendisi çalıştırıp doğrulayacağı"
biçimde sunmuyoruz (self-eval sayısı, hash-chain, counterfactual, dürüst metrik); (3)
**erişilebilirlik** — CI/Action/kolay on-ramp eksik. İyi haber: bunların çoğu **kod değil paketleme
ve sunum** işi, ve bir kısmı (control, replay, INCONCLUSIVE, benchmark) **zaten var, sadece vitrine
çıkmamış.**

## Örüntü tablosu — hangi ders kaç repoda çıktı?
| Ders | TRACE X | NoScam | SlopGuard | ChainBreak | CyberShield | Sinyal |
|---|:-:|:-:|:-:|:-:|:-:|---|
| LLM-semantik / deterministik-uygula ayrımı | ✅ | ✅ | ✅ | ✅ | ✅ | **5/5 — çekirdek tez, doğru yoldayız** |
| Dürüst metrik + açık limitations | ✅ | ✅ | ✅ | ✅ | ⚠️(yok) | **olmazsa-olmaz** |
| Çalıştırılabilir/dürüst eval seti | ✅ | ✅ | ✅ | ✅ | ❌ | **olmazsa-olmaz** |
| Hash-chain tamper-evident kanıt | ✅ | ✅ | — | — | — | güçlü |
| Erişilebilirlik (web/CLI/Action/MCP) | — | ✅ | ✅ | ✅ | ✅ | **zayıf yanımız** |
| Counterfactual / baseline-vs-korumalı sunum | ✅ | — | ✅(fix) | ✅ | — | güçlü sunum kartı |
| Ajan-çağı / trajectory yetki | — | — | — | ✅ | ⚠️ | **gizli gücümüz** |
| Bağlamsal impact/consequence skoru | ✅ | — | — | — | ✅ | orta |

## Önceliklendirilmiş yol haritası

### Faz 0 — Kod GEREKTİRMEYEN, en yüksek getiri (birkaç gün, hemen)
Bunlar "yarışma sonrası" değil, **profil/README için hemen** yapılabilir ve en çok puanı bunlar
kaybettirmiş:
- **Q — Anlatıyı yeniden çerçevele:** README/DESIGN/deck'i "klasik API yetki (IDOR/BOLA/BFLA) +
  ajan-çağı yetki (confused-deputy, exfiltration, destructive-write, untrusted→action), **ikisini
  de deterministik KANITLA**" olarak konumlandır. 4 predicate'i isimli, belgeli kontrat yap.
- **D — Açık "Kısıtlar" bölümü** + **U — IMPACT anlatısı** (access-control neden önemli: gerçek
  ihlaller/$/PII).
- **"zero hallucination in security decisions"** ifadesini (ChainBreak) tezimizi anlatırken kullan.
- **N — INCONCLUSIVE disiplinini** ("güvenli demeyiz, kanıt raporlarız") vitrine çıkar.

### Faz 1 — Kanıt-vitrini (var olanı çıktıya çevir; orta iş)
- **M (+A, C, J, R) — Çalıştırılabilir eval artefaktı:** `eval/labeled.json` + `eval/evaluate.py` →
  planted TP + FP + **near-miss** vakalarını çalıştır, **FP=%0 / recall=%X** yayınla. Bu tek artefakt
  A(self-eval)+C(dürüst metrik)+J(benign negative-control)+R(near-miss)'i birden karşılar.
- **P — Counterfactual dual-track kanıt:** var olan positive/negative control + replay'i
  "baseline-savunmasız vs kontrollü sonuç" yan yana + adım lineage olarak rapora/web UI'ya koy.
- **F — Tek komut `make prove`:** tests + eval + (B) integrity, tek çıktı.

### Faz 2 — Kod işi (gerçek yetenek/altyapı; yarışma-sonrası yol haritası)
- **G — Verdict-invariance testi:** LLM'e adversarial çıktı → verdict değişmiyor (ucuz, yüksek etki).
- **B — Hash-zincirli evidence + integrity verify + tamper-drill** (iki winner de yaptı).
- **O — Trajectory-level exfiltration + nedensel lineage** (`triggered_by`) — ÖNCE mevcut
  `world_model.py`/`agent/exfiltration.py` derinliğini kontrol et; per-action ise gerçek boşluk.
- **K — GitHub Action + exit-code gating** (SARIF zaten var → sarmalayıcı).
- **I — Prompt-injection sertleştirmesi** (yanıt içeriği LLM'e label+truncate).

### Faz 3 — İyileştirme (nice-to-have)
- **H** Policy truth-table · **L** bulgu-başına remediation · **S** bağlamsal impact skoru ·
  **T** taksonomi eşleme (OWASP API Top 10 / CWE / MITRE).

## En kritik 3 hamle (eğer sadece 3 şey yapılacaksa)
1. **Q (anlatı):** Ajan-çağı yetki yeteneğini öne çıkar — 3 farklı kaynak (ChainBreak + eski galeri
   + bu sentez) aynı şeyi söylüyor. Kod yok, en yüksek getiri.
2. **M (çalıştırılabilir eval + dürüst sayı):** 4/5 winner'da var, bizde yok. "Kendim doğruladım"
   dedirtir.
3. **P (counterfactual kanıt sunumu):** Var olan control/replay'i görsel, ikna edici kanıta çevir.

## Doğrulanacaklar (koda bakılmadan varsayım yapmadım — bunları teyit et)
- [x] EXFILTRATION/agent predicate'i **per-action mı, birikimli-trajectory mi?** (`world_model.py`,
  `agent/exfiltration.py`) → **Trace-seviyesi** (tüm `AgentTrace`'i tarar) ama **nedensel
  `triggered_by` soy-ağacı YOK**: `ToolCall`'da yalnızca `step`+`source` var, causal graph yok.
  → **O gerçek (kısmi) boşluk**: model zaten trajectory-level; eksik olan lineage grafiği.
- [x] Bulgular **OWASP API Top 10 / CWE** ile eşleniyor mu? (`classify.py`) → **EVET, tam.**
  `TYPE_META` her türü CWE+OWASP'a eşler, `assign()` yazar, SARIF `properties`'e taşır.
  → **T motor seviyesinde BİTMİŞ**; kalan sadece MITRE ATT&CK eşlemesi + rapor vitrini (küçük).
- [x] `EvidenceStore` hash-**chain** tutuyor mu yoksa tekil hash mi? (`evidence/store.py`) →
  **Bulgu-başına tekil SHA-256 (+opsiyonel HMAC) proof bundle** (`proof.py`). Append-only
  **zincir / `integrity verify` / tamper-drill YOK**. → **B gerçek boşluk.**
- [x] Benchmark'ta **near-miss** (saldırı-benzeri-ama-masum) vaka var mı? (`bench/`) → **HAYIR**
  (yalnız analiz belgesinde geçiyor). `bench/twins.py` vulnerable↔hardened ikizleri var ama
  "saldırıya-benzer-ama-masum" ayrı kategori değil. → **R gerçek boşluk.**

> **Ek tespitler (bu tur):** `K` (GitHub Action) büyük ölçüde **var** — `.github/workflows/
> sentinel.yml` SARIF yükler + `--fail-on` ile exit-code kapısı yapar; eksik olan yalnızca başka
> repoların `uses:` ile çağırabileceği tekrar-kullanılabilir **composite `action.yml`**.
> `C` (dürüst metrik tablosu) README'de **zaten var**. `F` (`make prove`) ve `M` (`eval/`
> artefaktı) **yok**. `G` (verdict-invariance testi) ayrı test olarak **yok**.
