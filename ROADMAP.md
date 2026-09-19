# ROADMAP.md — Rakip Kıyası + Yol Haritası

> Bu dosya, Sentinel-Agent'ı benzer araçlarla (AI pentest ajanları, differential-auth
> araçları, API-DAST ürünleri, akademik BOLA çalışmaları) kıyaslar ve **yarışmadan bağımsız,
> uzun vadeli** bir geliştirme yol haritası çizer. Mimari/stil için **[DESIGN.md](DESIGN.md)** +
> **[CLAUDE.md](CLAUDE.md)**; kısa vadeli kalite turu için **[GOREVLER_Q.md](GOREVLER_Q.md)**;
> mimariye oturmayan breadth işleri için **[TIER_C.md](TIER_C.md)**.
>
> **Temel tez (değişmez):** *LLM akıl yürütür, deterministik motor kanıtlar.* Aşağıdaki hiçbir
> madde CLAUDE.md §5'i ihlal etmez: CONFIRMED'i yalnız kod verir · redaction zorunlu · scope
> kapısı her istekte · kontroller geçmeden verdict yok.

---

## 1. Konumlandırma — Sentinel nerede duruyor?

### 1.1 Manzara (üç kova)

1. **AI/LLM pentest ajanları** — PentestGPT V2, Shannon, Strix, MANTIS, MAPTA, HPTSA…
   Otonom recon→exploit→rapor. Standart ölçüt **XBOW (104 web CTF)**; Shannon %96, MAPTA %77,
   PentestGPT V2 %85. Ortak ders: *multi-agent > single-agent (4.3×)*, kanıt-güdümlü budama,
   yapılandırılmış state/memory.
2. **Differential-auth araçları** — Autorize, AuthMatrix, AuthScope, akademik **AuthProbe**.
   Yetkili trafiği düşük-yetkili/anonim replay edip **Enforced / Bypassed / Undetermined** sınıflar.
   Sentinel'in tam yaptığı iş.
3. **API-DAST ürünleri** — Akto, Escape, StackHawk. "Tarayıcılar BOLA'yı kaçırır çünkü *kimin
   neyi sahiplendiğini* bilemez" tezi. Escape iş-mantığı odaklı; StackHawk BOLA/BFLA'yı
   OpenAPI + ön-provizyonlu hesap zorunluğuyla yapıyor.

### 1.2 Kıyas tablosu

Durum: ✅ var · 🟡 kısmi · ⬜ yok (hedef)

| Yetenek | Sentinel | AuthProbe | Autorize | Escape/Akto | StackHawk | AI ajanları (XBOW/MAPTA) |
|---|---|---|---|---|---|---|
| Differential çok-aktörlü BOLA/IDOR | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| BFLA (dikey) | ✅ | ⬜ | 🟡 | ✅ | ✅ | 🟡 |
| Write-verb (mass-assign / state-change / stored-XSS) | ✅ | ⬜ (read-only) | 🟡 (manuel) | ✅ | 🟡 | ✅ |
| **Verdict'i KOD verir (LLM oy kullanamaz)** | ✅✅ | ✅ | ✅ | 🟡 (AI classification) | ✅ | 🟡 ("zero-FP garanti edemeyiz") |
| Leaked-marker / kanıtlı ispat | ✅ | ✅ (identifier match) | 🟡 (fingerprint) | ✅ | 🟡 | 🟡 |
| **Canary planting (aktif işaret ekme)** | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ (MAPTA "gelecek iş") |
| LLM-opsiyonel (kural-only çalışır) | ✅ | — | ✅ | ⬜ | ✅ | ⬜ |
| Yerel model (Ollama) | ✅ | — | — | ⬜ | ⬜ | 🟡 |
| Çıktıda PII/sır redaction | ✅ | 🟡 | ⬜ | 🟡 | 🟡 | ⬜ |
| OpenAPI/GraphQL-güdümlü keşif | ✅ | ✅ | ⬜ | ✅ | ✅ (zorunlu) | 🟡 |
| Çok-hedefli benchmark + precision/recall | 🟡 (Q3) | ✅ | ⬜ | 🟡 | ⬜ | ✅✅ |
| Replay edilebilir PoC/kanıt paketi | 🟡 (repro-curl) | 🟡 | 🟡 | ✅ (graf/ekran) | 🟡 | ✅✅ |
| SARIF / CI entegrasyonu | ✅ (Q2) | ⬜ | ⬜ | ✅ | ✅ | 🟡 |
| Baseline / diff (yalnız yeni bulgu) | ⬜ | ⬜ | ⬜ | ✅ | ✅ | 🟡 |
| Per-role coverage raporu | ⬜ | ⬜ | 🟡 | ✅ | 🟡 | ⬜ |
| Dedup + agreement-based confidence | 🟡 | ⬜ | ⬜ | ✅ | 🟡 | 🟡 |
| MCP tool-server (ajan-entegre) | ⬜ | ⬜ | ⬜ | 🟡 (IDE-MCP) | ⬜ | ✅ (strix, en hızlı büyüyen kalıp) |

### 1.3 Sentinel'in kenarı — **koru ve vurgula**

- **Verdict'i kesinlikle kod verir.** XBOW/MAPTA "validation agent" kullanıyor ama yine de
  "zero-FP garanti edemeyiz" diyor; Sentinel'in *LLM-oy-kullanamaz* değişmezi daha katı bir garanti.
- **Write-verb + BFLA + BOPLA + mass-assignment.** AuthProbe read-only; StackHawk yalnız
  cross-profile BOLA/BFLA. Sentinel akademik SOTA'dan **kapsamlı**.
- **LLM-opsiyonel + yerel-model + redaction.** appsecsanta "mimari > model ölçeği; fine-tuned
  mid-size kazanıyor" diyor → Sentinel'in yerel/Ollama yönü doğrulanıyor. Gizlilik/kurumsal değer.

### 1.4 Boşluklar — **nereyi kapatmalı**

1. Ölçülü güven: **çok-hedefli benchmark** (şu an tek hedef, 7 vaka).
2. Kanıtın taşınabilirliği: **replay edilebilir kanıt paketi** (repro-curl'den öteye).
3. Erişim kontrolünde **çift-yönlü + 2×2 matris + iç-içe id** kapsamı.
4. **Baseline/diff + FP-triyaj** olmadan CI'da gerçek benimsenme zor.
5. **MCP backend** olmadan "AI ajanlarının deterministik hâkimi" konumu boşta.

---

## 2. Yol haritası — eksenler ve görevler

### Ortak ilkeler
- CLAUDE.md §5 değişmezleri her maddede korunur (özellikle: yeni "canlı" adımlar
  `destructive_tests` + scope kapısı arkasında; LLM asla verdict/severity/CONFIRMED vermez).
- Her görev = bileşen sınıfı (OOP, DI) + network'süz testler + (uygunsa) canlı kalibrasyon.
- Her yeni motor/entegrasyon **DI ile enjekte**, mevcut sınıflar değiştirilmeden genişletilir (Open/Closed).

Durum: ✅ var · 🟡 kısmi · ⬜ yeni. Efor kabaca adam-saat.

### Eksen A — Güven / kanıt motoru *(çekirdeği derinleştir)*

| ID | Görev | Kaynak | Durum | Efor | Bağımlılık | Kabul kriteri |
|---|---|---|---|---|---|---|
| **R-A1** | **Canary planting** — tarama öncesi kurban hesabına benzersiz işaret verisi ek; saldırgan cevabında belirirse tartışmasız leaked-marker | MAPTA, AuthProbe | ✅ | ~7s | B1 write kapısı | `CanaryPlanter` (`oracle/canary.py`) + `IdorOracle.run(canary=...)` + Scanner'da `state_change_authz` hipotezinden eşleşen PUT/PATCH ile otomatik planting. Yazma yolu/hedef yoksa sessizce None (davranış değişmez) |
| **R-A2** | **Replay edilebilir kanıt paketi** — her CONFIRMED bulguya tam istek/yanıt fixture'ı + çevrimdışı yeniden-ispat scripti | XBOW, Shannon, MAPTA | 🟡 | ~5s | — | `runs/<id>/proof/<fid>.json` + `replay.py` bulguyu ağsız yeniden ispatlıyor |
| **R-A3** | **Çok-hedefli benchmark** — VAmPI + crAPI + Juice Shop; AuthProbe'un "vulnerable↔hardened ikiz, 0-FP" metodolojisi; advisory metnini gizle | AuthProbe, appsecsanta | 🟡 | ~8s | Q3 harness | ≥3 hedef, ≥30 etiketli vaka, koşulan precision/recall/FP tablosu README'de |

### Eksen B — Kapsam / derinlik *(erişim kontrolünde ileri)*

| ID | Görev | Kaynak | Durum | Efor | Bağımlılık | Kabul kriteri |
|---|---|---|---|---|---|---|
| **R-B1** | **2×2 yetki matrisi + çift-yönlü** — (own/peer obje)×(own/higher rol); A→B kadar B→A | StingrAI | 🟡 | ~4s | — | Her iki yön test ediliyor; matris raporda; asimetrik izolasyon yakalanıyor |
| **R-B2** | **ID varyasyonu + iç-içe/dolaylı referans** — int & UUID; gövde/ikinci-el lookup'taki id'ler | StingrAI | 🟡 | ~5s | — | Gövdedeki obje id'sinde IDOR CONFIRMED testi geçiyor |
| **R-B3** | **Scalar inference / feedback-driven keşif** — yanıtlardan veri ilişkisini çıkarıp otomatik bootstrap | Escape | ⬜ | ~5s | — | own_object_ids elle verilmeden bulunabiliyor (Juice Shop'ta) |

### Eksen C — Benimsenme / CI *(demo → gerçek kullanım)*

| ID | Görev | Kaynak | Durum | Efor | Bağımlılık | Kabul kriteri |
|---|---|---|---|---|---|---|
| **R-C1** | **Baseline + diff modu** — bilinen FP'leri baseline'da bastır, yalnız yeni bulguyu raporla, "no silent drops" (bastırılan sebeple raporda kalır) | Snyk, ZAP, p1-triage | ⬜ | ~5s | — | `--baseline` verilince yalnız yeni bulgular gate'ler; bastırılanlar sebeple listede |
| **R-C2** | **LLM FP-triyajı `likely_fp`** — yerel Ollama, verdict+confidence+reason, **asla silmez**, fallback `unreviewed` | p1-triage | ⬜ | ~4s | LLM opsiyonel | LLM kapalıyken davranış değişmez; açıkken bulgu `likely_fp` etiketi alır, verdict değişmez |
| **R-C3** | **MCP tool-server** — Replayer + oracle'ları tipli MCP araçları olarak aç → diğer ajanlar (Claude Code) Sentinel'i "hâkim" olarak çağırır | appsecsanta, strix | ⬜ | ~6s | — | `sentinel-mcp` sunucusu authorize→replay→oracle'ı tipli araç olarak sunuyor |

### Eksen D — Rapor / olgunluk

| ID | Görev | Kaynak | Durum | Efor | Bağımlılık | Kabul kriteri |
|---|---|---|---|---|---|---|
| **R-D1** | **Per-role coverage + profil-etiketli bulgu** — "hangi aktör hangi endpoint'e ulaştı", "found as user_A" | Escape, StackHawk | ✅ | ~3s | — | `Finding.found_as`/`victim_as` (`Scanner._tag`, oracle'lara dokunmadan) + `CoverageReporter` (`report/coverage.py`) → Markdown "Per-Role Coverage" tablosu + HTML "Kapsam" sekmesi (`sessions` verilince) |
| **R-D2** | **Dedup: `CWE+endpoint+param`; `sources[]` izi + agreement bump** (çok sinyal → confidence↑) | p1-triage | ✅ | ~3s | — | `FindingDeduplicator` (`report/dedup.py`) — kök-neden tek grup, verdict değişmez, agreement>1'de confidence bump (kopya üzerinde); Markdown "Correlated Findings" özeti (ayrıntı listesi kaybolmaz) |
| **R-D3** | **Olgunluk paketi** — kurulabilir CLI (`sentinel scan`), scan modları (quick/standard/deep), CVSS/EPSS, budget-tabanlı erken durdurma (~40 çağrı/$0.30/300s) | StackHawk, strix, MAPTA, appsecsanta | 🟡 | ~6s | — | `pip install` → `sentinel scan …`; modlar bütçeyi ölçekliyor; erken durdurma çalışıyor |

---

## 3. Öncelik — dalga planı

| Dalga | Tema | Görevler | Toplam |
|---|---|---|---|
| **1** | Güven derinleştirme (en yüksek getiri) | R-A1, R-B1, R-A3, R-D1 | ~22s |
| **2** | Benimsenme + kanıt | R-C1, R-A2, R-C2, R-D2 | ~17s |
| **3** | Konumlandırma + olgunluk | R-C3, R-B2, R-B3, R-D3 | ~22s |

**Önerilen başlangıç:** Dalga 1 → **R-A1 (canary planting)** + **R-B1 (çift-yönlü/matris)**, sonuç
**R-A3 (çok-hedefli benchmark)** ile ölçülür. Bu üçü, projenin tek-cümlelik iddiasını
("kanıtlı, deterministik, düşük-FP") rakiplerin de ötesine taşır.

---

## 4. Tier C ile ilişki

Araştırma net: alanın kazanan formülü **breadth değil, güven + benchmark + benimsenme**.
**[TIER_C.md](TIER_C.md)** (tarayıcı motoru, request smuggling, race, OAuth) bu resimde *sonra*
gelen bir genişlemedir — Dalga 1–2 oturmadan yeni zafiyet türü eklemek kumun üstüne inşa olur.
Tier C'ye girildiğinde tek maddeyle ve en demo-dostu/deterministik-kanıta uygun adayla (C1 DOM XSS)
başlanmalı.

---

## 5. Kaynakça

- [strix-claude-code](https://github.com/tghastings/strix-claude-code) — Claude CLI + Kali + MCP tek-ajan
- [awesome-ai-pentest](https://github.com/insidetrust/awesome-ai-pentest) — kategoriler, benchmark'lar
- [AI Pentesting Agents 2026 (appsecsanta)](https://appsecsanta.com/research/ai-pentesting-agents-2026) — 6 mimari kalıp, 39+ araç
- [AuthProbe: Multi-Identity BOLA Detection (arXiv)](https://arxiv.org/html/2607.20574v1)
- [MAPTA: Multi-Agent Pentesting AI (arXiv)](https://arxiv.org/html/2508.20816v1)
- [XBOW — nasıl #1 oldu](https://xbow.com/blog/top-1-how-xbow-did-it) · [XBOW platform](https://xbow.com/)
- [Autorize (PortSwigger/Burp)](https://github.com/PortSwigger/autorize)
- [StingrAI — API scanners miss BOLA/IDOR](https://www.stingrai.io/blog/api-scanners-miss-bola-idor-authorization-testing)
- [Escape vs StackHawk](https://escape.tech/blog/escape-vs-stackhawk/)
- [Snyk — DAST in CI/CD](https://snyk.io/articles/dast-ci-cd-pipelines/)
- [p1-sast-dast-triage — dedup + LLM FP-filter + SARIF](https://github.com/PyHackSecGP/p1-sast-dast-triage)
