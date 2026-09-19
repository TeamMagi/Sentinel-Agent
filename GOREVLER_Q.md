# Görev Listesi — Kalite Turu (Q) · kanıt, cila, entegrasyon

> Bağlam: **Tier A + Tier B tamamlandı** ([GOREVLER.md](GOREVLER.md)), 272 test yeşil. Tier C
> (mimariye uymayan / yeni motor gerektiren) işler teslim sonrasına ertelendi ([TIER_C.md](TIER_C.md)).
> Bu tur **kapsamı genişletmez**; projenin tek-cümlelik iddiasını — *"LLM akıl yürütür,
> deterministik motor kanıtlar; false-positive yok"* — **ölçülebilir kanıta** bağlar ve çıktıyı
> profesyonelleştirir. Mimari ve stil için **[DESIGN.md](DESIGN.md)** + **[CLAUDE.md](CLAUDE.md)**.
>
> **Takvim:** teslim 19–20 Eylül. Bu tur bilinçli olarak **düşük riskli, mimariye oturan** işlerden
> oluşur; hiçbir görev yeni yürütme motoru gerektirmez.

---

## Ortak ilkeler (CLAUDE.md §3, §5, §6)

- **Değişmezler korunur:** CONFIRMED'i yalnız kod verir · redaction zorunlu · scope kapısı her istekte ·
  yeni format/çıktı = yeni sınıf (Open/Closed), mevcut sınıf değiştirilmez.
- **Severity/CWE/OWASP de deterministiktir:** verdict gibi, bunları da **kod** belirler; LLM önerisi
  ayrı alanda saklanır ama karar değildir (§5 ruhu).
- **Network'süz testler** (`httpx.MockTransport`/`respx`), her yol ayrı test; `pytest -q` yeşil olmadan merge yok.
- **Redaction:** SARIF, benchmark özeti, yeni alanlar dahil hiçbir çıktıya ham token/PII yazılmaz.

## Önerilen sıra (bağımlılık)

```
Q1 (temel: model alanları)  →  Q2 (SARIF, CWE'yi kullanır)  ∥  Q3 (benchmark, severity'yi kullanır)
                            →  Q4 (dedup)  →  Q5 (demo cila)
```

Q1 önce yapılmalı: hem Q2 (SARIF `rule.cwe`) hem Q3 (severity dağılımı) `Finding`'in yeni alanlarını tüketir.

---

## Aşama Q — Çekirdek (12 saat)

### Q1 — CWE/OWASP eşlemesi + deterministik severity  ·  *(~3 saat)*  · **temel/bloklayıcı**
Her bulguya standart sınıflandırma ve **kod-belirli** önem derecesi.

- **Model** (`models/__init__.py` · `Finding`): `cwe: Optional[str]` (ör. `"CWE-639"`),
  `owasp: Optional[str]` (API Top 10 *veya* Web Top 10 uygun kategori, ör. `"API1:2023"`),
  ve severity anlamı netleşir: `severity` = **kod kararı**; LLM önerisi `severity_suggested`'a taşınır.
- **Saf modül** (`enrich.py`'ye ek ya da yeni `classify.py`): `TYPE_META: dict[str, (cwe, owasp, base_severity)]`
  — ~30 `Finding.type` (idor, bfla, bopla, excessive_data_exposure, csrf, file_upload, injection,
  mass_assignment, method_bypass, state_change, stored_xss, timing/blind_sqli, command_injection,
  unauthorized_access, cors, clickjacking, open_redirect, exposure, info_leak, jwt, user_enumeration,
  default_credentials, debug_mode, cve, rate_limit, ssrf/xxe/rfi, cache_poisoning, prototype_pollution…).
  `assign(finding)` → verdict + kanıta göre severity ayarı (ör. CONFIRMED write/delete state_change =
  bir üst; INCONCLUSIVE = düşür). Saf fonksiyon, DI'a gerek yok.
- **Bağlama:** Scanner bulguyu üretince `assign` çağrılır (LLM'den önce/bağımsız).
- **Değişmez:** severity'yi kod verir; eksik `type` için map zorunlu (test guard: haritada olmayan tür = hata).
- **Test:** her `type` haritada var · aynı girdi → aynı severity (determinizm) · LLM önerisi kararı ezmiyor.

### Q2 — SARIF çıktısı + exit-code + GitHub Action  ·  *(~4 saat)*
Aracı "CI'da çalışır, PR'ı bloklar" dev-aracına dönüştürür; jüriye somut entegrasyon hikâyesi.

- **Reporter** (yeni `report/render_sarif.py` · `SarifReporter(Reporter)`): SARIF 2.1.0 —
  `rules` = vuln tür (Q1'in `cwe`/`owasp`'ı `properties`'e), `results` = bulgular,
  `level` = severity→(error/warning/note), `partialFingerprints` = `finding.id` (kararlı dedup için),
  `message` = redakte repro özeti. **redact() zorunlu.**
- **CLI** (`scripts/run_scan.py` + `scanner`): `--sarif <path>` çıktısı; **anlamlı exit-code**
  (eşik ≥ severity CONFIRMED → non-zero; eşik konfigüre edilebilir `--fail-on`).
- **CI** (`.github/workflows/sentinel.yml`): docker compose ile Juice Shop kaldır → tara →
  SARIF'i `github/codeql-action/upload-sarif` ile yükle (repo Security sekmesinde görünür).
- **Test:** SARIF minimal-şema geçerliliği (zorunlu alanlar) · redaction (token/PII yok) · exit-code eşiği.

### Q3 — Kalibrasyon / benchmark harness (precision · recall · FP)  ·  *(~5 saat)*  · **en yüksek değer**
İddianın kanıtı: bilinen-açık hedefte beklenen↔gerçek bulgu karşılaştırması.

- **Beklenen set** (`benchmarks/juiceshop.expected.yaml`): endpoint + type + beklenen verdict listesi
  (Juice Shop için doğrulanmış gerçek açıklar).
- **Harness** (`scripts/benchmark.py` veya `src/pentestai/bench/`): bir koşumun `findings.json`'ını
  beklenene eşle → **TP/FP/FN**, precision, recall, **FP-rate**, "CONFIRMED doğruluğu"; çıktı
  `runs/<id>/benchmark.md` + makine-okur `benchmark.json` (README rozeti/tablosu için).
- **Kanıt/hikâye:** hedef "FP = 0, CONFIRMED'lerin tamamı doğru".
- **Test:** eşleştirme mantığı sabit fixture'larla (network'süz) — TP/FP/FN sayımı ve metrik hesabı.

---

## Aşama Q+ — Cila (stretch, +5 saat)

### Q4 — Bulgu dedup / korelasyon  ·  *(~3 saat)*
Aynı kök-nedenin N endpoint'te tekrarı tek grupta toplanır (SARIF fingerprint ile uyumlu). Rapor
gürültüsünü düşürür. Saf gruplama fonksiyonu + rapor katmanında sunum; verdict'e dokunmaz.

### Q5 — Demo sağlamlaştırma  ·  *(~2 saat)*
[docs/video-senaryo.md](docs/video-senaryo.md) yolunu **tek komutla tekrarlanabilir** hale getir
(Makefile hedefi: compose up → scan → benchmark → rapor aç). Kırık/yavaş adım kalmasın.

---

## Toplam yük

| Görev | Saat | Bağımlılık |
|---|---|---|
| Q1 CWE/OWASP + severity | 3 | — (temel) |
| Q2 SARIF + CI | 4 | Q1 |
| Q3 Benchmark | 5 | Q1 (yumuşak) |
| **Çekirdek toplam** | **12** | |
| Q4 Dedup | 3 | Q1 |
| Q5 Demo cila | 2 | Q2, Q3 |
| **Genel toplam** | **17** | |

> Atamalar (Serhat / Görkem) bu turda serbest — Q1 tek kişi bitirip Q2 ve Q3 paralel bölüştürülebilir.
