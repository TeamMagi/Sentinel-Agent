# Geçiş Planı — Sentinel-Agent'ı Agentic + Local-LLM Sisteme Dönüştürme

> Tek plan, fazlara bölünmüş. Her faz kendi başına **shippable** (çalışır + testleri yeşil) ve
> bir öncekine dayanır. İstediğin fazda durabilir, geri alabilirsin. Mevcut çalışan `Pipeline`
> hiçbir fazda kırılmaz — yeni orchestrator bir bayrağın (`--agent`) arkasında paralel yaşar,
> hazır olunca varsayılan olur.
>
> Bu plan, daha önce yazdığımız **7 maddelik manifesto**yu somut mühendislik adımlarına döker.
> Mimarinin tamamı: [DESIGN.md](../DESIGN.md) · Takım kuralları: [CLAUDE.md](../CLAUDE.md).

---

## 0. Hedef ve dokunulmazlar

**Hedef:** Önceden planlanmış hipotez listesini sırayla tüketen mekanik tarayıcıyı; **her turda
duruma bakıp bir sonraki hamlesine karar veren**, tipli/güvenli aletlerle icra eden, hafıza tutan,
aynı yerin üstünden birkaç kez geçen ve gerekirse kendini güvenle çoğaltan **agentic bir açık
avcısına** çevirmek — API key yerine **local LLM (Ollama)** ile.

**Değişmezler (bu plan boyunca ASLA ihlal edilmez — DESIGN §5 / CLAUDE §5):**

1. LLM ağa asla dokunmaz; yalnızca **tipli aksiyon** önerir, tüm trafik `Replayer`'dan geçer.
2. `CONFIRMED` kararını **her zaman kod** verir (deterministik leaked-marker/mutasyon), asla LLM.
3. İki aktör asla session/cookie paylaşmaz (`SessionStore` izolasyonu, `test_replay` korur).
4. Kontroller (positive/negative/stability) geçmeden verdict yok.
5. Scope kapısı her istekte (`PolicyEngine.authorize`) — LLM önerisine güvenilmez.
6. Redaction zorunlu — token/cookie/PII log/evidence/rapora ham yazılmaz.

**Kabul edilen takas:** Keşif **yolu** artık deterministik değil (iki koşum farklı gezebilir).
Ama her bulgunun **kanıtı** (repro-curl) sabit ve tekrar-oynatılabilir kalır.

---

## Mevcut durum → hedef durum

| | Mevcut | Hedef |
|---|---|---|
| Orchestrator | `Pipeline` (RECON→PLAN→TEST→VERIFY→EXPAND, katı state machine) | `AgenticOrchestrator` (reasoning döngüsü: gözlemle→düşün→eyle→gözlemle) |
| LLM rolü | Toplu hipotez üretir (`HypothesisGenerator.generate`) | Her adımda **bir sonraki tipli aksiyonu** seçer |
| Eylem uzayı | Sabit: `swap_actor` mutasyonu | Zengin tipli aletler (probe/enumerate/mutate/escalate/inspect/reverify) |
| Hafıza | `ScanState` (pasif taşıyıcı) | `WorldModel` (aktif: keşifler, denenenler, aktör yetenekleri, durum raporu) |
| Doğrulama | Tek geçiş | Çok geçişli + re-verify |
| Paralellik | Yok (sıralı) | Güvenli eşzamanlı scout'lar, tek hâkim/bütçe |
| LLM sağlayıcı | Ağırlıkla API (Gemini/Anthropic) | Local varsayılan (Ollama), API opsiyonel |

---

## Faz 0 — Local LLM zemini (bağımsız, düşük risk)

**Amaç:** API key'e bağımlılığı kır, local modelle güvenilir yapılandırılmış çıktı al. Bu faz
agentic dönüşümden **bağımsız** — tek başına da değerli, hemen yapılabilir.

**Yapılacaklar:**
- `llm/client.py` → `OllamaLLMClient`'i birinci sınıf yap: `--llm ollama` için kolay model seçimi,
  `OLLAMA_HOST` env, retry/timeout.
- **Kısıtlı JSON çıktı:** Ollama `format: json` veya GBNF grammar ile modelin geçersiz JSON
  üretememesini garanti et. `llm/prompts.py`'ye few-shot örnekleri ekle.
- `config/scope.example.yaml` yanına `config/llm.example.yaml`: sağlayıcı, model, quantization,
  context uzunluğu, sıcaklık (temperature=0 → tekrar-üretilebilir öneri).
- README'ye local kurulum: `ollama pull qwen2.5:14b-instruct` + örnek komut.

**Önerilen modeller (24GB / RTX 3090 Ti):**
- Döngü motoru → **Qwen2.5-14B-Instruct (Q4_K_M, ~9GB)**: hızlı, uzun context, bol headroom.
- Ağır reasoning → **Qwen2.5-Coder-32B-Instruct (Q4_K_M, ~20GB)**: en iyi JSON+akıl yürütme.
- (Kurulum anında daha yeni nesil varsa — Qwen3 vb. — aynı boyut sınıfında en yeniyi seç.)

**Kabul kriteri:** Mevcut `Pipeline`, `--llm ollama --llm-model qwen2.5:14b-instruct` ile uçtan
uca çalışır ve Juice Shop'ta `CONFIRMED` üretir. Model saçmalasa bile çıktı şema-doğrulamasından
geçer (bozuk öneri sessizce elenir). **Eğitim/fine-tune YOK** — prompt + few-shot + kısıtlı çıktı.

---

## Faz 1 — Tipli aksiyon uzayı + deterministik icracı

**Amaç:** LLM'in dokunabileceği "aletleri" tanımla; ama önce **LLM'siz**, deterministik kurallarla
çalıştırıp icracının doğruluğunu kanıtla (manifesto adım 2).

**Yapılacaklar:**
- `models/actions.py` (yeni): Pydantic tipli aksiyonlar —
  `ProbeEndpoint`, `EnumerateIds`, `MutateIdFormat`, `SwapActor`, `EscalateRole`,
  `InspectResponseForIds`, `ReVerify`. Her biri **tipli girdi/çıktı**, `Any` yok.
- `orchestrator/executor.py` (yeni): `ActionExecutor` — her aksiyonu `Replayer` + uygun `Oracle`
  çağrısına çevirir. **Her istek `PolicyEngine.authorize`'dan geçer** (değişmez 1 & 5). Executor
  asla verdict vermez — sadece icra eder ve gözlem (`NormalizedResponse` / `Finding`) döner.
- Executor, mevcut `Oracle` alt sınıflarını (`idor`, `state_change`, `bfla`, `bopla`, `injection`)
  **değiştirmeden** kullanır (Open/Closed).

**Kabul kriteri:** `tests/test_executor.py` — `httpx.MockTransport` ile her aksiyon tipi için
network'süz test; policy reddinde `ScopeError`→temiz gözlem; hiçbir aksiyon verdict üretemez.
LLM olmadan, elle kurulmuş bir aksiyon dizisi Juice Shop'ta `CONFIRMED` üretebilir.

**Risk/dikkat:** Executor'ın bütçe/rate-limit'i `Replayer` üzerinden sayması (yeni bir sayaç ekleme).

---

## Faz 2 — Hafıza / WorldModel + durum raporu

**Amaç:** Adımlar arası durum biriktir; her turda LLM'e kompakt bir "durum raporu" ver
(manifesto adım 3).

**Yapılacaklar:**
- `orchestrator/world_model.py` (yeni): `WorldModel` —
  - keşfedilen endpoint'ler + davranışları (status dağılımı, id şeması ipuçları),
  - aktör başına yetenekler (neye erişebiliyor, own_object_ids),
  - denenen `(aksiyon, sonuç)` geçmişi (aynı şeyi iki kez denememek için),
  - mevcut bulgular (verdict'leriyle).
- `situation_report()`: token-bütçeli, özetlenmiş context dilimi (uzun context local'de VRAM yer —
  Faz 0 context ayarıyla uyumlu). Redaction burada da zorunlu (değişmez 6).
- `ScanState`'i genişlet ya da `WorldModel`'i içine göm (DESIGN §7 veri modeli tek yön).

**Kabul kriteri:** `tests/test_world_model.py` — keşifler doğru birikir; `situation_report()`
belirli bir token sınırını aşmaz; redaction uygulanır; tekrarlanan aksiyon "already tried" olarak
işaretlenir.

---

## Faz 3 — Reasoning döngüsü (AgenticOrchestrator) — KALP

**Amaç:** Manifesto adım 1. Katı state machine yerine gerçek gözlemle→düşün→eyle döngüsü.

**Yapılacaklar:**
- `orchestrator/agent.py` (yeni): `AgenticOrchestrator`. Döngü:
  1. `WorldModel.situation_report()` üret,
  2. LLM'e ver → **bir sonraki tipli aksiyon(lar)ı** öner (kısıtlı JSON, Faz 0),
  3. **Doğrula:** şema + `PolicyEngine` (geçersiz/kapsam-dışı öneri elenir, değişmez 5),
  4. `ActionExecutor` ile icra et (Faz 1),
  5. Gözlemi `WorldModel`'e yaz (Faz 2),
  6. `CONFIRMED`/yeni gözlem → devam; bütçe (`BudgetExceeded`) / `max_iterations` / "yeni bilgi
     yok" → dur.
- **Mevcut `Pipeline` KALIR.** `scripts/run_scan.py`'ye `--agent` bayrağı: verildiğinde
  `AgenticOrchestrator`, verilmediğinde eski `Pipeline`. Hiçbir şey kırılmaz.
- LLM tamamen kapalıyken (`--llm none`) döngü **deterministik bir politikayla** çalışsın
  (kural-tabanlı aksiyon seçimi) — araç LLM'siz de avlanabilsin.

**Kabul kriteri:** `tests/test_agent.py` — sahte (mock) LLM ile döngü; LLM'in kapsam-dışı önerisi
reddedilir ve **hiçbir zaman** ağa çıkmaz (değişmez 1); `CONFIRMED` yalnızca oracle kanıtıyla
gelir (değişmez 2); bütçe kill-switch döngüyü durdurur. Juice Shop'ta `--agent --llm ollama` ile
canlı `CONFIRMED`.

**Risk/dikkat:** Sonsuz döngü/israf → "yeni bilgi yok" dedektörü + sıkı `max_iterations` + bütçe.
Local LLM latency → tur başına çağrı sayısını sınırla; 14B modelle hız.

---

## Faz 4 — Zengin mutasyon + recon-from-response (recall motoru)

**Amaç:** Kapsamı asıl açan faz. Aksiyon icracılarına gerçek stratejiler doldur.

**Yapılacaklar (executor'da, hepsi deterministik):**
- `EnumerateIds`: sıralı-id şeması tespit et (int artan mı?) → komşu id'leri tara.
- `MutateIdFormat`: int / UUID / base64 decode-artır-encode varyantları.
- `InspectResponseForIds`: cevaplardaki id/link'leri çıkar → `WorldModel`'e yeni hedef ekle
  (mevcut `recon/crawl.py` + `MarkerExtractor` ile hizala).
- Kardeş-obje keşfi, HTTP method swap, parametre kirliliği (parameter pollution).
- `EscalateRole`: düşük→yüksek yetki denemeleri (BFLA'yı besler).

**Kabul kriteri:** Her mutasyon için network'süz test; recall artışını gösteren bir "genişletilmiş
Juice Shop senaryosu" (birden çok endpoint, id şeması) → önceki fazdan daha çok endpoint keşfi.

---

## Faz 5 — Çok geçişli doğrulama (precision + stateful recall)

**Amaç:** Manifesto adım 5 — "aynı yerin üstünden birkaç kez geç".

**Yapılacaklar:**
- İteratif derinleşme: 1) geniş+ucuz temel geçiş, 2) LIKELY/şüpheli üstüne fazla mutasyonla dönüş,
  3) tüm CONFIRMED/LIKELY'yi **yeniden doğrula** (`ReVerify` aksiyonu, N kez).
- Kontrol setini derinleştir (DESIGN §12): tekrarlı-stabilite (flakiness eleme), çok-aktörlü
  diferansiyel (A vs B vs C vs unauth), gecikmeli yeniden-okuma (state-change için değerli).
- Stabiliteye göre **promote/demote**: kararlı tekrar → LIKELY'den CONFIRMED'e ancak leaked-marker
  varsa (baraj DÜŞMEZ, değişmez 2 & 4).

**Kabul kriteri:** Kararsız yanıt veren sahte endpoint → tekrar doğrulama yanlış CONFIRMED'i eler
(precision). Stateful sahte senaryo → çok geçişle yakalanır (recall).

---

## Faz 6 — Güvenli paralellik (concurrent scouts)

**Amaç:** Manifesto adım 6 — çoğalt ama huniden geçir.

**Yapılacaklar:**
- Birden çok `AgenticOrchestrator` döngüsü `asyncio.gather` + semaphore ile eşzamanlı; farklı
  endpoint/hipotez bölgelerini keşfeder.
- **Tek** paylaşılan `ActionExecutor` + `PolicyEngine` + `BudgetTracker` + `EvidenceStore`
  (global bütçe/rate-limit hepsini bağlar → kendi hedefini DoS'lamazsın).
- `WorldModel`'e eşzamanlı-güvenli yazma (lock/kuyruk); aktör-session izolasyonu korunur
  (değişmez 3).

**Kabul kriteri:** `tests` — N paralel scout tek bütçeyi paylaşır ve aşmaz; cross-contamination
guard (`test_replay` mantığı) paralel altında da geçer; determinizm: yol farklı, her CONFIRMED'in
repro-curl'ü hâlâ tek-komut tekrar-oynatılır.

---

## Faz 7 — Gözlemlenebilirlik + rapor

**Amaç:** Ajanın "neden şunu denedim" kararlarını görünür kıl; local LLM maliyet/latency izle.

**Yapılacaklar:**
- Karar izi (decision trace): her tur için durum→öneri→aksiyon→gözlem, redaksiyonlu.
- HTML rapora "ajanın yolu" sekmesi (mevcut `report/render_html.py` viewer'ına ek).
- Local LLM metrikleri: tur sayısı, token, süre.

**Kabul kriteri:** Rapor, bir `CONFIRMED` bulgunun **nasıl** bulunduğunu adım adım gösterir;
kanıt (leaked-marker + repro-curl) hâlâ merkezde.

---

## Kesişen konular (her fazda geçerli)

- **Test disiplini:** Network'süz (`httpx.MockTransport`/`respx`), her davranış yolu ayrı test;
  `pytest -q` yeşil olmadan merge yok (CLAUDE §6). Özellikle her fazda değişmezlerin testi.
- **Config:** `scope.yaml`'a agentic ayarlar (max_iterations, paralel scout sayısı, per-tur çağrı
  sınırı); `llm.yaml` (Faz 0). Gerçek `*.yaml` git-ignore, sadece `*.example.yaml` izlenir (CLAUDE §8).
- **Bütçe/kill-switch:** `BudgetTracker` her fazda tek otorite; agentic + paralel altında sıkı.
- **Commit/branch:** Türkçe, imzasız, `tür: özet`; `feature/agentic-fazN` dalları, küçük PR'lar
  (CLAUDE §1, §7). Her faz = ayrı PR.
- **Geri dönüş güvenliği:** Eski `Pipeline` en az Faz 6 sonuna kadar yaşar; agentic kanıtlanınca
  varsayılan olur, sonra emekliye ayrılır.

---

## Sıralama ve bağımlılıklar

```
Faz 0 (local LLM)  ─── bağımsız, hemen ───┐
                                          ▼
Faz 1 (aksiyonlar) → Faz 2 (hafıza) → Faz 3 (döngü/KALP)
                                          │
                        ┌─────────────────┼─────────────────┐
                        ▼                 ▼                 ▼
                 Faz 4 (mutasyon)   Faz 5 (çok-geçiş)   Faz 6 (paralel)
                        └─────────────────┼─────────────────┘
                                          ▼
                                   Faz 7 (gözlem/rapor)
```

- **En yüksek etki/emek:** Faz 3 (kalp) + Faz 4 (recall). Faz 0 en kolay hızlı kazanç.
- Faz 4/5/6 birbirinden büyük ölçüde bağımsız — sırayı ihtiyaca göre değiştirebilirsin.
- Faz 7 en sona bırakılabilir ama demo/jüri için değerli (kararların görünürlüğü).

---

## Bir sonraki somut adım

Faz 0 veya Faz 1'den başla. Önerim: **Faz 1'in `models/actions.py` tipli şemasını** birlikte
tasarlamak (LLM'siz, saf tip tanımı) — çünkü tüm agentic mimari bu şemanın üstüne oturuyor ve
tasarlaması risksiz. Onaylarsan o dosyanın alan-alan tasarımıyla devam ederiz.
