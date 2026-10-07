# Görev Paketi — Faz 0, Faz 4, Faz 7 (Sentinel-Agent agentic geçişi)

> Bu doküman **kendi başına yeterlidir** — projeyi ilk kez alıyormuş gibi okuyabilirsin.
> Sana atanan 3 faz burada. Kritik yolu (Faz 1→2→3, agentic çekirdek) ekipteki diğer kişi yapıyor;
> senin fazların **ayrı katmanlara** dokunuyor, o yüzden paralel ilerleyebilirsin.
> Tam mimari: [DESIGN.md](../DESIGN.md) · Takım kuralları: [CLAUDE.md](../CLAUDE.md) · Geçiş planının
> tamamı: [gecis-plani.md](gecis-plani.md).

---

## 0. 5 dakikada proje

Sentinel-Agent, authenticated web/API uygulamalarındaki **erişim kontrolü açıklarını**
(IDOR/BOLA, BFLA, aşırı veri ifşası, yazma/silme yetki hataları) bulur ve **kanıtlar**.

Temel ilke: **LLM akıl yürütür, deterministik motor kanıtlar.** LLM yalnızca "neyi test edelim"
ve "sonuç ne demek" der; "gerçekten açık var mı" kararını **her zaman kod** verir.

Geçiş projesi: mevcut mekanik tarayıcıyı, her turda duruma bakıp bir sonraki hamlesine karar veren
**agentic bir avcıya** çeviriyoruz — API key yerine **local LLM (Ollama)** ile.

### İHLAL EDİLEMEZ 6 kural (kodun her yerinde geçerli)
1. **LLM ağa asla dokunmaz** — tüm trafik `Replayer`'dan geçer.
2. **`CONFIRMED` kararını her zaman kod verir**, asla LLM (yalnızca deterministik leaked-marker).
3. İki aktör asla session/cookie paylaşmaz (`SessionStore` izolasyonu).
4. Kontroller (positive/negative/stability) geçmeden verdict yok.
5. Scope kapısı her istekte (`PolicyEngine.authorize`).
6. **Redaction zorunlu** — token/cookie/PII log'a, evidence'a, rapora **ham** yazılmaz.

### Ortam / çalıştırma
```bash
docker compose up -d juice-shop                       # kalibrasyon hedefi (localhost:3000)
docker compose run --rm sentinel pytest -q            # testler (senin işin buna EKLENECEK)
```
- Dil: **kod tanımlayıcıları İngilizce, yorum/docstring/çıktı Türkçe.** UTF-8, LF.
- Commit: **Türkçe, imzasız**, `tür: özet` (`özellik|düzeltme|bakım|refaktör|test|doküman`).
- Dal: `feature/fazN-...`; küçük PR; **testler yeşil olmadan merge yok.**
- OOP + DI: bağımlılıklar constructor'dan enjekte; yeni yetenek = yeni sınıf (mevcutu şişirme).

---

## 🟢 FAZ 0 — Local LLM zemini (HEMEN başlayabilirsin, bağımlılık YOK)

**Amaç:** API key'e bağımlılığı kır; local modelle (Ollama) güvenilir yapılandırılmış çıktı al.
Yalnızca `llm/` katmanına + config'e dokunur.

### 0.1 — Ollama'da kısıtlı JSON çıktı
Dosya: [src/pentestai/llm/client.py](../src/pentestai/llm/client.py) → `OllamaLLMClient.complete`
(satır ~143).
- Payload'a `"format": "json"` ekle (Ollama'yı geçerli JSON üretmeye zorlar — local modeller katı
  JSON'da zayıftır, bu şart).
- `temperature`'ı `__init__` parametresine çek; **varsayılan `0`** (tekrar-üretilebilir öneri için).
  Şu an `options` içinde `0.2` sabit.

### 0.2 — Bayat aksiyon şemasını 5 tipe hizala
Dosyalar: [src/pentestai/llm/actions.py](../src/pentestai/llm/actions.py),
[src/pentestai/llm/prompts.py](../src/pentestai/llm/prompts.py).
- `ProposeHypothesis.type` şu an sadece `idor|bfla|excessive_data_exposure`. Deterministik planner
  zaten `injection` ve `state_change_authz` üretiyor → şemaya bu ikisini de **ekle**.
- `SYSTEM_PROMPT`'taki tip listesini ve örnek JSON şemasını buna göre güncelle.
- `injection` için `param`/`param_location`, `state_change_authz` için gerekli alanların
  `to_hypothesis()`'e doğru geçtiğinden emin ol (bkz. `models.Hypothesis`).

### 0.3 — LLM config dosyası
- Yeni: `config/llm.example.yaml` — `provider` (none|ollama|gemini|anthropic), `model`, `host`,
  `temperature`, `max_tokens`.
- [src/pentestai/config.py](../src/pentestai/config.py)'ye `load_llm_config(path) -> dict` ekle
  (mevcut `load_*` fonksiyonları örnek al).
- [scripts/run_scan.py](../scripts/run_scan.py) `_build_llm` bunu okusun; **CLI flag'i config'i
  override etsin** (`--llm` verilirse o kazanır).
- `.gitignore` gerçek `config/*.yaml`'ı zaten kapsıyor — sadece `*.example.yaml` commit edilir.

### 0.4 — Docs
- [README.md](../README.md) "Kurulum" bölümüne local blok: `ollama pull qwen2.5:14b-instruct`,
  örnek `--llm ollama` komutu. (Model önerisi: 24GB GPU → Qwen2.5-14B hız / Coder-32B kalite.)
- [docs/ai-kullanimi.md](ai-kullanimi.md)'ye "local modelde hedef verisi buluta çıkmaz" notu.

### Testler (network'süz — `httpx.MockTransport`)
- `tests/test_llm_ollama.py`: `complete` payload'ında `format:json` gönderildiğini + yanıtın
  doğru parse edildiğini doğrula.
- `tests/test_llm_actions.py`: `ProposeHypothesis` 5 tipin tamamını kabul eder; `to_hypothesis()`
  doğru `Hypothesis` üretir.
- `tests/test_config.py` (varsa genişlet): `load_llm_config` doğru okur.

### Kabul kriteri
`docker compose run --rm sentinel python -m scripts.run_scan ... --llm ollama --llm-model
qwen2.5:14b-instruct` ile mevcut tarama Juice Shop'ta `CONFIRMED` üretir; model bozuk JSON verse
bile sessizce elenir (crash yok). `pytest -q` yeşil.

---

## 🟡 FAZ 7 — Gözlemlenebilirlik + rapor (neredeyse bağımsız)

**Amaç:** Agentic avcının "neden şunu denedim" kararlarını görünür kıl; local LLM maliyet/süre
metrikleri. Yalnızca `report/` katmanına + küçük bir model'e dokunur.

### Bağımlılık / kontrat (mock'la, bekleme)
Faz 3'ün üreteceği "karar izi" (decision trace) şemasına bağlısın. **Aşağıdaki şemayı sabit kabul
et ve buna karşı geliştir** (kritik yol sahibi bunu `models/`'a bu haliyle koyacak; ufak değişirse
kolay uyarlarsın):

```python
class DecisionStep(BaseModel):
    turn: int
    situation_digest: str          # REDAKTE durum özeti
    proposed_action: str           # aksiyon tipi + kısa özet
    rationale: str                 # LLM'in gerekçesi (REDAKTE)
    observation: str               # sonuç özeti (ör. "HTTP 200, 3 yeni id keşfedildi")
    verdict_delta: Optional[str]   # ör. "F-003 → CONFIRMED" | None

class DecisionTrace(BaseModel):
    steps: list[DecisionStep]
    llm_calls: int = 0
    tokens: int = 0
    wall_sec: float = 0.0
```
Örnek/mock bir `DecisionTrace` JSON'u kendin yazıp onun üstünde çalış — Faz 3'ü beklemene gerek yok.

### Yapılacaklar
- HTML rapora **"Ajan Yolu" (agent path)** sekmesi: turları sırayla göster (situation → rationale
  → action → observation), `verdict_delta` olan adımları vurgula.
  Dosyalar: [src/pentestai/report/render_html.py](../src/pentestai/report/render_html.py) +
  `src/pentestai/report/viewer_template.html`.
- Üstte küçük metrik şeridi: tur sayısı, `llm_calls`, `tokens`, `wall_sec`.
- **Redaction'a dikkat (kural 6):** trace zaten redakte gelmeli; yine de rapor tarafında ham
  token/PII gösterme. Kanıt (leaked-marker + repro-curl) merkezde kalsın — ajan yolu ek sekme.
- Açık/koyu tema mevcut viewer ile uyumlu olsun.

### Testler
- `tests/test_report_trace.py`: örnek `DecisionTrace` verildiğinde HTML doğru render eder;
  `verdict_delta` vurgulanır; ham sır sızmaz.

### Kabul kriteri
Örnek trace ile bir `CONFIRMED` bulgunun **nasıl** bulunduğu adım adım görünür; `pytest -q` yeşil.

---

## 🟠 FAZ 4 — Zengin mutasyon + recon-from-response (kapsam/recall motoru)

**Amaç:** Kapsamı asıl açan faz. `ActionExecutor`'a gerçek keşif stratejileri doldur — hepsi
**deterministik** (LLM yok; LLM sadece hangi aksiyonu çağıracağını seçer, Faz 3'te).

### Bağımlılık / kontrat (Faz 1'in arayüzü — mock'la, sonra gerçeğe bağla)
Faz 1'de tanımlanacak aksiyon/executor arayüzüne bağlısın. **Şu kontratı sabit kabul et** (Faz 1
sahibi `orchestrator/actions.py` + `orchestrator/executor.py`'yi bu iskeletle merge edecek):

```python
# orchestrator/actions.py
class Action(BaseModel): ...                       # taban
class Probe(Action):        endpoint: Endpoint; actor_name: str
class RunOracle(Action):    oracle: str; endpoint: Endpoint; victim_name: str
                            attacker_name: str; resource_key: str = "id"
# --- FAZ 4'TE SEN EKLE: ---
class EnumerateIds(Action):     endpoint: Endpoint; actor_name: str; around_id: str; span: int = 5
class MutateIdFormat(Action):   endpoint: Endpoint; actor_name: str; base_id: str
class InspectResponseForIds(Action): source_note: str          # önceki gözlemin gövdesinden id çıkar
class EscalateRole(Action):     endpoint: Endpoint; low_actor_name: str

# models/ (Faz 1 TANIMLADI — sabit kontrat)
class Observation(BaseModel):
    action_type: str
    status: Optional[int] = None       # tekil istek varsa HTTP durum kodu
    response_summary: Optional[str] = None
    finding: Optional[Finding] = None
    discovered_ids: list[str] = []     # ← senin mutasyonların bunu doldurur
    note: str = ""

# orchestrator/executor.py
class ActionExecutor:
    def __init__(self, replayer: Replayer, oracles: dict[str, Oracle], base_url: str): ...
    async def execute(self, action: Action, sessions: dict[str, Session]) -> Observation: ...
```
Sen bu `ActionExecutor.execute`'a **yeni aksiyon dallarını** eklersin (ya da her aksiyona bir
`Strategy` sınıfı — Open/Closed). Faz 1 gerçeği merge olana kadar bu iskeleti kendi dalında
mock'layarak ilerle.

### Yapılacaklar (hepsi deterministik, her istek `Replayer→PolicyEngine`'den geçer)
- **EnumerateIds:** id şemasını tespit et (sıralı int mi?) → `around_id` çevresindeki komşu id'leri
  tara; erişilebilenleri `discovered_ids`'e yaz.
- **MutateIdFormat:** `base_id`'nin int / UUID / base64 varyantlarını üret-dene (base64 decode →
  artır → encode dahil).
- **InspectResponseForIds:** önceki gözlemin gövdesinden id/link çıkar → yeni hedefler
  ([recon/crawl.py](../src/pentestai/recon/crawl.py) + `oracle/markers.py` `MarkerExtractor` ile
  hizala, tekerleği yeniden icat etme).
- **EscalateRole:** düşük-yetkili aktörle yüksek-yetki denemesi (BFLA'yı besler; mevcut
  `BflaOracle`'ı kullan).
- (Opsiyonel) HTTP method swap, parametre kirliliği (parameter pollution).
- **Executor asla verdict vermez** (kural 2) — yalnızca icra + gözlem döner.

### Testler (network'süz — mevcut `tests/test_oracle_*` mock-app desenini kullan)
- `tests/test_mutations.py`: her mutasyon tipi için ayrı test.
- Sıralı-id'li, çok-endpoint'li **genişletilmiş sahte app**: `InspectResponseForIds` yeni hedef
  keşfeder, `EnumerateIds` komşu objeye ulaşır.
- Policy reddinde (`ScopeError`) temiz gözlem döner, crash yok.

### Kabul kriteri
Elle kurulmuş bir aksiyon dizisi, genişletilmiş sahte app'te önceki fazdan **daha çok endpoint/id
keşfeder**; `pytest -q` yeşil.

---

## Sıra önerisi (senin için)
1. **Faz 0** — bağımlılığı yok, hemen başla, hızlı kazanç.
2. **Faz 7** — yukarıdaki `DecisionTrace` mock'una karşı çalış (Faz 3'ü bekleme).
3. **Faz 4** — Faz 1'in `ActionExecutor` iskeleti `develop`'a düşünce gerçeğe bağla (o zamana kadar
   mock kontrat üstünde ilerle).

## Koordinasyon (kopukluk olmasın diye)
- İki kontrat baştan sabit: **(a)** `Action`/`ActionExecutor`/`Observation` (Faz 4 için),
  **(b)** `DecisionTrace` (Faz 7 için). Değişirse ekip kanalında haber ver, tek noktadan güncelle.
- Sık sık `develop`'a **rebase** et; dalın uzaklaşmasın.
- Her faz ayrı PR, Türkçe açıklama, testler yeşil.

Takıldığın yerde `DESIGN.md` (mimari) + ilgili mevcut modülün docstring'i ilk başvuru kaynağın.
Kolay gelsin!
