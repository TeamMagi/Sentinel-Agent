<div align="center">

# 🛡️ Sentinel-Agent

**AI destekli, kanıt-temelli erişim kontrolü (access-control) pentest aracı**

_LLM akıl yürütür — deterministik motor kanıtlar._

[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-303%20passing-brightgreen.svg)](tests/)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg)](docker-compose.yml)
[![Web UI](https://img.shields.io/badge/web%20ui-stdlib%20(0%20dep)-9775fa.svg)](#-web-arayüzü-kontrol-paneli)
[![OWASP API](https://img.shields.io/badge/OWASP%20API%20Top%2010-%231%20BOLA-red.svg)](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

</div>

---

Sentinel-Agent, kendi web uygulamalarındaki **yetkilendirme açıklarını** (IDOR/BOLA, BFLA, aşırı
veri ifşası, yazma/silme yetki hataları) ve bir dizi klasik web zafiyetini (injection, SSRF/XXE,
CSRF, stored XSS, bilgi sızıntısı, güvenlik yanlış-yapılandırmaları…) bulur — ve her bulguyu
**tekrar-üretilebilir kanıtla** raporlar. İki gerçek kullanıcı hesabıyla oturum açar, birinin
diğerinin nesnesine erişip erişemediğini **differential test** ile ölçer ve sonucu yalnızca
deterministik kanıt varsa `CONFIRMED` işaretler.

> **Neden önemli?** Broken Object Level Authorization (BOLA/IDOR), yıllardır **OWASP API Security
> Top 10'da 1 numara** — ama klasik tarayıcıların (ZAP/Burp) en zayıf olduğu yer, çünkü "kimin nesi
> kimde" sorusunu anlamazlar. Sentinel-Agent tam da bu boşluğu doldurur.

<div align="center">

![Sentinel-Agent web arayüzü — CONFIRMED IDOR bulgusu: açığın yeri + nasıl çözülür](docs/web-ui-bulgu.png)

<sub>Web arayüzünden bir bulgu: doğrulama kontrolleri, temel↔saldırı yanıt diff'i, sızan-marker vurgusu, kopyalanabilir repro-curl ve <b>“nasıl çözülür”</b> önerisi.</sub>

</div>

---

## ✨ Neyle farklı?

Çoğu "AI pentest ajanı" demosu modeli hedefe salar ve model "buldum" der — kanıt yok, determinizm
yok, false-positive riski yüksek. Sentinel-Agent'ın mimarisi bunun tersini garanti eder:

> 🔭 **LLM = keşif kolu (scout):** *neyi* test edeceğini önerir, sonucun ne anlama geldiğini yorumlar.
> ⚖️ **Deterministik motor = hâkim (judge):** açığın gerçek olup olmadığına **her zaman kod** karar verir.

Bu ayrım sayesinde aracın çıktısına güvenilebilir: aynı taramayı iki kez koş, aynı sonucu al; her
`CONFIRMED` bulgunun altında bir güvenlik ekibinin elle doğrulayabileceği kanıt vardır. Üstelik LLM
**zorunlu değildir** — araç deterministik kural-tabanlı hipotezlerle tek başına da kanıtlı bulgu üretir.

### 🔒 İhlal edilemez güvenlik değişmezleri

| # | Değişmez |
|---|---|
| 1 | **LLM ağa asla dokunmaz** — yalnızca tipli aksiyon önerir; tüm trafik tek bir `Replayer`'dan geçer |
| 2 | **`CONFIRMED` kararını her zaman kod verir**, asla LLM — yalnızca deterministik leaked-marker ile |
| 3 | **İki aktör asla session/cookie paylaşmaz** — `test_replay` cross-contamination guard'ı bunu korur |
| 4 | **Kontroller geçmeden verdict yok** — positive + negative + baseline-stability zorunlu |
| 5 | **Scope kapısı her istekte** — allowlist + IP pinning; LLM önerisine (ve UI girdisine) güvenilmez |
| 6 | **Redaction zorunlu** — token/cookie ve PII değerleri (e-posta, JWT, kart, IBAN, hash…) log'a, evidence'a, rapora ve web arayüzüne ham yazılmaz |

---

## 🎯 Verdict merdiveni

Her bulgu dört karardan biriyle etiketlenir — belirsizlik **gizlenmez**, açıkça raporlanır:

| Verdict | Anlamı |
|---|---|
| ✅ **CONFIRMED** | Kanıtlı açık: kurbanın özel verisi saldırganın cevabında göründü, veya yazma/silme kurbanın nesnesinde kalıcı etki yaptı |
| 🟡 **LIKELY** | Güçlü belirti var ama kesin kanıt (leaked-marker) doğrulanamadı |
| ⛔ **REJECTED** | Yetki kontrolü çalışıyor — açık yok |
| ❔ **INCONCLUSIVE** | Kontroller geçmedi / oracle emin olamadı — sessizce yanlış yargı vermez, çekimser kalır |

---

## 🧪 Tespit yetenekleri

Araç iki tür denetleyici kullanır: **Oracle'lar** (çok-aktörlü, karşılaştırmalı, kanıt-temelli) ve
**Dedektörler** (tek-istek, imza/davranış-tabanlı). Her açık tipi ayrı bir alt sınıftır
(Open/Closed — yeni tip = yeni sınıf, mevcut kod bozulmaz).

### ⚖️ Oracle'lar — karşılaştırmalı, kanıt-temelli

| Oracle | Açık tipi | Kanıt yöntemi |
|---|---|---|
| `IdorOracle` | **IDOR / BOLA** (obje okuma) | leaked-marker: kurbanın verisi saldırganın cevabında |
| `StateChangingOracle` | **BOLA-write** (PUT/PATCH/DELETE yetki) | kalıcı mutasyon/silme: işlem sonrası kurban olarak yeniden okuma |
| `BflaOracle` | **BFLA** (fonksiyon-seviyesi yetki) | düşük-yetkili aktör yüksek-yetki fonksiyonuna erişebiliyor mu |
| `BoplaOracle` | **BOPLA** (aşırı veri ifşası) | cevapta görülmemesi gereken hassas alan diff'i |
| `UnauthorizedAccessOracle` | **Kimlik doğrulamasız erişim** | anonim (token'sız) oturum korumalı kaynağa erişebiliyor mu |
| `MethodBypassOracle` | **HTTP metodu ile yetki atlatma** | farklı metod/override başlığıyla yetki kapısı aşılıyor mu |
| `MassAssignmentOracle` | **Mass assignment** | istekle set edilen ayrıcalıklı alan (role/isAdmin…) kalıcı oldu mu |
| `CsrfOracle` | **CSRF** | durum değiştiren istek anti-CSRF koruması olmadan geçiyor mu |
| `FileUploadOracle` | **Güvensiz dosya yükleme** | tehlikeli tür/uzantı kabul edilip sunuluyor mu |
| `StoredXssOracle` | **Depolanan (stored) XSS** | store→retrieve: enjekte edilen script başka aktöre kodlanmadan dönüyor mu |
| `InjectionOracle` | **XSS · SQLi · NoSQLi · SSTI · Path Traversal** | yansıma / hata-diferansiyeli / şablon değerlendirme imzası |
| `TimingOracle` | **Zamanlama-tabanlı kör enjeksiyon** | ölçülü gecikme farkı (blind SQLi/komut) |

### 🔎 Dedektörler — tek-istek imza / davranış

| Dedektör | Açık tipi (OWASP) |
|---|---|
| `ExposureScanner` | İfşa olmuş dosya/endpoint: `.env`/`.git`/yedek/config/swagger/dizin listesi + eski API sürümleri (A05) |
| `InfoLeakDetector` | Bilgi sızıntısı: stack-trace, sürüm/fingerprint, iç IP, SQL/DB hata imzaları (A05) |
| `RateLimitDetector` | Hız sınırı eksikliği + brute-force/credential-stuffing + zayıf şifre politikası (A07) |
| `VersionCveDetector` | Sürüm → bilinen CVE eşleme (Vulnerable & Outdated Components, A06) |
| `DefaultCredentialsDetector` | Varsayılan kimlik bilgileri (güvenli deneme listesi) |
| `SessionLifecycleDetector` | Logout sonrası token geçerliliği + JWT `exp` claim'i + session fixation |
| `OpenRedirectDetector` | Açık yönlendirme (`redirect`/`url`/`next`… → Location) |
| `CorsDetector` | CORS yanlış yapılandırması (joker origin + credentials) |
| `SecurityHeadersDetector` | Eksik güvenlik başlıkları + clickjacking (CSP/HSTS/X-Frame-Options…) |
| `JwtDetector` | JWT zayıf/`none` algoritma, imza/`exp` sorunları |
| `SsrfDetector` · `XxeDetector` · `RfiDetector` | Server-side istek/ayrıştırma: SSRF/XXE/RFI — in-band **ve** blind (OOB toplayıcı ile) |
| `PrototypePollutionDetector` · `CacheDetector` | İleri server-side: prototype pollution + web cache poisoning |
| `UserEnumDetector` | Kullanıcı enümerasyonu (geçerli/geçersiz hesap yanıt farkı) |
| `WordlistRecon` · `GraphQLRecon` | Endpoint enümerasyonu + GraphQL introspection ifşası |

---

## 🖥️ Web arayüzü (kontrol paneli)

CLI'a ek olarak, **tarayıcıdan** tarama yönetip bulguları inceleyebileceğin bir kontrol paneli
gelir. Sunucu bilinçli olarak Python **standart kütüphanesiyle** yazıldı — **yeni bağımlılık yok**,
takım imajını değiştirmez. Varsayılan olarak yalnızca `127.0.0.1`'e bağlanır (kazara dışa açılmaz).

```bash
cp config/scope.example.yaml config/scope.yaml   # panel scope'u BURADAN kilitler (aşağıya bkz.)
python -m scripts.serve_ui                 # → http://127.0.0.1:8787
python -m scripts.serve_ui --port 9000 --out runs/
```

**Scope kilidi:** panel taramaya başlarken kullandığı scope'u (host/port/method/destructive_tests/…)
İSTEKTEN değil `--scope` ile verilen dosyadan (varsayılan `config/scope.yaml`) okur; formdan
gönderilen scope bunu yalnızca **daraltabilir**, asla genişletemez. Dosya yoksa panel açılır ama
tarama başlatılamaz (503) — önce `cp config/scope.example.yaml config/scope.yaml`.

**Ağa açma:** `--host 0.0.0.0` (LAN'dan erişim) ile başlatırken en az bir `--allowed-host
<ip>:<port>` vermen GEREKİR — panel her isteğin `Host` başlığını bir allowlist'e karşı denetler
(DNS-rebinding savunması); allowlist boşsa hiçbir istek geçemez ve panel kimseye açılmaz.

Üç görünüm:

| Görünüm | Ne yapar |
|---|---|
| 🎯 **Tarama** | Hedef, scope, aktörler (kimlik bilgileriyle), endpoint'ler ve modüller formdan girilir; “Taramayı başlat” canlı ilerlemeyle koşar |
| 🔎 **Bulgular** | Verdict sayaçları + filtre/arama; her bulguda **“Açığın yeri”** (istek/yanıt kanıtı, sızan-marker vurgusu, repro-curl) ve **“Nasıl çözülür”** (adım adım öneri + OWASP kaynakları) |
| 🗂️ **Geçmiş** | `runs/` altındaki önceki koşumları açıp aynı ayrıntıyla incele |

**Güvenlik:** Hedef host, panelin kilitlediği scope dışındaysa tarama **submit anında reddedilir**;
her istek yine `PolicyEngine`'den geçer. Panelin kendisi bir `RequestGuard` ile korunur — bilinmeyen
`Host` başlığı (DNS-rebinding) ve `application/json` dışındaki `POST` gövdeleri (CSRF) reddedilir.
`storagestate_path` yalnızca `.secrets/` içinden bir dosyayı gösterebilir. Parolalar sunucuda
yalnızca girişte kullanılır — log'a/rapora/arayüze ham yazılmaz, bulgular arayüze dönmeden
redaction'dan geçer. Çözüm önerileri deterministik bir katalogdan gelir (LLM `--enrich` ile
zenginleştirdiyse onun metni öne çıkar).

<div align="center">

![Sentinel-Agent web arayüzü — tarama kontrol formu](docs/web-ui-tarama.png)

<sub>Tarama görünümü: hedef, scope, aktörler ve endpoint'ler doğrudan tarayıcıdan yönetilir (config dosyalarından ön-doldurulur).</sub>

</div>

---

## 🚀 Tek komutla demo

Kurulum sürtünmesi yok — Docker + Docker Compose yeterli. Aşağıdaki komut hedefi ayağa kaldırır,
kalibrasyon hesaplarını hazırlar, taramayı koşar ve kanıtlı raporu üretir:

```bash
make demo
# make yoksa (ör. Windows / Git Bash):
bash scripts/demo.sh
```

Çıktı:

```
[done] 6 bulgu · 1 CONFIRMED · runs/run-.../
```

Ardından `runs/<run-id>/report.html` dosyasını tarayıcıda aç (veya `python -m scripts.serve_ui`
ile paneli açıp **Geçmiş**'ten koşumu incele). `CONFIRMED` bulgusu, `attacker`'ın `victim`'in
sepetini (`/rest/basket/{id}`) okuyabildiğini ve kurbana ait verinin (ürün adı, fiyat)
**sızdığını** deterministik leaked-marker ile kanıtlar. Komut idempotenttir — tekrar koşmak güvenli.

---

## ⚙️ Kurulum ve çalıştırma

**Ön koşul:** Docker + Docker Compose (Windows'ta Docker Desktop, WSL2 backend ile). Repoyu **WSL2
içindeki Linux dosya sistemine** klonla (nedeni: [aşağıda](#-neden-wsl2--docker-takım-için)).

```bash
git clone https://github.com/Hybrid-Translation-Project/Sentinel-Agent.git
cd Sentinel-Agent

docker compose up -d juice-shop            # kalibrasyon hedefi → http://localhost:3000
docker compose run --rm sentinel bash      # bağımlılıklar + Playwright hazır dev kabuğu
#   imaj içinde:  pytest -q   |   python -m scripts.run_scan --help
```

Yerel `venv` ile (Docker'sız) çalışmak için: [DESIGN.md §5](DESIGN.md).

### 🎛️ Kendi hedefine karşı çalıştırma

Aracın ihtiyacı **paralel bir ajan ordusu değil**, en az **iki gerçek kullanıcı hesabıdır** — biri
kurban, biri saldırgan. (Opsiyonel `admin` ile BFLA de test edilir.) İki yol var:

**A) Web arayüzünden** — `python -m scripts.serve_ui`, ardından “Tarama” formunu doldur.

**B) CLI'dan** — config dosyalarıyla:

```bash
# 1) Scope: hedefin host/port/path/method allowlist'i
cp config/scope.example.yaml     config/scope.yaml

# 2) Aktörler: en az 2 hesap (token | storagestate | static | browser auth)
cp config/actors.example.yaml    config/actors.yaml

# 3) Endpoint'ler: elle liste, ya da --openapi / --har ile otomatik keşif
cp config/endpoints.example.yaml config/endpoints.yaml

# 4) Taramayı koş (LLM opsiyonel — varsayılan kapalı)
docker compose run --rm sentinel python -m scripts.run_scan \
    --scope config/scope.yaml --actors config/actors.yaml \
    --endpoints config/endpoints.yaml --mode active --out runs/
```

> 💡 İlk denemede `--dry-run` ekle: hiçbir istek göndermeden, policy'nin hangi isteklere
> ALLOW/DENY verdiğini önizlersin.

**Kurulabilir CLI (Docker'sız, R-D3):** `pip install .` sonrası aynı tarama `sentinel scan ...`
komutuyla da çalışır (`--scope/--actors/--endpoints` aynı bayraklar); `--scan-mode
quick|standard|deep` bütçeyi ve tarama genişliğini ölçekler (`quick` ≈ 40 istek/300s, hızlı
IDOR/BFLA-only geçiş; `deep` geniş bütçe + wordlist/GraphQL enümerasyonu):

```bash
pip install .
sentinel scan --scope config/scope.yaml --actors config/actors.yaml \
    --endpoints config/endpoints.yaml --scan-mode quick --out runs/
```

**Kimlik doğrulama türleri** (`config/actors.yaml` → `auth.type`):

| Tür | Ne zaman | Nasıl |
|---|---|---|
| `token` | Basit login (tek `POST` → JSON'da token) | `login_url` + `credentials` + `token_location` |
| `static` | Token/cookie zaten elinde | doğrudan `headers`/`cookies` |
| `storagestate` | SPA/OAuth login — elle login, Playwright'la EXPORT | `storagestate_path` (`.secrets/` altından) |
| `browser` | SPA/OAuth login + **TOTP MFA** — export adımını otomatikleştir | `login_url` + `credentials` + (opsiyonel) `mfa_totp_secret` — bkz. `config/actors.example.yaml` |

`browser`, `StorageStateAuthProvider`'ın "elle login → export" adımını gerçek bir (varsayılan
headless) tarayıcıyla otomatikleştirir; yalnızca **TOTP** MFA'yı otomatik çözer (SMS/push
desteklenmez — `mfa_code_selector` algılanıp `mfa_totp_secret` verilmemişse net bir hatayla durur,
sessizce yanlış bir oturum üretmez). Refresh-token döngüsü yoktur (tek seferlik `AuthState`, tıpkı
`storagestate` gibi). Ayrıntı: `src/pentestai/auth/browser.py` docstring'i.

### CLI referansı (`run_scan.py`)

| Flag | Açıklama |
|---|---|
| `--scope / --actors / --endpoints` | config YAML dosyaları (zorunlu: scope + actors; endpoint kaynağı) |
| `--openapi <spec>` / `--har <file>` | endpoint'leri OpenAPI spec'inden veya tarayıcı HAR export'undan keşfet |
| `--mode passive\|active` | `passive`: yalnızca listele · `active`: gerçek differential test |
| `--scan-mode quick\|standard\|deep` | bütçeyi + tarama genişliğini ölçekler (`quick`≈40 istek/300s; `deep`=geniş bütçe+enümerasyon); verilmezse scope.yaml'daki budget aynen kalır |
| `--dry-run` | istekleri authorize'dan geçir ama **gönderme** (plan önizlemesi) |
| `--enumerate` | wordlist endpoint enümerasyonu + GraphQL introspection (recon genişletme) |
| `--login-url / --register-url / --logout-url` | brute-force/default-creds · zayıf şifre · session-lifecycle taramalarını tetikler |
| `--no-exposure-scan / --no-info-leak-scan / --no-rate-limit-scan / --no-cve-scan` | ilgili dedektör ailesini atla |
| `--loop` | self-improving orchestrator: CONFIRMED bulgudan pivot hipotezler türet |
| `--agent [--scouts N]` | agentic reasoning döngüsü; `--scouts>1` ile paralel scout'lar (tek bütçe/policy paylaşır) |
| `--llm none\|gemini\|ollama\|anthropic` | hipotez/triyaj LLM'i (varsayılan `none` — **LLM'siz de çalışır**) |
| `--llm-config <dosya>` | LLM ayarlarını dosyadan oku (ör. `config/llm.yaml`); CLI flag'leri dosyayı override eder |
| `--llm-model <ad>` | model adı (ör. `qwen3.8:27b`, `qwen2.5:14b-instruct`, `gemini-3.6-flash`) |
| `--enrich` | bulgulara LLM ile severity/impact/remediation ekle (`--llm` gerekir) |
| `--no-bootstrap` | per-actor own-id crawl'ını atla (id'leri config'te verdiysen) |
| `--fail-on none\|low\|medium\|high\|critical` | CI kapısı: bu eşik ve üstünde CONFIRMED bulgu varsa çıkış kodu 2 |
| `--baseline <önceki-findings.json>` | bilinen (aynı kök-neden+verdict) bulguları `--fail-on`'dan muaf tut — raporda sebebiyle kalır, silinmez |

> 🤖 **LLM zorunlu değil.** Varsayılan `--llm none`; deterministik kural-tabanlı hipotezlerle araç
> tam çalışır ve kanıtlı `CONFIRMED` üretir. LLM yalnızca **kapsamı ve açıklama kalitesini** artırır.

### 🔌 MCP tool-server — "diğer AI ajanlarının kanıt motoru"

**Konumlandırma (RK-13):** XBOW/Strix gibi ajanik pentest araçları da IDOR/BOLA *şüphesi*
üretebilir — ama LLM'in kendi çıkarımı "zero false-positive" garantisi vermez. Sentinel'in
`authorize→replay→oracle` çekirdeği [Model Context Protocol](https://modelcontextprotocol.io)
üzerinden tipli araçlar olarak açık: **başka bir ajan kendi verdict'ini üretmek yerine
Sentinel'i çağırıp deterministik, leaked-marker'lı kanıt alır** — "LLM akıl yürütür,
deterministik motor kanıtlar" ilkesi kendi sınırları dışındaki ajanlara da hizmet eder.

```bash
pip install -e ".[mcp]"     # opsiyonel bağımlılık — mcp SDK
sentinel-mcp --scope config/scope.yaml --actors config/actors.yaml --endpoints config/endpoints.yaml
```

Araçlar: `list_actors`, `list_endpoints`, `probe` (keşif, verdict yok), `run_oracle`
(authorize→replay→oracle — `verdict`'i her zaman deterministik Oracle verir), `reverify`
(flakiness eleme). Tüm sonuçlar redaction'lıdır; MCP istemcisi asla ağa dokunmaz.

#### Örnek akış: Claude Code + sentinel-mcp

Claude Code'u (ya da MCP destekleyen herhangi bir ajanı) proje dizininde `sentinel-mcp`'ye bağla:

```bash
claude mcp add sentinel -- sentinel-mcp \
    --scope config/scope.yaml --actors config/actors.yaml --endpoints config/endpoints.yaml
```

(Eşdeğeri: proje köküne bir `.mcp.json` eklemek —

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "sentinel-mcp",
      "args": ["--scope", "config/scope.yaml", "--actors", "config/actors.yaml",
                "--endpoints", "config/endpoints.yaml"]
    }
  }
}
```
)

Artık Claude Code kendi kod-inceleme sezgisini **kanıtla doğrulatabilir** — kendi verdict'ini
uydurmak yerine Sentinel'i çağırır:

> **Sen:** `GET /api/orders/{id}` bence IDOR'a açık, kontrol eder misin?
>
> **Claude Code:** `list_actors` → `user_A`, `user_B` kayıtlı.
> `run_oracle(oracle="idor", method="GET", path_template="/api/orders/{id}", victim_name="user_A", attacker_name="user_B", resource_key="order")`
> → `{"finding": {"verdict": "CONFIRMED", "confidence": "high", "leaked_markers": ["<REDACTED>"], ...}}`
>
> Sentinel'in deterministik oracle'ı **CONFIRMED** dedi (kurbanın kendi verisi saldırganın
> yanıtında sızmış bulundu) — bu benim tahminim değil, kod kararı. `reverify(..., runs=3)` ile
> flakiness'i de eleyebilirim.

Bu akışta hiçbir verdict LLM'den gelmez (CLAUDE.md §5 kural 2 burada da geçerli) — Claude Code
yalnızca *hangi* testin çalıştırılacağına karar verir, *sonucu* her zaman Sentinel'in Oracle'ı verir.

### 🧠 Local LLM (Ollama) — buluta veri çıkmadan

API key istemeden, **yerel** bir modelle hipotez üretmek için Ollama kullan. Hedef verisi
(endpoint envanteri vb.) makineden çıkmaz — bulut API'sine gitmez.

```bash
# 1) Modeli indir
ollama pull qwen2.5:14b-instruct     # hızlı instruct modeli
# ya da bir reasoning modeli (24GB GPU'ya Q4 olarak sığar, thinking destekli):
ollama pull qwen3.8:27b

# 2) LLM ayar dosyasını hazırla (opsiyonel; CLI flag'i de yeterli)
cp config/llm.example.yaml config/llm.yaml   # provider / model / host / think burada

# 3) --llm ollama ile tara (flag config'i override eder)
docker compose run --rm sentinel python -m scripts.run_scan \
    --scope config/scope.yaml --actors config/actors.yaml \
    --endpoints config/endpoints.yaml --mode active --out runs/ \
    --llm ollama --llm-model qwen3.8:27b --enrich
```

**Yapılandırılmış çıktı (structured outputs).** Hipotez üretimi, enrich ve aksiyon-seçimde model bir
JSON **şemaya** (grammar-constrained) zorlanır; bu, local modellerin `format:"json"` ile verdiği
bozuk/eksik/tek-nesne JSON'ı giderir. Model yine şema-dışı bir şey üretirse öneri sessizce elenir —
tarama çökmez. `temperature` varsayılanı `0`'dır (tekrar-üretilebilir öneri).

**Reasoning ("thinking") modelleri (ör. `qwen3.8:27b`).** `config/llm.yaml`'daki `think` alanı:
- `false` → düşünme kapalı; tüm üretim bütçesi JSON'a gider — **hızlı ve yeterli (önerilen)**.
- `true` → düşünme açık; daha kapsamlı ama yavaş — bu durumda `max_tokens`'ı yükselt (düşünme bütçeyi yer).
- (satırı sil → klasik instruct modelleri için `think` anahtarı hiç gönderilmez — geriye tam uyum.)

> `host` alanı Ollama sunucusunu gösterir (varsayılan `http://localhost:11434`). Sistem kurulumu yerine
> kullanıcı-alanı bir sunucu çalıştırıyorsan (ör. `:11435`), `host`'u ona yönlendir.

---

## 📐 Çok-hedefli benchmark (kalibrasyon)

İddia ("kanıtlı, deterministik, düşük false-positive") ölçülebilir olmalı. Benchmark, **etiketli
yer-gerçeği** (ground truth) üstünde bir taramanın `findings.json`'ını değerlendirir → precision /
recall / **FP-rate**. Metodoloji, AuthProbe'un **"vulnerable ↔ hardened ikiz, 0-FP"** yaklaşımıdır:
her hedefte hem gerçek zafiyet (pozitif) hem tasarım-gereği güvenli (`not_vulnerable`, negatif)
vakalar bulunur; böylece FP oranı **varsayıma değil etikete** dayanır. Etiketler araç çıktısından
değil, doğrudan HTTP ile bağımsız doğrulanarak konur (döngüsellik yok).

**Sonuçlar** (canlı koşum, 2026-09-16 — 3 hedef, 31 etiketli vaka; her etiket doğrudan HTTP ile
hedefin **gerçek davranışından** bağımsız doğrulandı):

| Hedef | Vaka | Precision | Recall | FP-rate | TP/FN/FP/TN |
|---|---|---|---|---|---|
| OWASP Juice Shop (`v20.2.0`) | 7 | %100 | %100 | **%0** | 4/0/0/3 |
| VAmPI (`vulnerable=1`) | 12 | %100 | %50 | **%0** | 2/2/0/8 |
| crAPI (`main`) | 12 | %100 | %40 | **%0** | 2/3/0/7 |
| **TOPLAM** | **31** | **%100** | **%61.5** | **%0** | **8/5/0/18** |

> **FP-rate %0** — 18 negatif "FP kapanı" vakasının (tasarım-gereği public endpoint, method-not-allowed,
> auth zorunlu, obje-referansı taşımayan endpoint vb.) hiçbirinde yanlış CONFIRMED üretilmedi;
> **precision %100**. Recall %61.5: kaçırılanlar (FN) çoğunlukla read-only (GET/HEAD) kapsamın
> ulaşamadığı yazma-metodu (POST register/mass-assignment, PUT) veya id-taşımayan endpoint'lerdir —
> araç mimarisinin dürüst sınırı, false-positive değil. Etiketler araç çıktısından değil gerçek
> davranıştan konduğu için VAmPI/crAPI'de birkaç "belgelenmiş" zafiyet bu build'de tutmadığından
> düzeltilmiştir (ör. VAmPI email-güncelleme yalnızca kendi hesabını değiştirir; crAPI mechanic_report
> POST = 405) — `benchmarks/*.expected.yaml` başlıklarındaki doğrulama kanıtına bakınız.

**Yeniden üretme** — her hedefi ayrı tarayıp birleşik tabloyu üret:

```bash
# hedefleri kaldır: juice-shop (:3000), erev0s/vampi (:5000, vulnerable=1), OWASP/crAPI (:8888)
# her hedef için scope/actors/endpoints hazırla (config/<hedef>/), tara → runs/<hedef>/findings.json
python -m scripts.run_scan --scope config/vampi/scope.yaml --actors config/vampi/actors.yaml \
    --endpoints config/vampi/endpoints.yaml --out runs/vampi_scan/
cp runs/vampi_scan/run-*/findings.json runs/vampi/findings.json   # suite.yaml bu yolu okur
# ... (juiceshop, crapi benzer: config/juiceshop|crapi/) ...

# birleşik precision/recall/FP-rate tablosu → benchmark_suite.md
python -m scripts.benchmark --suite benchmarks/suite.yaml
```

Tek hedef için: `python -m scripts.benchmark --run runs/<id> --expected benchmarks/juiceshop.expected.yaml`
(regresyon kapısı: `--min-precision 1.0 --min-recall 1.0`).

---

## 🏗️ Mimari

```
recon → hipotez → authorize(scope) → replay(actor) → oracle → finding → report
   │        │            │                 │            │          │
 keşif   LLM+kural    güvenlik kapısı   tek choke     3 kontrol   JSON / Markdown /
                      (LLM'siz, saf)    point (auth)  + leaked-   HTML + Web UI
                                                       marker
```

**Modüler bağımlılık yönü (tek yönlü):**
`models → policy → net → oracle → auth → evidence → report → scripts(Scanner) · webui`

Her ana bileşen tek sorumluluklu bir sınıf: `PolicyEngine`, `Replayer`, `ResponseNormalizer`,
`SessionStore`, `Oracle`+alt sınıfları, `Detector`+alt sınıfları, `AuthProvider`+alt sınıfları,
`EvidenceStore`, `Reporter`+alt sınıfları, `Scanner`, `Pipeline` ve web katmanı
(`WebServer`/`WebApp`/`ScanManager`). Bağımlılıklar constructor'dan enjekte edilir (DI) →
testlerde `httpx.MockTransport`/sahte koşucu ile network'süz doğrulama.

### İnşa aşamaları

| Aşama | İçerik | LLM? |
|---|---|---|
| **Stage 0** | multi-actor session + replay + differential oracle + policy engine | ❌ |
| **Stage 1** | recon + LLM hipotez + INCONCLUSIVE triyaj + rapor + tüm oracle/dedektör ailesi | ✅ (ops.) |
| **Stage 2** | orchestrator state machine + self-improving/agentic döngü (CONFIRMED → pivot) | ✅ (ops.) |

Deterministik omurga (Stage 0) LLM'siz bitirilir; sonra üstüne zekâ konur. Tam mimari ve yol
haritası: **[DESIGN.md](DESIGN.md)**.

---

## 📊 Raporlama

Her koşum `runs/<run-id>/` altına birden çok formatta rapor yazar (hepsi redaction'lı):

| Dosya | Format | Kullanım |
|---|---|---|
| `findings.json` | JSON | ham bulgu verisi (viewer/entegrasyon) |
| `report.md` | Markdown | insan-okur özet + yetki matrisi |
| `report.html` | HTML | bağımsız, tek dosyalık interaktif panel (`file://` ile de açılır) |
| `report.sarif` | SARIF 2.1.0 | GitHub code-scanning "Security" sekmesi |
| `junit.xml` | JUnit XML | CI "Tests" sekmesi (RK-2) — verdict→test sonucu |
| `report.csv` | CSV | kaynak-yetenek matrisi (RK-2) — elektronik tablo |
| `proof/<id>.json` | JSON | çevrimdışı yeniden-ispatlanabilir kanıt fixture'ı |
| `proof/<id>.bundle.json` | JSON | **imzalı/hash'li** taşınabilir kanıt-paketi (RK-9) |

`report.html`/`report.md` gösterir:

- 📋 Bulgu listesi + özet sayaçları (CONFIRMED / LIKELY / REJECTED / INCONCLUSIVE)
- ✔️ Doğrulama kontrolleri (positive / negative / baseline-stable) rozetleri
- 🔍 Baseline ↔ saldırı yanıt **diff'i**, sızan-marker vurgusuyla
- 📎 Kopyalanabilir **repro-curl** (token redaction'lı)
- 🌗 Açık/koyu tema

Statik viewer'a herhangi bir `findings.json` dosyasını sürükle-bırak ile de yükleyebilirsin.

### 🔏 İmzalı kanıt-paketi ve çevrimdışı yeniden-ispat (RK-9)

Her CONFIRMED bulgu için `proof/<id>.bundle.json`, kanıt fixture'ını bir SHA-256 bütünlük
hash'iyle mühürler → bir güvenlik ekibine/bug-bounty'ye **değiştirilemez kanıtla** teslim
edilir. `SENTINEL_PROOF_KEY` ortam değişkeni verilirse paket ayrıca **HMAC-SHA256 ile imzalanır**
(özgünlük). Çevrimdışı doğrulama (ağ/LLM yok):

```bash
python -m scripts.replay runs/<run-id>                 # bundle varsa hash + reprove
python -m scripts.replay runs/<run-id> --key "$SENTINEL_PROOF_KEY"   # imzayı da doğrula
```

Hash doğrulanır ve kanıt yeniden-ispatlanırsa `PROVEN`; fixture kurcalanırsa (hash uyuşmaz) `FAILED`.

### 🧩 Topluluk template ekosistemi (RK-12)

Dedektör ailesi bir **YAML template formatına** açıktır — topluluk yeni imza/misconfig ekler,
çekirdek kod değişmez:

```bash
python -m scripts.run_scan ... --templates templates/
```

Her template tek-istek + imza denetimidir (`templates/*.yaml`); geçersiz template'ler yükleme/koşum
anında güvenle elenir (tarama çökmez).

### 🛡️ 0-FP negatif-ikiz regresyon kapısı (RK-10)

`make bench-guard` gerçek oracle'ları vulnerable↔hardened ikizlere karşı **ağsız** koşar;
hardened ikizde tek bir yanlış CONFIRMED çıkarsa kırmızıya döner → kendi pipeline'ında
"FP hâlâ 0 mı?" sorusunu belirlenimci yanıtlarsın (CI'da `bench-guard` işi).

---

## 🐳 Neden WSL2 + Docker (takım için)

1. **Reproducibility:** `docker-compose` herkese (Windows/Mac/Linux) **aynı** Python + Playwright + bağımlılık sürümünü verir → "bende çalışıyordu" biter.
2. **WSL2 zaten Docker'ın altında:** kod da WSL2 Linux FS'inde (`~/projects/...`) olmalı; `/mnt/c` üzerinden bind-mount **çok yavaştır** ve dosya-izleme (`inotify`) bozulur.
3. **Prod-benzeri davranış:** Playwright/Chromium ve async network Linux'ta prod gibi davranır.
4. **Takım tutarlılığı:** CRLF/satır sonu, path ve dosya-izni farkları Linux'ta ortadan kalkar.
5. **OneDrive tuzağı:** `.git`/`.venv`/`node_modules` OneDrive-senkronlu klasörde bozulur — repo **OneDrive dışında** olmalı.

---

## 📁 Proje yapısı

```
Sentinel-Agent/
├── DESIGN.md              # tam mimari + MVP planı (tek kaynak)
├── CLAUDE.md              # takım standartları (commit/dil/OOP/güvenlik kuralları)
├── docker-compose.yml     # dev + juice-shop (kalibrasyon hedefi)
├── Dockerfile             # Python 3.11 + Playwright dev imajı
├── Makefile               # `make demo` / `make test`
├── config/                # scope / actors / endpoints / llm — *.example.yaml (gerçekler git-ignore)
├── docs/                  # rapor + web-ui ekran görüntüleri, AI-kullanımı, Devpost taslağı, video senaryosu
├── src/pentestai/         # models · policy · net · oracle · detector · auth · recon · llm · orchestrator · evidence · report · webui
│   ├── oracle/            # idor · state_change · bfla · bopla · injection · timing · unauthorized · method_bypass · csrf · mass_assignment · file_upload · stored_xss
│   ├── detector/          # exposure · info_leak · rate_limit · cve · default_creds · session_lifecycle · response_inspect · auth_probes · oob_probes · server_side
│   ├── orchestrator/      # pipeline (--loop) · agent (--agent) · parallel (--scouts)
│   ├── report/            # JSON + Markdown + HTML (statik viewer) reporter'ları
│   └── webui/             # stdlib sunucu · saf yönlendirici · tarama yöneticisi · çözüm kataloğu · SPA
├── tests/                 # network'süz birim testleri (276 test)
├── runs/                  # tarama çıktıları: findings.json + report.{md,html,json} (git-ignore)
└── scripts/
    ├── run_scan.py        # CLI tarayıcı
    ├── serve_ui.py        # Web UI sunucusu
    ├── bootstrap_demo.py  # Juice Shop kalibrasyon hesabı + config üretimi
    └── demo.sh            # tek-komut demo
```

---

## 🧑‍💻 Katkı / takım kuralları

- **Sırları asla commit'leme.** Gerçek parola/token/`storageState` → `.secrets/` (git-ignore'lu). Config'te yalnızca `*.example.yaml`.
- **Commit mesajları Türkçe**, imzasız (`tür: özet`). Detay: [CLAUDE.md](CLAUDE.md).
- **Branch akışı:** `main` korumalı; `feature/...` / `fix/...` + PR. Küçük, gözden geçirilebilir PR'lar.
- **Testler yeşil olmadan merge yok** (özellikle `test_replay` cross-contamination guard'ı):
  ```bash
  make test          # veya: docker compose run --rm sentinel pytest -q
  ```

---

## ⚖️ Etik / kapsam uyarısı

Yalnızca **sahibi olduğun veya açık yazılı yetkin bulunan** hedeflerde çalıştır: kendi
localhost/staging uygulaman ya da kalibrasyon için OWASP Juice Shop gibi kasıtlı-zafiyetli
hedefler. Scope/policy engine tüm istekleri allowlist + IP pinning ile denetler ve scope dışına
çıkışı engeller — ama nihai sorumluluk sende.

## 📄 Lisans

[Apache License 2.0](LICENSE) — topluluk/portföy kullanımı için izinli, patent korumalı bir lisans.
Katkıda bulunanlar aynı lisans altında katkı sunar (bkz. [LICENSE](LICENSE) §5).

## 🔒 Güvenlik açığı bildirimi

Aracın kendisinde bir güvenlik açığı bulduysanız bkz. [SECURITY.md](SECURITY.md) — herkese
açık issue açmak yerine GitHub'ın özel bildirim akışını kullanın.
