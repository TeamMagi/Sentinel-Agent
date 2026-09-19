# Sentinel-Agent

> AI-assisted **authenticated access-control** pentest aracı — kendi web uygulamalarındaki
> yetkilendirme açıklarını (IDOR/BOLA + BFLA) **kanıtlı** biçimde bulur.

**Durum:** Çalışır MVP. Stage 0–2 (multi-actor replay + differential oracle + policy engine +
recon + LLM hipotez + self-improving orchestrator) implement edildi ve OWASP Juice Shop'a karşı
**false-positive üretmeden `CONFIRMED` IDOR** üretmesi doğrulandı (aşağıdaki rapor görüntüleyici
gerçek koşumdan). Tam mimari ve yol haritası: **[DESIGN.md](DESIGN.md)**.

---

## Temel ilke

LLM saldırıyı *yapan* değil, *planlayan ve yorumlayan* katmandır. Değer üç katmanın ayrımından gelir:

- **Deterministik güvenlik motoru** (session + oracle + policy) → gerçeği söyler ve kanıtlar.
- **AI reasoning** → neyi test edeceğini ve sonucun ne anlama geldiğini akıl yürütür.
- **Evidence-based verification** → `CONFIRMED` kararını **her zaman kod** verir, asla LLM değil.

## Kapsam (MVP / v0)

| | |
|---|---|
| **IN** | object-level authz (IDOR/BOLA), function-level authz (BFLA), read-only (GET/HEAD) |
| **OUT (v2+)** | XSS, SQLi, SSRF, CSRF exploit, business logic, race condition |

Başarı kriteri: OWASP Juice Shop'taki bilinen bir access-control bug'ını **false-positive üretmeden** `CONFIRMED` bulmak.

## Mimari (özet)

```
recon → hipotez → authorize(scope) → replay(actor) → oracle → finding → report
                       │                   │            │
                  güvenlik kapısı     tek choke point   differential test
                  (LLM'siz, saf)      (auth + evidence) (+ 3 kontrol + leaked-marker)
```

**Değişmezler:** LLM ağa dokunmaz (yalnızca tipli aksiyon önerir) · `CONFIRMED`'i kod verir · iki aktör asla session paylaşmaz · kontroller geçmeden verdict yok. Ayrıntı: [DESIGN.md](DESIGN.md).

## İnşa sırası

| Aşama | İçerik | LLM? |
|---|---|---|
| Stage 0 | multi-actor session + replay + differential oracle + policy engine | ❌ |
| Stage 1 | recon + LLM hipotez + INCONCLUSIVE triage + rapor + BFLA | ✅ |
| Stage 2 | orchestrator state machine + self-improving döngü | ✅ |

Deterministik omurga (Stage 0) LLM'siz bitirilir; sonra üstüne zeka konur.

---

## Hızlı başlangıç (Docker)

Ön koşul: Docker + docker-compose (Windows'ta Docker Desktop, WSL2 backend ile). Repoyu **WSL2 içindeki Linux dosya sistemine** klonla (nedenini aşağıda anlattık).

```bash
git clone https://github.com/Hybrid-Translation-Project/Sentinel-Agent.git
cd Sentinel-Agent

# Kalibrasyon hedefini ayağa kaldır (OWASP Juice Shop → http://localhost:3000)
docker compose up -d juice-shop

# Geliştirme kabuğu (bağımlılıklar + Playwright kurulu imaj)
docker compose run --rm sentinel bash
# imaj içinde:  pytest   |   python -m scripts.run_scan --help
```

`docker compose` kullanmak istemeyen (yerel venv) için adımlar [DESIGN.md §5](DESIGN.md)'te.

## Demo — kanıtlı bulgu üret

Amaç: kurulum sürtünmesi olmadan, tek hedefe (yerel Juice Shop) karşı gerçek bir tarama koşup
**kanıtlı bir `CONFIRMED` IDOR** ve bunu gösteren statik HTML raporu üretmek.

```bash
# 0) Gerçek config'i örnekten türet (gerçek *.yaml git-ignore'lu)
cp config/scope.example.yaml     config/scope.yaml
cp config/actors.example.yaml    config/actors.yaml       # aşağıdaki iki hesabı token-auth ile gir
cp config/endpoints.example.yaml config/endpoints.yaml    # /rest/basket/{id} (resource_key: basket)

# 1) Kalibrasyon hedefini ayağa kaldır (OWASP Juice Shop → http://localhost:3000)
docker compose up -d juice-shop

# 2) İki kalibrasyon hesabını oluştur ve kurbanın sepetine ürün ekle (sızacak marker için)
#    (Bu adım tek-komut demoda otomatikleşecek — bkz. alttaki not)
for U in "sentinel_victim@test.local:Passw0rd!Victim1" "sentinel_attacker@test.local:Passw0rd!Attack1"; do
  E=${U%%:*}; P=${U##*:}
  curl -s -X POST http://localhost:3000/api/Users -H "Content-Type: application/json" \
    -d "{\"email\":\"$E\",\"password\":\"$P\",\"passwordRepeat\":\"$P\",\"securityQuestion\":{\"id\":1,\"question\":\"x\",\"createdAt\":\"\",\"updatedAt\":\"\"},\"securityAnswer\":\"blue\"}" >/dev/null
done
# Kurban olarak giriş yap → token + sepet id'sini (bid) al, sepete ürün ekle
read TOKEN BID < <(curl -s -X POST http://localhost:3000/rest/user/login -H "Content-Type: application/json" \
  -d '{"email":"sentinel_victim@test.local","password":"Passw0rd!Victim1"}' \
  | python3 -c "import sys,json;a=json.load(sys.stdin)['authentication'];print(a['token'],a['bid'])")
curl -s -X POST http://localhost:3000/api/BasketItems -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" -d "{\"ProductId\":1,\"BasketId\":$BID,\"quantity\":3}" >/dev/null
# config/actors.yaml → her aktörün own_object_ids.basket değerini login'deki bid ile eşleştir.

# 3) Taramayı koş → runs/<run-id>/ altında findings.json + report.md + report.html
docker compose run --rm sentinel python -m scripts.run_scan \
    --scope config/scope.yaml --actors config/actors.yaml \
    --endpoints config/endpoints.yaml --mode active --no-bootstrap --out runs/

# 4) Raporu tarayıcıda aç:  runs/<run-id>/report.html
```

Çıktı örneği: `[done] 6 bulgu · 1 CONFIRMED · runs/run-...`. `CONFIRMED` bulgusu, `user_B`'nin
`user_A`'nın sepetini (`/rest/basket/{id}`) okuyabildiğini ve kurbana ait verinin (ürün adı, fiyat)
**sızdığını** deterministik leaked-marker ile kanıtlar — repro-curl rapora gömülüdür (token redaction'lı).

> Not: Hesap bootstrap'ini de içeren **tam otomatik tek-komut** akışı (`make demo`) hazırlanıyor;
> yukarıdaki adımlar bugün çalışan doğrulanmış demodur.

## Rapor görüntüleyici

`report.html` bağımlısız, tek dosyalık statik bir sayfadır (`file://` ile de açılır). Bulgu listesi,
özet sayaçları, doğrulama kontrolleri (positive/negative/baseline-stable), baseline↔saldırı yanıt
diff'i, **sızan marker vurgusu** ve kopyalanabilir repro-curl'ü gösterir; açık/koyu tema destekler.

![Sentinel-Agent rapor görüntüleyici — gerçek koşumdan CONFIRMED IDOR](docs/report-viewer.png)

Herhangi bir `findings.json` dosyasını sürükle-bırak ile de yükleyebilirsin (gömülü veri olmadan
açılan şablon dosya-bırak moduna düşer).

## Neden WSL2 + Docker (takım için)

Birden fazla kişi çalışacağı ve Docker uyumu istendiği için ortam kararı şu:

1. **Reproducibility:** `docker-compose` herkese (Windows/Mac/Linux) **aynı** Python + Playwright + bağımlılık sürümünü verir → "bende çalışıyordu" biter.
2. **WSL2 zaten Docker'ın altında:** Docker Desktop for Windows motorunu WSL2'de çalıştırır. Kodun da WSL2 Linux dosya sisteminde (`~/projects/...`) olması gerekir; `/mnt/c` (Windows FS) üzerinden bind-mount **çok yavaştır** ve dosya-izleme (hot reload/watch, `inotify`) bozulur.
3. **Prod-benzeri davranış:** Playwright/Chromium ve async network Linux'ta prod gibi davranır — Windows'a özgü kırılmalar olmaz.
4. **Takım tutarlılığı:** CRLF/satır sonu, path ve dosya-izni farkları Linux tabanlı ortamda ortadan kalkar.
5. **OneDrive tuzağı (ayrı ama kritik):** `.git`/`.venv`/`node_modules` OneDrive-senkronlu klasörde bozulur ve çakışır — repo **OneDrive dışında** olmalı.

> Kısaca: Windows'ta bile "Docker uyumlu takım projesi" pratikte "WSL2 içinde, Linux dosya sisteminde, docker-compose ile" demektir.

## Proje yapısı

```
Sentinel-Agent/
├── DESIGN.md              # tam mimari + MVP planı (tek kaynak)
├── docker-compose.yml     # dev + juice-shop (kalibrasyon hedefi)
├── Dockerfile             # Python 3.11 + Playwright dev imajı
├── requirements.txt
├── config/                # scope.example.yaml, actors.example.yaml, endpoints.example.yaml
├── docs/                  # rapor görüntüleyici ekran görüntüsü vb.
├── src/pentestai/         # models, auth, net, policy, oracle, recon, llm, orchestrator, evidence, report
│   └── report/            # JSON + Markdown + HTML (statik viewer_template.html) reporter'ları
├── tests/                 # authorize / oracle / replay / orchestrator (network'süz)
├── runs/                  # tarama çıktıları: findings.json + report.md + report.html (git-ignore)
└── scripts/run_scan.py    # CLI (--mode passive|active, --dry-run, --loop, --llm ...)
```

## Katkı / takım kuralları

- **Sırları asla commit'leme.** Gerçek parola/token/`storageState` → `.secrets/` (git-ignore'lu). Config'te yalnızca `*.example.yaml`.
- **Branch akışı:** `main` korumalı; feature branch + PR. Küçük, gözden geçirilebilir PR'lar.
- **Testler yeşil olmadan merge yok** (özellikle `test_replay` cross-contamination guard'ı).
- **Config kopyala:** `cp config/scope.example.yaml config/scope.yaml` (gerçek `*.yaml`'lar ignore'lu).

## Etik / kapsam uyarısı

Yalnızca **sahibi olduğun veya açık yazılı yetkin bulunan** hedeflerde çalıştır: kendi localhost/staging
uygulaman ya da kalibrasyon için OWASP Juice Shop gibi kasıtlı-zafiyetli hedefler. Scope/policy engine
tüm istekleri allowlist + IP pinning ile denetler ve scope dışına çıkışı engeller.

## Lisans

TBD (takımla kararlaştırılacak).
