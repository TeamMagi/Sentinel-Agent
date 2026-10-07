# CLAUDE.md — Sentinel-Agent Takım Standartları

Bu dosya, depoda çalışan herkesin (ve Claude Code'unun) uyması gereken proje kurallarıdır.
Mimarinin tamamı için **[DESIGN.md](DESIGN.md)**. Bu dosya "nasıl çalışırız"ı tanımlar.

> **Proje:** authenticated access-control (IDOR/BOLA + BFLA) açıklarını kanıtlı bulan
> AI-assisted pentest aracı. Temel ilke: LLM akıl yürütür, deterministik motor kanıtlar.

---

## 1. Commit kuralları (ZORUNLU)

- **Tüm commit mesajları Türkçe.**
- **İmza YASAK.** Hiçbir commit'te `Co-Authored-By`, `Generated with`, `🤖`, "Claude" vb. **bulunmayacak**.
- Format: `tür: özet` — özet Türkçe, emir kipi, küçük harf, ≤ 72 karakter.
  - `tür` ∈ `özellik` | `düzeltme` | `bakım` | `refaktör` | `test` | `doküman`
  - Örnek: `özellik: idor oracle'a retry/backoff ekle`
  - Örnek: `düzeltme: replay'de cross-contamination sızıntısını gider`
- Gövde (opsiyonel) Türkçe; **neden**i açıkla, sadece **ne**yi değil.
- Küçük, tek konulu commit'ler. Test kırıkken commit atma.

## 2. Dil kuralları

- **Kod tanımlayıcıları (değişken/fonksiyon/sınıf): İngilizce.** (`PolicyEngine`, `replay`, `victim`)
- **Yorumlar ve docstring'ler: Türkçe.**
- **Kullanıcıya/CLI'ya çıktı: Türkçe.**
- Dosya kodlaması UTF-8; satır sonu LF (`.gitattributes` zorluyor).

## 3. Nesne Tabanlı Programlama (OOP) standartları

Proje OOP + modüler olmalı. Kurallar:

- **Her ana bileşen bir sınıf** ve tek sorumluluğu var:
  `PolicyEngine`, `Replayer`, `ResponseNormalizer`, `SessionStore`, `Oracle`+alt sınıfları,
  `AuthProvider`+alt sınıfları, `MarkerExtractor`, `EvidenceStore`, `Reporter`+alt sınıfları, `Scanner`.
- **Soyutlama ile genişlet:** ortak davranış `ABC` (soyut taban sınıf) + `@abstractmethod`.
  Yeni zafiyet tipi = yeni `Oracle` alt sınıfı; yeni auth = yeni `AuthProvider` alt sınıfı.
  Mevcut sınıfları değiştirmeden ekle (Open/Closed).
- **Dependency Injection:** bağımlılıklar constructor'dan enjekte edilir (global/singleton yok).
  Örn. `IdorOracle(replayer, base_url)`; `Replayer(policy, normalizer, budget, limiter, retry)`.
  Bu, testlerde sahte bağımlılık vermeyi (MockTransport vb.) mümkün kılar.
- **Veri modelleri Pydantic** (`models/`), davranış modelleri düz sınıf.
- **Saf yardımcılar** (ör. `structurally_same`, `redact`) fonksiyon veya `@staticmethod` olabilir —
  OOP "fonksiyon yasak" demek değildir; durumsuz yardımcıyı sınıfa hapsetme.
- **Tip ipuçları (type hints) zorunlu.** Genel API'de `Any` kaçınılır.

## 4. Modüler yapı ve bağımlılık yönü

Paketler ve tek işleri (bkz. DESIGN.md §7):
`models` → `policy` → `net` → `oracle` → `auth` → `evidence` → `report` → `scripts(Scanner)`

- Bağımlılık **tek yönlü**: alt katman üst katmanı import etmez (`models` hiçbir şey import etmez;
  `oracle` `net`+`models`'e bağlı; `report` `models`+`evidence`'a bağlı).
- Döngüsel import yasak. Her modül tek bir işten sorumlu.
- Yeni yetenek = yeni modül/sınıf; mevcut dosyayı şişirme.

## 5. Güvenlik değişmezleri (İHLAL EDİLEMEZ)

1. **LLM ağa dokunmaz** — yalnızca tipli aksiyon önerir; tüm trafik `Replayer`'dan geçer.
2. **`CONFIRMED` kararını kod verir**, asla LLM — yalnızca deterministik kanıt (leaked-marker) ile.
3. **İki aktör asla session/cookie paylaşmaz** (`SessionStore` izolasyonu; `test_replay` korur).
4. **Kontroller (positive/negative/stability) geçmeden verdict yok.**
5. **Redaction zorunlu:** token/cookie/PII log'a, evidence'a, rapora **ham** yazılmaz.
6. **Scope kapısı her istekte:** `PolicyEngine.authorize` — LLM önerisine güvenilmez.

## 6. Test standartları

- **Network'süz** unit test: `httpx.MockTransport` veya `respx`. Gerçek hedefe unit testte gidilmez.
- Her davranış yolu ayrı test (oracle'da CONFIRMED/LIKELY/REJECTED/INCONCLUSIVE).
- `pytest` yeşil olmadan **merge yok** — özellikle `test_replay` (cross-contamination).
- Testler `tests/`; `pytest -q` ile çalışır (`pyproject.toml` `pythonpath=["src"]`, `asyncio_mode=auto`).

## 7. Dal (branch) ve PR akışı

- `main` korumalı. Doğrudan `main`'e push etme; `feature/...` veya `fix/...` dalı aç, PR ile birleştir.
- Küçük, gözden geçirilebilir PR'lar. En az bir onay + yeşil testler.
- PR açıklaması Türkçe.

## 8. Sırlar ve config

- Gerçek parola/token/`storageState` **asla commit edilmez** → `.secrets/` (git-ignore).
- Yalnızca `config/*.example.yaml` izlenir; gerçek `config/*.yaml` git-ignore.
- Kopyala-çalıştır: `cp config/scope.example.yaml config/scope.yaml`.

## 9. Çalıştırma (Docker — takım için tek ortam)

```bash
docker compose up -d juice-shop                    # kalibrasyon hedefi (localhost:3000)
docker compose run --rm sentinel pytest -q         # testler
docker compose run --rm sentinel python -m scripts.run_scan \
    --scope config/scope.yaml --actors config/actors.yaml \
    --endpoints config/endpoints.yaml --mode active --out runs/
```

Windows'ta: WSL2 içinde, Linux dosya sisteminde, OneDrive dışında çalış (bkz. README).

## 10. Etik

Yalnızca sahibi olunan veya açık yazılı yetki verilen hedeflerde çalıştır. Scope engine dışına çıkma.
