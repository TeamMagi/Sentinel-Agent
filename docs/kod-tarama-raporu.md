# Kod Tarama Raporu — Sentinel-Agent

**Tarih:** 2026-09-16 · **Dal:** `develop` (`ed1f647`) · **Yöntem:** dosya-dosya manuel inceleme + otomatik denetim
(`py_compile`, bare-except, TODO/FIXME taraması)

Bu rapor bulguları **listeler; düzeltme uygulanmamıştır.** Öncelik sırası verilmiştir.

## Kapsam

**Satır satır okunan (güvenlik- ve verdict-kritik çekirdek):**
`net/{replay,session_store,pinning,csrf,limits,normalize}`, `policy/authorize`,
`oracle/{idor,bopla,state_change,injection,base,markers,csrf,mass_assignment,method_bypass,canary}`,
`classify`, `models`, `config`, `webui/{server,guard,scan_manager,app}`,
`evidence/{proof,store}`, `report/{render_sarif,dedup,coverage,baseline}`, `bench/suite`,
`detector/{cve,session_lifecycle,rate_limit,exposure,default_creds,info_leak}`,
`planner`, `enrich`, `triage`, `auth/provider`, `llm/client`, `cli`.

**Örnekleyerek geçilen (satır satır okunmadı):** `orchestrator/*`, `recon/*`, `report/render_md|html`,
`detector/{response_inspect,server_side,oob_probes,auth_probes}`,
`oracle/{stored_xss,timing,file_upload,bfla,unauthorized_access}`, `mcpserver`,
`webui/{api_models,remediation}`, `net/burst`.

**Genel durum:** Kod tutarlı ve dikkatli yazılmış. Tüm kaynak `py_compile` temiz, bare-except yok,
gerçek TODO/FIXME yok, 432 test yeşil. Oracle ailesi gerçek (differential) kontrollere sahip; aşağıdaki
sorunlar çoğunlukla signature-detektörlerinde ve heuristik eşiklerdedir.

---

## Bulgular

### 1. [ORTA] Logout-invalidation detektöründe negatif kontrol yok → public endpoint'te false-positive

**Dosya:** `src/pentestai/detector/session_lifecycle.py:42-79` (`check_logout_invalidation`)

Mantık: `before = GET protected_url` (200 ise devam) → logout → `after = GET protected_url`;
`after == 200` ise **CONFIRMED**. Ancak endpoint'in gerçekten kimlik doğrulama gerektirdiği
(anonim/token'sız erişimde reddedildiği) **hiç doğrulanmıyor**.

`protected_url` tasarımca public ise (ör. `/rest/products/search`), before ve after zaten token'dan
bağımsız 200 döner → **yanlış CONFIRMED** ("logout sonrası oturum hâlâ geçerli"). Diğer
signature-detektörlerinin aksine buradaki "kanıt" (after=200) kendi başına belirleyici değildir.

Bu, projenin **§5.4 "kontroller geçmeden verdict yok"** değişmezinden gerçek bir sapmadır.
`--logout-url` verildiğinde ve `endpoints[0]` public olduğunda tetiklenir.

**Öneri:** logout'tan önce anonim (token'sız) bir istekle endpoint'in korunduğunu (401/403)
doğrulayan bir negatif kontrol ekle; geçmezse INCONCLUSIVE dön.

### 2. [DÜŞÜK] `SAFE_METHODS` iki yerde farklı tanımlı → OPTIONS tutarsız

**Dosya:** `src/pentestai/models/__init__.py:16` `{GET, HEAD, OPTIONS}` ⟂
`src/pentestai/policy/authorize.py:19` `{GET, HEAD}`

`OPTIONS`, model tarafında "safe" sayılır (`is_state_changing=False` → retry'lanır, CSRF eklenmez)
ama policy tarafında "safe" değildir → `destructive_tests=false` iken "destructive method blocked"
ile reddedilir. Şu an OPTIONS test edilmediği için **latent**; ileride kullanılırsa tutarsız davranır.

**Öneri:** tek kaynak (`models.SAFE_METHODS`) kullan ya da ikisini bilinçli olarak hizala.

### 3. [DÜŞÜK] BOPLA alan-adı substring eşleşmesi → false-positive riski

**Dosya:** `src/pentestai/oracle/bopla.py:26,63-64` (`HARD_SUBSTR`, `_is_hard`)

`HARD_SUBSTR` "password" içerdiğinden, **değeri sır olmayan** alan adları da CONFIRMED
`excessive_data_exposure` üretebilir: `passwordChangedAt` (zaman damgası), `passwordResetEnabled`
(boolean), `hasPassword` gibi. Değere değil yalnızca alan ADINA bakılır ve dolu değerli her eşleşme
CONFIRMED sayılır.

**Öneri:** substring eşleşmesini değer-tipi/deseniyle destekle (ör. bool/tarih değerli alanları hariç
tut) veya bu alanları SOFT (LIKELY) sınıfına al.

### 4. [DÜŞÜK] CVE sürüm karşılaştırması kısa-sürümde false-positive

**Dosya:** `src/pentestai/detector/cve.py:51-69` (`_parse_version`, `lookup`)

Sürümler tuple'a çevrilip `<` ile karşılaştırılır. Python'da `(1, 21) < (1, 21, 0)` → `True`.
Sunucu tam-düzeltme sürümünü kısa yazarsa (ör. `Server: nginx/1.21`, `fixed_in="1.21.0"`) sürüm
düzeltmeye **eşit** olmasına rağmen "zafiyetli" işaretlenir.

**Öneri:** karşılaştırmadan önce tuple'ları eşit uzunluğa sıfırla doldur (zero-pad).

### 5. [DÜŞÜK] `default_credentials`'ta negatif kontrol yok

**Dosya:** `src/pentestai/detector/default_creds.py:52-65`

Yanlış kimlik bilgisiyle de token dönen bozuk bir login endpoint'i (her girişe 200+token)
default-cred false-positive'i üretebilir; "yanlış kimlik reddediliyor mu?" doğrulanmıyor.
Bulgu #1 ile aynı sınıf ama daha zayıf risk (admin/admin'in token alması yine de güçlü bir sinyal).

**Öneri:** bilinen-yanlış bir kimlikle bir negatif kontrol dene; o da başarılıysa endpoint her
girişi kabul ediyor demektir → default-cred olarak CONFIRMED verme.

### 6. [BİLGİ / kozmetik] Tek-aktör bulgularda `f.victim`/`f.attacker` boş kalıyor

**Dosya:** `src/pentestai/scanner.py:342-393` (edx/csrf/mass_assignment dalları)

Bu tek-aktör alt-taramalar `_tag` ile `victim_as`/`found_as` set ediyor ama `f.victim`/`f.attacker`
alanlarını doldurmuyor → R-B1 yetki matrisi (`report/matrix.py`) bu bulguları eksik gösterebilir.
**Verdict ve benchmark etkilenmez.**

### 7. [BİLGİ] `rate_limit` eşik heuristiği over-report edebilir

**Dosya:** `src/pentestai/detector/rate_limit.py:41-71` (`scan_endpoint`)

Küçük bir burst'te hiç 429/503 görülmezse CONFIRMED "rate limit eksikliği" (medium) verilir.
Burst sayısı/eşik düşükse, aslında makul bir hız sınırı olan endpoint'lerde de tetiklenebilir
(by-design davranışsal heuristik; differential değil).

---

## Elenen şüphe (yanlış alarm)

- `mass_assignment._field_set` — kompakt JSON'da (`"role":"admin"`) kaçırır sanılmıştı; ancak
  `net/normalize.py:49` `body_normalized`'ı `json.dumps` varsayılan `": "` ayırıcısıyla yeniden
  serileştirdiği için eşleşme doğru çalışır. **False-negative yok.**

## Doğrulanan güvenlik değişmezleri (sorun bulunmadı)

- Tek choke point (`Replayer`) + strip→inject sırası; auth header sızıntısı yok.
- Scope kapısı (`PolicyEngine`): path-traversal/çift-kodlama/matrix-param/dot-segment normalize,
  DNS-pin + soket-seviyesi `PinnedTransport` ikinci savunma; fail-closed.
- Web UI: `RequestGuard` (Host allowlist + JSON-only + Origin) CSRF/rebinding savunması;
  run-id/secrets-path traversal `relative_to` ile kapalı; scope istekten değil sunucudan gelir.
- Oracle ailesi (idor/bopla/state_change/csrf/mass_assignment/method_bypass): gerçek
  positive/negative/stability kontrolleri; CONFIRMED yalnızca deterministik leaked-marker/mutasyonla.
- Redaction (`evidence/store.redact`): token/JWT/e-posta/PII değerleri log/evidence/rapora ham yazılmaz.

## Önceliklendirme

**#1** gerçek false-positive üretebildiği ve projenin "0 false-positive" iddiasına dokunduğu için
önce ele alınmalı. #2–#5 düşük etkili, ayrı küçük `fix/` dallarında birleştirilebilir. #6–#7 bilgi
amaçlı (isteğe bağlı).
