# Görev Listesi — Zafiyet Kapsamı Genişletme (Tier A + Tier B)

> Bağlam: MVP (IDOR/BOLA + BFLA + BOPLA + reflected-XSS/error-SQLi + local LLM) **tamamlandı**
> ve canlı doğrulandı. Bu dosya, yeni zafiyet türlerini eklemek için **Tier A** (mevcut oracle
> desenine doğal uyan, hızlı kazanım) ve **Tier B** (yeni yetenek gerektiren) işleri kapsar.
> Mimari ve stil için **[DESIGN.md](DESIGN.md)** + **[CLAUDE.md](CLAUDE.md)**.
> Tier C (mimariye uymayan / ayrı araç gerektiren) işler ayrı dosyada: **[TIER_C.md](TIER_C.md)**.

Sorumluluklar Serhat ve Görkem arasında **toplam yük eşit** (32/32 saat) olacak şekilde paylaştırıldı;
her ikisine birer **bloklayıcı altyapı** görevi geldi (Serhat: B1 write, Görkem: B6 OOB).
Atamalar değiştirilebilir — önemli olan yükün dengeli kalması.

---

## Ortak ilkeler (her yeni tür için — CLAUDE.md §3, §5, §6)

Her yeni dedektör görevi şu **beş parçayı** içerir (aksi belirtilmedikçe):
1. **Bileşen sınıfı** — differential türler için `Oracle` ABC'den yeni alt sınıf; tek-istek/imza
   türleri için yeni hafif `Prober`/`Scanner` ailesi (bkz. "Mimari not").
2. **planner + dispatch + expander** bağlama (`Scanner`, `HypothesisGenerator`).
3. **LLM aksiyon/hipotez tipi** — `ProposeHypothesis`/`ProposeAction` enum + `prompts` + structured-outputs şeması.
4. **Network'süz testler** (`httpx.MockTransport`/`respx`) — her verdict yolu.
5. **Canlı kalibrasyon** — Juice Shop veya uygun hedefte doğrulama.

**Değişmezler korunur:** LLM ağa dokunmaz · CONFIRMED'i yalnız kod verir (deterministik kanıt) ·
kontroller geçmeden verdict yok · redaction zorunlu · scope kapısı her istekte.

### Mimari not (bir kereye mahsus tasarım kararı — ilk Tier A görevinde netleşir)
Tier A'nın bir kısmı differential değil **tek-istek + imza/header** denetimidir (ör. Open Redirect,
CORS, header eksikleri, dosya ifşası). Bunlar için `Oracle`'a ek olarak `Probe`/`Detector` ADT'si
tanımlanmalı (aynı `Finding`/`Evidence`/redaction sözleşmesi, differential kontrol yerine imza kanıtı).

### Bağımlılıklar (önce yapılmalı — bloklayıcı; B1 ve B6 paralel başlar)
- **[B1] write-method desteği** (`executor` + `destructive_tests` kapısı) → Mass Assignment, File Upload, CSRF, Stored XSS'in yazma adımı buna bağlı.
- **[B6] OOB collector** (out-of-band geri çağrı altyapısı) → blind SSRF/XXE/RFI buna bağlı.
- **[B2] timing primitive** → time-based blind SQLi/command injection buna bağlı.

---

## Aşama A — Tier A (doğal uyum, read-only, deterministik)

### A1 — Access-control genişletmeleri  ·  *(Sorumlu: Serhat · ~4 saat)*
Horizontal privilege escalation (aynı-rol aktörler arası IDOR akışı), Admin panel bypass +
Function-level authorization bypass (BFLA varyantları), Unauthorized API access, **HTTP method bypass**
(alternatif method → durum farkı). Mevcut IDOR/BFLA oracle'ları örnek alınır.

### A2 — Injection oracle genişletmeleri  ·  *(Sorumlu: Görkem · ~5 saat)*
**NoSQL injection** (operatör enjeksiyonu → auth-bypass/hata imzası), **SSTI** (`{{7*7}}`→`49`
yansıması), **Path Traversal / LFI** (`../../etc/passwd` → `root:x:0:0` imzası). `InjectionOracle`
deseninden türetilir; zararsız payload, read-only.

### A3 — Response-inspection prober (header/redirect/CORS)  ·  *(Sorumlu: Görkem · ~4 saat)*
**Open Redirect** (Location header attacker domain), **CORS misconfiguration** (Origin→ACAO yansıması + credentials),
**güvenlik header eksikleri** (HSTS/CSP/X-Frame → **Clickjacking tespiti**). Yeni `Probe` ADT'sini bu görev tanımlar (Mimari not).

### A4 — Exposure scanner (dosya/endpoint ifşası)  ·  *(Sorumlu: Serhat · ~4 saat)*
Bilinen path probe + imza: `.env` / `.git` / backup / source / config / log / source-map exposure,
**Directory listing**, Swagger/GraphQL introspection & debug/doc exposure, **eski API versiyonları** (`/v1`,`/v2`).
Yeni `ExposureScanner`; recon'a bağlanır. Kanıt = imza; PII/secret redakte.

### A5 — Bilgi sızıntısı oracle  ·  *(Sorumlu: Serhat · ~3 saat)*
Stack trace / error message disclosure, version & framework fingerprinting, internal IP / DB info disclosure.
Hata tetikleme + response/header imza analizi. Ham sır/PII evidence'a yazılmaz (yalnızca tür/varlık).

### A6 — User enumeration + JWT vulnerabilities  ·  *(Sorumlu: Görkem · ~4 saat)*
**User/email enumeration** (login/reset/register'da geçerli-geçersiz kullanıcı differential yanıt/timing).
**JWT vulns**: `alg=none`, imza doğrulanmıyor, zayıf secret (token forge → hâlâ 200 = deterministik kanıt).

---

## Aşama B — Tier B (yeni yetenek gerektirir)

### B1 — Write-method altyapısı + Mass Assignment + File Upload + PUT/DELETE·CSRF authz  ·  *(Sorumlu: Serhat · ~7 saat)*  · **bloklayıcı altyapı**
`executor`'a güvenli **yazma-metodu** desteği (`destructive_tests` kapısı, otomatik-retry yok).
Üstüne: **Mass Assignment** (fazla alan — `role`/`isAdmin` — set oluyor mu?), **File Upload** (ext/MIME bypass),
**tam PUT/DELETE authz + CSRF**.

### B2 — Timing oracle (blind)  ·  *(Sorumlu: Görkem · ~4 saat)*  · **timing primitive**
Zamanlama-tabanlı differential primitive; üstüne **time-based blind SQLi** ve **blind Command Injection**.
Gürültüye karşı çoklu-örnek + eşik; budget dostu.

### B3 — Stored XSS + Session lifecycle  ·  *(Sorumlu: Serhat · ~5 saat)*
**Stored XSS** (store→retrieve iki-adım; B1'in yazma desteğini kullanır). **Session** lifecycle:
fixation, logout sonrası geçerlilik, expiration, hijacking (kısmi). Çok-aktörlü oturum modeline oturur.

### B4 — Rate-limit / burst harness  ·  *(Sorumlu: Serhat · ~5 saat)*
Kontrollü burst altyapısı (budget-farkında). Üstüne: **rate limit eksikliği**, **brute force / credential
stuffing / password spraying** tespiti, **weak password policy**. Hedefi ezmeyecek eşikler + kill-switch.

### B5 — Recon/wordlist genişletme  ·  *(Sorumlu: Görkem · ~4 saat)*
**API endpoint enumeration** (wordlist + differential varlık), **GraphQL** introspection → BOLA/BFLA
GraphQL sorgularına uyarlama. recon katmanına eklenir.

### B6 — OOB collector + SSRF/XXE/RFI  ·  *(Sorumlu: Görkem · ~6 saat)*  · **bloklayıcı altyapı**
Out-of-band geri çağrı altyapısı (benzersiz token → dış geri-çağrı yakalama). Üstüne: **SSRF**,
**XXE**, **RFI** (in-band varsa kısmi, blind için OOB).

### B7 — Sürüm→CVE eşleme + server misconfig  ·  *(Sorumlu: Serhat · ~4 saat)*
Version fingerprint → **known-CVE** eşleme (yerel/çevrimdışı CVE veri kaynağı), **default credentials**
denemesi (güvenli liste), **debug mode** tespiti. Vulnerable/Outdated Components (OWASP A06).

### B8 — Server-side ileri  ·  *(Sorumlu: Görkem · ~5 saat)*
**Server-side Prototype Pollution** (kirlet→davranış değişimi gözle), **Web Cache Poisoning/Deception**
(unkeyed header probe, çok-istek differential).

---

## Toplam yük (eşit — 32/32)

| | Tier A | Tier B | Toplam |
|---|---|---|---|
| **Serhat** | A1(4) + A4(4) + A5(3) = 11 | B1(7) + B3(5) + B4(5) + B7(4) = 21 | **32 saat** |
| **Görkem** | A2(5) + A3(4) + A6(4) = 13 | B2(4) + B5(4) + B6(6) + B8(5) = 19 | **32 saat** |

**Önerilen sıra:** önce bağımlılıklar paralelde (Serhat B1 · Görkem B6, B2) → sonra onlara bağlı
dedektörler → Tier A bağımsız olduğundan boşluklarda paralel ilerler.
