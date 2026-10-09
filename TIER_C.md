# Tier C — İleride Ele Alınacak Zafiyet Türleri

> Bu maddeler **mevcut mimariye doğrudan oturmaz**: sistem kimlik-doğrulamalı HTTP/JSON differential
> test + deterministik oracle üzerine kurulu (tarayıcı DOM motoru yok, OOB collector yok, altyapı/ağ
> tarayıcı yok, raw-socket yok, varsayılan read-only). Aşağıdakiler ya **yeni bir yürütme motoru**,
> ya **ayrı bir araç entegrasyonu**, ya da **ağır durum/iş-mantığı modellemesi** gerektirir.
> Öncelik: **Tier A + Tier B** ([GOREVLER.md](GOREVLER.md)) bittikten sonra.

---

## C1 — Tarayıcı DOM motoru gerektirenler
**Gereken yetenek:** gerçek headless tarayıcıda JS çalıştırma + DOM/olay gözlemi (Playwright şu an
yalnızca login için). Yeni bir `BrowserDriver` yürütme motoru gerekir.
- [x] **DOM XSS** — `BrowserDriver` (`browser/driver.py`) + `DomXssOracle` (`oracle/dom_xss.py`)
  eklendi (ROADMAP.md §4'ün önerdiği tek-madde giriş noktası). Kanıt `InjectionOracle`'ın
  string-yansıması DEĞİL: gerçek Chromium'da payload'ın JS olarak **İCRA EDİLDİĞİ**
  (`window.__sentinelReport` geri-çağrısı veya `alert/confirm/prompt` diyaloğu), query **ve**
  sunucuya hiç gitmeyen URL-fragment (hash) üzerinden, baseline/attack differential kontrolüyle
  gözlenir. Scope kapısından geçer (CLAUDE.md §5 kural 6); maliyetli olduğu için Scanner'a
  YALNIZCA `--dom-xss` ile opt-in DI edilir (varsayılan kapalı). Testler: `tests/test_browser_driver.py`
  + `tests/test_oracle_dom_xss.py` (network'süz, `context.route()` ile).
- Client-side authorization
- LocalStorage / SessionStorage hassas veri
- Gerçek Clickjacking exploit (tespit Tier A'da; PoC-render burada)
- Client-side Prototype Pollution

> C1'in geri kalanı (client-side authorization, localStorage/sessionStorage sızıntısı,
> clickjacking PoC-render, client-side prototype pollution) `BrowserDriver`'ı **yeniden
> kullanabilir** ama her biri kendi Oracle'ı + kanıt modelini gerektirir — henüz yapılmadı.

## C2 — Ağ / altyapı tarama (HTTP-differential dışı)
**Gereken yetenek:** nmap / sslscan / DNS çözümleme / CVE-DB gibi harici araç entegrasyonları;
choke-point (authorize→replay) modelinin dışında ayrı bir tarama hattı.
- Açık portlar / gereksiz servisler
- Eski servis/web server sürümleri + port-tabanlı known-CVE taraması
- [x] **TLS/SSL misconfiguration, certificate misconfiguration** — `TlsInspector`
  (`netscan/tls.py`, choke-point'in dışında ayrı bir yürütme motoru: ham `ssl`/`asyncio` TLS
  handshake, `Replayer`'a UĞRAMAZ) + `TlsDetector` (`detector/tls.py`). Kanıt bizim yorumumuz
  DEĞİL: OpenSSL'in kendi zincir-doğrulama motoru (`ssl.create_default_context()` ile "verified"
  bağlantı) — başarısız olursa `verify_message`'ı (expired/self-signed/untrusted-issuer/hostname-
  mismatch) bilinen imzalara göre kategorize eder; ayrı bir "raw" (`CERT_NONE`) bağlantı, güven
  durumundan bağımsız olarak zayıf protokol sürümü (TLS<1.2) ve zayıf cipher suite'i (RC4/DES/
  3DES/NULL/anon) gözler. Yeni bağımlılık EKLENMEDİ (`cryptography`/`pyOpenSSL` yok — yalnızca
  stdlib `ssl`). Scope kapısından geçer; varsayılan AÇIK (ucuz/salt-okunur), `--no-tls-scan` ile
  kapatılır. Testler: `tests/test_tls_inspector.py` (gerçek yerel 127.0.0.1 TLS sunucusu, self-
  signed sertifika `openssl` CLI ile üretilir — internete gidilmez) + `tests/test_detector_tls.py`
  (kategorizasyon, sahte `TlsInspector` ile).
- Subdomain enumeration / takeover, dangling DNS records, DNS misconfiguration

> C2'nin geri kalanı (açık port taraması, port-tabanlı known-CVE, subdomain enumeration/takeover,
> dangling DNS) `netscan/` paketini genişletebilir ama her biri kendi motoru/veri kaynağını
> (TCP-connect port tarayıcı, DNS çözücü + takeover fingerprint listesi) gerektirir — henüz
> yapılmadı.

> Not: **security header / HSTS / CSP / directory listing / debug / default creds** gibi *HTTP üzerinden
> tek-istekle* görülen "server misconfig" alt kümesi Tier A/B'ye alındı; burada kalanlar gerçek ağ/altyapı taramasıdır.

## C3 — Protokol/raw-socket seviyesi
**Gereken yetenek:** ham TCP kontrolü, TE/CL desync, hassas zamanlama (httpx yetmez).
- [x] **HTTP Request Smuggling** — `RawHttpClient` (`rawsocket/http_client.py`, choke-point'in
  dışında ayrı bir yürütme motoru: ham `asyncio`/`socket` TCP, `Replayer`'a UĞRAMAZ) +
  `SmugglingOracle` (`oracle/smuggling.py`, `TimingOracle`'ın zamanlama-diferansiyel desenini
  izler). PortSwigger'ın kamuya açık "timing-based detection" metodolojisi: **CL.TE** (chunk-size
  satırı + eksik chunk verisi, sonlandırıcı YOK — front-end Content-Length'e güvenirse böyle
  iletir) ve **TE.CL** (tamamlanmış chunked gövde + fazladan beyan edilen Content-Length —
  front-end Transfer-Encoding'e güvenirse böyle iletir) probları; taban (temiz istek) hızlıysa VE
  prob ya zaman aşımına uğrarsa ya da belirgin biçimde yavaşsa CONFIRMED. Saf tespit — tam
  istismar (ikinci bir "kurban" isteği) DENENMEZ; tek hedefte yalnızca 1 taban + en fazla 2 prob
  gönderilir, tekrar/döngü yok. **Üçlü kapı** (riskin büyüklüğüyle orantılı): yalnızca
  `scope.destructive_tests=True` (oracle içinde AÇIKÇA da zorunlu kılınır — ikinci katman) VE
  `raw_http_client` DI edilirse (Scanner) VE `--smuggling-scan` CLI bayrağı verilirse çalışır;
  varsayılan tamamen KAPALI. Yeni bağımlılık YOK (yalnızca stdlib `asyncio`/`ssl`/`socket`).
  Testler: `tests/test_rawsocket_http_client.py` (gerçek yerel `127.0.0.1` TCP sunucusu — internete
  gidilmez) + `tests/test_oracle_smuggling.py` (karar mantığı, sahte `RawHttpClient` ile).

## C4 — Ağır durum / iş mantığı
**Gereken yetenek:** uygulamaya-özel iş akışı modeli + çok-adımlı durum + eşzamanlılık (race) harness'i.
Deterministik kanıt üretmek uygulama semantiğine bağımlı; büyük ölçüde yarı-otomatik.
- Ödeme bypass, fiyat manipülasyonu, kupon/promosyon abuse
- Yetki/iş-akışı bypass, premium özellik bypass, hesap/işlem limiti bypass
- [x] **Race Condition** (TOCTOU) — `RaceHarness` (`net/race.py`, yeni "eşzamanlılık harness'i":
  `asyncio.Barrier` ile N isteği TAM OLARAK aynı anda gönderir — `BurstHarness`'ın sıralı-hızlı
  göndermesi TOCTOU penceresini açmaya YETMEZ) + `RaceConditionOracle`
  (`oracle/race_condition.py`). C4'ün kendi notuyla dürüstçe uyumlu: uygulamanın "bu aksiyon tek
  kullanımlık/limitli" semantiği OTOMATİK keşfedilmez — operatör `--race-endpoint` ile AÇIKÇA
  belirtir (tıpkı halihazırda var olan `--login-url`/`--logout-url`/`--register-url` gibi
  yarı-otomatik girdiler). Oracle'ın kendisi TAMAMEN deterministiktir: N eşzamanlı istekten
  DOĞRUDAN gözlenen başarı sayısını sayar — 1 başarılı → REJECTED (doğru serileştirilmiş), >1
  başarılı → CONFIRMED (tartışmasız kanıt, tahmin YOK). `RateLimiter`'ı bypass eder ama
  `PolicyEngine`/`BudgetTracker` korunur (bütçe UPFRONT sayılır — barrier deadlock'unu önler).
  Yeni bağımlılık YOK (yalnızca stdlib `asyncio.Barrier`, 3.11+). Testler:
  `tests/test_race_harness.py` (gerçek eşzamanlılık kanıtı — `max_active == N`) +
  `tests/test_oracle_race_condition.py` (savunmasız/güvenli sahte backend'ler, `httpx.MockTransport`).
- Duplicate transaction, negative quantity/value

> Ödeme bypass/fiyat manipülasyonu/kupon abuse, yetki-iş-akışı/premium/limit bypass, ve
> duplicate-transaction/negative-quantity hâlâ AÇIK — bunlar `RaceHarness`'ın aksine GENEL bir
> teknikle test edilemez, her biri hedefin KENDİ iş kuralı bilgisini (hangi alan "fiyat", hangi
> aksiyon "premium", hangi limit "aşılmamalı") gerektirir; TIER_C.md'nin kendi notuyla ("büyük
> ölçüde yarı-otomatik") tutarlı biçimde otomatikleştirilmedi.

## C5 — Çok-adımlı kimlik akışları / gadget
**Gereken yetenek:** sağlayıcıya-özel çok-adımlı akış otomasyonu ve/veya gadget/OOB zinciri.
- OAuth vulnerabilities
- MFA bypass, OTP bypass
- [x] **Password reset zincirleri — host-header injection** (token predictability HÂLÂ açık, aşağı
  bkz.) — `HostHeaderInjectionDetector` (`detector/host_header.py`). Klasik "password reset
  poisoning": `Host`/`X-Forwarded-Host` başlığına saldırgan-domain enjekte edilir; enjekte edilen
  marker response body'de veya `Location`/`Link`/`Content-Location` header'ında yansırsa CONFIRMED
  — aynı (savunmasız) kod yolu e-postaya giden linki de bu başlıktan türettiği için bu,
  gerçek e-postayı OKUMADAN (IMAP/SMTP entegrasyonu YOK) elde edilen deterministik kanıttır
  (`OpenRedirectDetector`'ın Location-yansıması deseniyle AYNI epistemoloji). C5'in "sağlayıcıya-
  özel çok-adımlı akış" gereksinimine rağmen bu TEK madde tek-istekle test edilebilir olduğu için
  **yeni bir yürütme motoru GEREKMEDİ** — mevcut `Detector`/`Replayer`'a doğrudan oturur (httpx
  özel `Host` header'ını olduğu gibi tel üzerine yazar — ampirik doğrulandı). Planner'a "reset"/
  "forgot" path anahtar kelimesiyle **otomatik** hipotez eklendi (CLI opt-in bayrağı GEREKMEDİ —
  C1/C3/C4'ün aksine bu teknik zararsız/tek-istek). Testler: `tests/test_detector_host_header.py`.
- Account Takeover (bileşik)
- Insecure Deserialization (gadget/OOB)

> C5'in geri kalanı (OAuth zafiyetleri, MFA/OTP bypass, parola-sıfırlama token tahmin edilebilirliği,
> bileşik Account Takeover, Insecure Deserialization) GERÇEKTEN "sağlayıcıya-özel çok-adımlı akış
> otomasyonu ve/veya gadget/OOB zinciri" gerektiriyor — token predictability için IMAP/SMTP OOB
> okuyucusu (bu araçta YOK, yalnızca HTTP geri-çağrı OOB'u var), OAuth/MFA için sağlayıcıya özel
> akış tanımı (hangi adım hangi selector/endpoint) şart; genel bir teknikle test edilemez.

---

## Ele alınırken dikkat (hepsi için)
- CLAUDE.md §5 değişmezleri korunur: kanıt olmadan CONFIRMED yok, redaction zorunlu, scope kapısı her istekte.
- Yıkıcı/aktif adımlar `destructive_tests` + scope kapısı arkasında; yalnızca yetkili hedeflerde.
- Her yeni motor (BrowserDriver, OOB collector, ağ-tarayıcı köprüsü) **DI ile enjekte edilir**;
  mevcut `Oracle`/`Scanner` sınıfları değiştirilmeden genişletilir (Open/Closed).
