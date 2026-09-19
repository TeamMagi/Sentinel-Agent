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
- DOM XSS
- Client-side authorization
- LocalStorage / SessionStorage hassas veri
- Gerçek Clickjacking exploit (tespit Tier A'da; PoC-render burada)
- Client-side Prototype Pollution

## C2 — Ağ / altyapı tarama (HTTP-differential dışı)
**Gereken yetenek:** nmap / sslscan / DNS çözümleme / CVE-DB gibi harici araç entegrasyonları;
choke-point (authorize→replay) modelinin dışında ayrı bir tarama hattı.
- Açık portlar / gereksiz servisler
- Eski servis/web server sürümleri + port-tabanlı known-CVE taraması
- TLS/SSL misconfiguration, certificate misconfiguration
- Subdomain enumeration / takeover, dangling DNS records, DNS misconfiguration

> Not: **security header / HSTS / CSP / directory listing / debug / default creds** gibi *HTTP üzerinden
> tek-istekle* görülen "server misconfig" alt kümesi Tier A/B'ye alındı; burada kalanlar gerçek ağ/altyapı taramasıdır.

## C3 — Protokol/raw-socket seviyesi
**Gereken yetenek:** ham TCP kontrolü, TE/CL desync, hassas zamanlama (httpx yetmez).
- HTTP Request Smuggling

## C4 — Ağır durum / iş mantığı
**Gereken yetenek:** uygulamaya-özel iş akışı modeli + çok-adımlı durum + eşzamanlılık (race) harness'i.
Deterministik kanıt üretmek uygulama semantiğine bağımlı; büyük ölçüde yarı-otomatik.
- Ödeme bypass, fiyat manipülasyonu, kupon/promosyon abuse
- Yetki/iş-akışı bypass, premium özellik bypass, hesap/işlem limiti bypass
- Race Condition, duplicate transaction, negative quantity/value

## C5 — Çok-adımlı kimlik akışları / gadget
**Gereken yetenek:** sağlayıcıya-özel çok-adımlı akış otomasyonu ve/veya gadget/OOB zinciri.
- OAuth vulnerabilities
- MFA bypass, OTP bypass
- Password reset zincirleri (host-header injection, token predictability)
- Account Takeover (bileşik)
- Insecure Deserialization (gadget/OOB)

---

## Ele alınırken dikkat (hepsi için)
- CLAUDE.md §5 değişmezleri korunur: kanıt olmadan CONFIRMED yok, redaction zorunlu, scope kapısı her istekte.
- Yıkıcı/aktif adımlar `destructive_tests` + scope kapısı arkasında; yalnızca yetkili hedeflerde.
- Her yeni motor (BrowserDriver, OOB collector, ağ-tarayıcı köprüsü) **DI ile enjekte edilir**;
  mevcut `Oracle`/`Scanner` sınıfları değiştirilmeden genişletilir (Open/Closed).
