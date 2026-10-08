# Güvenlik Politikası

Sentinel-Agent, yetkilendirme (IDOR/BOLA + BFLA) açıklarını **kanıtlı** şekilde bulan bir
pentest aracıdır. Aracın kendisinde bir güvenlik açığı bulmanız durumunda aşağıdaki süreci
izlemenizi rica ederiz.

## Kapsam

**Kapsam içi** — Sentinel-Agent'ın KENDİSİNDEKİ açıklar:

- Scope kapısının (`PolicyEngine`) atlatılabilmesi (ör. `allowed_hosts`/`allowed_ports` dışına
  istek çıkarılması, DNS-pin/rebinding koruması atlatılması).
- İki aktör arasında session/cookie sızıntısı (cross-contamination).
- Redaction'ın (`evidence/store.redact`) token/JWT/PII'yi log, evidence veya rapora ham
  yazması.
- Web UI'da CSRF/host-rebinding/path-traversal (`RequestGuard`, run-id/secrets-path kontrolleri).
- LLM önerisinin, kod kararı olmadan (deterministik leaked-marker kanıtı olmadan) doğrudan
  ağa istek attırabilmesi veya `CONFIRMED` üretebilmesi.
- Bağımlılık/yerel yürütme açıkları (ör. `repro_curl` üretiminde komut enjeksiyonu).

**Kapsam dışı** — bunlar Sentinel-Agent'ın *amaçlanan işlevidir*, güvenlik açığı değildir:

- Sentinel-Agent'ın, kullanıcının **yetkili olduğu ve tarama için yapılandırdığı** bir hedefte
  gerçek bir IDOR/BFLA/vb. bulması (bu aracın amacı).
- Üçüncü taraf hedeflerde, sahibi olmadığınız veya açık yazılı yetki almadığınız sistemlerde
  bu aracın kullanılması — bu tamamen kullanıcının sorumluluğundadır (bkz. [README §Etik](README.md)
  ve [CLAUDE.md §10](CLAUDE.md)).

## Nasıl bildirilir

Herkese açık bir issue **AÇMAYIN** — açık bir güvenlik açığı, düzeltme yayınlanmadan önce
istismar edilebilir hâle gelir.

Bunun yerine GitHub'ın özel bildirim akışını kullanın:
**Repo → Security sekmesi → "Report a vulnerability"**
(https://github.com/Hybrid-Translation-Project/Sentinel-Agent/security/advisories/new)

Bildiriminize şunları ekleyin:

- Etkilenen dosya/fonksiyon (mümkünse `path:satır`) ve commit/sürüm.
- Yeniden üretme adımları veya minimal bir PoC (gerçek bir hedefe değil, `httpx.MockTransport`
  gibi kontrollü bir ortama karşı — bkz. [CLAUDE.md §6](CLAUDE.md)).
- Etkisi: hangi güvenlik değişmezi ihlal ediliyor (bkz. [CLAUDE.md §5](CLAUDE.md)).

## Süreç

Bu, gönüllü emekle yürütülen bir proje olduğu için kesin bir SLA veremiyoruz; ancak:

- Bildirimi aldığımızda makul sürede (hedef: birkaç iş günü içinde) ilk yanıtı vermeye
  çalışırız.
- Düzeltme yayınlanana kadar bulguyu paylaşmamanızı (sorumlu ifşa) rica ederiz.
- Düzeltme sonrası, isterseniz bildirimde bulunan kişi olarak teşekkür/atıf ekleriz (aksi
  belirtilmedikçe).

## Desteklenen sürümler

Proje henüz sürümlenmiş (tagged release) bir aşamada değil; güvenlik düzeltmeleri yalnızca
`main`/`develop` dallarının GÜNCEL haline uygulanır.
