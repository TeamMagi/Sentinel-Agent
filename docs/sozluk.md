# Terimler Sözlüğü

> AS-9 (GOREVLER.md — ops olgunluğu). DESIGN.md §2'deki kısa sözlüğün **genişletilmiş** hâli:
> oracle/detector/marker/verdict/canary/holdout gibi kod tabanında sık geçen ama §2'de
> tanımlanmamış terimler de burada. Amaç terim birliği — aynı kelimeyi iki farklı anlamda
> kullanmamak (ör. "kontrol" hem "positive/negative control" hem "erişim denetimi" anlamına
> gelebilirdi, burada ayrıştırılmıştır).

## Temel kavramlar

| Terim | Açıklama |
|---|---|
| **Actor** | Test için kullanılan bir kimlik/oturum (`user_A`, `user_B`, `admin`) — `models.Actor` |
| **Session** | Bir `Actor`'a bağlı, izole `httpx.AsyncClient` (`net/session_store.py`) — cookie/token asla paylaşılmaz |
| **Endpoint** | Test edilecek bir HTTP yol şablonu (`method` + `path_template` + `id_param`) |
| **Hypothesis** | Bir endpoint'in belirli bir zafiyet türü için test edilmesi gerektiğine dair aday (deterministik veya LLM kaynaklı) — henüz kanıt değil |
| **Finding** | Bir `Oracle`/`Detector`'ın ürettiği, `verdict` + `Evidence` taşıyan sonuç kaydı |
| **Oracle** | İki aktörle (victim/attacker) differential test yapıp deterministik karar veren bileşen (`oracle/base.py`) — "deney, yargı değil" |
| **AgentOracle** | `Oracle`'ın ajan-hedef karşılığı — HTTP victim/attacker yerine bir `AgentTrace` (tool-call izi) üzerinde çalışır (AS-1) |
| **Detector** | Tek-istek/imza tabanlı denetim bileşeni (`detector/base.py`) — differential değil, `Oracle`'dan ayrı aile |
| **Replayer** | Tüm giden trafiğin geçtiği tek choke point — auth enjeksiyonu + policy zorlaması burada (`net/replay.py`) |
| **PolicyEngine** | Saf, LLM'siz scope/güvenlik kapısı (`policy/authorize.py`) — `authorize()` her istekte zorlanır |

## Verdict merdiveni

| Terim | Açıklama |
|---|---|
| **CONFIRMED** | Kanıt tartışmasız (leaked-marker veya canary görüldü) — **yalnızca kod** verir, LLM asla |
| **LIKELY** | Güçlü ama tartışmasız olmayan sinyal (ör. yapısal fark var ama marker yok) |
| **REJECTED** | Kontroller geçti ama zafiyet gözlenmedi — "denendi, bulunamadı" |
| **INCONCLUSIVE** | Kontroller tamamlanamadı (ör. baseline kararsız) — karar verilemez |

## Kanıt / kontrol terimleri

| Terim | Açıklama |
|---|---|
| **Leaked-marker** | Aktör A'ya ait benzersiz verinin, aktör B'nin cevabında görünmesi — kesin sızıntı kanıtı |
| **Canary** | Tarama başlamadan kurbanın objesine yazılan, saldırganın önceden bilemeyeceği rastgele işaret (`oracle/canary.py`, R-A1) — tanım gereği asla public/paylaşımlı olamaz |
| **Positive control** | "Doğru koşulda zafiyet gerçekten tetikleniyor mu" kontrolü — oracle'ın kendi testi çalışıyor mu'nun kanıtı |
| **Negative control** | "Yanlış-pozitif üretmiyor muyum" kontrolü — meşru/izinli erişimde CONFIRMED çıkmamalı |
| **Baseline stability** | Aynı isteğin tekrarında cevabın yapısal olarak sabit kalması — kararsız baseline verdict'i geçersiz kılar |
| **Structural diff** | İki cevabın DEĞER değil TİP/anahtar iskeleti (`oracle/base.py::_shape`) üzerinden karşılaştırılması |
| **Confirmation margin** | Bir CONFIRMED/LIKELY kararının ne kadar "rahat" verildiği — kaç bağımsız marker sızdı + baseline'dan ayrışma (AS-6, `margin.py`). Verdict'i değiştirmez, yalnızca kıl payı geçen kararları işaretler |
| **Düşük marj ("kıl payı")** | `confirmation_margin` asgari eşiğin üstüne çıkmamış CONFIRMED/LIKELY — ortam sürüklenmesine (sürüm/konfig değişimi) karşı kırılgan olabilir |

## Kalibrasyon / benchmark terimleri

| Terim | Açıklama |
|---|---|
| **Precision / Recall / FP-rate** | Etiketli vaka setine (`benchmarks/*.expected.yaml`) karşı ölçülen standart metrikler (`bench/`) |
| **Holdout hedef** | Kalibrasyonda hiç "dokunulmamış", yalnızca değerlendirme için kullanılan hedef — genelleme (overfit-dışı) ölçer (AS-5) |
| **Negative-twin** | Aynı uygulamanın "hardened" (düzeltilmiş) ikizi — 0-FP regresyon kapısının (RK-10, `bench/twins.py`) test verisi |
| **Dedup / agreement** | Aynı kök-nedenin (CWE+endpoint+param) birden çok kaynaktan (farklı aktör/oracle) doğrulanması (R-D2, `report/dedup.py`) |

## Agent-security terimleri (AS-1..AS-4)

| Terim | Açıklama |
|---|---|
| **AgentTrace** | Bir ajan/MCP hedefine gönderilen görevin normalize edilmiş tool-call izi (`models.AgentTrace`) |
| **ToolCall** | Tek bir ajan aksiyonu — isim, argümanlar, çıktı, `source` (kim tetikledi), varsa `target_url` |
| **Untrusted content** | Saldırgan-kontrollü dış içerik (web.search/email.read çıktısı) — kullanıcı DEĞİL |
| **UNTRUSTED_TO_ACTION** | Güvenilmez içeriğe gömülü bir yönergenin ayrıcalıklı bir tool-call'u tetiklemesi (AS-3) |
| **Kaynak-izleme (taint)** | Hangi güvenilmez çıktının hangi aksiyonu beslediğinin kanıt olarak kaydedilmesi |

---

Kısa temel sözlük için: [DESIGN.md §2](../DESIGN.md#2-sözlük). Agent-security bağlamı için:
[rakip-analizi-agent-security-2026-09.md](rakip-analizi-agent-security-2026-09.md).
