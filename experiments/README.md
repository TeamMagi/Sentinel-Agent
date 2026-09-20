# experiments/ — benchmark koşu düzeni

> AS-9 (GOREVLER.md — ops olgunluğu). Kaynak: tomokazu-rikioka'nın `experiments/expNNN/` +
> "tek doğruluk kaynağı" disiplini (docs/rakip-analizi-agent-security-2026-09.md §4).

**İlke: değerlendirilen konfig = koşulan konfig.** `scripts/benchmark.py --run <dizin>` bir
koşumun `findings.json`'ını okur; o koşumu ÜRETEN scope/actors/endpoints config'i ayrı bir
yerde tutulup elle senkronize edilirse (kopyala-yapıştır) zamanla sapar — "test ettiğin şey
gönderdiğin şeyle aynı değil" hatasına düşülür.

## Düzen

Her deney kendi dizininde, konfig + çıktı BİR ARADA:

```
experiments/
  <ad>/                      # ör. juiceshop-baseline, crapi-holdout-2026-09
    scope.yaml               # config/scope.example.yaml'dan kopyalanır (gerçek scope — git-ignore'lu
                              #  olabilir; sır içermiyorsa commit edilebilir)
    actors.yaml
    endpoints.yaml
    README.md                # ne test ediliyor, neden, beklenen sonuç (1-2 paragraf)
    runs/                    # scripts/run_scan.py --out buraya yazar (git-ignore'lu)
```

Koşum: `run_scan.py --scope experiments/<ad>/scope.yaml --actors experiments/<ad>/actors.yaml
--endpoints experiments/<ad>/endpoints.yaml --out experiments/<ad>/runs/`. Değerlendirme aynı
dizini okur: `python -m scripts.benchmark --run experiments/<ad>/runs/<run-id>`.

## `runs/` ile ilişki

Mevcut `runs/` (repo kökü) tek-seferlik/ad-hoc koşumlar için kalır — `experiments/` bunun
YERİNE geçmez; **tekrarlanabilir, adlandırılmış kalibrasyon koşumları** (kıyaslama, regresyon
karşılaştırması, holdout değerlendirmesi — AS-5) için ek bir kongridir. Sırf bir kez
`sentinel scan` çalıştırmak için `experiments/` dizini açmaya gerek yok.

`.gitignore`, her deneyin kendi `runs/` alt dizinini (findings/evidence — potansiyel PII/sır
içerebilir) dışlar; `scope.yaml`/`actors.yaml`/`endpoints.yaml`/`README.md` (yapılandırma,
sır İÇERMEMESİ gerekir — CLAUDE.md §8) commit edilebilir.
