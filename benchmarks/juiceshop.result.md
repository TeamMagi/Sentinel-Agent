<!-- T4 — GERÇEK koşum sonucu. Elle YAZILMAZ; aşağıdaki komutla yeniden üretilir.
     Bu dosya, README'deki rakamın tek kaynağıdır (runs/ git-ignore'lu olduğu için
     koşum artefaktı repoda tutulamaz; sonuç burada sabitlenir). -->

# Juice Shop — gerçek koşum sonucu (T4)

| | |
|---|---|
| **Tarih** | 2026-09-18 |
| **Hedef** | OWASP Juice Shop @ `http://localhost:3000` |
| **Kod sürümü** | `8caeec0` + T3 (LLM'siz çıkarım) |
| **LLM** | `--llm none` — **hiç LLM kullanılmadı** |
| **Vaka seti** | [`juiceshop.expected.yaml`](juiceshop.expected.yaml) — 7 etiketli vaka (4 pozitif / 3 negatif) |

## Yeniden üretme

```bash
python -m scripts.bootstrap_demo --base-url http://localhost:3000 --out /tmp/js   # hesap + config
# /tmp/js/endpoints.yaml'ı 7 vakayı kapsayacak şekilde genişlet (basket/{id}, products/search?q,
# api/products, rest/user/login) ve scope budget'ını ~2000 isteğe çıkar
python -m scripts.run_scan --scope /tmp/js/scope.yaml --actors /tmp/js/actors.yaml \
    --endpoints /tmp/js/endpoints.yaml --mode active --llm none --out runs/juiceshop/
python -m scripts.benchmark --run runs/juiceshop/run-* \
    --expected benchmarks/juiceshop.expected.yaml --target "OWASP Juice Shop"
```

---


**Hedef:** `OWASP Juice Shop`

| Metrik | Değer |
|---|---|
| Precision | **100.0%** |
| Recall | **100.0%** |
| False-positive oranı | **0.0%** |
| F1 | 100.0% |
| TP / FN / FP / TN | 4 / 0 / 0 / 3 |

## Vakalar

| Vaka | Beklenen | Gerçek | Sonuç |
|---|---|---|---|
| `idor @ GET /rest/basket/{id}` | CONFIRMED | CONFIRMED | ✅ TP |
| `sqli @ GET /rest/products/search` | CONFIRMED | CONFIRMED | ✅ TP |
| `jwt @ GET /rest/basket/{id}` | CONFIRMED | CONFIRMED | ✅ TP |
| `info_leak @ GET /rest/products/search` | CONFIRMED | CONFIRMED | ✅ TP |
| `unauthorized_access @ GET /rest/products/search` | not_vulnerable | LIKELY | ✅ TN |
| `unauthorized_access @ GET /api/products` | not_vulnerable | LIKELY | ✅ TN |
| `idor @ GET /rest/user/login` | not_vulnerable | absent | ✅ TN |

## Etiketsiz CONFIRMED bulgular (metriklere katılmaz)

- `info_leak @ GET /rest/basket/{id}`
- `rate_limit @ GET /rest/basket/{id}`

---

## Bu sayı ne demek, ne demek DEĞİL

- **Precision/recall etiketli 7 vaka ÜZERİNDEDİR** — aracın tüm çıktısı üzerinde değil. Koşum
  toplam 49 bulgu üretti; bunların 6'sı CONFIRMED, 2'si etiket setinde yok (yukarıda listeli)
  ve metriklere **katılmaz**.
- **FP-rate %0**, 3 negatif vakanın ("FP kapanı") hiçbirinde yanlış CONFIRMED çıkmadığı anlamına
  gelir; "araç hiç yanlış pozitif üretmez" anlamına **gelmez**.
- Juice Shop **kalibre** bir hedeftir (etiketler ona bakılarak konmuştur) → bu metrikler
  iyimserdir ve **genellemeyi ölçmez**. Genelleme yalnızca holdout hedefte ölçülür (bkz.
  [`suite.yaml`](suite.yaml) ve README'deki holdout notu).
