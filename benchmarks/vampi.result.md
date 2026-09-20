<!-- GERÇEK koşum sonucu. Elle YAZILMAZ; aşağıdaki komutlarla yeniden üretilir.
     Bu dosya, README'deki VAmPI rakamının tek kaynağıdır (runs/ git-ignore'lu olduğu için
     koşum artefaktı repoda tutulamaz; sonuç burada sabitlenir). -->

# VAmPI — gerçek koşum sonucu

| | |
|---|---|
| **Tarih** | 2026-09-20 |
| **Hedef** | erev0s/VAmPI ("vulnerable" mod) @ `http://localhost:5000` |
| **Kod sürümü** | `b13e33c` (anon public-by-design kapısı + recon scope dayanıklılığı dahil) |
| **LLM** | `--llm ollama --llm-model qwen3.8:27b` — **yerel model**, hedef verisi buluta çıkmaz |
| **Vaka seti** | [`vampi.expected.yaml`](vampi.expected.yaml) — 12 etiketli vaka (4 pozitif / 8 negatif) |

## Yeniden üretme

VAmPI'nin kitap başlıkları her `/createdb`'de rastgele üretildiği için config, seed'den SONRA
mevcut başlıklar okunarak kurulur (aksi halde IDOR pozitif kontrolü "Book not found" alır).

```bash
# 1) hedefi seed'le (name1/pass1, name2/pass2, admin; her kullanıcıya bir kitap+secret)
curl -s http://localhost:5000/createdb

# 2) scope/actors/endpoints üret — actors.own_object_ids anahtarları HESAPLANAN resource_key
#    ile eşleşmeli: /books/v1/{book_title} -> "books", /users/v1/{username} -> "users".
#    own_object_ids.books = o kullanıcının GÜNCEL kitap başlığı (GET /books/v1'den okunur).
#    token_location: json:auth_token · allowed_methods: GET,HEAD,POST,PUT (DELETE YOK —
#    yıkıcı BFLA testi test kullanıcılarını silebilir) · denied: */createdb*
#    endpoints: /users/v1/_debug, /books/v1/{book_title}, /users/v1/register,
#               /users/v1/{username}, /users/v1, /users/v1/{username}/email (PUT), /books/v1 (POST)

# 3) tara (seed'i TEKRAR çalıştırma — kitap başlıkları değişir)
python -m scripts.run_scan --scope vampi/scope.yaml --actors vampi/actors.yaml \
    --endpoints vampi/endpoints.yaml --mode active --llm ollama --llm-model qwen3.8:27b \
    --out runs/vampi/

# 4) ölç
python -m scripts.benchmark --run runs/vampi/run-* \
    --expected benchmarks/vampi.expected.yaml --target "VAmPI (Ollama qwen3.8:27b)"
```

---

**Hedef:** `VAmPI (Ollama qwen3.8:27b)`

| Metrik | Değer |
|---|---|
| Precision | **100.0%** |
| Recall | **50.0%** |
| False-positive oranı | **0.0%** |
| F1 | 66.7% |
| TP / FN / FP / TN | 2 / 2 / 0 / 8 |

## Vakalar

| Vaka | Beklenen | Gerçek | Sonuç |
|---|---|---|---|
| `excessive_data_exposure @ GET /users/v1/_debug` | CONFIRMED | absent | ❌ FN |
| `idor @ GET /books/v1/{book_title}` | CONFIRMED | CONFIRMED | ✅ TP |
| `mass_assignment @ POST /users/v1/register` | CONFIRMED | absent | ❌ FN |
| `sqli @ GET /users/v1/{username}` | CONFIRMED | CONFIRMED | ✅ TP |
| `idor @ GET /users/v1/{username}` | not_vulnerable | REJECTED | ✅ TN |
| `state_change_authz @ PUT /users/v1/{username}/email` | not_vulnerable | absent | ✅ TN |
| `bfla @ DELETE /users/v1/{username}` | not_vulnerable | absent | ✅ TN |
| `jwt @ PUT /users/v1/{username}/email` | not_vulnerable | absent | ✅ TN |
| `unauthorized_access @ GET /users/v1` | not_vulnerable | LIKELY | ✅ TN |
| `idor @ POST /users/v1/login` | not_vulnerable | absent | ✅ TN |
| `unauthorized_access @ GET /` | not_vulnerable | absent | ✅ TN |
| `mass_assignment @ POST /books/v1` | not_vulnerable | absent | ✅ TN |

## Etiketsiz CONFIRMED bulgular (metriklere katılmaz)

- `excessive_data_exposure @ GET /books/v1/{book_title}`
- `info_leak @ GET /users/v1/{username}`
- `jwt @ GET /users/v1/_debug`
- `rate_limit @ GET /users/v1/_debug`
- `unauthorized_access @ GET /users/v1/{username}`

---

## Bu sayı ne demek, ne demek DEĞİL

- **Precision/recall etiketli 12 vaka ÜZERİNDEDİR** — aracın tüm çıktısı üzerinde değil. Koşum
  toplam 70 bulgu üretti; 17'si CONFIRMED, bunların 5'i etiket setinde yok (yukarıda listeli) ve
  metriklere **katılmaz**.
- **FP-rate %0:** 8 negatif vakanın ("FP kapanı") hiçbirinde yanlış CONFIRMED çıkmadı. Özellikle
  `idor @ /users/v1/{username}` (e-postayı anonim de dönen public-by-design endpoint) doğru şekilde
  **REJECTED** oldu — bu, benchmark sırasında bulunup düzeltilen bir hataydı (IdorOracle'a
  **anonim erişim kapısı** eklendi: "sızan" veri auth'suz da erişilebiliyorsa yetki sınırı yoktur).
- **Recall %50:** 2 gerçek zafiyet kanıtlandı (cross-user BOLA `books/{book_title}`; error-based
  SQLi `users/{username}`). Kaçan 2 vaka (`_debug` aşırı-veri ifşası, `register` mass-assignment)
  **id'siz endpoint**lerdir; deterministik planlayıcı bu tür endpoint'lere IDOR/edx/mass-assignment
  hipotezi üretmez (bkz. planner.py — hipotezler `has_id` endpoint'lere bağlı) ve LLM de explicit-
  endpoint modunda bu boşluğu kapatmadı. Bu bir **kapsama** sınırı, doğruluk sınırı değil.
- VAmPI **kalibre** bir hedeftir (etiketler 2026-09-16'da canlı HTTP ile doğrulandı, bkz.
  `vampi.expected.yaml` başlığı) → metrikler iyimserdir ve **genellemeyi ölçmez**. Genelleme
  yalnızca holdout hedefte ölçülür (bkz. [`suite.yaml`](suite.yaml)).
