# Sentinel-Agent — Çalıştırılabilir self-eval (planted TP + FP + near-miss)

**Vaka:** 12 · **TP/FP/FN/TN:** 6/0/0/6

- **Precision:** %100.0
- **Recall:** %100.0
- **FP-rate:** %0.0
- **Near-miss disiplini:** ✅ hepsi doğru flag'lenmedi

| Vaka | Tip | Kategori | Beklenen | Verdict | Sonuç |
|---|---|---|---|---|---|
| idor-basket:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-basket:hardened | idor | negative | not:CONFIRMED | REJECTED | ✅ |
| bfla-admin:vulnerable | bfla | positive | CONFIRMED | CONFIRMED | ✅ |
| bfla-admin:hardened | bfla | negative | not:CONFIRMED | REJECTED | ✅ |
| idor-public-by-design:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-public-by-design:near-miss | idor | near_miss | not:CONFIRMED | REJECTED | ✅ |
| idor-session-scoped:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-session-scoped:near-miss | idor | near_miss | not:CONFIRMED | INCONCLUSIVE | ✅ |
| idor-query-param:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-query-param:hardened | idor | negative | not:CONFIRMED | REJECTED | ✅ |
| idor-empty-result:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-empty-result:near-miss | idor | near_miss | not:CONFIRMED | LIKELY | ✅ |
