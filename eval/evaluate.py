#!/usr/bin/env python3
"""Çalıştırılabilir self-eval kapısı (M+A+C+J+R) — ağsız, tek komut.

    python eval/evaluate.py            # koş, tabloyu yazdır, eval/results.{json,md} üret
    python eval/evaluate.py --quiet    # yalnızca özet + çıkış kodu (CI)

Kanıt artefaktı: "yalancı çıktı üretmiyoruz". GERÇEK oracle'ları planted TP + FP + near-miss
fixture'larına karşı `httpx.MockTransport` ile koşar (ağ yok, LLM yok), precision/recall/FP-rate
yayımlar. **Çıkış kodu:** FP>0 ya da bir near-miss CONFIRMED ise (ya da katalog↔labeled.json
sürüklenmesi varsa) ≠ 0 — CI kapısı. Recall < 1 dürüst bir sınırdır, kapıyı KIRMAZ.

Depoya bağımlı çalışır: `src/` PYTHONPATH'te olmalı (pip install -e . ya da PYTHONPATH=src).
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from pathlib import Path

# pip install -e . yapılmadıysa src/'i yola ekle (tek-komut kolaylığı).
_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pentestai.bench.eval import (  # noqa: E402
    check_consistency,
    default_cases,
    load_labeled,
    run_cases,
)

_OUT_DIR = Path(__file__).resolve().parent


async def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Sentinel-Agent self-eval (ağsız).")
    ap.add_argument("--quiet", action="store_true", help="yalnızca özet satırı yazdır")
    ap.add_argument("--no-write", action="store_true", help="results.{json,md} yazma")
    args = ap.parse_args(argv)

    cases = default_cases()

    # 1) Katalog ↔ labeled.json bütünlüğü (drift = sessiz iddia geçersizleşmesi).
    drift = check_consistency(cases, load_labeled())
    if drift:
        print("🚨 labeled.json ↔ katalog uyuşmazlığı:", file=sys.stderr)
        for e in drift:
            print(f"   - {e}", file=sys.stderr)
        return 2

    # 2) Koş (ağsız, deterministik).
    metrics = await run_cases(cases)

    if not args.quiet:
        print(metrics.to_markdown())

    if not args.no_write:
        (_OUT_DIR / "results.json").write_text(
            json.dumps(metrics.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        (_OUT_DIR / "results.md").write_text(metrics.to_markdown(), encoding="utf-8")

    summary = (f"eval: {len(metrics.outcomes)} vaka · precision=%{round(metrics.precision*100,1)} "
               f"· recall=%{round(metrics.recall*100,1)} · FP-rate=%{round(metrics.fp_rate*100,1)} "
               f"· near-miss-confirmed={len(metrics.near_miss_confirmed)}")
    print(summary)

    # 3) Kapı: sıfır false-positive (near-miss dahil). Recall dürüst sınır, kapıyı kırmaz.
    if not metrics.clean:
        print(f"🚨 FP kapısı KIRILDI: {metrics.fp} yanlış CONFIRMED "
              f"(near-miss: {metrics.near_miss_confirmed})", file=sys.stderr)
        return 1
    print("✅ FP-rate %0 — near-miss dahil hiçbir masum vaka flag'lenmedi.")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows konsolu (cp1254) emoji basınca çökmesin — çıktıyı UTF-8'e sabitle (Linux/CI'da no-op).
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    return asyncio.run(_main(argv))


if __name__ == "__main__":
    raise SystemExit(main())
