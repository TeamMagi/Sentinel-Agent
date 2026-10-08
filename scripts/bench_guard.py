"""0-FP negatif-ikiz regresyon kapısı (RK-10). GOREVLER.md Dalga 3.

GERÇEK oracle'ları vulnerable ↔ hardened ikizlere karşı AĞSIZ koşar; hardened ikizde tek bir
yanlış CONFIRMED çıkarsa çıkış kodu 1 (CI kırmızıya döner). Kullanıcı kendi pipeline'ında
"FP hâlâ 0 mı?" diye koşar. Ağ/LLM yok.

Kullanım:
  python -m scripts.bench_guard                 # tüm varsayılan ikizler
  python -m scripts.bench_guard --out runs/     # ayrıca bench_guard.md yaz
  make bench-guard
Çıkış kodu: hardened'da yanlış CONFIRMED varsa 1; --strict-recall ile vulnerable kaçırılırsa da 1.
"""
from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.bench.twins import NegativeTwinGuard  # noqa: E402


async def _run(args) -> int:
    result = await NegativeTwinGuard().run()

    for o in result.outcomes:
        fp = "0-FP OK" if o.fp_ok else "🚨 YANLIŞ CONFIRMED"
        rc = "recall OK" if o.recall_ok else "❌ KAÇIRILDI"
        print(f"[{o.name}] {o.vuln_type}: vulnerable={o.vulnerable_verdict} "
              f"hardened={o.hardened_verdict} · {fp} · {rc}")

    if args.out:
        out_dir = pathlib.Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "bench_guard.md").write_text(result.to_markdown(), encoding="utf-8")
        print(f"[guard] yazıldı: {out_dir / 'bench_guard.md'}")

    print(f"[guard] {len(result.outcomes)} ikiz · yanlış CONFIRMED: {result.fp_count} · "
          f"kaçırılan: {len(result.missed)}")

    if not result.zero_fp:
        print(f"[guard] 0-FP KAPISI KIRILDI: {', '.join(result.false_confirmed)}")
        return 1
    if args.strict_recall and result.missed:
        print(f"[guard] recall regresyonu: {', '.join(result.missed)}")
        return 1
    print("[guard] 0-FP korundu ✅")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="bench_guard",
                                description="0-FP negatif-ikiz regresyon kapısı (RK-10)")
    p.add_argument("--out", help="bench_guard.md çıktısı için dizin")
    p.add_argument("--strict-recall", action="store_true",
                   help="vulnerable ikizi kaçırmak da kapıyı kırar (yalnız FP değil)")
    args = p.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
