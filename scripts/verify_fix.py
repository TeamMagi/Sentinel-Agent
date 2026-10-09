"""Fix-verification CLI (Y2 — Crucible dersi): düzeltme öncesi↔sonrası iki koşumu karşılaştırır.

    python -m scripts.verify_fix <önce-findings.json> <sonra-findings.json>

Her CONFIRMED açığın kapanıp kapanmadığını raporlar (fixed / failed-repair / regressed). Çıkış
kodu: kapatılmamış (failed-repair) ya da geri gelen (regressed) açık varsa 1, hepsi kapandıysa 0.
Ağsız (iki findings.json'ı okur; taramaları operatör düzeltme öncesi ve sonrası koşar)."""
from __future__ import annotations

import argparse
import contextlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.models import Finding  # noqa: E402
from pentestai.report.remediation_verify import RemediationVerifier  # noqa: E402


def _load(path: str) -> list[Finding]:
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return [Finding.model_validate(d) for d in data]


def main(argv=None) -> int:
    for s in (sys.stdout, sys.stderr):   # Windows cp1254 emoji güvenliği
        with contextlib.suppress(AttributeError, ValueError):
            s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    p = argparse.ArgumentParser(prog="verify_fix",
                                description="Remediation doğrulama (fix-verification) — Y2")
    p.add_argument("before", help="düzeltme ÖNCESİ findings.json")
    p.add_argument("after", help="düzeltme SONRASI findings.json")
    p.add_argument("--quiet", action="store_true", help="yalnızca özet satırı")
    args = p.parse_args(argv)

    result = RemediationVerifier().verify(_load(args.before), _load(args.after))
    if not args.quiet:
        print(result.to_markdown())
    print(f"[verify-fix] kapandı={len(result.fixed)} · failed-repair={len(result.failed_repair)} "
          f"· regressed={len(result.regressed)}")
    if not result.clean:
        print("🚨 kapatılmamış ya da geri gelen açık var", file=sys.stderr)
        return 1
    print("✅ önceki tüm CONFIRMED açıklar kapandı, regresyon yok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
