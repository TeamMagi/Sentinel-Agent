"""Çevrimdışı kanıt yeniden-ispat aracı (R-A2 + RK-9). GOREVLER.md Dalga 1–2.

Bir koşum dizinindeki (`runs/<id>/proof/*.json`) ya da tek bir kanıt dosyasındaki CONFIRMED
bulguları AĞSIZ yeniden-ispatlar (deterministik, tahrif-duyarlı). Ağ/LLM YOK.

İki dosya türü desteklenir:
  - `<fid>.bundle.json`  → imzalı/hash'li taşınabilir paket (RK-9): önce bütünlük hash'i (+ varsa
                           imza) doğrulanır, sonra yeniden-ispat. Tahrifte FAILED.
  - `<fid>.json`         → düz kanıt fixture'ı (R-A2): doğrudan yeniden-ispat.
Bir koşum dizininde bundle'lar VARSA yalnızca onlar (daha katı) doğrulanır; yoksa düz fixture'lar.

Kullanım:
  python -m scripts.replay runs/run-20260915-...            # koşum dizinindeki tüm kanıtlar
  python -m scripts.replay runs/run-.../proof/F-001.bundle.json
  python -m scripts.replay runs/run-... --key "$SENTINEL_PROOF_KEY"   # imza doğrula
Çıkış kodu: herhangi bir kanıt yeniden-ispatlanamazsa (tahrif/eksik) 1, aksi halde 0.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.evidence.proof import is_bundle, reprove_any  # noqa: E402


def _proof_files(target: pathlib.Path) -> list[pathlib.Path]:
    if target.is_file():
        return [target]
    proof_dir = target / "proof" if (target / "proof").is_dir() else target
    bundles = sorted(proof_dir.glob("*.bundle.json"))
    if bundles:   # RK-9: bundle'lar varsa yalnızca onları (hash/imza + reprove) doğrula
        return bundles
    return sorted(proof_dir.glob("*.json"))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="replay",
                                description="Çevrimdışı kanıt yeniden-ispat (R-A2 + RK-9)")
    p.add_argument("target", help="runs/<id> dizini veya tek proof/bundle dosyası")
    p.add_argument("--key", default=os.environ.get("SENTINEL_PROOF_KEY"),
                   help="bundle imzası için paylaşılan HMAC anahtarı (env: SENTINEL_PROOF_KEY)")
    args = p.parse_args(argv)

    target = pathlib.Path(args.target)
    files = _proof_files(target)
    if not files:
        print(f"[replay] kanıt dosyası bulunamadı: {target}")
        return 2

    ok_all = True
    for pf in files:
        try:
            obj = json.loads(pf.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"[HATA] {pf.name}: okunamadı ({e})")
            ok_all = False
            continue
        proven, reason = reprove_any(obj, key=args.key)
        tag = "PROVEN" if proven else "FAILED"
        kind = "bundle" if is_bundle(obj) else "fixture"
        fid = obj.get("finding_id", pf.stem)
        print(f"[{tag}] {fid} ({obj.get('type')}, {kind}): {reason}")
        ok_all = ok_all and proven

    print(f"[replay] {len(files)} kanıt · {'hepsi yeniden-ispatlandı' if ok_all else 'BAŞARISIZ var'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
