"""Çevrimdışı kanıt yeniden-ispat aracı (R-A2). GOREVLER.md Dalga 2.

Bir koşum dizinindeki (`runs/<id>/proof/*.json`) ya da tek bir kanıt dosyasındaki CONFIRMED
bulguları AĞSIZ yeniden-ispatlar (deterministik, tahrif-duyarlı). Ağ/LLM YOK.

Kullanım:
  python -m scripts.replay runs/run-20260915-...       # koşum dizinindeki tüm kanıtlar
  python -m scripts.replay runs/run-.../proof/F-001.json
Çıkış kodu: herhangi bir kanıt yeniden-ispatlanamazsa (tahrif/eksik) 1, aksi halde 0.
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.evidence.proof import reprove  # noqa: E402


def _proof_files(target: pathlib.Path) -> list[pathlib.Path]:
    if target.is_file():
        return [target]
    proof_dir = target / "proof" if (target / "proof").is_dir() else target
    return sorted(proof_dir.glob("*.json"))


def main(argv=None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("kullanım: python -m scripts.replay <runs/<id> | proof.json>")
        return 2
    target = pathlib.Path(args[0])
    files = _proof_files(target)
    if not files:
        print(f"[replay] kanıt dosyası bulunamadı: {target}")
        return 2

    ok_all = True
    for pf in files:
        try:
            proof = json.loads(pf.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"[HATA] {pf.name}: okunamadı ({e})")
            ok_all = False
            continue
        proven, reason = reprove(proof)
        tag = "PROVEN" if proven else "FAILED"
        fid = proof.get("finding_id", pf.stem)
        print(f"[{tag}] {fid} ({proof.get('type')}): {reason}")
        ok_all = ok_all and proven

    print(f"[replay] {len(files)} kanıt · {'hepsi yeniden-ispatlandı' if ok_all else 'BAŞARISIZ var'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
