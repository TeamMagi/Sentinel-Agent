"""Kanıt defteri bütünlük doğrulayıcı + tamper-drill (B — TRACE X/NoScam dersi).

Bir koşumun hash-zincirli kanıt defterini (`runs/<id>/proof/ledger.jsonl`) çevrimdışı doğrular:
zinciri yeniden yürür (her kaydın hash'i + prev bağı) VE her proof dosyasını yeniden hash'leyip
deftere karşı karşılaştırır. Tahrif (kayıt/sıra değişimi ya da proof dosyası kurcalama) yakalanır.

Kullanım:
  python -m scripts.integrity runs/run-...            # zinciri + proof'ları doğrula
  python -m scripts.integrity runs/run-... --drill    # canlı tamper-drill (kopya üstünde)

`--drill`: gerçek koşumu bir geçici kopyaya alır, bir proof dosyasını KURCALAR (leaked-marker'ı
siler — kanıtı "gizlemeye" çalışır) ve doğrulamanın bunu YAKALADIĞINI gösterir — TRACE X'in
"₺480.000'i ₺1'e bozup entegrite kontrolünün yakalamasını izlet" demosunun karşılığı. Orijinal
koşuma dokunmaz. Ağ/LLM yok. Çıkış kodu: tahrif/eksik → 1, temiz → 0."""
from __future__ import annotations

import argparse
import contextlib
import json
import pathlib
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.evidence.ledger import IntegrityLedger  # noqa: E402


def _reconfigure_stdio() -> None:
    # Windows konsolu (cp1254) emoji basınca çökmesin (Linux/CI'da no-op).
    for s in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]


def _proof_dir(run: pathlib.Path) -> pathlib.Path:
    return run / "proof" if (run / "proof").is_dir() else run


def _load_ledger(run: pathlib.Path) -> tuple[IntegrityLedger | None, pathlib.Path]:
    proof_dir = _proof_dir(run)
    ledger_path = proof_dir / "ledger.jsonl"
    if not ledger_path.exists():
        return None, proof_dir
    return IntegrityLedger.load(ledger_path), proof_dir


def _verify(run: pathlib.Path, *, quiet: bool = False) -> int:
    ledger, proof_dir = _load_ledger(run)
    if ledger is None:
        print(f"[integrity] defter bulunamadı: {proof_dir / 'ledger.jsonl'} "
              f"(CONFIRMED bulgu yoksa defter yazılmaz)")
        return 2

    chain = ledger.verify()
    proofs = ledger.verify_proofs(proof_dir)
    chain_status = "✅ tutarlı" if chain.ok else f"🚨 KIRIK (seq {chain.broken_at})"
    proof_status = "✅ hash defterle eşleşiyor" if proofs.ok else "🚨 TAHRİF"
    if not quiet:
        print(f"[integrity] {run}")
        print(f"  zincir : {chain.checked} kayıt · {chain_status}")
        print(f"  proof  : {proofs.checked} dosya · {proof_status}")
        for e in chain.errors + proofs.errors:
            print(f"     - {e}")
    ok = chain.ok and proofs.ok
    overall = "✅ DOĞRULANDI — kanıt zinciri tahrif edilmemiş" if ok else "🚨 BÜTÜNLÜK İHLALİ"
    print(f"[integrity] {overall} ({run.name})")
    return 0 if ok else 1


def _drill(run: pathlib.Path) -> int:
    """Tamper-drill: kopya üstünde bir proof'u kurcala, yakalandığını göster (orijinale dokunma)."""
    ledger, proof_dir = _load_ledger(run)
    if ledger is None or not ledger.entries:
        print(f"[drill] defter/kayıt yok: {proof_dir / 'ledger.jsonl'}")
        return 2

    print(f"[drill] TRACE-X tarzı tamper-drill — orijinal koşuma DOKUNULMAZ ({run.name})\n")
    print("  1) Orijinali doğrula (tahrif öncesi):")
    before = _verify(run, quiet=True)
    if before != 0:
        print("  [drill] orijinal zaten doğrulanamıyor — drill iptal.")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        tmp_run = pathlib.Path(tmp) / run.name
        shutil.copytree(run, tmp_run)
        tmp_proof = _proof_dir(tmp_run)
        target_fid = ledger.entries[0].finding_id
        victim = tmp_proof / f"{target_fid}.json"
        proof = json.loads(victim.read_text(encoding="utf-8"))

        # KURCALA: kanıtı "gizle" — leaked-marker'ları sil, attack yanıt gövdesini boşalt.
        proof["leaked_markers"] = []
        if isinstance(proof.get("attack_response"), dict):
            proof["attack_response"]["body_text"] = '{"status":"ok"}'
        victim.write_text(json.dumps(proof, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n  2) Saldırgan {target_fid}.json'daki kanıtı sildi (marker'lar + attack gövdesi).")

        print("  3) Bütünlük kontrolünü tahrif edilmiş kopyada tekrar çalıştır:")
        after = _verify(tmp_run, quiet=True)

    if after != 0:
        print("\n[drill] ✅ BEKLENDİĞİ GİBİ: tahrif YAKALANDI — proof dosyası hash'i defterle "
              "uyuşmadı. Hash-zinciri kanıtın sessizce değiştirilmesini imkânsız kılar.")
        return 0
    print("\n[drill] 🚨 BEKLENMEDİK: tahrif yakalanmadı — bu bir hatadır.")
    return 1


def main(argv=None) -> int:
    _reconfigure_stdio()
    p = argparse.ArgumentParser(prog="integrity",
                                description="Kanıt defteri bütünlük doğrulayıcı + tamper-drill (B)")
    p.add_argument("run", help="runs/<id> koşum dizini")
    p.add_argument("--drill", action="store_true",
                   help="canlı tamper-drill: kopya üstünde kanıtı kurcala, yakalandığını göster")
    args = p.parse_args(argv)

    run = pathlib.Path(args.run)
    if not run.exists():
        print(f"[integrity] koşum dizini yok: {run}")
        return 2
    return _drill(run) if args.drill else _verify(run)


if __name__ == "__main__":
    raise SystemExit(main())
