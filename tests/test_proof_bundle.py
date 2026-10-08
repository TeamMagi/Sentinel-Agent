"""İmzalı taşınabilir kanıt-paketi (RK-9) — build_bundle + verify_bundle + store + replay. Network yok.

Kabul: bundle üretiliyor; hash doğrulanınca ağsız PROVEN, tahrifte FAILED; imza (varsa) özgünlüğü
kanıtlıyor; scripts/replay.py bundle'ı doğruluyor."""
import json
import pathlib
import sys

# `scripts/` paketi pythonpath'te (src) değil; replay glue'sunu ağsız test etmek için depo kökünü ekle.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from pentestai.evidence.proof import (
    build_bundle, build_proof, is_bundle, proof_hash, reprove_any, verify_bundle,
)
from pentestai.evidence.store import EvidenceStore
from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse

MARKER = "orderRef-XYZ-777"   # PII değil → redaction'dan sağ çıkar (tahrif testi anlamlı)


def _confirmed() -> Finding:
    ev = Evidence(
        baseline_request=CapturedRequest(method="GET", url="http://t/api/orders/V-1"),
        baseline_response=NormalizedResponse(status=200, body_text=f'{{"ref":"{MARKER}"}}'),
        attack_request=CapturedRequest(method="GET", url="http://t/api/orders/V-1"),
        attack_response=NormalizedResponse(status=200, body_text=f'{{"ref":"{MARKER}"}}'),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=[MARKER],
    )
    return Finding(id="F-001", type="idor", endpoint="/api/orders/{id}", verdict="CONFIRMED",
                   confidence="high", cwe="CWE-639", owasp="API1:2023", severity="High",
                   victim="user_A", attacker="user_B", evidence=ev)


def _bundle(**kw):
    return build_bundle(build_proof(_confirmed()), **kw)


def test_bundle_has_integrity_hash_and_summary():
    b = _bundle()
    assert is_bundle(b)
    assert b["bundle_version"] == "1" and b["finding_id"] == "F-001"
    assert b["integrity"]["algorithm"] == "sha256"
    assert b["integrity"]["proof_hash"] == proof_hash(b["proof"])
    assert "signature" not in b["integrity"]   # anahtarsız → imza yok


def test_verify_proven_without_key():
    ok, reason = verify_bundle(_bundle())
    assert ok is True and "bütünlük hash'i doğrulandı" in reason


def test_verify_failed_when_proof_tampered():
    b = _bundle()
    b["proof"]["attack_response"]["body_text"] = '{"ref":"HARMLESS"}'   # kanıt kurcalandı
    ok, reason = verify_bundle(b)
    assert ok is False and "uyuşmuyor" in reason


def test_verify_failed_on_metadata_spoof():
    b = _bundle()
    b["verdict"] = "REJECTED"   # özet alan tahrifi (proof hâlâ CONFIRMED)
    ok, reason = verify_bundle(b)
    assert ok is False and "tutarsız" in reason


def test_signed_bundle_verifies_with_key_and_fails_with_wrong_key():
    b = _bundle(key="s3cret")
    assert b["integrity"]["signature_algorithm"] == "hmac-sha256"
    ok, reason = verify_bundle(b, key="s3cret")
    assert ok is True and "imza doğrulandı" in reason
    ok2, reason2 = verify_bundle(b, key="wrong")
    assert ok2 is False and "imza" in reason2


def test_signed_bundle_hash_still_enforced_without_key():
    b = _bundle(key="s3cret")
    ok, reason = verify_bundle(b)   # anahtar yok → hash zorlanır, imza doğrulanmadı notu
    assert ok is True and "doğrulanmadı" in reason


def test_reprove_any_dispatches_bundle_vs_fixture():
    assert reprove_any(_bundle())[0] is True
    assert reprove_any(build_proof(_confirmed()))[0] is True   # düz fixture


def test_store_writes_bundle_and_replay_proves_it(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    rid = store.new_run_id()
    root = store.save_run(rid, [_confirmed()])
    bundle_file = root / "proof" / "F-001.bundle.json"
    assert bundle_file.exists()
    bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    assert verify_bundle(bundle)[0] is True

    from scripts.replay import main as replay_main
    assert replay_main([str(root)]) == 0   # bundle'lar tercih edilir; hepsi PROVEN


def test_store_bundle_tamper_makes_replay_fail(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    rid = store.new_run_id()
    root = store.save_run(rid, [_confirmed()])
    bundle_file = root / "proof" / "F-001.bundle.json"
    bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    bundle["proof"]["leaked_markers"] = []   # kanıtı boşalt (tahrif)
    bundle_file.write_text(json.dumps(bundle), encoding="utf-8")

    from scripts.replay import main as replay_main
    assert replay_main([str(root)]) == 1   # tahrif → FAILED → non-zero
