"""Replay edilebilir kanıt paketi (R-A2) — build_proof + reprove + store yazımı. Network yok."""
import json

from pentestai.evidence.proof import build_proof, reprove
from pentestai.evidence.store import EvidenceStore
from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse

MARKER = "orderRef-XYZ-777"   # PII değil → redaction'dan sağ çıkar (tahrif testi anlamlı)


def _confirmed_idor() -> Finding:
    ev = Evidence(
        baseline_request=CapturedRequest(method="GET", url="http://t/api/orders/V-1"),
        baseline_response=NormalizedResponse(status=200, body_text=f'{{"ref":"{MARKER}"}}',
                                             body_normalized=f'{{"ref":"{MARKER}"}}'),
        attack_request=CapturedRequest(method="GET", url="http://t/api/orders/V-1"),
        attack_response=NormalizedResponse(status=200, body_text=f'{{"ref":"{MARKER}"}}',
                                           body_normalized=f'{{"ref":"{MARKER}"}}'),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=[MARKER],
    )
    return Finding(id="F-001", type="idor", endpoint="/api/orders/{id}", verdict="CONFIRMED",
                   confidence="high", victim="user_A", attacker="user_B", evidence=ev)


def test_build_proof_has_fixture_and_literal_flag():
    p = build_proof(_confirmed_idor())
    assert p["finding_id"] == "F-001" and p["literal_markers"] is True
    assert p["attack_response"]["body_text"].find(MARKER) >= 0
    assert p["controls"]["positive"] is True


def test_reprove_proven_when_marker_present():
    proven, reason = reprove(build_proof(_confirmed_idor()))
    assert proven is True and "doğrulandı" in reason


def test_reprove_failed_when_fixture_tampered():
    p = build_proof(_confirmed_idor())
    p["attack_response"]["body_text"] = '{"ref":"HARMLESS"}'   # marker silindi (tahrif)
    proven, reason = reprove(p)
    assert proven is False and "tahrif" in reason


def test_reprove_only_confirmed():
    p = build_proof(_confirmed_idor())
    p["verdict"] = "REJECTED"
    assert reprove(p)[0] is False


def test_store_writes_replayable_proof(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    rid = store.new_run_id()
    root = store.save_run(rid, [_confirmed_idor()])
    proof_file = root / "proof" / "F-001.json"
    assert proof_file.exists()
    proof = json.loads(proof_file.read_text(encoding="utf-8"))
    assert reprove(proof)[0] is True   # store'un yazdığı (redakte) fixture ağsız yeniden-ispatlanıyor


def test_store_no_proof_dir_without_confirmed(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    rid = store.new_run_id()
    f = Finding(id="F-001", type="idor", endpoint="/x", verdict="REJECTED")
    root = store.save_run(rid, [f])
    assert not (root / "proof").exists()


def _confirmed_with_markers(mtype, markers, body_text):
    """Verilen tip + marker listesi + gövde ile CONFIRMED bulgu (redaction/harf-büyüklüğü senaryoları)."""
    ev = Evidence(
        attack_request=CapturedRequest(method="GET", url="http://t/x"),
        attack_response=NormalizedResponse(status=200, body_text=body_text, body_normalized=body_text),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=markers,
    )
    return Finding(id="F-009", type=mtype, endpoint="/x", verdict="CONFIRMED",
                   confidence="high", victim="A", attacker="B", evidence=ev)


def test_reprove_proven_when_one_marker_redacted_but_another_survives():
    # Redaction gövdedeki ürün adını <REDACTED> yaptı ama fiyat sağ kaldı → hâlâ PROVEN.
    p = build_proof(_confirmed_with_markers(
        "idor", ["Apple Juice (1000ml)", "1.99"],
        '{"Products":[{"name":"<REDACTED>","price":1.99}]}'))
    proven, reason = reprove(p)
    assert proven is True and "doğrulandı" in reason


def test_reprove_signature_marker_case_insensitive():
    # İmza-tipi marker küçük harf saklanır ('sqlite'), gövdede büyük harf geçer (SQLITE_ERROR).
    p = build_proof(_confirmed_with_markers(
        "sqli", ["sqlite"], "<title>Error: SQLITE_ERROR: syntax error</title>"))
    assert reprove(p)[0] is True


def test_reprove_failed_when_all_markers_removed():
    # Redaction değil, tahrif: tüm marker'lar gövdeden silinirse FAILED (tahrif-duyarlılık).
    p = build_proof(_confirmed_with_markers(
        "idor", ["Apple Juice (1000ml)", "1.99"], '{"Products":[]}'))
    proven, reason = reprove(p)
    assert proven is False and "tahrif" in reason
