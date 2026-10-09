"""Hash-zincirli kanıt defteri + integrity verify + tamper-drill (B). Ağsız, stdlib."""
from __future__ import annotations

import json

from pentestai.evidence.ledger import GENESIS, IntegrityLedger
from pentestai.evidence.proof import build_proof, proof_hash
from pentestai.evidence.store import EvidenceStore
from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse
from scripts import integrity


# --- Defter birim testleri ---

def _ledger(n: int = 3) -> IntegrityLedger:
    led = IntegrityLedger()
    for i in range(n):
        led.append(f"F-{i:03d}", proof_hash({"finding_id": f"F-{i:03d}", "x": i}))
    return led


def test_chain_links_and_verifies():
    led = _ledger(3)
    assert led.entries[0].prev_hash == GENESIS
    assert led.entries[1].prev_hash == led.entries[0].entry_hash    # zincir bağı
    v = led.verify()
    assert v.ok and v.checked == 3 and v.broken_at is None


def test_tampered_entry_hash_is_caught():
    led = _ledger(3)
    led.entries[1].proof_hash = "deadbeef" * 8                       # kaydı kurcala, entry_hash'i güncelleme
    v = led.verify()
    assert not v.ok and v.broken_at == 1


def test_deleted_middle_entry_breaks_chain():
    led = _ledger(3)
    del led.entries[1]                                              # ortadaki kaydı sil → prev bağı kırılır
    # seq'ler artık 0,2 → hem seq süreksizliği hem prev_hash uyuşmazlığı
    v = led.verify()
    assert not v.ok


def test_jsonl_roundtrip():
    led = _ledger(2)
    round = IntegrityLedger.from_jsonl(led.to_jsonl())
    assert [e.to_dict() for e in round.entries] == [e.to_dict() for e in led.entries]
    assert round.verify().ok


def test_verify_proofs_detects_file_tamper(tmp_path):
    proof_dir = tmp_path / "proof"
    proof_dir.mkdir()
    led = IntegrityLedger()
    p = {"finding_id": "F-001", "verdict": "CONFIRMED", "leaked_markers": ["secret@x"]}
    (proof_dir / "F-001.json").write_text(json.dumps(p), encoding="utf-8")
    led.append("F-001", proof_hash(p))
    assert led.verify_proofs(proof_dir).ok                          # dosya defterle uyumlu
    # kanıtı "gizle": marker'ı sil → dosya hash'i defterdekiyle uyuşmaz
    p["leaked_markers"] = []
    (proof_dir / "F-001.json").write_text(json.dumps(p), encoding="utf-8")
    v = led.verify_proofs(proof_dir)
    assert not v.ok and v.broken_at == 0


# --- EvidenceStore entegrasyonu + CLI ---

def _confirmed_finding(fid: str = "F-001") -> Finding:
    ev = Evidence(
        baseline_request=CapturedRequest(method="GET", url="http://t/api/orders/1"),
        baseline_response=NormalizedResponse(status=200, body_text='{"email":"a@t.local"}'),
        attack_request=CapturedRequest(method="GET", url="http://t/api/orders/1"),
        attack_response=NormalizedResponse(status=200, body_text='{"email":"a@t.local"}'),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=["a@t.local"],
    )
    return Finding(id=fid, type="idor", endpoint="/api/orders/{id}", verdict="CONFIRMED",
                   confidence="high", victim="user_A", attacker="user_B", evidence=ev)


def test_store_writes_ledger_and_cli_verifies(tmp_path, capsys):
    store = EvidenceStore(out_dir=str(tmp_path))
    root = store.save_run("run-x", [_confirmed_finding("F-001"), _confirmed_finding("F-002")])
    ledger_path = root / "proof" / "ledger.jsonl"
    assert ledger_path.exists()
    led = IntegrityLedger.load(ledger_path)
    assert led.verify().ok and led.verify_proofs(root / "proof").ok
    # CLI: temiz koşum → çıkış 0
    assert integrity.main([str(root)]) == 0


def test_cli_catches_tampered_proof(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    root = store.save_run("run-y", [_confirmed_finding("F-001")])
    victim = root / "proof" / "F-001.json"
    proof = json.loads(victim.read_text(encoding="utf-8"))
    proof["verdict"] = "REJECTED"                                   # kanıtı tahrif et
    victim.write_text(json.dumps(proof), encoding="utf-8")
    assert integrity.main([str(root)]) == 1                         # yakalanır


def test_tamper_drill_catches_and_leaves_original_intact(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    root = store.save_run("run-z", [_confirmed_finding("F-001")])
    before = (root / "proof" / "F-001.json").read_text(encoding="utf-8")
    assert integrity.main([str(root), "--drill"]) == 0              # drill tahrifi yakalar
    after = (root / "proof" / "F-001.json").read_text(encoding="utf-8")
    assert before == after                                         # orijinale dokunulmadı
    assert integrity.main([str(root)]) == 0                        # orijinal hâlâ doğrulanır
