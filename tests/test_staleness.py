"""Proof-bundle staleness — hedef değişince kanıt bayatlar (Y1, Crucible dersi). Ağsız."""
from __future__ import annotations

from pentestai.evidence.proof import (
    build_proof, is_stale, response_fingerprint,
)
from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse


def _confirmed() -> Finding:
    ev = Evidence(
        attack_request=CapturedRequest(method="GET", url="http://t/api/orders/1"),
        attack_response=NormalizedResponse(status=200, body_text='{"email":"a@t.local"}'),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=["a@t.local"],
    )
    return Finding(id="F-1", type="idor", endpoint="/api/orders/{id}", verdict="CONFIRMED",
                   evidence=ev)


def test_proof_records_input_fingerprint():
    p = build_proof(_confirmed())
    assert p["input_fingerprint"]                                   # boş değil
    assert p["input_fingerprint"] == response_fingerprint(p["attack_response"])


def test_not_stale_when_target_unchanged():
    p = build_proof(_confirmed())
    assert is_stale(p, 200, '{"email":"a@t.local"}') is False       # aynı davranış → güncel


def test_stale_when_target_changes():
    p = build_proof(_confirmed())
    assert is_stale(p, 403, '{"error":"forbidden"}') is True        # açık kapanmış/değişmiş → bayat
    assert is_stale(p, 200, '{"email":"different@t.local"}') is True  # gövde değişti → bayat


def test_unknown_when_fingerprint_absent():
    """Eski proof (fingerprint yok) → belirlenemez (None), sessizce bayat sayılmaz."""
    assert is_stale({"finding_id": "F-1"}, 200, "x") is None


def test_fingerprint_deterministic():
    r = {"status": 200, "body_text": "same"}
    assert response_fingerprint(r) == response_fingerprint(dict(r))
    assert response_fingerprint(None) == ""
