"""margin — kanıt/robustluk marjı (AS-6). Verdict'e dokunmaz, yalnızca işaretler.

Ağsız: yalnızca Evidence/Finding üzerinde saf hesap. `classify.py` testleriyle aynı desen.
"""
from pentestai.margin import LOW_MARGIN_THRESHOLD, assign_margin, assign_margin_all, compute_margin
from pentestai.models import Evidence, Finding, NormalizedResponse


def _finding(verdict: str, *, leaked=None, baseline=None, attack=None) -> Finding:
    ev = Evidence(leaked_markers=leaked or [], baseline_response=baseline, attack_response=attack)
    return Finding(id="F-001", type="idor", endpoint="/x", verdict=verdict, evidence=ev)


def test_rejected_and_inconclusive_have_no_margin():
    for verdict in ("REJECTED", "INCONCLUSIVE"):
        f = _finding(verdict, leaked=["snt-canary-abc"])
        assert compute_margin(f) == 0.0
        assign_margin(f)
        assert f.confirmation_margin is None
        assert f.low_margin is None


def test_confirmed_single_marker_is_low_margin():
    # Yalnızca 1 sızan marker (CONFIRMED için ZORUNLU asgari) → kıl payı.
    f = _finding("CONFIRMED", leaked=["snt-canary-abc"])
    assign_margin(f)
    assert f.confirmation_margin == 0.0
    assert f.confirmation_margin <= LOW_MARGIN_THRESHOLD
    assert f.low_margin is True


def test_confirmed_multiple_markers_raises_margin():
    f = _finding("CONFIRMED", leaked=["snt-canary-abc", "snt-canary-def"])
    assign_margin(f)
    assert f.confirmation_margin == 1.0
    assert f.low_margin is False


def test_baseline_divergence_adds_margin():
    baseline = NormalizedResponse(status=404)
    attack = NormalizedResponse(status=200)
    f = _finding("CONFIRMED", leaked=["snt-canary-abc"], baseline=baseline, attack=attack)
    assign_margin(f)
    assert f.confirmation_margin == 1.0
    assert f.low_margin is False


def test_confirmed_zero_leaked_markers_is_not_low_margin_flagged_as_zero():
    # Kanıtsız CONFIRMED normalde oluşmaz (değişmez §5.2) ama marj hesabı yine de güvenli:
    # 0 marker → 0.0 marj → kıl payı sayılır (asgari bile karşılanmamış, en düşük marj).
    f = _finding("CONFIRMED", leaked=[])
    assign_margin(f)
    assert f.confirmation_margin == 0.0
    assert f.low_margin is True


def test_likely_verdict_gets_margin_too():
    f = _finding("LIKELY", leaked=["snt-canary-abc", "snt-canary-def"])
    assign_margin(f)
    assert f.confirmation_margin == 1.0
    assert f.low_margin is False


def test_assign_margin_is_idempotent():
    f = _finding("CONFIRMED", leaked=["a", "b"])
    assign_margin(f)
    before = (f.confirmation_margin, f.low_margin)
    assign_margin(f)
    assert (f.confirmation_margin, f.low_margin) == before


def test_assign_margin_all_covers_list():
    fs = [_finding("CONFIRMED", leaked=["a"]), _finding("CONFIRMED", leaked=["a", "b"])]
    assign_margin_all(fs)
    assert fs[0].low_margin is True
    assert fs[1].low_margin is False
