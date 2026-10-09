"""Fix-verification / remediation doğrulama (Y2). Ağsız, saf diff."""
from __future__ import annotations

from pentestai.models import Finding
from pentestai.report.remediation_verify import RemediationVerifier


def _f(vtype: str, endpoint: str, verdict: str, method: str = "GET", param: str = "id") -> Finding:
    return Finding(id="F", type=vtype, endpoint=endpoint, method=method, parameter=param,
                   verdict=verdict)


def test_fixed_when_previously_confirmed_now_rejected():
    prev = [_f("idor", "/api/orders/{id}", "CONFIRMED")]
    cur = [_f("idor", "/api/orders/{id}", "REJECTED")]
    r = RemediationVerifier().verify(prev, cur)
    assert len(r.fixed) == 1 and not r.failed_repair and r.clean


def test_fixed_when_finding_absent_after():
    prev = [_f("idor", "/api/orders/{id}", "CONFIRMED")]
    r = RemediationVerifier().verify(prev, [])          # açık artık yok → kapandı
    assert len(r.fixed) == 1 and r.fixed[0].current_verdict is None and r.clean


def test_failed_repair_when_still_confirmed():
    prev = [_f("idor", "/api/orders/{id}", "CONFIRMED")]
    cur = [_f("idor", "/api/orders/{id}", "CONFIRMED")]
    r = RemediationVerifier().verify(prev, cur)
    assert len(r.failed_repair) == 1 and not r.clean   # düzeltme açığı kapatmadı


def test_regressed_when_new_confirmed_appears():
    prev = [_f("idor", "/api/orders/{id}", "REJECTED")]
    cur = [_f("bfla", "/api/admin/users", "CONFIRMED", param="")]
    r = RemediationVerifier().verify(prev, cur)
    assert len(r.regressed) == 1 and not r.clean


def test_markdown_renders_statuses():
    prev = [_f("idor", "/api/orders/{id}", "CONFIRMED")]
    cur = [_f("idor", "/api/orders/{id}", "CONFIRMED")]
    md = RemediationVerifier().verify(prev, cur).to_markdown()
    assert "failed-repair" in md and "fix-verification" in md.lower()


def test_verdict_ladder_not_loosened():
    """Y2 yalnızca DİFF yapar; verdict'leri değiştirmez (bulguların verdict'i olduğu gibi kalır)."""
    prev = [_f("idor", "/x/{id}", "CONFIRMED")]
    cur = [_f("idor", "/x/{id}", "INCONCLUSIVE")]       # INCONCLUSIVE de "CONFIRMED değil" → fixed
    r = RemediationVerifier().verify(prev, cur)
    assert len(r.fixed) == 1 and r.fixed[0].current_verdict == "INCONCLUSIVE"
