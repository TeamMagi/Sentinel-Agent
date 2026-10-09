"""Tek-sayfa yönetici özeti raporu (#8). Ağsız."""
from __future__ import annotations

from pentestai.classify import assign
from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse
from pentestai.report.render_exec import ExecSummaryReporter


def _confirmed_idor() -> Finding:
    ev = Evidence(
        baseline_request=CapturedRequest(method="GET", url="http://t/api/orders/A-100"),
        baseline_response=NormalizedResponse(status=200, body_text='{"email":"alice@t.local"}'),
        attack_request=CapturedRequest(method="GET", url="http://t/api/orders/A-100"),
        attack_response=NormalizedResponse(status=200, body_text='{"email":"alice@t.local"}'),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=["alice@t.local"],
    )
    return assign(Finding(id="F-1", type="idor", endpoint="/api/orders/{id}", method="GET",
                          verdict="CONFIRMED", confidence="high", victim="user_A", attacker="user_B",
                          evidence=ev))


def test_exec_summary_has_core_sections():
    out = ExecSummaryReporter().render([_confirmed_idor()], target="http://t", run_id="run-x")
    assert "<!doctype html>" in out.lower()
    assert "Yönetici Özeti" in out
    assert "Duruş" in out                        # posture line
    assert "IDOR" in out and "CONFIRMED" in out
    assert "Counterfactual" in out               # CONFIRMED'de counterfactual özeti
    assert "Nasıl çözülür" in out
    assert "CWE-639" in out                       # taksonomi görünüyor


def test_exec_summary_omits_pii():
    """Özet yanıt gövdesini hiç basmaz → owner-private değer (e-posta) çıktıda yok."""
    out = ExecSummaryReporter().render([_confirmed_idor()])
    assert "alice@t.local" not in out            # owner-private değer sızmıyor
    assert "user_A" in out and "user_B" in out   # counterfactual aktör adlarıyla özetlenir


def test_rejected_excluded_from_cards_but_counted():
    rej = Finding(id="F-2", type="idor", endpoint="/x", verdict="REJECTED")
    out = ExecSummaryReporter().render([_confirmed_idor(), rej])
    assert "REJECTED: 1" in out                   # sayaçta var
    assert out.count('class="card"') == 1         # ama kartlarda yalnızca CONFIRMED


def test_empty_findings_is_clean_posture():
    out = ExecSummaryReporter().render([])
    assert "100/100" in out
    assert "bulgu yok" in out


def test_posture_line_has_no_markdown_bold():
    out = ExecSummaryReporter().render([_confirmed_idor()])
    assert "**" not in out                        # markdown kaba biçim HTML'e sızmadı
