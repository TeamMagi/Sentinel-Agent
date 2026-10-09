"""Counterfactual dual-track kanıt sunumu (P) — saf presentation, ağsız."""
from __future__ import annotations

from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse
from pentestai.report.counterfactual import build_view, markdown_block
from pentestai.report.render_md import MarkdownReporter


def _confirmed_idor() -> Finding:
    ev = Evidence(
        baseline_request=CapturedRequest(method="GET", url="http://t/api/orders/A-100"),
        baseline_response=NormalizedResponse(status=200, body_text='{"email":"alice@t.local"}'),
        attack_request=CapturedRequest(method="GET", url="http://t/api/orders/A-100"),
        attack_response=NormalizedResponse(status=200, body_text='{"email":"alice@t.local"}'),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=["alice@t.local"],
    )
    return Finding(id="F-1", type="idor", endpoint="/api/orders/{id}", method="GET",
                   verdict="CONFIRMED", confidence="high", victim="user_A", attacker="user_B",
                   evidence=ev)


def test_build_view_confirmed_has_both_tracks():
    view = build_view(_confirmed_idor())
    assert view is not None
    assert view.is_proof is True
    assert view.authorized.actor == "user_A"
    assert view.unprotected.actor == "user_B"
    assert view.authorized.status == 200 and view.unprotected.status == 200
    assert len(view.steps) == 3                      # sahip okur → saldırgan erişir → deterministik fark


def test_markdown_block_redacts_pii():
    md = "\n".join(markdown_block(_confirmed_idor()))
    assert "korumasız" in md.lower() or "kontrolsüz" in md
    assert "alice@t.local" not in md                 # owner-private değer REDAKTE (§5.5)
    assert "<REDACTED>" in md


def test_rejected_view_frames_as_observation_not_proof():
    ev = Evidence(
        baseline_request=CapturedRequest(method="GET", url="http://t/api/products/1"),
        baseline_response=NormalizedResponse(status=200, body_text='{"name":"Apple Juice"}'),
        attack_request=CapturedRequest(method="GET", url="http://t/api/products/1"),
        attack_response=NormalizedResponse(status=200, body_text='{"name":"Apple Juice"}'),
        positive_control=True, negative_control=True, baseline_stable=True,
    )
    f = Finding(id="F-2", type="idor", endpoint="/api/products/{id}", verdict="REJECTED",
                victim="user_A", attacker="user_B", evidence=ev)
    view = build_view(f)
    assert view is not None and view.is_proof is False
    md = "\n".join(view.to_markdown())
    assert "gözlem" in md                            # "gözlem", "kanıt" değil


def test_no_tracks_yields_empty_block():
    """Detector-tarzı (baseline/attack yakalamayan) bulguda counterfactual blok gösterilmez."""
    f = Finding(id="F-3", type="info_leak", endpoint="/", verdict="LIKELY")
    assert build_view(f) is None
    assert markdown_block(f) == []


def test_reporter_includes_counterfactual_for_idor():
    out = MarkdownReporter().render([_confirmed_idor()], target="http://t")
    assert "Counterfactual kanıt" in out
    assert "Yetkili (baseline)" in out and "Kontrolsüz (saldırı)" in out
