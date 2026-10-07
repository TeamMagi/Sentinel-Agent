"""HtmlReporter — Ajan Yolu (decision trace) render + redaction. Faz 7.

Render istemci tarafında JS ile olduğu için burada gömülü veri + şablon makinesi
(sekme/vurgu) + redaction değişmezi doğrulanır.
"""
from pentestai.models import DecisionStep, DecisionTrace, Evidence, Finding
from pentestai.report import HtmlReporter


def _finding() -> Finding:
    return Finding(
        id="F-003", type="idor", endpoint="/api/orders/3", method="GET",
        verdict="CONFIRMED", confidence="high",
        evidence=Evidence(leaked_markers=["victim@example.com"]),
    )


def _trace() -> DecisionTrace:
    return DecisionTrace(
        steps=[
            DecisionStep(
                turn=1, situation_digest="2 aktör, 5 endpoint keşfedildi",
                proposed_action="Probe /api/orders/{id}",
                rationale="obje id'si var → IDOR adayı",
                observation="HTTP 200, 3 yeni id keşfedildi", verdict_delta=None,
            ),
            DecisionStep(
                turn=2, situation_digest="saldırgan kurbanın objesini istedi",
                proposed_action="RunOracle idor",
                rationale="komşu id erişilebilir olabilir",
                # Ham token bilerek konuldu → redaction'ın elemesi gerekir.
                observation="Authorization: Bearer SECRETTOKEN123 ile 200 döndü; marker sızdı",
                verdict_delta="F-003 → CONFIRMED",
            ),
        ],
        llm_calls=4, tokens=1234, wall_sec=7.5,
    )


def test_trace_embedded_and_machinery_present():
    html = HtmlReporter().render(
        [_finding()], target="http://localhost:3000", run_id="run-x",
        generated_at="2026-09-13", trace=_trace(),
    )
    assert "__REPORT_DATA__" not in html                 # yer tutucu dolduruldu
    # Karar izi gömülü:
    assert "RunOracle idor" in html
    assert "2 aktör, 5 endpoint keşfedildi" in html
    assert "F-003 → CONFIRMED" in html                   # verdict_delta
    # Metrik şeridi verisi gömülü:
    assert '"llm_calls": 4' in html
    assert '"tokens": 1234' in html
    assert '"wall_sec": 7.5' in html
    # Şablon makinesi: sekme + vurgu mevcut:
    assert "Ajan Yolu" in html
    assert "delta-badge" in html


def test_trace_secrets_are_redacted():
    html = HtmlReporter().render([_finding()], trace=_trace())
    assert "SECRETTOKEN123" not in html                  # kural 6: ham token sızmamalı
    assert "<REDACTED>" in html


def test_render_without_trace_is_backward_compatible():
    html = HtmlReporter().render([_finding()])
    assert "__REPORT_DATA__" not in html
    assert '"trace":' not in html                         # gömülü JSON'da trace anahtarı yok
