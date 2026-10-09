"""Advisory güvenlik-duruşu özeti (V2). Ağsız, deterministik."""
from __future__ import annotations

from pentestai.models import Finding
from pentestai.report.posture import compute
from pentestai.report.render_md import MarkdownReporter


def _f(verdict: str, severity: str = "High") -> Finding:
    return Finding(id="F", type="idor", endpoint="/x", verdict=verdict, severity=severity)


def test_no_confirmed_scores_100_and_avoids_word_safe():
    p = compute([_f("REJECTED", "Info"), _f("LIKELY", "High"), _f("INCONCLUSIVE", "Medium")])
    assert p.score == 100 and p.grade == "A" and p.confirmed == 0
    assert "güvenli" in p.line()          # "'güvenli' anlamına gelmez" ibaresi — N disiplini


def test_confirmed_critical_reduces_score():
    p = compute([_f("CONFIRMED", "Critical")])
    assert p.score == 60 and p.grade == "C" and p.confirmed == 1


def test_multiple_confirmed_sum_penalty_deterministic():
    p = compute([_f("CONFIRMED", "High"), _f("CONFIRMED", "Medium")])   # 100-25-12
    assert p.score == 63
    assert compute([_f("CONFIRMED", "High"), _f("CONFIRMED", "Medium")]).score == p.score


def test_likely_and_inconclusive_do_not_reduce_score():
    assert compute([_f("LIKELY", "Critical"), _f("INCONCLUSIVE", "Critical")]).score == 100


def test_report_includes_posture_line():
    assert "Duruş (advisory)" in MarkdownReporter().render([_f("CONFIRMED", "High")])
