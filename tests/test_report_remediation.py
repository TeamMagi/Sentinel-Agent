"""Bulgu-başına remediation ipucu markdown raporda (L). Ağsız."""
from __future__ import annotations

from pentestai.models import Finding
from pentestai.report.render_md import MarkdownReporter


def _f(vtype: str, verdict: str, remediation: str = "") -> Finding:
    return Finding(id="F-1", type=vtype, endpoint="/api/x/{id}", verdict=verdict,
                   remediation=remediation or None)


def test_confirmed_finding_gets_catalog_remediation():
    out = MarkdownReporter().render([_f("idor", "CONFIRMED")])
    assert "Nasıl çözülür (katalog)" in out
    assert "OWASP" in out                                # kaynak linki iliştirildi


def test_llm_remediation_is_preferred_as_source():
    out = MarkdownReporter().render([_f("idor", "CONFIRMED", remediation="Sahiplik kontrolü ekle.")])
    assert "Nasıl çözülür (LLM)" in out
    assert "Sahiplik kontrolü ekle." in out


def test_rejected_finding_has_no_remediation_line():
    out = MarkdownReporter().render([_f("idor", "REJECTED")])
    assert "Nasıl çözülür" not in out                    # gürültü yok


def test_unknown_type_falls_back_to_generic_guide():
    out = MarkdownReporter().render([_f("totally_new_type", "LIKELY")])
    assert "Nasıl çözülür" in out                         # generic rehber boş bırakmaz
