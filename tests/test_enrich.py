"""FindingEnricher — LLM zenginleştirme. DESIGN.md §14 (1.4).

Değişmezler: LLM verdict'i DEĞİŞTİRMEZ; LLM'e giden özet REDAKTE (marker değeri sızmaz).
"""
import pytest

from pentestai.enrich import FindingEnricher
from pentestai.llm import MockLLMClient
from pentestai.models import Evidence, Finding

ENRICHMENT = '{"severity":"High","impact":"IMPACT-METNI","remediation":"FIX-METNI","triage_note":"NEDEN"}'


def _finding(verdict, markers=None):
    return Finding(
        id="F-001", type="idor", endpoint="/api/orders/{id}", method="GET", parameter="id",
        verdict=verdict, confidence="high",
        evidence=Evidence(positive_control=True, negative_control=True, baseline_stable=True,
                          leaked_markers=markers or []),
    )


@pytest.mark.asyncio
async def test_enrich_sets_fields_but_not_verdict():
    enricher = FindingEnricher(MockLLMClient(completion=ENRICHMENT))
    f = await enricher.enrich(_finding("CONFIRMED", markers=["alice@secret.com"]))
    assert f.severity == "High" and f.impact == "IMPACT-METNI" and f.remediation == "FIX-METNI"
    assert f.verdict == "CONFIRMED"      # LLM verdict'e DOKUNMADI
    assert f.triage_note is None          # CONFIRMED'de triage yok


@pytest.mark.asyncio
async def test_rejected_is_skipped():
    enricher = FindingEnricher(MockLLMClient(completion=ENRICHMENT))
    f = await enricher.enrich(_finding("REJECTED"))
    assert f.severity is None and f.impact is None and f.verdict == "REJECTED"


@pytest.mark.asyncio
async def test_inconclusive_gets_triage_note():
    enricher = FindingEnricher(MockLLMClient(completion=ENRICHMENT))
    f = await enricher.enrich(_finding("INCONCLUSIVE"))
    assert f.triage_note == "NEDEN" and f.verdict == "INCONCLUSIVE"


def test_summary_is_redacted():
    # marker DEĞERİ (PII) LLM'e giden özette görünmemeli
    summary = FindingEnricher.summarize(_finding("CONFIRMED", markers=["alice@secret.com", "42.5"]))
    assert "alice@secret.com" not in summary
    assert "42.5" not in summary
    assert "2 kimliklendirici alan sızdı" in summary
