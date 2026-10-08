"""LLM FP-triyajı (R-C2) — likely_fp işareti; verdict ASLA değişmez; hata → unreviewed. Network yok."""
import pytest

from pentestai.llm.client import LLMClient
from pentestai.models import Finding
from pentestai.triage import FpTriager


class FakeLLM(LLMClient):
    def __init__(self, reply: str = "", raises: bool = False):
        self.reply = reply
        self.raises = raises
        self.calls = 0

    async def complete(self, system: str, user: str, *, fmt=None) -> str:
        self.calls += 1
        if self.raises:
            raise RuntimeError("ollama down")
        return self.reply


def _finding(verdict="CONFIRMED"):
    return Finding(id="F-001", type="idor", endpoint="/api/orders/{id}", verdict=verdict,
                   confidence="high")


@pytest.mark.asyncio
async def test_marks_likely_fp_without_changing_verdict():
    f = _finding()
    await FpTriager(FakeLLM('{"likely_fp": true, "reason": "public endpoint olabilir"}')).triage(f)
    assert f.likely_fp is True
    assert f.triage_reason and "public" in f.triage_reason
    assert f.verdict == "CONFIRMED"          # verdict ASLA değişmez (§5)


@pytest.mark.asyncio
async def test_not_fp_marks_false():
    f = _finding()
    await FpTriager(FakeLLM('{"likely_fp": false, "reason": "gerçek sızıntı"}')).triage(f)
    assert f.likely_fp is False and f.verdict == "CONFIRMED"


@pytest.mark.asyncio
async def test_llm_error_leaves_unreviewed():
    f = _finding()
    await FpTriager(FakeLLM(raises=True)).triage(f)
    assert f.likely_fp is None               # hata → unreviewed (silme/düşürme YOK)
    assert f.verdict == "CONFIRMED"


@pytest.mark.asyncio
async def test_garbage_output_leaves_unreviewed():
    f = _finding()
    await FpTriager(FakeLLM("bu json değil")).triage(f)
    assert f.likely_fp is None and f.verdict == "CONFIRMED"


@pytest.mark.asyncio
async def test_skips_rejected_and_inconclusive():
    llm = FakeLLM('{"likely_fp": true}')
    triager = FpTriager(llm)
    for v in ("REJECTED", "INCONCLUSIVE"):
        f = _finding(v)
        await triager.triage(f)
        assert f.likely_fp is None
    assert llm.calls == 0                    # rapora girmeyen verdict'ler LLM'e sorulmaz


@pytest.mark.asyncio
async def test_triage_all_only_touches_reported_verdicts():
    llm = FakeLLM('{"likely_fp": true, "reason": "x"}')
    findings = [_finding("CONFIRMED"), _finding("LIKELY"), _finding("REJECTED")]
    await FpTriager(llm).triage_all(findings)
    assert findings[0].likely_fp is True and findings[1].likely_fp is True
    assert findings[2].likely_fp is None
