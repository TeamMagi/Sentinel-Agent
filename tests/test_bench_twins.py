"""0-FP negatif-ikiz regresyon paketi (RK-10). Network yok — GERÇEK oracle, MockTransport ikizler.

Kabul: hardened ikizde yanlış CONFIRMED çıkarsa guard kapıyı kırar (bench_guard çıkış kodu 1);
temiz koşumda 0-FP korunur (çıkış kodu 0)."""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from pentestai.bench.twins import (
    BflaTwin, IdorTwin, NegativeTwin, NegativeTwinGuard, PublicEndpointTwin, TwinResult,
)
from pentestai.models import Evidence, Finding
from pentestai.oracle.base import CONFIRMED, REJECTED


@pytest.mark.asyncio
async def test_default_twins_preserve_zero_fp_and_recall():
    result = await NegativeTwinGuard().run()
    assert result.zero_fp, f"hardened ikizde yanlış CONFIRMED: {result.false_confirmed}"
    assert result.fp_count == 0
    # vulnerable ikizler gerçekten yakalanmalı (recall regresyonu yok)
    assert result.missed == [], f"kaçırılan vulnerable ikiz: {result.missed}"


@pytest.mark.asyncio
async def test_each_twin_vulnerable_confirmed_hardened_not():
    for twin in (IdorTwin(), PublicEndpointTwin(), BflaTwin()):
        vuln, hard = await twin.run()
        assert vuln.verdict == CONFIRMED, f"{twin.name}: vulnerable CONFIRMED değil ({vuln.verdict})"
        assert hard.verdict != CONFIRMED, f"{twin.name}: hardened yanlış CONFIRMED ({hard.verdict})"


class _BrokenTwin(NegativeTwin):
    """Bozuk dedektör simülasyonu: hardened ikizde de CONFIRMED üretir → guard yakalamalı."""

    name = "broken"
    vuln_type = "idor"

    def _f(self, verdict):
        return Finding(id="F", type="idor", endpoint="/x", verdict=verdict, evidence=Evidence())

    async def run(self):
        return self._f(CONFIRMED), self._f(CONFIRMED)   # hardened da CONFIRMED (regresyon)


@pytest.mark.asyncio
async def test_guard_flags_false_confirmed_regression():
    result = await NegativeTwinGuard([_BrokenTwin()]).run()
    assert not result.zero_fp
    assert result.false_confirmed == ["broken"]


class _MissTwin(NegativeTwin):
    name = "miss"
    vuln_type = "idor"

    def _f(self, verdict):
        return Finding(id="F", type="idor", endpoint="/x", verdict=verdict, evidence=Evidence())

    async def run(self):
        return self._f(REJECTED), self._f(REJECTED)   # vulnerable kaçırıldı, ama FP yok


@pytest.mark.asyncio
async def test_recall_miss_is_not_fp():
    result = await NegativeTwinGuard([_MissTwin()]).run()
    assert result.zero_fp                    # FP kapısı geçer
    assert result.missed == ["miss"]         # ama recall regresyonu işaretlenir


def test_bench_guard_cli_returns_zero_on_clean(tmp_path):
    from scripts.bench_guard import main
    assert main(["--out", str(tmp_path)]) == 0
    assert (tmp_path / "bench_guard.md").exists()


def test_twin_result_markdown_renders():
    md = TwinResult(outcomes=[]).to_markdown()
    assert "Negatif-ikiz regresyon" in md
