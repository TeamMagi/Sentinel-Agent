"""Baseline + diff modu — R-C1 (GOREVLER.md, ROADMAP.md Eksen C).

Aynı kimlik (fingerprint) + AYNI verdict → 'known' (CI kapısını tetiklemez, ama gizlenmez).
Kimlik yeni YA DA verdict kötüleştiyse (ör. REJECTED→CONFIRMED) → 'new' (regresyon sessizce
bastırılmaz — "no silent drops").
"""
import json

import pytest

from pentestai.models import Evidence, Finding
from pentestai.report import MarkdownReporter
from pentestai.report.baseline import Baseline


def _f(fid, *, type_="idor", endpoint="/api/orders/{id}", method="GET", param="id",
       verdict="CONFIRMED") -> Finding:
    return Finding(id=fid, type=type_, endpoint=endpoint, method=method, parameter=param,
                   verdict=verdict, evidence=Evidence())


def test_same_identity_and_verdict_is_known():
    prior = [_f("F-001", verdict="CONFIRMED")]
    current = [_f("F-777", verdict="CONFIRMED")]   # id farklı olabilir — fingerprint id'den bağımsız
    Baseline.from_findings(prior).apply(current)
    assert current[0].baseline_status == "known"


def test_new_endpoint_is_new():
    prior = [_f("F-001", endpoint="/api/orders/{id}", verdict="CONFIRMED")]
    current = [_f("F-002", endpoint="/api/baskets/{id}", verdict="CONFIRMED")]
    Baseline.from_findings(prior).apply(current)
    assert current[0].baseline_status == "new"


def test_verdict_regression_is_not_suppressed():
    # Aynı endpoint önceden REJECTED'dı, şimdi CONFIRMED → regresyon, ASLA 'known' sayılmaz.
    prior = [_f("F-001", verdict="REJECTED")]
    current = [_f("F-002", verdict="CONFIRMED")]
    Baseline.from_findings(prior).apply(current)
    assert current[0].baseline_status == "new"


def test_apply_never_removes_findings_no_silent_drops():
    prior = [_f("F-001", verdict="CONFIRMED")]
    current = [_f("F-002", verdict="CONFIRMED"), _f("F-003", endpoint="/x", verdict="CONFIRMED")]
    out = Baseline.from_findings(prior).apply(current)
    assert len(out) == 2   # bilinen bulgu da listede kalır, silinmez
    assert {f.baseline_status for f in out} == {"known", "new"}


def test_markdown_shows_baseline_reason_without_dropping_finding():
    known = _f("F-001", verdict="CONFIRMED")
    known.baseline_status = "known"
    md = MarkdownReporter().render([known])
    assert "(F-001)" in md                       # bulgu raporda kalıyor
    assert "known (same root cause" in md
    assert "CI gate" in md


def test_load_from_findings_json_file(tmp_path):
    prior = [_f("F-001", verdict="CONFIRMED")]
    p = tmp_path / "findings.json"
    p.write_text(json.dumps([f.model_dump(mode="json") for f in prior]), encoding="utf-8")
    current = [_f("F-999", verdict="CONFIRMED")]
    Baseline.load(str(p)).apply(current)
    assert current[0].baseline_status == "known"


@pytest.mark.asyncio
async def test_ci_gate_skips_known_findings():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from run_scan import _fail_exit

    known = _f("F-001", verdict="CONFIRMED")
    known.severity = "Critical"
    known.baseline_status = "known"
    assert _fail_exit([known], "high") == 0   # bilinen → gate'lemez

    new = _f("F-002", verdict="CONFIRMED")
    new.severity = "Critical"
    new.baseline_status = "new"
    assert _fail_exit([new], "high") == 2     # yeni CONFIRMED → gate'ler
