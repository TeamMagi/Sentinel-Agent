"""Çok-hedefli benchmark toplulaştırması (R-A3). Network yok."""
from pathlib import Path

from pentestai.bench import Benchmark, ExpectedCase
from pentestai.bench.suite import BenchmarkSuite
from pentestai.models import Finding

REPO = Path(__file__).resolve().parents[1]


def _suite():
    b1 = Benchmark([ExpectedCase(type="idor", endpoint="/a", expect="CONFIRMED"),
                    ExpectedCase(type="cors", endpoint="/b", expect="not_vulnerable")])
    b2 = Benchmark([ExpectedCase(type="idor", endpoint="/c", expect="CONFIRMED")])
    return BenchmarkSuite([("t1", b1), ("t2", b2)])


def _f(type_, endpoint, verdict):
    return Finding(id="F", type=type_, endpoint=endpoint, verdict=verdict)


def test_suite_aggregates_counts_and_metrics():
    findings = {
        "t1": [_f("idor", "/a", "CONFIRMED")],   # TP; /b CONFIRM edilmedi → TN
        "t2": [],                                # /c yok → FN
    }
    res = _suite().evaluate(findings)
    assert (res.tp, res.fn, res.fp, res.tn) == (1, 1, 0, 1)
    assert res.precision == 1.0            # FP yok
    assert res.recall == 0.5               # 2 pozitiften 1'i yakalandı
    assert res.cases == 3


def test_suite_counts_false_positive_across_targets():
    findings = {
        "t1": [_f("idor", "/a", "CONFIRMED"), _f("cors", "/b", "CONFIRMED")],  # /b negatifti → FP
        "t2": [_f("idor", "/c", "CONFIRMED")],                                 # TP
    }
    res = _suite().evaluate(findings)
    assert res.fp == 1 and res.tp == 2
    assert abs(res.precision - 2 / 3) < 1e-9   # 2 TP / (2 TP + 1 FP)
    assert res.fp_rate == 1.0                  # tek negatif vaka FP oldu


def test_suite_markdown_has_total_row():
    md = _suite().evaluate({"t1": [], "t2": []}).to_markdown()
    assert "TOPLAM" in md and "`t1`" in md and "`t2`" in md


def test_real_suite_yaml_loads_three_targets_and_min_cases():
    suite, meta = BenchmarkSuite.from_yaml(REPO / "benchmarks" / "suite.yaml")
    assert len(suite.targets) == 3
    names = {n for n, _ in suite.targets}
    assert names == {"juiceshop", "vampi", "crapi"}
    total_cases = sum(len(b.cases) for _, b in suite.targets)
    assert total_cases >= 30                     # R-A3 kabul: ≥3 hedef, ≥30 etiketli vaka
