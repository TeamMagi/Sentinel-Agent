"""Holdout hedef + genelleme raporu (AS-5). Network yok — saf değerlendirme.

Kabul: holdout işaretli hedefle suite değerlendirmesi çalışır; rapor kalibre ↔ holdout
metriklerini AYRI tablolarda verir; genelleme farkı overfit'i görünür kılar.
"""
from pathlib import Path

from pentestai.bench import Benchmark, ExpectedCase
from pentestai.bench.suite import BenchmarkSuite, MetricSet
from pentestai.models import Finding

REPO = Path(__file__).resolve().parents[1]


def _f(type_, endpoint, verdict="CONFIRMED"):
    return Finding(id="F", type=type_, endpoint=endpoint, verdict=verdict)


def _suite():
    """t1 = kalibre (2 pozitif), t2 = holdout (2 pozitif)."""
    cal = Benchmark([ExpectedCase(type="idor", endpoint="/a", expect="CONFIRMED"),
                     ExpectedCase(type="idor", endpoint="/b", expect="CONFIRMED")])
    hold = Benchmark([ExpectedCase(type="idor", endpoint="/c", expect="CONFIRMED"),
                      ExpectedCase(type="idor", endpoint="/d", expect="CONFIRMED")])
    return BenchmarkSuite([("t1", cal), ("t2", hold)], holdout=["t2"])


def test_holdout_flag_marks_only_holdout_targets():
    res = _suite().evaluate({})
    assert [r.target for r in res.calibrated_results] == ["t1"]
    assert [r.target for r in res.holdout_results] == ["t2"]
    assert res.has_holdout is True


def test_calibrated_and_holdout_metrics_are_separate():
    # Kalibrede her şey yakalanıyor, holdout'ta hiçbiri → klasik overfit tablosu.
    findings = {"t1": [_f("idor", "/a"), _f("idor", "/b")], "t2": []}
    res = _suite().evaluate(findings)
    assert res.calibrated_metrics.recall == 1.0
    assert res.holdout_metrics.recall == 0.0
    assert res.recall == 0.5                       # birleşik metrik ikisinin ortası
    assert res.generalization_gap["recall"] == 1.0   # pozitif = holdout'ta daha kötü


def test_no_gap_when_generalizes():
    findings = {"t1": [_f("idor", "/a"), _f("idor", "/b")],
                "t2": [_f("idor", "/c"), _f("idor", "/d")]}
    res = _suite().evaluate(findings)
    assert res.generalization_gap["recall"] == 0.0
    assert res.holdout_metrics.recall == 1.0


def test_markdown_has_both_tables_and_gap_section():
    md = _suite().evaluate({"t1": [_f("idor", "/a")], "t2": []}).to_markdown()
    assert "Kalibre hedefler" in md
    assert "Holdout hedefler" in md
    assert "Genelleme farkı" in md
    assert "Tümü (birleşik)" in md


def test_dict_has_generalization_block():
    d = _suite().evaluate({"t1": [_f("idor", "/a")], "t2": []}).to_dict()
    assert "generalization" in d
    assert set(d["generalization"]) == {"calibrated", "holdout", "gap"}
    assert d["aggregate"]["counts"]["targets"] == 2     # eski şema korunuyor


def test_without_holdout_markdown_keeps_single_table_and_warns():
    plain = BenchmarkSuite([("t1", Benchmark([ExpectedCase(type="idor", endpoint="/a")]))])
    res = plain.evaluate({})
    md = res.to_markdown()
    assert res.has_holdout is False
    assert "Genelleme farkı" not in md
    assert "holdout` işaretli değil" in md          # ölçülmediği açıkça yazılıyor
    assert "generalization" not in res.to_dict()


def test_metricset_empty_is_neutral():
    m = MetricSet.of([], "boş")
    assert m.precision == 1.0 and m.recall == 1.0 and m.fp_rate == 0.0


def test_real_suite_yaml_exposes_holdout_field():
    # Depodaki suite.yaml `holdout` alanını taşıyor; bugün üçü de kalibre (dürüstlük notu).
    suite, meta = BenchmarkSuite.from_yaml(REPO / "benchmarks" / "suite.yaml")
    assert all("holdout" in t for t in meta), "suite.yaml'da holdout alanı eksik"
    assert suite.holdout == set(), "kalibre edilmiş hedef holdout olarak işaretlenemez"
