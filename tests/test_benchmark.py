"""Benchmark harness — beklenen ↔ gerçek bulgu değerlendirmesi. Q3. Ağsız, saf.

Kural: yalnızca CONFIRMED "tespit" sayılır (LIKELY/INCONCLUSIVE değil) — CLAUDE.md §5 ruhu.
"""
from pentestai.bench import Benchmark, ExpectedCase
from pentestai.models import Evidence, Finding


def _f(vtype, endpoint, verdict, method="GET"):
    return Finding(id="F", type=vtype, endpoint=endpoint, method=method, verdict=verdict,
                   evidence=Evidence())


def _case(vtype, endpoint, expect, method=None):
    return ExpectedCase(type=vtype, endpoint=endpoint, expect=expect, method=method)


def test_true_positive_perfect_scores():
    bench = Benchmark([_case("idor", "/b/{id}", "CONFIRMED")])
    r = bench.evaluate([_f("idor", "/b/{id}", "CONFIRMED")])
    assert (r.tp, r.fn, r.fp, r.tn) == (1, 0, 0, 0)
    assert r.precision == 1.0 and r.recall == 1.0 and r.fp_rate == 0.0


def test_false_negative_when_not_confirmed():
    bench = Benchmark([_case("idor", "/b/{id}", "CONFIRMED")])
    # LIKELY tespit sayılmaz → FN
    r = bench.evaluate([_f("idor", "/b/{id}", "LIKELY")])
    assert (r.tp, r.fn) == (0, 1) and r.recall == 0.0


def test_false_negative_when_absent():
    bench = Benchmark([_case("idor", "/b/{id}", "CONFIRMED")])
    r = bench.evaluate([])   # hiç bulgu yok
    assert r.fn == 1 and r.outcomes[0].actual == "absent"


def test_false_positive_on_negative_case():
    bench = Benchmark([_case("idor", "/login", "not_vulnerable")])
    r = bench.evaluate([_f("idor", "/login", "CONFIRMED")])
    assert (r.fp, r.tn) == (1, 0) and r.fp_rate == 1.0


def test_true_negative_keeps_fp_rate_zero():
    bench = Benchmark([_case("idor", "/login", "not_vulnerable")])
    # LIKELY negatif vakada FP değildir (yalnız CONFIRMED FP sayılır) → TN
    r = bench.evaluate([_f("idor", "/login", "LIKELY")])
    assert (r.fp, r.tn) == (0, 1) and r.fp_rate == 0.0


def test_precision_with_mixed_tp_and_fp():
    bench = Benchmark([
        _case("idor", "/b/{id}", "CONFIRMED"),
        _case("bfla", "/admin", "not_vulnerable"),
    ])
    r = bench.evaluate([
        _f("idor", "/b/{id}", "CONFIRMED"),   # TP
        _f("bfla", "/admin", "CONFIRMED"),    # FP
    ])
    assert r.tp == 1 and r.fp == 1
    assert r.precision == 0.5


def test_method_is_matched_when_given():
    bench = Benchmark([_case("csrf", "/o/{id}", "CONFIRMED", method="DELETE")])
    # method uyuşmuyor → eşleşme yok → FN
    r = bench.evaluate([_f("csrf", "/o/{id}", "CONFIRMED", method="GET")])
    assert r.fn == 1


def test_strongest_verdict_is_picked():
    bench = Benchmark([_case("idor", "/b/{id}", "CONFIRMED")])
    r = bench.evaluate([
        _f("idor", "/b/{id}", "REJECTED"),
        _f("idor", "/b/{id}", "CONFIRMED"),   # bu seçilmeli
    ])
    assert r.tp == 1


def test_uncovered_confirmed_listed_not_counted():
    bench = Benchmark([_case("idor", "/b/{id}", "CONFIRMED")])
    r = bench.evaluate([
        _f("idor", "/b/{id}", "CONFIRMED"),      # kapsanan
        _f("exposure", "/.env", "CONFIRMED"),    # etiketsiz CONFIRMED
    ])
    assert r.tp == 1 and r.fp == 0
    assert any("/.env" in k for k in r.uncovered_confirmed)


def test_shipped_expected_file_loads_and_evaluates():
    bench = Benchmark.from_yaml("benchmarks/juiceshop.expected.yaml")
    positives = [c for c in bench.cases if c.expect == "CONFIRMED"]
    negatives = [c for c in bench.cases if c.expect == "not_vulnerable"]
    assert positives and negatives            # hem pozitif hem negatif vaka içermeli
    # tüm pozitif vakaları CONFIRM eden 'ideal' bir araç → tam tespit, sıfır FP
    findings = [_f(c.type, c.endpoint, "CONFIRMED", method=c.method or "GET") for c in positives]
    r = bench.evaluate(findings)
    assert r.tp == len(positives) and r.fn == 0
    assert r.fp == 0 and r.tn == len(negatives)
    assert r.precision == 1.0 and r.recall == 1.0 and r.fp_rate == 0.0


def test_to_dict_and_markdown_smoke():
    bench = Benchmark([_case("idor", "/b/{id}", "CONFIRMED")])
    r = bench.evaluate([_f("idor", "/b/{id}", "CONFIRMED")], target="http://t")
    d = r.to_dict()
    assert d["metrics"]["precision"] == 1.0 and d["counts"]["tp"] == 1
    md = r.to_markdown()
    assert "Precision" in md and "✅ TP" in md
