"""FindingDeduplicator — R-D2 (GOREVLER.md, ROADMAP.md Eksen D; Q4 stretch).

Aynı kök-neden (CWE+endpoint+param) tek grupta toplanır; verdict ASLA değişmez, yalnızca
birden fazla üye AYNI verdict'te birleşirse temsilcinin confidence'ı bir basamak yükselir.
"""
from pentestai.models import Evidence, Finding
from pentestai.report import MarkdownReporter
from pentestai.report.dedup import FindingDeduplicator, root_cause_key


def _f(fid, *, type_="idor", endpoint="/api/orders/{id}", param="id",
       verdict="CONFIRMED", confidence="high", cwe=None) -> Finding:
    return Finding(id=fid, type=type_, endpoint=endpoint, parameter=param,
                   verdict=verdict, confidence=confidence, cwe=cwe, evidence=Evidence())


def test_same_root_cause_groups_into_one():
    findings = [
        _f("F-001", verdict="CONFIRMED", confidence="high", cwe="CWE-639"),
        _f("F-002", verdict="CONFIRMED", confidence="high", cwe="CWE-639"),
        _f("F-003", verdict="CONFIRMED", confidence="high", cwe="CWE-639"),
    ]
    groups = FindingDeduplicator().group(findings)
    assert len(groups) == 1
    g = groups[0]
    assert g.agreement == 3
    assert set(g.sources) == {"F-001", "F-002", "F-003"}
    assert g.representative.verdict == "CONFIRMED"          # verdict değişmedi


def test_agreement_bumps_confidence_but_never_verdict():
    findings = [
        _f("F-001", verdict="LIKELY", confidence="medium", cwe="CWE-639"),
        _f("F-002", verdict="LIKELY", confidence="medium", cwe="CWE-639"),
    ]
    groups = FindingDeduplicator().group(findings)
    rep = groups[0].representative
    assert rep.verdict == "LIKELY"           # asla CONFIRMED'e yükseltilmedi (§5 kural 2)
    assert rep.confidence == "high"          # medium → high (agreement>1)
    # orijinal Finding'ler DEĞİŞMEDİ (kopya üzerinde çalışıldı) — no side effects.
    assert findings[0].confidence == "medium"


def test_single_member_group_no_bump():
    groups = FindingDeduplicator().group([_f("F-001", confidence="medium", verdict="LIKELY")])
    assert groups[0].agreement == 1
    assert groups[0].representative.confidence == "medium"   # bump yok


def test_different_endpoint_or_param_stays_separate():
    findings = [
        _f("F-001", endpoint="/api/orders/{id}", param="id", cwe="CWE-639"),
        _f("F-002", endpoint="/api/baskets/{id}", param="id", cwe="CWE-639"),
        _f("F-003", endpoint="/api/orders/{id}", param="userId", cwe="CWE-639"),
    ]
    groups = FindingDeduplicator().group(findings)
    assert len(groups) == 3


def test_different_cwe_stays_separate_even_on_same_endpoint():
    # csrf (CWE-352) ve mass_assignment (CWE-915) aynı PUT endpoint'inde ama FARKLI kök-neden.
    findings = [
        _f("F-001", type_="csrf", endpoint="/api/orders/{id}", param="id", cwe="CWE-352"),
        _f("F-002", type_="mass_assignment", endpoint="/api/orders/{id}", param="id", cwe="CWE-915"),
    ]
    groups = FindingDeduplicator().group(findings)
    assert len(groups) == 2


def test_representative_is_strongest_verdict_then_confidence():
    findings = [
        _f("F-001", verdict="INCONCLUSIVE", confidence="low", cwe="CWE-639"),
        _f("F-002", verdict="CONFIRMED", confidence="high", cwe="CWE-639"),
        _f("F-003", verdict="REJECTED", confidence="low", cwe="CWE-639"),
    ]
    groups = FindingDeduplicator().group(findings)
    assert groups[0].representative.id == "F-002"
    assert groups[0].agreement == 1   # yalnızca F-002 CONFIRMED (diğerleri farklı verdict)


def test_root_cause_key_falls_back_to_type_meta_cwe_when_unset():
    f = _f("F-001", type_="idor", cwe=None)
    key = root_cause_key(f)
    assert key[0] == "CWE-639"   # classify.meta_for("idor").cwe


def test_markdown_report_shows_correlated_section_only_when_agreement():
    solo = [_f("F-001", verdict="CONFIRMED", confidence="high", cwe="CWE-639")]
    md_solo = MarkdownReporter().render(solo)
    assert "Correlated Findings" not in md_solo

    dup = [
        _f("F-001", verdict="CONFIRMED", confidence="high", cwe="CWE-639"),
        _f("F-002", verdict="CONFIRMED", confidence="high", cwe="CWE-639"),
    ]
    md_dup = MarkdownReporter().render(dup)
    assert "## Correlated Findings (Dedup)" in md_dup
    assert "F-001" in md_dup and "F-002" in md_dup
    # tüm bulgular ayrıca ayrıntılı bölümde de var — "no silent drops":
    assert md_dup.count("(F-001)") == 1 and md_dup.count("(F-002)") == 1
