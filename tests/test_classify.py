"""classify — tür → CWE/OWASP/severity (deterministik, kod kararı). Q1.

Değişmez: severity kararını KOD verir (verdict gibi); LLM önerisi severity_suggested'da kalır.
"""
from pentestai.classify import (
    CVSS_BASE_SCORE, SEVERITY_ORDER, TYPE_META, assign, assign_all, cvss_for, meta_for,
    missing_types, severity_for_verdict, severity_of,
)
from pentestai.models import Evidence, Finding

# Kodun gerçekten ürettiği tüm Finding.type değerleri (planner + *.vuln_type + injection/timing
# alt-tipleri + graphql). Yeni tür eklenince buraya + TYPE_META'ya eklenmeli — bu guard onu yakalar.
PRODUCED_TYPES = [
    "idor", "excessive_data_exposure", "unauthorized_access", "method_bypass", "bfla",
    "injection", "sqli", "nosqli", "ssti", "path_traversal",
    "timing", "blind_sqli", "command_injection",
    "state_change_authz", "csrf", "mass_assignment", "stored_xss", "file_upload",
    "open_redirect", "cors", "clickjacking", "jwt", "user_enumeration",
    "ssrf", "rfi", "xxe", "cache_poisoning", "prototype_pollution",
    "info_leak", "exposure", "default_credentials", "vulnerable_component",
    "rate_limit", "session_lifecycle", "graphql_introspection", "graphql_bola",
    # Dalga 5 — agent-security predicate'leri (agent/*.py vuln_type'ları)
    "exfiltration", "destructive_write", "confused_deputy",
]


def _finding(vtype: str, verdict: str = "CONFIRMED") -> Finding:
    return Finding(id="F-001", type=vtype, endpoint="/x", verdict=verdict,
                   evidence=Evidence())


def test_every_produced_type_is_mapped():
    # Üretilen hiçbir tür haritada eksik olmamalı (aksi halde rapor 'generic'e düşer).
    assert missing_types(PRODUCED_TYPES) == []


def test_table_values_are_wellformed():
    for t, m in TYPE_META.items():
        assert m.cwe.startswith("CWE-"), t
        assert m.severity in SEVERITY_ORDER, t
        assert m.owasp, t


def test_meta_for_unknown_falls_back_to_generic():
    m = meta_for("kesinlikle_yok_boyle_bir_tip")
    assert m == TYPE_META["generic"]
    assert severity_of("kesinlikle_yok_boyle_bir_tip") == "Info"


def test_rejected_is_info():
    assert severity_for_verdict("idor", "REJECTED") == "Info"


def test_inconclusive_downgrades_one_step():
    # idor temel High → INCONCLUSIVE bir basamak düşer → Medium
    assert severity_for_verdict("idor", "INCONCLUSIVE") == "Medium"
    # taban Info olan bir tür daha aşağı inemez (kırpma)
    assert severity_for_verdict("generic", "INCONCLUSIVE") == "Info"


def test_confirmed_escalates_high_impact_write_types():
    # state_change_authz temel High → CONFIRMED yazma istismarı → Critical
    assert severity_for_verdict("state_change_authz", "CONFIRMED") == "Critical"
    assert severity_for_verdict("mass_assignment", "CONFIRMED") == "Critical"
    # zaten Critical olan escalate edilse de tavanda kalır
    assert severity_for_verdict("file_upload", "CONFIRMED") == "Critical"
    # escalate listesinde olmayan tür temelinde kalır
    assert severity_for_verdict("idor", "CONFIRMED") == "High"


def test_likely_keeps_base_severity():
    assert severity_for_verdict("idor", "LIKELY") == "High"


def test_assign_writes_cwe_owasp_severity_and_is_idempotent():
    f = _finding("idor", "CONFIRMED")
    assign(f)
    assert f.cwe == "CWE-639" and f.owasp == "API1:2023" and f.severity == "High"
    # ikinci kez uygulamak sonucu değiştirmez (idempotent)
    before = (f.cwe, f.owasp, f.severity)
    assign(f)
    assert (f.cwe, f.owasp, f.severity) == before


def test_assign_does_not_touch_llm_suggestion():
    f = _finding("idor", "CONFIRMED")
    f.severity_suggested = "Critical"   # LLM önerisi
    assign(f)
    assert f.severity == "High"           # kod kararı kazanır
    assert f.severity_suggested == "Critical"   # öneri korunur


def test_assign_all_covers_list():
    fs = [_finding("bfla"), _finding("jwt")]
    assign_all(fs)
    assert fs[0].owasp == "API5:2023"
    assert fs[1].cwe == "CWE-347"


def test_cvss_for_covers_every_severity_tier():
    assert set(CVSS_BASE_SCORE) == set(SEVERITY_ORDER)
    scores = [CVSS_BASE_SCORE[s] for s in SEVERITY_ORDER]
    assert scores == sorted(scores)   # düşük→yüksek severity ile monotonik artıyor
    assert cvss_for("bilinmeyen-severity") == 0.0


def test_assign_writes_cvss_consistent_with_severity():
    f = _finding("idor", "CONFIRMED")
    assign(f)
    assert f.severity == "High"
    assert f.cvss == CVSS_BASE_SCORE["High"]
    # verdict severity'yi değiştirirse (escalate/downgrade) cvss da TUTARLI kalmalı — aynı kaynak.
    f2 = _finding("idor", "INCONCLUSIVE")
    assign(f2)
    assert f2.severity == "Medium" and f2.cvss == CVSS_BASE_SCORE["Medium"]
