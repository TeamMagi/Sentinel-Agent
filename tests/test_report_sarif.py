"""SarifReporter — SARIF 2.1.0 çıktısı (CI/code-scanning). Q2.

Değişmezler: redaction (marker DEĞERİ sızmaz), REJECTED dışlanır, fingerprint KARARLI.
"""
import json

from pentestai.classify import assign
from pentestai.models import Evidence, Finding
from pentestai.report import SarifReporter


def _f(vtype, verdict="CONFIRMED", endpoint="/rest/basket/{id}", markers=None, param="id"):
    return Finding(id="F-001", type=vtype, endpoint=endpoint, method="GET", parameter=param,
                   verdict=verdict,
                   evidence=Evidence(leaked_markers=markers or [], repro_curl="curl ..."))


def _doc(findings, **kw):
    return json.loads(SarifReporter(**kw).render(findings, target="http://localhost:3000"))


def test_valid_sarif_skeleton():
    doc = _doc([_f("idor")])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Sentinel-Agent"
    assert doc["runs"][0]["originalUriBaseIds"]["TARGET"]["uri"] == "http://localhost:3000"


def test_rule_carries_cwe_and_owasp():
    doc = _doc([_f("idor")])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "idor"
    assert rule["properties"]["cwe"] == "CWE-639"
    assert rule["properties"]["owasp"] == "API1:2023"
    assert rule["properties"]["security-severity"] == "7.0"   # High


def test_rejected_excluded_by_default_but_optIn_includes():
    findings = [_f("idor", "CONFIRMED"), _f("bfla", "REJECTED")]
    assert len(_doc(findings)["runs"][0]["results"]) == 1
    assert len(_doc(findings, include_rejected=True)["runs"][0]["results"]) == 2


def test_level_from_severity():
    conf = assign(_f("idor", "CONFIRMED"))          # High → error
    med = assign(_f("open_redirect", "CONFIRMED"))  # Medium → warning
    low = assign(_f("security_headers", "CONFIRMED"))  # Low → note
    doc = _doc([conf, med, low])
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["idor"] == "error"
    assert levels["open_redirect"] == "warning"
    assert levels["security_headers"] == "note"


def test_fingerprint_is_stable_and_distinct():
    a1 = _doc([_f("idor", endpoint="/rest/basket/{id}")])["runs"][0]["results"][0]
    a2 = _doc([_f("idor", endpoint="/rest/basket/{id}")])["runs"][0]["results"][0]
    b = _doc([_f("idor", endpoint="/api/OtherThing/{id}")])["runs"][0]["results"][0]
    def fp(r):
        return r["partialFingerprints"]["sentinel/v1"]
    assert fp(a1) == fp(a2)          # aynı bulgu → aynı imza (koşumlar arası dedup)
    assert fp(a1) != fp(b)           # farklı endpoint → farklı imza


def test_marker_values_are_not_leaked():
    # marker DEĞERİ (PII) SARIF'e girmemeli — mesaj yalnızca SAYI taşır.
    raw = SarifReporter().render([_f("idor", markers=["alice@secret.com"])], target="")
    assert "alice@secret.com" not in raw
    assert "1 kimliklendirici alan sızdı" in raw
