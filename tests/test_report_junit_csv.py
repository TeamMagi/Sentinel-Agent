"""JUnit XML + CSV reporter'ları (RK-2). Network yok — saf render + store yazımı.

Kabul: `runs/<id>/` altında junit.xml + report.csv üretilir; verdict test sonucuna eşlenir;
redaction korunur (ham PII/marker değeri sızmaz)."""
import csv
import io
import xml.etree.ElementTree as ET

from pentestai.evidence.store import EvidenceStore
from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse
from pentestai.report import CsvReporter, JUnitReporter


def _finding(fid, vtype, verdict, *, leaked=None, endpoint="/rest/basket/{id}", method="GET"):
    ev = Evidence(
        attack_request=CapturedRequest(method=method, url="http://t" + endpoint),
        attack_response=NormalizedResponse(status=200, body_text="{}"),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=leaked or [],
    )
    return Finding(id=fid, type=vtype, endpoint=endpoint, method=method, parameter="id",
                   verdict=verdict, confidence="high", severity="High", cwe="CWE-639",
                   owasp="API1:2023", victim="user_A", attacker="user_B", evidence=ev)


def _sample() -> list[Finding]:
    return [
        _finding("F-001", "idor", "CONFIRMED", leaked=["alice@test.local", "orderRef-1"]),
        _finding("F-002", "bfla", "REJECTED"),
        _finding("F-003", "excessive_data_exposure", "INCONCLUSIVE"),
        _finding("F-004", "csrf", "LIKELY"),
    ]


# ---------------- JUnit ----------------

def test_junit_is_valid_xml_with_verdict_mapping():
    xml = JUnitReporter().render(_sample(), target="http://localhost:3000")
    root = ET.fromstring(xml)
    assert root.tag == "testsuites"
    assert root.attrib["tests"] == "4"
    assert root.attrib["failures"] == "2"    # CONFIRMED + LIKELY
    assert root.attrib["skipped"] == "1"     # INCONCLUSIVE

    cases = {tc.attrib["name"]: tc for tc in root.iter("testcase")}
    confirmed = cases["idor @ GET /rest/basket/{id}"]
    assert confirmed.find("failure") is not None
    rejected = cases["bfla @ GET /rest/basket/{id}"]
    assert rejected.find("failure") is None and rejected.find("skipped") is None
    inconclusive = cases["excessive_data_exposure @ GET /rest/basket/{id}"]
    assert inconclusive.find("skipped") is not None


def test_junit_redacts_and_hides_marker_values():
    xml = JUnitReporter().render(_sample())
    assert "alice@test.local" not in xml       # PII sızmadı
    assert "orderRef-1" not in xml             # marker DEĞERİ yok
    assert "2 kimliklendirici alan sızdı" in xml   # yalnızca SAYI


def test_junit_no_findings_is_valid_empty_suite():
    root = ET.fromstring(JUnitReporter().render([]))
    assert root.attrib["tests"] == "0" and list(root.iter("testcase")) == []


# ---------------- CSV ----------------

def test_csv_has_header_and_one_row_per_finding():
    text = CsvReporter().render(_sample())
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 4
    r0 = rows[0]
    assert r0["id"] == "F-001" and r0["type"] == "idor" and r0["verdict"] == "CONFIRMED"
    assert r0["attacker"] == "user_B" and r0["victim"] == "user_A"
    assert r0["leaked_field_count"] == "2"
    assert r0["cwe"] == "CWE-639" and r0["owasp"] == "API1:2023"


def test_csv_redacts_pii_and_omits_raw_marker_values():
    text = CsvReporter().render(_sample())
    assert "alice@test.local" not in text
    assert "orderRef-1" not in text


# ---------------- Store yazımı ----------------

def test_store_writes_junit_and_csv(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    rid = store.new_run_id()
    root = store.save_run(
        rid, _sample(),
        report_junit=JUnitReporter().render(_sample()),
        report_csv=CsvReporter().render(_sample()),
    )
    assert (root / "junit.xml").exists()
    assert (root / "report.csv").exists()
    # yazılan junit yeniden ayrıştırılabilir
    ET.fromstring((root / "junit.xml").read_text(encoding="utf-8"))
