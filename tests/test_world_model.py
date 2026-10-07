"""WorldModel — agentic döngünün hafızası (Faz 2).

Doğrulananlar: keşifler birikir; tekrarlanan aksiyon "already tried" işaretlenir; durum raporu
token sınırına uyar ve redaksiyon korunur (ham leaked-marker DEĞERİ sızmaz).
"""
from pentestai.models import Endpoint, Evidence, Finding, Observation
from pentestai.orchestrator.actions import Probe, RunOracle
from pentestai.orchestrator.world_model import WorldModel

EP = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")


def _finding(verdict, markers=None):
    return Finding(id="F-001", type="idor", endpoint="/api/orders/{id}", method="GET",
                   verdict=verdict, evidence=Evidence(leaked_markers=markers or []))


def test_records_status_and_findings():
    wm = WorldModel(target="http://localhost:3000")
    wm.record(Probe(endpoint=EP, actor_name="user_A"),
              Observation(action_type="probe", status=200))
    wm.record(Probe(endpoint=EP, actor_name="user_B"),
              Observation(action_type="probe", status=403))
    wm.record(RunOracle(oracle="idor", endpoint=EP, victim_name="user_A", attacker_name="user_B"),
              Observation(action_type="run_oracle", finding=_finding("CONFIRMED", ["alice@x"])))

    key = "GET /api/orders/{id}"
    assert wm.endpoint_status[key] == {200: 1, 403: 1}
    assert len(wm.findings) == 1
    assert len(wm.confirmed()) == 1


def test_discovered_ids_union():
    wm = WorldModel()
    wm.record(Probe(endpoint=EP, actor_name="user_A"),
              Observation(action_type="probe", discovered_ids=["x1", "x2"]))
    wm.record(Probe(endpoint=EP, actor_name="user_B"),
              Observation(action_type="probe", discovered_ids=["x2", "x3"]))
    assert wm.discovered_ids == {"x1", "x2", "x3"}


def test_already_tried_dedupe():
    wm = WorldModel()
    action = RunOracle(oracle="idor", endpoint=EP, victim_name="user_A", attacker_name="user_B")
    assert not wm.already_tried(action)
    wm.record(action, Observation(action_type="run_oracle"))
    assert wm.already_tried(action)
    # Farklı kurban → farklı anahtar → henüz denenmemiş
    other = RunOracle(oracle="idor", endpoint=EP, victim_name="user_B", attacker_name="user_A")
    assert not wm.already_tried(other)


def test_claim_is_atomic_dedupe():
    wm = WorldModel()
    action = RunOracle(oracle="idor", endpoint=EP, victim_name="user_A", attacker_name="user_B")
    assert wm.claim(action) is True          # ilk claim başarılı
    assert wm.claim(action) is False         # ikinci claim (başka scout) reddedilir
    assert wm.already_tried(action)


def test_situation_report_is_redacted_and_bounded():
    wm = WorldModel(target="http://localhost:3000")
    wm.record(RunOracle(oracle="idor", endpoint=EP, victim_name="user_A", attacker_name="user_B"),
              Observation(action_type="run_oracle",
                          finding=_finding("CONFIRMED", ["alice@secret.local"])))
    report = wm.situation_report(max_chars=500)
    assert "CONFIRMED" in report
    assert "1 sızıntı" in report            # sayı gider
    assert "alice@secret.local" not in report   # ham marker DEĞERİ sızmaz (redaction)
    assert len(report) <= 500


def test_situation_report_truncates():
    wm = WorldModel(target="t")
    for i in range(200):
        ep = Endpoint(method="GET", path_template=f"/api/x{i}/{{id}}", id_param="id")
        wm.record(Probe(endpoint=ep, actor_name="a"),
                  Observation(action_type="probe", status=200))
    report = wm.situation_report(max_chars=300)
    assert len(report) <= 300 and report.endswith("…")
