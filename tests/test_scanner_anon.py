"""RK-7 — Scanner.save(anon_handles=True) uçtan uca. GOREVLER.md Dalga 3.

Gerçek aktör adı/ham id'nin YALNIZCA insan-okunur Markdown raporundan çıktığını, ama
findings.json'ın (CI/replay için) gerçek veriyle kaldığını doğrular.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
ENDPOINTS = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]
ORDERS = {
    "A-100": {"id": "A-100", "owner": "user_A", "email": "alice@test.local"},
    "B-200": {"id": "B-200", "owner": "user_B", "email": "bob@test.local"},
}


def handler(request):
    oid = request.url.path.rsplit("/", 1)[-1]
    return httpx.Response(200, json=ORDERS[oid]) if oid in ORDERS else httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_anon_handles_hides_identity_in_report_but_findings_json_keeps_real_data(tmp_path):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000), out_dir=str(tmp_path))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"orders": "A-100"}))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"}),
                           own_object_ids={"orders": "B-200"}))

    hypotheses = await scanner.planner.generate(ENDPOINTS)
    findings = await scanner.run_hypotheses([A, B], hypotheses)
    assert any(f.verdict == "CONFIRMED" for f in findings), "IDOR CONFIRMED bekleniyordu"

    run_id, root = scanner.save(findings, "active", sessions=[A, B], anon_handles=True)

    report_md = (root / "report.md").read_text(encoding="utf-8")
    assert "user_A" not in report_md and "user_B" not in report_md
    assert "A-100" not in report_md and "B-200" not in report_md
    assert "alice@test.local" not in report_md   # redaction zaten kapsıyor, iki katman da tutarlı
    assert "identity-1" in report_md and "identity-2" in report_md

    report_html = (root / "report.html").read_text(encoding="utf-8")
    assert "user_A" not in report_html and "A-100" not in report_html

    # findings.json ETKİLENMEZ — CI/replay gerçek id/URL'e ihtiyaç duyar (§5.4, R-A2 proof).
    findings_json = (root / "findings.json").read_text(encoding="utf-8")
    assert "user_A" in findings_json and "A-100" in findings_json

    await scanner.aclose()
