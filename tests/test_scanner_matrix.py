"""RK-4 — çift-yönlü 2×2 yetki matrisi: gerçek oracle koşumu + rapor. GOREVLER.md Dalga 1.

`report/matrix.py`'nin asimetrik-izolasyon tespiti daha önce yalnızca elle kurulmuş Finding
stub'larıyla test edilmişti (test_report_matrix.py). Bu dosya, `Scanner.run_hypotheses`'ın
GERÇEKTEN A→B kadar B→A koştuğunu ve sonucun matris raporuna uçtan uca (gerçek IdorOracle
kararlarıyla) doğru şekilde aktığını doğrular — asimetrik ownership check'li sahte bir API ile.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.report.matrix import AuthMatrixReporter, build_auth_matrix
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
ENDPOINTS = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]
TOKEN_ACTOR = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}
# Kasıtlı ASİMETRİK ownership check: yalnızca B1 (user_B'nin objesi) korunuyor; A1 herkese açık
# (vulnerable) — gerçek dünyadaki "bir endpoint'te unutulan kontrol" senaryosunu simüle eder.
ORDERS = {
    "A1": {"id": "A1", "owner": "user_A", "email": "alice@test.local"},
    "B1": {"id": "B1", "owner": "user_B", "email": "bob@test.local"},
}


def app_handler(request):
    actor = TOKEN_ACTOR.get(request.headers.get("authorization", "").replace("Bearer ", ""))
    path = request.url.path
    if not path.startswith("/api/orders/"):
        return httpx.Response(404, json={})
    obj = ORDERS.get(path.rsplit("/", 1)[-1])
    if obj is None:
        return httpx.Response(404, json={"error": "not found"})
    if obj["owner"] == "user_B" and actor != "user_B":
        return httpx.Response(403, json={"error": "forbidden"})   # yalnızca B1 korunuyor
    return httpx.Response(200, json=obj)                          # A1 KORUNMUYOR


@pytest.mark.asyncio
async def test_bidirectional_idor_run_feeds_asymmetric_matrix():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(app_handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
                           own_object_ids={"orders": "A1"}))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
                           own_object_ids={"orders": "B1"}))

    hypotheses = await scanner.planner.generate(ENDPOINTS)
    findings = await scanner.run_hypotheses([A, B], hypotheses)

    idor = [f for f in findings if f.type == "idor"]
    pairs = {(f.victim, f.attacker): f.verdict for f in idor}
    # İKİ YÖN de gerçekten koşuldu (elle stub değil — IdorOracle'ın kendi kararı):
    assert pairs.get(("user_A", "user_B")) == "CONFIRMED"   # B, A'nın korunmayan objesini okuyor
    assert pairs.get(("user_B", "user_A")) == "REJECTED"    # A, B'nin korunan objesine erişemiyor

    matrix = build_auth_matrix(findings, scanner._roles)
    g = next(g for g in matrix if g["type"] == "idor")
    assert ("user_A", "user_B") in g["leaks"]
    assert g["asymmetric"] == [("user_A", "user_B")]        # tek-yön sızıntı gerçek koşumla yakalandı

    md = AuthMatrixReporter().render(findings, scanner._roles)
    assert "Yetki Matrisi" in md and "asimetrik izolasyon" in md
    await store.aclose_all()
