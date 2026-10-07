"""Scanner orchestrator — recon→plan→(crawl bootstrap)→IDOR+BFLA. DESIGN.md §14.

Sahte uygulama: koleksiyon (/api/orders), IDOR (/api/orders/{id}), BFLA (/api/admin/users).
Tek akışta crawl id keşfi + hipotez üretimi + iki oracle dispatch'i doğrulanır.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.scanner import Scanner

ORDERS = {
    "A1": {"id": "A1", "email": "alice@test.local", "total": 10},
    "B1": {"id": "B1", "email": "bob@test.local", "total": 20},
}
TOKEN_OWNER = {"A": "A1", "B": "B1"}   # admin'in siparişi yok
BASE = "http://localhost:3000"
ENDPOINTS = [
    Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"),
    Endpoint(method="GET", path_template="/api/admin/users", id_param="id"),
]


def app_handler(request):
    tok = request.headers.get("authorization", "").replace("Bearer ", "")
    path = request.url.path
    if path == "/api/orders":                       # koleksiyon → aktörün kendi siparişi
        own = TOKEN_OWNER.get(tok)
        return httpx.Response(200, json=[ORDERS[own]] if own else [])
    if path.startswith("/api/orders/"):             # IDOR: sahiplik kontrolü YOK
        oid = path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=ORDERS[oid]) if oid in ORDERS else httpx.Response(404, json={})
    if path == "/api/admin/users":                  # BFLA: rol kontrolü YOK
        return httpx.Response(200, json={"users": [{"id": 1}, {"id": 2}]})
    return httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_full_recon_scan_finds_idor_and_bfla():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(app_handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"})))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"})))
    admin = store.create(Actor(name="admin", role="admin", auth=AuthState(headers={"Authorization": "Bearer ADMIN"})))

    findings = await scanner.run_recon_scan([A, B, admin], ENDPOINTS)

    # crawl bootstrap: aktörler kendi id'lerini keşfetti
    assert A.actor.own_object_ids.get("orders") == "A1"
    assert B.actor.own_object_ids.get("orders") == "B1"

    idor_confirmed = [f for f in findings if f.type == "idor" and f.verdict == "CONFIRMED"]
    bfla_confirmed = [f for f in findings if f.type == "bfla" and f.verdict == "CONFIRMED"]
    assert idor_confirmed, "IDOR CONFIRMED bekleniyordu"
    assert bfla_confirmed, "BFLA CONFIRMED bekleniyordu"
    assert any("alice@test.local" in f.evidence.leaked_markers for f in idor_confirmed)

    await store.aclose_all()
