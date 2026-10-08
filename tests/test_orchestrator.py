"""Scanner orchestrator — recon→plan→(crawl bootstrap)→IDOR+BFLA. DESIGN.md §14.

Sahte uygulama: koleksiyon (/api/orders), IDOR (/api/orders/{id}), BFLA (/api/admin/users).
Tek akışta crawl id keşfi + hipotez üretimi + iki oracle dispatch'i doğrulanır.
"""
import json

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

    # R-D1: her bulgu keşfeden/kurban aktörle etiketli ("found as user_A").
    assert all(f.found_as and f.victim_as for f in findings)
    assert all(f.victim_as == "admin" for f in bfla_confirmed)   # bfla: victim=admin, attacker=low
    assert all(f.found_as in ("user_A", "user_B") for f in bfla_confirmed)
    # R-B1 yetki matrisi (kod-tarama-raporu.md #6): tek-aktör alt-taramalar dahil (ör.
    # excessive_data_exposure) `victim`/`attacker` de dolu olmalı, yalnızca `*_as` alanları değil.
    assert all(f.victim and f.attacker for f in findings)

    await store.aclose_all()


# --- R-A1: canary planting Scanner'a uçtan uca kablolu mı? ---
# GET+PUT aynı resource_key'i ("orders") paylaşıyor → run_hypotheses, state_change_authz
# hipotezinden PUT endpoint'ini bulup victim'e canary yazmalı, sonra idor.run'a geçirmeli.
CANARY_ORDERS: dict = {
    "A1": {"id": "A1", "owner": "user_A"},
    "B1": {"id": "B1", "owner": "user_B"},
}
CANARY_ENDPOINTS = [
    Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"),
    Endpoint(method="PUT", path_template="/api/orders/{id}", id_param="id"),
]


def canary_app_handler(request):
    tok = request.headers.get("authorization", "").replace("Bearer ", "")
    path = request.url.path
    if path == "/api/orders":
        own = TOKEN_OWNER.get(tok)
        return httpx.Response(200, json=[CANARY_ORDERS[own]] if own else [])
    if path.startswith("/api/orders/"):
        oid = path.rsplit("/", 1)[-1]
        obj = CANARY_ORDERS.get(oid)
        if obj is None:
            return httpx.Response(404, json={})
        if request.method == "PUT":
            obj.update(json.loads(request.content or b"{}"))   # canary kalıcı yazılır
            return httpx.Response(200, json=obj)
        return httpx.Response(200, json=obj)                    # GET: sahiplik kontrolü YOK → IDOR
    return httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_idor_confirmed_via_planted_canary_through_scanner():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "PUT"], destructive_tests=True)
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(canary_app_handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"})))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"})))
    A.actor.own_object_ids["orders"] = "A1"
    B.actor.own_object_ids["orders"] = "B1"

    findings = await scanner.run_hypotheses(
        [A, B], await scanner.planner.generate(CANARY_ENDPOINTS))

    idor_confirmed = [f for f in findings if f.type == "idor" and f.verdict == "CONFIRMED"]
    assert idor_confirmed, "canary ile CONFIRMED IDOR bekleniyordu"
    assert any(f.evidence.canary_planted for f in idor_confirmed), \
        "run_hypotheses canary'yi planlayıp IdorOracle'a geçirmeliydi"
    assert any(f.evidence.canary_planted in f.evidence.leaked_markers for f in idor_confirmed)

    await store.aclose_all()
