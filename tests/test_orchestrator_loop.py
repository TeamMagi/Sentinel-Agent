"""Stage 2 — HypothesisExpander + self-improving Pipeline. DESIGN.md §14.

Döngü: /api/orders/{id} IDOR CONFIRMED → cevaptaki 'profileId'den /api/profiles/{id}
türetilir (başlangıç recon'unda YOK) → bootstrap → orada da IDOR CONFIRMED.
"""
import httpx
import pytest

from pentestai.models import (
    Actor, AuthState, BudgetConfig, Endpoint, Evidence, Finding, NormalizedResponse, Scope,
)
from pentestai.net import SessionStore
from pentestai.orchestrator import HypothesisExpander, Pipeline
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


# ---------------- HypothesisExpander birim testi ----------------

def _confirmed(json_body) -> Finding:
    return Finding(
        id="F-001", type="idor", endpoint="/api/orders/{id}", method="GET", parameter="id",
        verdict="CONFIRMED", confidence="high",
        evidence=Evidence(attack_response=NormalizedResponse(status=200, json_body=json_body)),
    )


def test_expander_matches_known_and_synthesizes():
    exp = HypothesisExpander([Endpoint(method="GET", path_template="/api/users/{id}", id_param="id")])
    hyps = exp.expand(_confirmed({"id": "A1", "userId": "U-9", "profileId": "P-3"}))
    paths = {h.endpoint.path_template for h in hyps}
    assert "/api/users/{id}" in paths        # bilinen endpoint eşleşti (userId)
    assert "/api/profiles/{id}" in paths      # bilinmeyen → sentezlendi (profileId)


def test_expander_ignores_non_confirmed():
    exp = HypothesisExpander([Endpoint(method="GET", path_template="/api/users/{id}")])
    f = _confirmed({"userId": "U-9"})
    f.verdict = "REJECTED"
    assert exp.expand(f) == []


# ---------------- self-improving Pipeline entegrasyonu ----------------

ORDERS = {"A1": {"id": "A1", "email": "alice@t.local", "profileId": "P-A"},
          "B1": {"id": "B1", "email": "bob@t.local", "profileId": "P-B"}}
PROFILES = {"P-A": {"id": "P-A", "email": "alice@t.local", "phone": "5550001111"},
            "P-B": {"id": "P-B", "email": "bob@t.local", "phone": "5550002222"}}
TOKEN_ORDER = {"A": "A1", "B": "B1"}
TOKEN_PROFILE = {"A": "P-A", "B": "P-B"}


def app_handler(request):
    tok = request.headers.get("authorization", "").replace("Bearer ", "")
    p = request.url.path
    if p == "/api/orders":
        o = TOKEN_ORDER.get(tok)
        return httpx.Response(200, json=[ORDERS[o]] if o else [])
    if p.startswith("/api/orders/"):
        oid = p.rsplit("/", 1)[-1]
        return httpx.Response(200, json=ORDERS[oid]) if oid in ORDERS else httpx.Response(404, json={})
    if p == "/api/profiles":
        pr = TOKEN_PROFILE.get(tok)
        return httpx.Response(200, json=[PROFILES[pr]] if pr else [])
    if p.startswith("/api/profiles/"):
        pid = p.rsplit("/", 1)[-1]
        return httpx.Response(200, json=PROFILES[pid]) if pid in PROFILES else httpx.Response(404, json={})
    return httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_self_improving_loop_discovers_pivot_endpoint():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(app_handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"})))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"})))

    # başlangıç recon'u SADECE orders — profiles yok
    initial = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]
    pipeline = Pipeline(scanner, initial, max_iterations=30)
    state = await pipeline.run([A, B])

    # döngü profiles endpoint'ini pivotla keşfetti
    assert any("/api/profiles/{id}" in t for t in pipeline.transitions if t.startswith("EXPAND"))

    confirmed = {(f.type, f.endpoint) for f in state.findings if f.verdict == "CONFIRMED"}
    assert ("idor", "/api/orders/{id}") in confirmed
    assert ("idor", "/api/profiles/{id}") in confirmed   # yalnızca self-improving ile bulundu

    await store.aclose_all()
