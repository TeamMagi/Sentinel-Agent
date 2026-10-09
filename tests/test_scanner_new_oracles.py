"""Yeni iki oracle'ın (NestedIdorOracle, JwtForgeAccessOracle) Scanner boru hattına UÇTAN UCA
kablolu olduğunu doğrular. Amaç: birim testlerinde çalışan oracle'ların gerçek `run_hypotheses`
dispatch'inden de tetiklenip CONFIRMED üretmesi (aksi halde oracle "orphan" — canlı tarama bulmaz).

Ağsız (MockTransport). İki senaryo:
  A) jwt_privilege_escalation → imza doğrulamayan /api/me'de claim forge (yatay kimlik yükseltme)
  B) nested_idor → iç-içe gövde alanında ("filter.orderId") IDOR
"""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Hypothesis, Scope
from pentestai.net import SessionStore
from pentestai.oracle.jwt_forge import encode_hs256
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"

USERS = {
    "user_A": {"sub": "user_A", "email": "alice@test.local", "balance": 1000},
    "user_B": {"sub": "user_B", "email": "bob@test.local", "balance": 2000},
}


# --- A) JWT forge: /api/me imzayı doğrulamaz, kimliği token'daki sub'tan alır ---

def me_insecure_app(request):
    tok = request.headers.get("authorization", "").replace("Bearer ", "")
    parts = tok.split(".")
    if len(parts) != 3:
        return httpx.Response(401, json={})
    import base64
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(pad))
    except Exception:
        return httpx.Response(401, json={})
    obj = USERS.get(payload.get("sub"))
    return httpx.Response(200, json=obj) if obj else httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_run_hypotheses_dispatches_jwt_privilege_escalation():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_path_prefixes=["/"], allowed_methods=["GET"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(me_insecure_app))
    A = store.create(Actor(name="user_A", auth=AuthState(
        headers={"Authorization": f"Bearer {encode_hs256({'sub': 'user_A', 'role': 'user'}, 'x')}"})))
    B = store.create(Actor(name="user_B", auth=AuthState(
        headers={"Authorization": f"Bearer {encode_hs256({'sub': 'user_B', 'role': 'user'}, 'x')}"})))

    ep = Endpoint(method="GET", path_template="/api/me")
    hyp = Hypothesis(type="jwt_privilege_escalation", endpoint=ep, source="deterministic")
    findings = await scanner.run_hypotheses([A, B], [hyp])

    confirmed = [f for f in findings
                 if f.type == "jwt_privilege_escalation" and f.verdict == "CONFIRMED"]
    assert confirmed, "JWT forge CONFIRMED bekleniyordu (oracle dispatch'e kablolu değil?)"
    assert all(f.victim and f.attacker for f in confirmed)   # R-B1 matris etiketi
    await store.aclose_all()


# --- B) nested_idor: iç-içe gövde alanı (filter.orderId) IDOR ---

ORDERS = {
    "A-1": {"id": "A-1", "owner": "user_A", "email": "alice@test.local", "total": 10},
    "B-2": {"id": "B-2", "owner": "user_B", "email": "bob@test.local", "total": 42},
}


def body_nested_insecure_app(request):
    body = json.loads(request.content or b"{}")
    oid = body.get("filter", {}).get("orderId")
    obj = ORDERS.get(oid)
    if obj is None:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=obj)   # sahiplik kontrolü YOK → IDOR


@pytest.mark.asyncio
async def test_run_hypotheses_dispatches_nested_idor():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["POST"], destructive_tests=True)
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(body_nested_insecure_app))
    A = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
                           own_object_ids={"getOrder": "A-1"}))
    B = store.create(Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
                           own_object_ids={"getOrder": "B-2"}))

    ep = Endpoint(method="POST", path_template="/api/getOrder")
    hyp = Hypothesis(type="nested_idor", endpoint=ep, body_path="filter.orderId",
                     template_body={"filter": {}, "page": 1}, source="deterministic")
    findings = await scanner.run_hypotheses([A, B], [hyp])

    confirmed = [f for f in findings if f.type == "idor" and f.verdict == "CONFIRMED"]
    assert confirmed, "nested_idor CONFIRMED bekleniyordu (oracle dispatch'e kablolu değil?)"
    assert any(any("bob@test.local" in m or "alice@test.local" in m for m in f.evidence.leaked_markers)
               for f in confirmed)
    await store.aclose_all()
