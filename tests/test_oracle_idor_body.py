"""IDOR — gövde (body) konumlu obje id'si + UUID id (R-B2). Network yok.

Obje id'si URL yerine JSON gövdesinde taşındığında da IDOR yakalanmalı; ayrıca id int
değil UUID olduğunda da akış çalışmalı (string id path'te).
"""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import IdorOracle, base
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"

DB = {
    "A-100": {"id": "A-100", "email": "alice@test.local", "owner": "user_A"},
    "B-200": {"id": "B-200", "email": "bob@test.local", "owner": "user_B"},
}
UUID_DB = {
    "11111111-1111-1111-1111-111111111111": {"email": "alice@test.local", "owner": "user_A"},
    "22222222-2222-2222-2222-222222222222": {"email": "bob@test.local", "owner": "user_B"},
}


def _body_id(request, field):
    try:
        return json.loads(request.content or b"{}").get(field)
    except ValueError:
        return None


def body_vuln_handler(request):
    """Obje id'si gövdede; ownership kontrolü YOK → IDOR."""
    oid = _body_id(request, "orderId")
    if oid not in DB:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=DB[oid])


def uuid_vuln_handler(request):
    oid = request.url.path.rsplit("/", 1)[-1]
    if oid not in UUID_DB:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=UUID_DB[oid])


def _setup(handler, endpoint, rk, a_id, b_id):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={rk: a_id})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={rk: b_id})
    oracle = IdorOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A), store.create(B)


@pytest.mark.asyncio
async def test_idor_confirmed_with_body_located_id():
    ep = Endpoint(method="GET", path_template="/api/getOrder", id_param="orderId", id_location="body")
    store, oracle, A, B = _setup(body_vuln_handler, ep, "getOrder", "A-100", "B-200")
    f = await oracle.run(ep, A, B, resource_key="getOrder")
    await store.aclose_all()
    assert f.verdict == base.CONFIRMED
    assert "alice@test.local" in f.evidence.leaked_markers
    # kanıt isteği gerçekten gövdede id taşıyor (redaction sonrası yine JSON gövdesi)
    assert b"orderId" in (f.evidence.attack_request.body or b"")


@pytest.mark.asyncio
async def test_idor_confirmed_with_uuid_id():
    ep = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
    store, oracle, A, B = _setup(
        uuid_vuln_handler, ep, "orders",
        "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
    f = await oracle.run(ep, A, B, resource_key="orders")
    await store.aclose_all()
    assert f.verdict == base.CONFIRMED
    assert "alice@test.local" in f.evidence.leaked_markers
