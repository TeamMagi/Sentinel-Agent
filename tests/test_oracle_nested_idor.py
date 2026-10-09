"""NestedIdorOracle — iç-içe body id + ikinci-el (dolaylı) referans IDOR. R-B2.

IdorOracle'ın üç kontrolü + leaked-marker kanıtı AYNEN korunur; yalnızca (a) isteğin nasıl
kurulduğu (nested body) ve (b) hedef id'nin nasıl türetildiği (kaynak yanıttan) değişir.
"""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.nested_idor import NestedIdorOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
TOKEN_ACTOR = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}


def _actor_of(request):
    return TOKEN_ACTOR.get(request.headers.get("authorization", "").replace("Bearer ", ""))


# --- (1) iç-içe body id: POST /api/getOrder {"filter":{"orderId":"X"},"page":1} ---

ORDERS = {
    "A-1": {"id": "A-1", "owner": "user_A", "email": "alice@test.local", "total": 10},
    "B-2": {"id": "B-2", "owner": "user_B", "email": "bob@test.local", "total": 42},
}


def body_nested_app(*, secure: bool):
    def handler(request):
        body = json.loads(request.content or b"{}")
        oid = body.get("filter", {}).get("orderId")
        obj = ORDERS.get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if secure and obj["owner"] != _actor_of(request):
            return httpx.Response(403, json={"error": "forbidden"})   # sahiplik kontrolü
        return httpx.Response(200, json=obj)
    return handler


def _setup_body(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["POST"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": "A-1"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": "B-2"})
    ep = Endpoint(method="POST", path_template="/api/getOrder")
    oracle = NestedIdorOracle(Replayer(PolicyEngine(scope)), BASE,
                              body_path="filter.orderId", template_body={"filter": {}, "page": 1})
    return store, oracle, ep, store.create(A), store.create(B)


@pytest.mark.asyncio
async def test_body_nested_idor_confirmed():
    store, oracle, ep, A, B = _setup_body(body_nested_app(secure=False))
    f = await oracle.run(ep, B, A, resource_key="order")   # victim=B, attacker=A (A, B'nin id'siyle)
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("bob@test.local" in m for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_body_nested_idor_rejected_when_ownership_enforced():
    store, oracle, ep, A, B = _setup_body(body_nested_app(secure=True))
    f = await oracle.run(ep, B, A, resource_key="order")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


# --- (2) ikinci-el: GET /api/orders/{id} → invoiceId; GET /api/invoices/{invoiceId} ---

ORDER_REFS = {"O-A": {"id": "O-A", "invoiceId": "INV-A"}, "O-B": {"id": "O-B", "invoiceId": "INV-B"}}
INVOICES = {
    "INV-A": {"id": "INV-A", "owner": "user_A", "email": "alice@test.local", "amount": 10},
    "INV-B": {"id": "INV-B", "owner": "user_B", "email": "bob@test.local", "amount": 42},
}


def second_order_app(*, secure: bool):
    def handler(request):
        path = request.url.path
        oid = path.rsplit("/", 1)[-1]
        if path.startswith("/api/orders/"):
            obj = ORDER_REFS.get(oid)
            return httpx.Response(200, json=obj) if obj else httpx.Response(404, json={})
        if path.startswith("/api/invoices/"):
            obj = INVOICES.get(oid)
            if obj is None:
                return httpx.Response(404, json={"error": "not found"})
            if secure and obj["owner"] != _actor_of(request):
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json=obj)
        return httpx.Response(404, json={})
    return handler


def _setup_second_order(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"orders": "O-A"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"orders": "O-B"})
    fetch_ep = Endpoint(method="GET", path_template="/api/invoices/{id}", id_param="id")
    source_ep = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
    oracle = NestedIdorOracle(Replayer(PolicyEngine(scope)), BASE,
                              source_endpoint=source_ep, source_field="invoiceId")
    return store, oracle, fetch_ep, store.create(A), store.create(B)


@pytest.mark.asyncio
async def test_second_order_idor_confirmed():
    store, oracle, ep, A, B = _setup_second_order(second_order_app(secure=False))
    f = await oracle.run(ep, B, A, resource_key="invoice")   # victim=B, attacker=A
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("bob@test.local" in m for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_second_order_idor_rejected_when_ownership_enforced():
    store, oracle, ep, A, B = _setup_second_order(second_order_app(secure=True))
    f = await oracle.run(ep, B, A, resource_key="invoice")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_second_order_inconclusive_when_source_ref_missing():
    # kaynak endpoint referans id döndürmezse (nested alan yok) hedef id türetilemez → INCONCLUSIVE
    def handler(request):
        if request.url.path.startswith("/api/orders/"):
            return httpx.Response(200, json={"id": "x"})   # invoiceId YOK
        return httpx.Response(404, json={})
    store, oracle, ep, A, B = _setup_second_order(handler)
    f = await oracle.run(ep, B, A, resource_key="invoice")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
