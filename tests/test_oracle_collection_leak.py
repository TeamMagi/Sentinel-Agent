"""Çapraz-kiracı koleksiyon/liste BOLA oracle'ı (recall). Ağsız (MockTransport)."""
from __future__ import annotations

import httpx

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import CollectionLeakOracle
from pentestai.oracle.base import CONFIRMED, INCONCLUSIVE, REJECTED
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="GET", path_template="/api/orders", id_param="id")   # id-siz koleksiyon
A_ITEM = {"id": "A-100", "email": "alice@t.local"}
B_ITEM = {"id": "B-200", "email": "bob@t.local"}


def _run(handler):
    async def _go():
        store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
        A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
                  own_object_ids={"order": "A-100"})
        B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
                  own_object_ids={"order": "B-200"})
        oracle = CollectionLeakOracle(Replayer(PolicyEngine(
            Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"]))), BASE)
        try:
            return await oracle.run(EP, store.create(A), store.create(B), resource_key="order")
        finally:
            await store.aclose_all()
    import asyncio
    return asyncio.run(_go())


def _tok(request):
    return request.headers.get("authorization", "").replace("Bearer ", "")


def test_confirmed_when_b_list_leaks_a_items():
    def handler(request):
        if _tok(request) == "TOKEN_A":
            return httpx.Response(200, json={"orders": [A_ITEM]})
        return httpx.Response(200, json={"orders": [B_ITEM, A_ITEM]})   # B, A'yı da görüyor → sızıntı
    f = _run(handler)
    assert f.verdict == CONFIRMED and f.type == "bola"
    assert "A-100" in f.evidence.leaked_markers


def test_rejected_when_lists_are_properly_scoped():
    def handler(request):
        if _tok(request) == "TOKEN_A":
            return httpx.Response(200, json={"orders": [A_ITEM]})
        return httpx.Response(200, json={"orders": [B_ITEM]})           # her aktör yalnız kendi verisi
    f = _run(handler)
    assert f.verdict == REJECTED
    assert f.evidence.negative_control is True                         # kapsam var, sızıntı yok


def test_rejected_public_catalog_identical_content():
    catalog = {"products": [{"id": "P-1"}, {"id": "P-2"}]}
    f = _run(lambda r: httpx.Response(200, json=catalog))              # herkese AYNI liste
    assert f.verdict == REJECTED
    assert f.evidence.negative_control is False                        # public → per-kullanıcı kapsam yok


def test_inconclusive_when_actor_cannot_list():
    def handler(request):
        if _tok(request) == "TOKEN_A":
            return httpx.Response(200, json={"orders": [A_ITEM]})
        return httpx.Response(500, json={"error": "boom"})             # B listeleyemedi
    assert _run(handler).verdict == INCONCLUSIVE


def test_short_ids_not_treated_as_markers():
    """Kısa/tesadüfi değerler (≥3 karakter değil) kanıt sayılmaz — FP güvenliği."""
    async def _go():
        store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"orders": [{"id": "7"}]}) if _tok(r) == "TOKEN_A"
            else httpx.Response(200, json={"orders": [{"id": "9"}, {"id": "7"}]})))
        A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
                  own_object_ids={"order": "7"})                       # kısa id (1 karakter)
        B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
                  own_object_ids={"order": "9"})
        oracle = CollectionLeakOracle(Replayer(PolicyEngine(
            Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"]))), BASE)
        try:
            return await oracle.run(EP, store.create(A), store.create(B), resource_key="order")
        finally:
            await store.aclose_all()
    import asyncio
    f = asyncio.run(_go())
    assert f.verdict == REJECTED           # "7" kısa → marker sayılmaz → yanlış CONFIRMED yok
