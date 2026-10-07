"""StateChangingOracle — yazma/silme yetki testi (v1). DESIGN.md §14.

Sahte durumlu uygulama (MockTransport): vulnerable → saldırgan kurbanın objesini siler/değiştirir
(CONFIRMED, kalıcı mutasyon kanıtı); secure → ownership check 403 döner (REJECTED).

NOT: destructive_tests bayrağının PolicyEngine.authorize'a bağlanması ve Juice Shop canlı
doğrulaması Görev 10'dadır; burada scope, yazma method'larına izin verecek şekilde kurulur.
"""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.state_change import StateChangingOracle
from pentestai.policy import PolicyEngine

TOKEN_ACTOR = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}
BASE = "http://localhost:3000"


def _id_of(request):
    return request.url.path.rsplit("/", 1)[-1]


def _actor_of(request):
    return TOKEN_ACTOR.get(request.headers.get("authorization", "").replace("Bearer ", ""))


def make_app(secure: bool):
    """Durumlu sahte API: GET/PUT/DELETE + opsiyonel ownership kontrolü."""
    db = {
        "A-1": {"id": "A-1", "owner": "user_A", "quantity": 1},
        "B-2": {"id": "B-2", "owner": "user_B", "quantity": 1},
    }

    def handler(request):
        oid = _id_of(request)
        actor = _actor_of(request)
        method = request.method.upper()
        obj = db.get(oid)

        if method == "GET":
            if obj is None:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json=obj)

        # state-changing: obje yoksa 404 (negative control bunu bekler)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if secure and obj["owner"] != actor:
            return httpx.Response(403, json={"error": "forbidden"})

        if method == "DELETE":
            db.pop(oid, None)
            return httpx.Response(200, json={"status": "success"})
        if method in ("PUT", "PATCH"):
            body = json.loads(request.content or b"{}")
            obj.update(body)                       # ownership check YOK (vulnerable) → mutasyon geçer
            return httpx.Response(200, json=obj)
        return httpx.Response(405, json={"error": "method"})

    return handler


def _setup(handler, method):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "PUT", "PATCH", "DELETE"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": "A-1"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": "B-2"})
    endpoint = Endpoint(method=method, path_template="/api/orders/{id}", id_param="id")
    oracle = StateChangingOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, endpoint, store.create(A), store.create(B)


@pytest.mark.asyncio
async def test_confirmed_delete_on_vulnerable():
    store, oracle, ep, A, B = _setup(make_app(secure=False), "DELETE")
    f = await oracle.run(ep, A, B, resource_key="order")   # victim=A, attacker=B
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.positive_control and f.evidence.negative_control and f.evidence.baseline_stable
    assert f.evidence.leaked_markers            # kalıcı silme kanıtı
    assert "-X DELETE" in f.evidence.repro_curl
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_delete_on_secure():
    store, oracle, ep, A, B = _setup(make_app(secure=True), "DELETE")
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_put_persisted_mutation():
    store, oracle, ep, A, B = _setup(make_app(secure=False), "PUT")
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("8931" in m for m in f.evidence.leaked_markers)   # sentinel kurbanın objesine yazıldı
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_put_on_secure():
    store, oracle, ep, A, B = _setup(make_app(secure=True), "PUT")
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_victim_id_missing():
    store, oracle, ep, A, B = _setup(make_app(secure=False), "DELETE")
    A.actor.own_object_ids.clear()               # kurbanın kendi id'si yok
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
