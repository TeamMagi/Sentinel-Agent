"""MethodBypassOracle — alternatif HTTP method / override header ile yetki atlatma. A1 (Tier A).

Obje-seviyesi (id'li): DELETE ownership kontrol ediyor ama PUT aynı işlemi kontrolsüz yapıyor
(vulnerable) → alt-method bypass CONFIRMED. Fonksiyon-seviyesi (id'siz, BFLA deseni): admin-only
DELETE korumalı ama PUT korumasız → aynı bypass, bu kez victim=admin pozitif kontrolü verir.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.method_bypass import MethodBypassOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP_OBJECT = Endpoint(method="DELETE", path_template="/api/orders/{id}", id_param="id")
EP_FUNC = Endpoint(method="DELETE", path_template="/api/admin/cache", id_param="id")


def _id_of(request):
    return request.url.path.rsplit("/", 1)[-1]


def _actor_of(request):
    return {"TOKEN_A": "user_A", "TOKEN_B": "user_B", "TOKEN_ADMIN": "admin"}.get(
        request.headers.get("authorization", "").replace("Bearer ", ""))


def make_object_app(*, put_bypasses: bool):
    """DELETE ownership kontrol eder; PUT `put_bypasses` ise AYNI silmeyi kontrolsüz yapar."""
    db = {"A-1": {"id": "A-1", "owner": "user_A"}, "B-2": {"id": "B-2", "owner": "user_B"}}

    def handler(request):
        oid, actor, method = _id_of(request), _actor_of(request), request.method.upper()
        obj = db.get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if method == "DELETE":
            if obj["owner"] != actor:
                return httpx.Response(403, json={"error": "forbidden"})
            db.pop(oid, None)
            return httpx.Response(200, json={"status": "success"})
        if method == "PUT":
            if not put_bypasses and obj["owner"] != actor:
                return httpx.Response(403, json={"error": "forbidden"})
            db.pop(oid, None)
            return httpx.Response(200, json={"status": "success"})
        return httpx.Response(405, json={"error": "method"})

    return handler


def make_func_app(*, put_bypasses: bool):
    def handler(request):
        actor, method = _actor_of(request), request.method.upper()
        if method == "DELETE":
            if actor != "admin":
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json={"status": "cleared"})
        if method == "PUT":
            if not put_bypasses and actor != "admin":
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json={"status": "cleared"})
        return httpx.Response(405, json={"error": "method"})

    return handler


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
                  destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": "A-1"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": "B-2"})
    admin = Actor(name="admin", role="admin", auth=AuthState(headers={"Authorization": "Bearer TOKEN_ADMIN"}))
    oracle = MethodBypassOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A), store.create(B), store.create(admin)


@pytest.mark.asyncio
async def test_confirmed_object_level_alt_method_bypass():
    store, oracle, A, B, _ = _setup(make_object_app(put_bypasses=True))
    f = await oracle.run(EP_OBJECT, A, B, resource_key="order")   # victim=A, attacker=B
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.positive_control and f.evidence.negative_control
    assert "method=PUT" in f.evidence.leaked_markers[0]
    assert f.evidence.attack_request.method == "PUT"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_object_level_when_all_methods_checked():
    store, oracle, A, B, _ = _setup(make_object_app(put_bypasses=False))
    f = await oracle.run(EP_OBJECT, A, B, resource_key="order")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_function_level_alt_method_bypass():
    store, oracle, _, B, admin = _setup(make_func_app(put_bypasses=True))
    f = await oracle.run(EP_FUNC, admin, B, resource_key="")   # victim=admin, attacker=low
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_function_level_when_all_methods_checked():
    store, oracle, _, B, admin = _setup(make_func_app(put_bypasses=False))
    f = await oracle.run(EP_FUNC, admin, B, resource_key="")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_victim_id_missing():
    store, oracle, A, B, _ = _setup(make_object_app(put_bypasses=True))
    A.actor.own_object_ids.clear()
    f = await oracle.run(EP_OBJECT, A, B, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_destructive_tests_disabled():
    # policy kapısı yıkıcı method'ları reddeder → tüm varyantlar ScopeError ile elenir,
    # kontroller de geçemez (positive/negative control da yazma method'u kullanır) → INCONCLUSIVE.
    store, oracle, A, B, _ = _setup(make_object_app(put_bypasses=True))
    oracle.replayer.policy.scope = oracle.replayer.policy.scope.model_copy(
        update={"destructive_tests": False})
    f = await oracle.run(EP_OBJECT, A, B, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
