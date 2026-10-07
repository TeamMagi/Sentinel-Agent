"""MassAssignmentOracle — fazla alan (role/isAdmin) set oluyor mu? B1."""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.mass_assignment import MassAssignmentOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="PUT", path_template="/api/users/{id}", id_param="id")


def make_app(*, whitelisted: bool):
    """`whitelisted=False` → sunucu body'deki HER alanı körlemesine bind eder (vulnerable)."""
    db = {"U-1": {"id": "U-1", "quantity": 1, "role": "user"}}
    allowed_fields = {"quantity"}

    def handler(request):
        oid = request.url.path.rsplit("/", 1)[-1]
        obj = db.get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if request.method == "GET":
            return httpx.Response(200, json=obj)
        body = json.loads(request.content or b"{}")
        if whitelisted:
            obj.update({k: v for k, v in body.items() if k in allowed_fields})
        else:
            obj.update(body)   # ownership/whitelisting YOK — mass assignment
        return httpx.Response(200, json=obj)

    return handler


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "PUT"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", own_object_ids={"user": "U-1"})
    oracle = MassAssignmentOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A)


@pytest.mark.asyncio
async def test_confirmed_when_privilege_field_accepted():
    store, oracle, A = _setup(make_app(whitelisted=False))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("role" in m for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_server_whitelists_fields():
    store, oracle, A = _setup(make_app(whitelisted=True))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_already_privileged():
    # negatif kontrol: saldırgan zaten role=admin ise trivial false-positive olmasın
    def handler(request):
        oid = request.url.path.rsplit("/", 1)[-1]
        if request.method == "GET":
            return httpx.Response(200, json={"id": oid, "quantity": 1, "role": "admin"})
        return httpx.Response(200, json={"id": oid, "quantity": 1, "role": "admin"})

    store, oracle, A = _setup(handler)
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_attacker_id_missing():
    store, oracle, A = _setup(make_app(whitelisted=False))
    A.actor.own_object_ids.clear()
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_without_id_endpoint():
    store, oracle, A = _setup(make_app(whitelisted=False))
    ep_no_id = Endpoint(method="PUT", path_template="/api/settings", id_param="id")
    f = await oracle.run(ep_no_id, A, A, resource_key="user")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
