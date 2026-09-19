"""StoredXssOracle — store→retrieve iki-adım XSS testi. B3."""
import json

import httpx
import pytest

from pentestai.models import Actor, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.stored_xss import StoredXssOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="PUT", path_template="/api/profiles/{id}", id_param="id")


def make_app(*, escapes_output: bool):
    db = {"P-1": {"id": "P-1", "comment": ""}}

    def _escape(s: str) -> str:
        return s.replace("<", "&lt;").replace(">", "&gt;")

    def handler(request):
        oid = request.url.path.rsplit("/", 1)[-1]
        obj = db.get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if request.method == "PUT":
            body = json.loads(request.content or b"{}")
            obj["comment"] = body.get("comment", "")
            return httpx.Response(200, json=obj)
        # GET: depolanan veriyi döndür (escapes_output=True → çıktı escape edilir)
        out = dict(obj)
        if escapes_output:
            out["comment"] = _escape(out["comment"])
        return httpx.Response(200, json=out)

    return handler


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "PUT"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", own_object_ids={"profile": "P-1"})
    oracle = StoredXssOracle(Replayer(PolicyEngine(scope)), BASE, field_name="comment")
    return store, oracle, store.create(A)


@pytest.mark.asyncio
async def test_confirmed_when_stored_unescaped():
    store, oracle, A = _setup(make_app(escapes_output=False))
    f = await oracle.run(EP, A, A, resource_key="profile")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_output_escaped():
    store, oracle, A = _setup(make_app(escapes_output=True))
    f = await oracle.run(EP, A, A, resource_key="profile")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_read_only_endpoint():
    store, oracle, A = _setup(make_app(escapes_output=False))
    get_ep = Endpoint(method="GET", path_template="/api/profiles/{id}", id_param="id")
    f = await oracle.run(get_ep, A, A, resource_key="profile")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_victim_id_missing():
    store, oracle, A = _setup(make_app(escapes_output=False))
    A.actor.own_object_ids.clear()
    f = await oracle.run(EP, A, A, resource_key="profile")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_destructive_tests_disabled():
    store, oracle, A = _setup(make_app(escapes_output=False))
    oracle.replayer.policy.scope = oracle.replayer.policy.scope.model_copy(
        update={"destructive_tests": False})
    f = await oracle.run(EP, A, A, resource_key="profile")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
