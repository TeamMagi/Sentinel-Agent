"""CsrfOracle — CSRF token'sız durum-değiştiren istek geçiyor mu? B1."""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, CSRFConfig, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.csrf import CsrfOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="PUT", path_template="/api/orders/{id}", id_param="id")


def make_app(*, csrf_enforced: bool):
    db = {"A-1": {"id": "A-1", "quantity": 1}}

    def handler(request):
        if request.url.path == "/csrf-token":
            return httpx.Response(200, json={"csrfToken": "real-token"})
        oid = request.url.path.rsplit("/", 1)[-1]
        obj = db.get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if request.method == "GET":
            return httpx.Response(200, json=obj)
        if csrf_enforced and request.headers.get("x-csrf-token") != "real-token":
            return httpx.Response(403, json={"error": "invalid csrf token"})
        body = json.loads(request.content or b"{}")
        obj.update(body)
        return httpx.Response(200, json=obj)

    return handler


def _setup(handler, *, with_csrf_cfg: bool = True, bearer: bool = False):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "PUT"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    csrf = CSRFConfig(fetch_url=f"{BASE}/csrf-token", extract="json:csrfToken") if with_csrf_cfg else None
    # bearer=True → auth başlık-tabanlı (Authorization); aksi halde ambient (cookie/başlıksız).
    headers = {"Authorization": "Bearer TOKEN_A"} if bearer else {}
    A = Actor(name="user_A", auth=AuthState(headers=headers, csrf=csrf), own_object_ids={"order": "A-1"})
    oracle = CsrfOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A)


@pytest.mark.asyncio
async def test_confirmed_when_csrf_not_enforced():
    store, oracle, A = _setup(make_app(csrf_enforced=False))
    f = await oracle.run(EP, A, A, resource_key="order")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.negative_control and f.evidence.positive_control
    assert "4271" in f.evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_likely_when_bearer_auth_not_ambient():
    """P1-FP düzeltmesi: token'sız yazma geçse bile auth başlık-tabanlıysa (bearer) tarayıcı
    başlığı cross-site göndermez → CSRF sömürülemez → CONFIRMED değil, LIKELY + not."""
    store, oracle, A = _setup(make_app(csrf_enforced=False), bearer=True)
    f = await oracle.run(EP, A, A, resource_key="order")
    assert f.verdict == base.LIKELY and f.confidence == "medium"
    assert f.verdict != base.CONFIRMED
    assert f.triage_note
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_csrf_enforced():
    store, oracle, A = _setup(make_app(csrf_enforced=True))
    f = await oracle.run(EP, A, A, resource_key="order")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_no_csrf_configured():
    store, oracle, A = _setup(make_app(csrf_enforced=True), with_csrf_cfg=False)
    f = await oracle.run(EP, A, A, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_destructive_tests_disabled():
    store, oracle, A = _setup(make_app(csrf_enforced=False))
    oracle.replayer.policy.scope = oracle.replayer.policy.scope.model_copy(
        update={"destructive_tests": False})
    f = await oracle.run(EP, A, A, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
