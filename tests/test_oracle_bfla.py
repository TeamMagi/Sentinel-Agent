"""BflaOracle — function-level authz. DESIGN.md §14 (Stage 1)."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.bfla import BflaOracle
from pentestai.policy import PolicyEngine

TOKEN_ROLE = {"ADMIN": "admin", "LOW": "user"}
ENDPOINT = Endpoint(method="GET", path_template="/api/admin/users", id_param="id")
BASE = "http://localhost:3000"
ADMIN_BODY = {"users": [{"id": 1, "email": "a@x"}, {"id": 2, "email": "b@x"}]}


def _role(request):
    return TOKEN_ROLE.get(request.headers.get("authorization", "").replace("Bearer ", ""))


def vulnerable_handler(request):
    return httpx.Response(200, json=ADMIN_BODY)          # yetki kontrolü YOK → BFLA


def secure_handler(request):
    if _role(request) == "admin":
        return httpx.Response(200, json=ADMIN_BODY)
    return httpx.Response(403, json={"error": "forbidden"})


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    admin = Actor(name="admin", role="admin", auth=AuthState(headers={"Authorization": "Bearer ADMIN"}))
    low = Actor(name="user_low", role="user", auth=AuthState(headers={"Authorization": "Bearer LOW"}))
    oracle = BflaOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(admin), store.create(low)


@pytest.mark.asyncio
async def test_confirmed_on_vulnerable():
    store, oracle, admin, low = _setup(vulnerable_handler)
    f = await oracle.run(ENDPOINT, admin, low)   # victim=admin, attacker=low
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.positive_control is True
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_on_secure():
    store, oracle, admin, low = _setup(secure_handler)
    f = await oracle.run(ENDPOINT, admin, low)
    assert f.verdict == base.REJECTED
    await store.aclose_all()
