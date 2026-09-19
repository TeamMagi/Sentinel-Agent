"""UnauthorizedAccessOracle — kimlik doğrulamasız (anonim) erişim testi. A1 (Tier A).

BflaOracle'ın kontrol/verdict akışını yeniden kullanır; attacker burada auth header/cookie
TAŞIMAYAN anonim bir Session'dır (gerçek "kimlik doğrulama zorunlu mu?" testi).
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.unauthorized_access import UnauthorizedAccessOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
PROFILE_BODY = {"email": "victim@test.local", "balance": 500}
ADMIN_BODY = {"users": [{"id": 1}, {"id": 2}]}


def _role(request):
    return "victim" if request.headers.get("authorization") == "Bearer VICTIM" else None


def vulnerable_id_handler(request):
    return httpx.Response(200, json=PROFILE_BODY)         # auth kontrolü YOK — herkes 200 alıyor


def secure_id_handler(request):
    if _role(request) == "victim":
        return httpx.Response(200, json=PROFILE_BODY)
    return httpx.Response(401, json={"error": "unauthorized"})


def vulnerable_admin_handler(request):
    return httpx.Response(200, json=ADMIN_BODY)


def _setup(handler, endpoint):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    victim = Actor(name="victim", role="user", auth=AuthState(headers={"Authorization": "Bearer VICTIM"}),
                   own_object_ids={"profile": "42"})
    anon = Actor(name="anonymous", role="anonymous")     # HİÇ auth header/cookie yok
    oracle = UnauthorizedAccessOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(victim), store.create(anon)


@pytest.mark.asyncio
async def test_confirmed_on_id_endpoint_without_auth_check():
    ep = Endpoint(method="GET", path_template="/api/profile/{id}", id_param="id")
    store, oracle, victim, anon = _setup(vulnerable_id_handler, ep)
    f = await oracle.run(ep, victim, anon, resource_key="profile")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.type == "unauthorized_access"
    assert f.evidence.positive_control is True
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_auth_enforced():
    ep = Endpoint(method="GET", path_template="/api/profile/{id}", id_param="id")
    store, oracle, victim, anon = _setup(secure_id_handler, ep)
    f = await oracle.run(ep, victim, anon, resource_key="profile")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_on_function_endpoint_without_id():
    ep = Endpoint(method="GET", path_template="/api/admin/users", id_param="id")
    store, oracle, victim, anon = _setup(vulnerable_admin_handler, ep)
    f = await oracle.run(ep, victim, anon, resource_key="")
    assert f.verdict == base.CONFIRMED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_anon_session_carries_no_credentials():
    ep = Endpoint(method="GET", path_template="/api/profile/{id}", id_param="id")
    store, oracle, victim, anon = _setup(secure_id_handler, ep)
    assert anon.actor.auth.headers == {} and anon.actor.auth.cookies == {}
    await store.aclose_all()
