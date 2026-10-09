"""HTTP Parametre Kirliliği (HPP) oracle — kirletme-ile erişim-kontrol atlatma.

Sahte hedef: yetki kontrolünü bir id değerine, veri getirmeyi diğerine uygular (klasik HPP).
Kanıt = kurbanın sahibe-özel verisinin KİRLETİLMİŞ istekte sızması. Network yok: httpx.MockTransport.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.hpp import HppOracle
from pentestai.policy import PolicyEngine

ENDPOINT = Endpoint(method="GET", path_template="/rest/order", id_param="id",
                    id_location="query", resource_key="order")
BASE = "http://localhost:3000"

# V1 kurbanın (A), A1 saldırganın (B) objesi. Değerler sahibe-özel (email/balance → marker).
OWNER = {"V1": "A", "A1": "B"}
DATA = {
    "V1": {"order": "V1", "email": "victim-secret@private.local", "balance": "777777"},
    "A1": {"order": "A1", "email": "attacker@test.local", "balance": "10"},
}


def _who(request) -> str:
    return request.headers.get("authorization", "").split(" ")[-1]


def _ids(request) -> list[str]:
    return [v for k, v in request.url.params.multi_items() if k == "id"]


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    victim = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"}),
                                own_object_ids={"order": "V1"}))
    attacker = store.create(Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer B"}),
                                  own_object_ids={"order": "A1"}))
    return store, HppOracle(Replayer(PolicyEngine(scope)), BASE), victim, attacker


async def _run(handler, endpoint=ENDPOINT):
    store, oracle, victim, attacker = _setup(handler)
    f = await oracle.run(endpoint, victim, attacker, resource_key="order")
    await store.aclose_all()
    return f


def hpp_vuln(request):
    """Yetki kontrolü İLK id'ye, veri getirme SON id'ye uygulanır → kirletmeyle bypass."""
    who, ids = _who(request), _ids(request)
    if not ids:
        return httpx.Response(400, text="missing id")
    if OWNER.get(ids[0]) != who:                 # authz: ilk değer üzerinde
        return httpx.Response(403, text="forbidden")
    return httpx.Response(200, json=DATA.get(ids[-1], {}))   # veri: son değer


def hpp_safe(request):
    """Yetki kontrolü veri getirilen (son) id'ye uygulanır → kirletme bypass etmez."""
    who, ids = _who(request), _ids(request)
    if not ids:
        return httpx.Response(400, text="missing id")
    if OWNER.get(ids[-1]) != who:
        return httpx.Response(403, text="forbidden")
    return httpx.Response(200, json=DATA.get(ids[-1], {}))


def plain_idor(request):
    """Hiç yetki kontrolü yok — tek param bile sızdırır (düz IDOR, HPP değil)."""
    ids = _ids(request)
    if not ids:
        return httpx.Response(400, text="missing id")
    return httpx.Response(200, json=DATA.get(ids[-1], {}))


@pytest.mark.asyncio
async def test_hpp_confirmed_when_pollution_bypasses_authz():
    f = await _run(hpp_vuln)
    assert f.type == "parameter_pollution"
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("777777" in m or "victim-secret" in m for m in f.evidence.leaked_markers)


@pytest.mark.asyncio
async def test_hpp_rejected_when_authz_on_data_id():
    f = await _run(hpp_safe)
    assert f.verdict == base.REJECTED


@pytest.mark.asyncio
async def test_hpp_defers_to_idor_when_plain_already_leaks():
    # Düz istek zaten sızdırıyorsa bu düz IDOR → HppOracle REJECTED (çift sayım yok).
    f = await _run(plain_idor)
    assert f.verdict == base.REJECTED


@pytest.mark.asyncio
async def test_hpp_inconclusive_on_path_location():
    # HPP yalnızca query'de anlamlı; path endpoint'inde INCONCLUSIVE.
    ep = Endpoint(method="GET", path_template="/rest/order/{id}", id_param="id",
                  id_location="path", resource_key="order")
    f = await _run(hpp_vuln, ep)
    assert f.verdict == base.INCONCLUSIVE
