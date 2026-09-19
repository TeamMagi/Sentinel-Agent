"""CanaryPlanter + IdorOracle canary entegrasyonu — R-A1 (GOREVLER.md, ROADMAP.md Eksen A).

Sahte durumlu API (MockTransport): PUT ile yazılan alan GET'te geri okunuyor. Canary
yalnızca kurbanın objesine yazılır; saldırganın yanıtında görülürse şüpheye yer
bırakmayan (tartışmasız) bir leaked-marker'dır — "public_data" filtresini bile aşar.
"""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import CanaryPlanter, IdorOracle, base
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
TOKEN_ACTOR = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}
READ_EP = Endpoint(method="GET", path_template="/api/notes/{id}", id_param="id")
WRITE_EP = Endpoint(method="PUT", path_template="/api/notes/{id}", id_param="id")


def _id_of(request):
    return request.url.path.rsplit("/", 1)[-1]


def _actor_of(request):
    return TOKEN_ACTOR.get(request.headers.get("authorization", "").replace("Bearer ", ""))


def make_app():
    """Sahiplik kontrolü OLMAYAN not defteri: GET herkese açık dönüyor (IDOR), PUT yazdığı
    alanı kalıcı tutuyor — canary'nin gerçekten "okunabilir" olduğunu simüle eder."""
    db = {"N-1": {"id": "N-1", "owner": "user_A"}, "N-2": {"id": "N-2", "owner": "user_B"}}

    def handler(request):
        oid = _id_of(request)
        obj = db.get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if request.method == "PUT":
            body = json.loads(request.content or b"{}")
            obj.update(body)
            return httpx.Response(200, json=obj)
        return httpx.Response(200, json=obj)          # GET: ownership check YOK → IDOR

    return handler


def _setup(handler, *, destructive_tests=True, allowed_methods=("GET", "PUT")):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=list(allowed_methods), destructive_tests=destructive_tests)
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"note": "N-1"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"note": "N-2"})
    replayer = Replayer(PolicyEngine(scope))
    planter = CanaryPlanter(replayer, BASE)
    oracle = IdorOracle(replayer, BASE)
    return store, planter, oracle, store.create(A), store.create(B)


@pytest.mark.asyncio
async def test_plant_returns_canary_on_success():
    store, planter, _oracle, A, _B = _setup(make_app())
    canary = await planter.plant(WRITE_EP, A, "N-1")
    assert canary is not None
    assert canary.startswith("snt-canary-")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_plant_noop_on_safe_method():
    store, planter, _oracle, A, _B = _setup(make_app())
    canary = await planter.plant(READ_EP, A, "N-1")   # GET → yazma denenmez
    assert canary is None
    await store.aclose_all()


@pytest.mark.asyncio
async def test_plant_none_when_policy_denies():
    # destructive_tests kapalı → policy kapısı PUT'u reddeder → sessizce None (§5.4).
    store, planter, _oracle, A, _B = _setup(make_app(), destructive_tests=False)
    canary = await planter.plant(WRITE_EP, A, "N-1")
    assert canary is None
    await store.aclose_all()


@pytest.mark.asyncio
async def test_plant_none_when_write_fails():
    def failing_handler(request):
        return httpx.Response(500, json={"error": "boom"})
    store, planter, _oracle, A, _B = _setup(failing_handler)
    canary = await planter.plant(WRITE_EP, A, "N-1")
    assert canary is None
    await store.aclose_all()


@pytest.mark.asyncio
async def test_idor_confirmed_via_canary_even_with_unrecognized_field_name():
    # "sentinel_canary" DEFAULT_IDENT_KEYS'te yok → canary verilmeden marker extractor bunu
    # ASLA yakalamaz. canary parametresiyle verilince yine de tartışmasız CONFIRMED üretilir.
    store, planter, oracle, A, B = _setup(make_app())
    canary = await planter.plant(WRITE_EP, A, "N-1")
    assert canary is not None
    f = await oracle.run(READ_EP, A, B, resource_key="note", canary=canary)
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert canary in f.evidence.leaked_markers
    assert f.evidence.canary_planted == canary
    await store.aclose_all()


@pytest.mark.asyncio
async def test_idor_not_falsely_confirmed_when_canary_absent_from_response():
    # Saldırgan kurbanın objesine ERİŞEMİYOR (403) → canary verilmiş olsa da yanlış CONFIRMED üretilmez.
    def secure_handler(request):
        oid = _id_of(request)
        db = {"N-1": {"id": "N-1", "owner": "user_A"}, "N-2": {"id": "N-2", "owner": "user_B"}}
        obj = db.get(oid)
        if obj is None:
            return httpx.Response(404, json={})
        if request.method == "PUT":
            return httpx.Response(200, json=obj)
        actor = _actor_of(request)
        owner_token = "TOKEN_A" if obj["owner"] == "user_A" else "TOKEN_B"
        if actor != TOKEN_ACTOR.get(owner_token):
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(200, json=obj)

    store, planter, oracle, A, B = _setup(secure_handler)
    canary = await planter.plant(WRITE_EP, A, "N-1")
    f = await oracle.run(READ_EP, A, B, resource_key="note", canary=canary)
    assert f.verdict == base.REJECTED
    assert not f.evidence.leaked_markers
    await store.aclose_all()
