"""GraphqlBolaOracle — RK-3 (GOREVLER.md Dalga 1). Network yok.

Sahte GraphQL sunucusu: `GET /graphql?query={ order(id: "X") { ... } }` sorgusunu (recon/
graphql.py'nin introspection'da kullandığıyla AYNI GET+query-param deseni — bkz. modül
docstring'i) ayrıştırıp obje döner. GraphQL'e özgü "erişim yok" biçimleri (`errors` alanı ya
da `data.order: null`) test edilir — IdorOracle'daki gibi HTTP status koduna güvenilmez.
"""
import re
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.graphql_bola import GraphqlBolaOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
TOKEN_ACTOR = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}
EP = Endpoint(method="GET", path_template="/graphql", id_param="id")
_QUERY_RE = re.compile(r'order\(id:\s*"([^"]+)"\)')


def _actor_of(request):
    return TOKEN_ACTOR.get(request.headers.get("authorization", "").replace("Bearer ", ""))


def _oid_of(request):
    qs = parse_qs(urlsplit(str(request.url)).query)
    query = qs.get("query", [""])[0]
    m = _QUERY_RE.search(query)
    return m.group(1) if m else None


def make_app(secure: bool):
    """Sahiplik kontrolü opsiyonel not defteri API'si (GraphQL)."""
    db = {
        "O-1": {"id": "O-1", "owner": "user_A", "email": "a@test.local"},
        "O-2": {"id": "O-2", "owner": "user_B", "email": "b@test.local"},
    }

    def handler(request):
        oid = _oid_of(request)
        obj = db.get(oid)
        actor = _actor_of(request)
        if obj is None:
            return httpx.Response(200, json={"data": {"order": None}})
        if secure and obj["owner"] != actor:
            return httpx.Response(200, json={"errors": [{"message": "forbidden"}]})
        return httpx.Response(200, json={"data": {"order": obj}})

    return handler


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": "O-1"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": "O-2"})
    oracle = GraphqlBolaOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A), store.create(B)


@pytest.mark.asyncio
async def test_confirmed_when_vulnerable():
    # destructive_tests=False (varsayılan) İLE de çalışır — GET+query-param, salt-okunur.
    store, oracle, A, B = _setup(make_app(secure=False))
    f = await oracle.run(EP, A, B, resource_key="order")   # victim=A, attacker=B
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.positive_control and f.evidence.negative_control and f.evidence.baseline_stable
    assert any("test.local" in m for m in f.evidence.leaked_markers)
    assert f.evidence.repro_curl.startswith("curl ")
    assert f.type == "graphql_bola" and f.method == "GET"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_secure():
    store, oracle, A, B = _setup(make_app(secure=True))
    f = await oracle.run(EP, A, B, resource_key="order")
    assert f.verdict == base.REJECTED
    assert not f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_victim_id_missing():
    store, oracle, A, B = _setup(make_app(secure=False))
    A.actor.own_object_ids.clear()
    f = await oracle.run(EP, A, B, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_server_ignores_id():
    # Sunucu id'yi hiç ayırt etmiyor (her zaman aynı objeyi dönüyor) → negative control düşer
    # → yanlış CONFIRMED yerine INCONCLUSIVE (§5.4).
    def handler(request):
        return httpx.Response(200, json={"data": {"order": {
            "id": "O-1", "owner": "user_A", "email": "a@test.local"}}})

    store, oracle, A, B = _setup(handler)
    f = await oracle.run(EP, A, B, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_data_is_public_not_owner_specific():
    # Kurbanın "marker"ı saldırganın KENDİ meşru yanıtında da varsa (paylaşımlı/public alan)
    # cross-owner sızıntı sayılmaz — false-positive'siz REJECTED.
    shared_name = "shared-catalog-name"

    def handler(request):
        oid = _oid_of(request)
        db = {
            "O-1": {"id": "O-1", "owner": "user_A", "name": shared_name},
            "O-2": {"id": "O-2", "owner": "user_B", "name": shared_name},
        }
        obj = db.get(oid)
        if obj is None:
            return httpx.Response(200, json={"data": {"order": None}})
        return httpx.Response(200, json={"data": {"order": obj}})

    store, oracle, A, B = _setup(handler)
    f = await oracle.run(EP, A, B, resource_key="order")
    assert f.verdict == base.REJECTED
    await store.aclose_all()
