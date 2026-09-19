"""GraphQLRecon (B5) — introspection tespiti + BOLA aday çıkarımı. Network yok."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.policy import PolicyEngine
from pentestai.recon.graphql import GraphQLRecon

BASE = "http://localhost:3000"

SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [{"name": "Query", "kind": "OBJECT", "fields": [
        {"name": "user", "args": [{"name": "id"}]},
        {"name": "products", "args": []},
    ]}],
}}}


def gql_enabled(request):
    if request.url.path == "/graphql" and "__schema" in str(request.url):
        return httpx.Response(200, json=SCHEMA)
    return httpx.Response(404, json={"error": "not found"})


def gql_disabled(request):
    # introspection kapalı: __schema sorgusu hata döner
    return httpx.Response(400, json={"errors": [{"message": "introspection disabled"}]})


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    return store, GraphQLRecon(Replayer(PolicyEngine(scope)), BASE), s


@pytest.mark.asyncio
async def test_introspection_enabled_yields_confirmed_and_bola_candidates():
    store, recon, s = _setup(gql_enabled)
    res = await recon.introspect(s)
    await store.aclose_all()
    assert res is not None and res.enabled
    assert res.path == "/graphql"
    assert res.finding.type == "graphql_introspection" and res.finding.verdict == base.CONFIRMED
    assert ("user", "id") in res.bola_candidates()   # id argümanlı sorgu → BOLA adayı


@pytest.mark.asyncio
async def test_build_query_produces_valid_graphql_body():
    _, recon, _ = _setup(gql_enabled)
    body = recon.build_query("user", "id", "42")
    assert '"query"' in body and "user(id:" in body.replace(" ", "")


@pytest.mark.asyncio
async def test_introspection_disabled_returns_none():
    store, recon, s = _setup(gql_disabled)
    res = await recon.introspect(s)
    await store.aclose_all()
    assert res is None
