"""Provider adaptörleri (RK-8, GOREVLER.md Dalga 2) — PostgREST/Supabase/Hasura/Firebase.

Her adaptörün YALNIZCA sağlayıcıya özgü bir imza gözlendiğinde evidence döndüğünü ve
en az bir arka uçta gerçek trafikten endpoint/obje envanteri çıkarıldığını doğrular.
Network yok (httpx.MockTransport).
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine
from pentestai.recon.providers import (
    FirebaseAdapter, HasuraAdapter, PostgrestAdapter, ProviderRecon, SupabaseAdapter,
)

BASE = "http://localhost:3000"


def _setup(handler, *, base_url=BASE, hosts=("localhost",), ports=(3000,)):
    scope = Scope(allowed_hosts=list(hosts), allowed_ports=list(ports), allowed_path_prefixes=["/"])
    store = SessionStore(base_url=base_url, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    replayer = Replayer(PolicyEngine(scope))
    return store, replayer, session


# --- PostgREST ---

POSTGREST_ROOT = {
    "swagger": "2.0",
    "paths": {"/orders": {"get": {}}, "/users": {"get": {}}},
    "definitions": {"orders": {}, "users": {}},
}


def postgrest_handler(request):
    if request.url.path == "/":
        return httpx.Response(200, json=POSTGREST_ROOT)
    return httpx.Response(404, json={"error": "not found"})


@pytest.mark.asyncio
async def test_postgrest_detects_and_lists_real_tables():
    store, replayer, session = _setup(postgrest_handler)
    adapter = PostgrestAdapter(replayer, BASE)
    ev = await adapter.detect(session)
    assert ev is not None and ev.kind == "postgrest"
    assert ev.tables == ["orders", "users"]
    endpoints = adapter.inventory(ev)
    paths = {e.path_template for e in endpoints}
    assert paths == {"/orders", "/users"}
    await store.aclose_all()


@pytest.mark.asyncio
async def test_postgrest_none_when_no_openapi_signature():
    def plain_handler(request):
        return httpx.Response(200, json={"hello": "world"})

    store, replayer, session = _setup(plain_handler)
    ev = await PostgrestAdapter(replayer, BASE).detect(session)
    assert ev is None
    await store.aclose_all()


# --- Supabase ---

def supabase_handler(request):
    path = request.url.path
    if path == "/auth/v1/health":
        return httpx.Response(200, json={
            "version": "1.180.0", "name": "GoTrue",
            "description": "GoTrue is a user registration and authentication API",
        })
    if path == "/rest/v1/":
        return httpx.Response(200, json={
            "swagger": "2.0", "paths": {"/todos": {"get": {}}}, "definitions": {"todos": {}},
        })
    return httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_supabase_detects_gotrue_and_reuses_postgrest_inventory():
    store, replayer, session = _setup(supabase_handler)
    adapter = SupabaseAdapter(replayer, BASE)
    ev = await adapter.detect(session)
    assert ev is not None and ev.kind == "supabase"
    assert ev.tables == ["todos"]
    endpoints = adapter.inventory(ev)
    assert endpoints and endpoints[0].path_template == "/rest/v1/todos"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_supabase_none_without_gotrue_health():
    def other_handler(request):
        return httpx.Response(404, json={})

    store, replayer, session = _setup(other_handler)
    ev = await SupabaseAdapter(replayer, BASE).detect(session)
    assert ev is None
    await store.aclose_all()


# --- Hasura ---

def hasura_handler(request):
    if request.url.path == "/v1/version":
        return httpx.Response(200, json={"version": "v2.35.0"})
    return httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_hasura_detects_version_signature():
    store, replayer, session = _setup(hasura_handler)
    adapter = HasuraAdapter(replayer, BASE)
    ev = await adapter.detect(session)
    assert ev is not None and ev.kind == "hasura"
    endpoints = adapter.inventory(ev)
    assert endpoints[0].path_template == "/v1/graphql"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_hasura_none_when_version_shape_differs():
    def other_version_handler(request):
        if request.url.path == "/v1/version":
            return httpx.Response(200, json={"version": "v2.35.0", "extra": "field"})
        return httpx.Response(404, json={})

    store, replayer, session = _setup(other_version_handler)
    ev = await HasuraAdapter(replayer, BASE).detect(session)
    assert ev is None   # ekstra alan → Hasura'nın minimal şekli değil, iddia edilmez
    await store.aclose_all()


# --- Firebase ---

FB_BASE = "https://myproj.firebaseio.com"


def firebase_handler(request):
    path = request.url.path
    if path == "/.json":
        return httpx.Response(200, content=b"null", headers={"content-type": "application/json"})
    if path == "/users.json":
        return httpx.Response(200, json={"u1": {"name": "alice"}})
    return httpx.Response(200, content=b"null", headers={"content-type": "application/json"})


@pytest.mark.asyncio
async def test_firebase_requires_both_host_pattern_and_json_probe():
    store, replayer, session = _setup(
        firebase_handler, base_url=FB_BASE, hosts=("myproj.firebaseio.com",), ports=(443,))
    adapter = FirebaseAdapter(replayer, FB_BASE)
    ev = await adapter.detect(session)
    assert ev is not None and ev.kind == "firebase"
    assert ev.tables == ["users"]
    endpoints = adapter.inventory(ev)
    assert endpoints[0].path_template == "/users/{id}.json"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_firebase_none_when_host_does_not_match():
    store, replayer, session = _setup(firebase_handler)   # localhost, Firebase host deseni YOK
    ev = await FirebaseAdapter(replayer, BASE).detect(session)
    assert ev is None
    await store.aclose_all()


# --- ProviderRecon facade ---

@pytest.mark.asyncio
async def test_provider_recon_discovers_postgrest_and_dedupes_endpoints():
    store, replayer, session = _setup(postgrest_handler)
    recon = ProviderRecon(replayer, BASE, adapters=[
        PostgrestAdapter(replayer, BASE), PostgrestAdapter(replayer, BASE),  # aynı adaptör 2x
    ])
    evidence, endpoints = await recon.discover(session)
    assert len(evidence) == 2   # her adaptör kendi kanıtını raporlar
    paths = [e.path_template for e in endpoints]
    assert sorted(paths) == ["/orders", "/users"]   # ama envanter tekrarlanmıyor (dedup)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_provider_recon_empty_when_nothing_detected():
    def generic_handler(request):
        return httpx.Response(200, json={"ok": True})

    store, replayer, session = _setup(generic_handler)
    evidence, endpoints = await ProviderRecon(replayer, BASE).discover(session)
    assert evidence == [] and endpoints == []
    await store.aclose_all()
