"""IdorOracle — her verdict yolu. DESIGN.md §14.

Sahte hedef uygulama (MockTransport) ile: vulnerable → CONFIRMED, secure → REJECTED,
kör oracle → INCONCLUSIVE.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import IdorOracle, base
from pentestai.policy import PolicyEngine

DB = {
    "A-100": {"id": "A-100", "email": "alice@test.local", "total": 42.5, "owner": "user_A"},
    "B-200": {"id": "B-200", "email": "bob@test.local", "total": 10.0, "owner": "user_B"},
}
TOKEN_ACTOR = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}
ENDPOINT = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
BASE = "http://localhost:3000"


def _id_of(request):
    return request.url.path.rsplit("/", 1)[-1]


def _actor_of(request):
    return TOKEN_ACTOR.get(request.headers.get("authorization", "").replace("Bearer ", ""))


def vulnerable_handler(request):
    oid = _id_of(request)
    if oid not in DB:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=DB[oid])          # ownership check YOK → IDOR


def secure_handler(request):
    oid = _id_of(request)
    if oid not in DB:
        return httpx.Response(404, json={"error": "not found"})
    if DB[oid]["owner"] != _actor_of(request):
        return httpx.Response(403, json={"error": "forbidden"})
    return httpx.Response(200, json=DB[oid])


def blind_handler(request):
    # id'yi TAMAMEN yok sayar → her istek aynı sabit cevap (gerçek körlük):
    # bogus == baseline olur, negative control düşer.
    return httpx.Response(200, json={"id": "X", "email": "same@test.local", "total": 1})


# Public endpoint: id'ye göre farklı cevap verir (negative control geçer) ama owner ayrımı YOK →
# herkes aynı public veriyi görür (ör. /rest/products/search). IDOR sayılmamalı.
PUBLIC = {"shared": {"status": "success", "data": [
    {"id": 1, "name": "Apple Juice (1000ml)", "price": 1.99},
    {"id": 2, "name": "Orange Juice (1000ml)", "price": 2.99}]}}


def public_handler(request):
    oid = _id_of(request)
    if oid not in PUBLIC:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=PUBLIC[oid])          # owner'a bakmadan aynı public veri


# Vulnerable ama ortak (public) bir marker paylaşan iki kayıt: total ikisinde de aynı.
MIXED = {
    "A-100": {"id": "A-100", "email": "alice@test.local", "total": 42.5},
    "B-200": {"id": "B-200", "email": "bob@test.local", "total": 42.5},   # ortak marker: 42.5
}


def mixed_handler(request):
    oid = _id_of(request)
    if oid not in MIXED:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=MIXED[oid])           # ownership check YOK → gerçek IDOR


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": "A-100"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": "B-200"})
    oracle = IdorOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A), store.create(B)


@pytest.mark.asyncio
async def test_confirmed_on_vulnerable():
    store, oracle, A, B = _setup(vulnerable_handler)
    f = await oracle.run(ENDPOINT, A, B, resource_key="order")
    assert f.verdict == base.CONFIRMED
    assert f.confidence == "high"
    assert "alice@test.local" in f.evidence.leaked_markers
    assert f.evidence.positive_control and f.evidence.negative_control and f.evidence.baseline_stable
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_on_secure():
    store, oracle, A, B = _setup(secure_handler)
    f = await oracle.run(ENDPOINT, A, B, resource_key="order")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_public_endpoint_not_confirmed():
    # Public/paylaşımlı veri: saldırganın KENDİ meşru yanıtı da aynı marker'ları içerir →
    # sahibe-özel sızıntı yok → CONFIRMED verilmez (REJECTED). (search FP'sinin panzehiri.)
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(public_handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": "shared"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": "shared"})
    oracle = IdorOracle(Replayer(PolicyEngine(scope)), BASE)
    f = await oracle.run(ENDPOINT, store.create(A), store.create(B), resource_key="order")
    assert f.verdict == base.REJECTED
    assert not f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_shared_marker_filtered_but_private_leak_confirms():
    # Ortak marker (42.5) elenir ama kurbana özel marker (alice) sızarsa yine CONFIRMED.
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(mixed_handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": "A-100"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": "B-200"})
    oracle = IdorOracle(Replayer(PolicyEngine(scope)), BASE)
    f = await oracle.run(ENDPOINT, store.create(A), store.create(B), resource_key="order")
    assert f.verdict == base.CONFIRMED
    assert "alice@test.local" in f.evidence.leaked_markers
    assert "42.5" not in f.evidence.leaked_markers          # ortak/public marker sayılmaz
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_oracle_blind():
    # negative control fails (her şey 200) → verdict üretme
    store, oracle, A, B = _setup(blind_handler)
    f = await oracle.run(ENDPOINT, A, B, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    assert f.evidence.negative_control is False
    await store.aclose_all()


# ---- public-by-design anon kapısı (DESIGN.md §12, bug düzeltmesi) ----

USERS = {
    "name1": {"username": "name1", "email": "mail1@test.local"},
    "name2": {"username": "name2", "email": "mail2@test.local"},
}


def auth_required_idor_handler(request):
    # Gerçek BOLA: geçerli token ZORUNLU (anon=401) ama sahiplik kontrolü YOK.
    if not _actor_of(request):
        return httpx.Response(401, json={"error": "unauthorized"})
    oid = _id_of(request)
    if oid not in DB:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=DB[oid])


def public_email_handler(request):
    # VAmPI /users/v1/{username} gibi: e-postayı kimlik doğrulamasız da döner (public-by-design).
    oid = _id_of(request)
    if oid not in USERS:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=USERS[oid])


@pytest.mark.asyncio
async def test_confirmed_when_anon_blocked_real_bola():
    # anon=401 → sızan marker anonim erişilemez → gerçek yetki aşımı → CONFIRMED (anon kapısı yanlış indirme yapmamalı).
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(auth_required_idor_handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": "A-100"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": "B-200"})
    anon = store.create(Actor(name="anonymous", role="anonymous"))   # boş AuthState
    oracle = IdorOracle(Replayer(PolicyEngine(scope)), BASE)
    f = await oracle.run(ENDPOINT, store.create(A), store.create(B), resource_key="order", anon=anon)
    assert f.verdict == base.CONFIRMED
    assert "alice@test.local" in f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_public_by_design_anon_rejects():
    # Kurbanın e-postası anonim de dönüyorsa yetki sınırı yoktur → CONFIRMED değil, REJECTED.
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(public_email_handler))
    ep = Endpoint(method="GET", path_template="/users/{id}", id_param="id")
    A = Actor(name="name1", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"users": "name1"})
    B = Actor(name="name2", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"users": "name2"})
    anon = store.create(Actor(name="anonymous", role="anonymous"))
    oracle = IdorOracle(Replayer(PolicyEngine(scope)), BASE)
    # victim=name2 (e-postası sızacak), attacker=name1
    f = await oracle.run(ep, store.create(B), store.create(A), resource_key="users", anon=anon)
    assert f.verdict == base.REJECTED
    assert not f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_public_by_design_confirmed_without_anon_session():
    # anon verilmezse eski davranış korunur (geriye dönük uyum): public endpoint yine CONFIRMED olabilir.
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(public_email_handler))
    ep = Endpoint(method="GET", path_template="/users/{id}", id_param="id")
    A = Actor(name="name1", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"users": "name1"})
    B = Actor(name="name2", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"users": "name2"})
    oracle = IdorOracle(Replayer(PolicyEngine(scope)), BASE)
    f = await oracle.run(ep, store.create(B), store.create(A), resource_key="users")   # anon=None
    assert f.verdict == base.CONFIRMED   # anon kapısı olmadan sahibe-özel görünür → eski davranış
    await store.aclose_all()
