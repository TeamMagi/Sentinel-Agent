"""JwtForgeAccessOracle — JWT claim forge → yetki yükseltme (yatay + dikey). ROADMAP.md (B).

Ağsız (MockTransport). Gerçek token'lar güçlü SERVER_SECRET ile HS256 imzalı; güvenli handler
imzayı doğrular (forge reddedilir → REJECTED), açık handler doğrulamaz (forge kabul → CONFIRMED).
Kanıt deterministik: forge edilen token kurbanın/ayrıcalıklının leaked-marker'ını sızdırıyor mu?
"""

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.jwt_forge import JwtForgeAccessOracle, decode_payload, encode_hs256, hs256
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
SERVER_SECRET = "server-strong-secret-not-in-wordlist-9f3a"   # zayıf liste DIŞI (kırılamaz)
EP = Endpoint(method="GET", path_template="/api/me")

# Kimliğe göre veri (yatay senaryo).
USERS = {
    "user_A": {"sub": "user_A", "email": "alice@test.local", "balance": 10},
    "user_B": {"sub": "user_B", "email": "bob@test.local", "balance": 42},
}


def _bearer(request):
    return request.headers.get("authorization", "").replace("Bearer ", "")


def _real_token(sub: str, role: str = "user") -> str:
    return encode_hs256({"sub": sub, "role": role}, SERVER_SECRET)


def _sig_valid(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    expected = hs256(f"{parts[0]}.{parts[1]}".encode(), SERVER_SECRET)
    return parts[2] == expected


# --- yatay: /api/me kimliğe göre veri döner ---

def me_app(*, verify_sig: bool):
    def handler(request):
        tok = _bearer(request)
        if verify_sig and not _sig_valid(tok):
            return httpx.Response(401, json={"error": "invalid token"})
        p = decode_payload(tok) or {}
        obj = USERS.get(p.get("sub"))
        return httpx.Response(200, json=obj) if obj else httpx.Response(404, json={})
    return handler


# --- dikey: /api/me role=admin ise tüm kullanıcıların (ayrıcalıklı) görünümü ---

def admin_view_app():
    def handler(request):
        p = decode_payload(_bearer(request)) or {}
        if p.get("role") == "admin":
            return httpx.Response(200, json={"sub": p.get("sub"),
                                             "users": [{"email": "root@internal.local"},
                                                       {"email": "alice@test.local"}]})
        obj = USERS.get(p.get("sub"))
        return httpx.Response(200, json=obj) if obj else httpx.Response(404, json={})
    return handler


def _setup(handler, *, attacker_has_jwt: bool = True, victim_role: str = "user"):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    a_headers = {"Authorization": f"Bearer {_real_token('user_A', 'user')}"} if attacker_has_jwt else {}
    A = Actor(name="user_A", auth=AuthState(headers=a_headers), own_object_ids={})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": f"Bearer {_real_token('user_B', victim_role)}"}))
    oracle = JwtForgeAccessOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A), store.create(B)


@pytest.mark.asyncio
async def test_horizontal_impersonation_confirmed():
    store, oracle, A, B = _setup(me_app(verify_sig=False))
    f = await oracle.run(EP, B, A)   # victim=B, attacker=A (A, B'nin kimliğini forge eder)
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("bob@test.local" in m for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_signature_verified():
    store, oracle, A, B = _setup(me_app(verify_sig=True))
    f = await oracle.run(EP, B, A)
    assert f.verdict == base.REJECTED   # forge (alg=none/tahrif/zayıf) reddedilir
    await store.aclose_all()


@pytest.mark.asyncio
async def test_vertical_role_escalation_confirmed():
    store, oracle, A, B = _setup(admin_view_app(), victim_role="admin")
    f = await oracle.run(EP, B, A)   # attacker=A (role=user) → role=admin forge → ayrıcalıklı görünüm
    assert f.verdict == base.CONFIRMED
    assert any("root@internal.local" in m for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_attacker_has_no_jwt():
    store, oracle, A, B = _setup(me_app(verify_sig=False), attacker_has_jwt=False)
    f = await oracle.run(EP, B, A)
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


def test_forge_variants_and_helpers_roundtrip():
    tok = encode_hs256({"sub": "x", "role": "user"}, SERVER_SECRET)
    assert decode_payload(tok) == {"sub": "x", "role": "user"}
    assert _sig_valid(tok)
    assert decode_payload("not-a-jwt") is None
