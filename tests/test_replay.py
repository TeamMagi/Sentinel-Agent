"""Replayer — cross-contamination guard. DESIGN.md §14 (en kritik test).

Bir aktörün auth'u başka aktörün isteğinde ASLA görünmemeli.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, CapturedRequest, Scope
from pentestai.net import Replayer, ScopeError, SessionStore
from pentestai.policy import PolicyEngine


def _replayer():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    return Replayer(PolicyEngine(scope))


@pytest.mark.asyncio
async def test_no_cross_contamination():
    captured: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"ok": True})

    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}))
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}))
    sA, sB = store.create(A), store.create(B)
    replayer = _replayer()

    # base, user_A'nın token'ıyla yakalanmış (kirli):
    base = CapturedRequest(
        method="GET", url="http://localhost:3000/api/orders/1",
        headers={"Authorization": "Bearer TOKEN_A"},
    )

    await replayer.replay(base, sB)          # B ile replay
    assert captured[-1] == "Bearer TOKEN_B"   # A sızmadı

    await replayer.replay(base, sA)          # A ile replay
    assert captured[-1] == "Bearer TOKEN_A"

    await store.aclose_all()


@pytest.mark.asyncio
async def test_actor_cookie_never_leaks_to_out_of_scope_host():
    # SessionStore, aktör cookie'sini base_url'ün host'una bağlar (domain-scoped) — bu jar
    # başka bir kod yolundan yanlışlıkla farklı bir host'a kullanılırsa bile cookie sızmamalı.
    captured: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers.get("cookie"))
        return httpx.Response(200)

    store = SessionStore(base_url="http://localhost:3000", transport=httpx.MockTransport(handler))
    actor = Actor(name="user_A", auth=AuthState(cookies={"session": "S3CR3T"}))
    session = store.create(actor)

    await session.client.get("http://localhost:3000/api/x")
    assert captured[-1] == "session=S3CR3T"

    await session.client.get("http://evil.example/csrf-token")
    assert captured[-1] is None   # cookie dış host'a GİTMEDİ

    await store.aclose_all()


@pytest.mark.asyncio
async def test_out_of_scope_raises():
    def handler(request):  # pragma: no cover - çağrılmamalı
        raise AssertionError("scope dışı istek gönderildi!")

    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer T"}))
    sA = store.create(A)
    base = CapturedRequest(method="GET", url="http://evil.example:3000/x")
    with pytest.raises(ScopeError):
        await _replayer().replay(base, sA)
    await store.aclose_all()
